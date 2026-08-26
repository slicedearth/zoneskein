import { toType } from '@dnsquery/dns-packet/types.js';

import type { DnsRecord } from '../dns/types';
import { canVerifyRrsigAlgorithm } from './algorithm-policy';
import { parseDnskey, parseRrsig } from './records';
import type { DnskeyInfo, RrsigInfo, SignatureVerification } from './types';
import { boundCanonicalRdata } from './wire-evidence';
import { DnssecWorkBudget } from './work-budget';

const MAX_RRSET_RECORDS = 64;
const MAX_RRSET_SIGNATURES = 16;
const MAX_VERIFICATION_KEYS = 32;

function uint16(value: number): Uint8Array {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

function uint32(value: number): Uint8Array {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function join(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((length, part) => length + part.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export function canonicalName(name: string): Uint8Array {
  const normalized = name.endsWith('.') ? name.slice(0, -1) : name;
  if (normalized === '') return new Uint8Array([0]);
  const encoder = new TextEncoder();
  const parts: number[] = [];
  for (const label of normalized.split('.')) {
    const bytes = encoder.encode(label);
    if (bytes.length === 0 || bytes.length > 63)
      throw new Error('DNS owner name contains an invalid label.');
    parts.push(
      bytes.length,
      ...bytes.map((byte) => (byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte)),
    );
  }
  parts.push(0);
  if (parts.length > 255) throw new Error('DNS owner name exceeds the wire-format limit.');
  return new Uint8Array(parts);
}

function ownerForSignature(owner: string, labels: number): string | null {
  const ownerLabels = owner.replace(/\.$/u, '').split('.').filter(Boolean);
  if (labels > ownerLabels.length) return null;
  if (ownerLabels.length === labels) return owner;
  const suffix = ownerLabels.slice(ownerLabels.length - labels).join('.');
  return suffix === '' ? '*.' : `*.${suffix}.`;
}

function nameIsAtOrBelow(owner: string, signer: string): boolean {
  const ownerLabels = owner.toLowerCase().replace(/\.$/u, '').split('.').filter(Boolean);
  const signerLabels = signer.toLowerCase().replace(/\.$/u, '').split('.').filter(Boolean);
  if (signerLabels.length > ownerLabels.length) return false;
  return signerLabels.every(
    (label, index) => ownerLabels[ownerLabels.length - signerLabels.length + index] === label,
  );
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function bytesKey(bytes: Uint8Array): string {
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value);
}

function recordTypeCode(type: string): number {
  if (type === 'SVCB') return 64;
  if (type === 'HTTPS') return 65;
  return toType(type);
}

function signaturePrefix(signature: RrsigInfo): Uint8Array {
  return join([
    uint16(recordTypeCode(signature.typeCovered)),
    new Uint8Array([signature.algorithm, signature.labels]),
    uint32(signature.originalTtl),
    uint32(signature.expiration),
    uint32(signature.inception),
    uint16(signature.keyTag),
    canonicalName(signature.signerName),
  ]);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object';
}

function integerField(
  value: Record<string, unknown>,
  field: string,
  maximum: number,
): number | null {
  const item = value[field];
  return typeof item === 'number' && Number.isInteger(item) && item >= 0 && item <= maximum
    ? item
    : null;
}

function stringField(value: Record<string, unknown>, field: string): string | null {
  const item = value[field];
  return typeof item === 'string' ? item : null;
}

function canonicalTargetRdata(target: unknown): Uint8Array | null {
  if (typeof target !== 'string') return null;
  try {
    return canonicalName(target);
  } catch {
    return null;
  }
}

function canonicalMxRdata(data: unknown): Uint8Array | null {
  if (!isObject(data)) return null;
  const preference = integerField(data, 'preference', 0xffff);
  const exchange = stringField(data, 'exchange');
  if (preference === null || exchange === null) return null;
  try {
    return join([uint16(preference), canonicalName(exchange)]);
  } catch {
    return null;
  }
}

function canonicalSoaRdata(data: unknown): Uint8Array | null {
  if (!isObject(data)) return null;
  const mname = stringField(data, 'mname');
  const rname = stringField(data, 'rname');
  const serial = integerField(data, 'serial', 0xffff_ffff);
  const refresh = integerField(data, 'refresh', 0xffff_ffff);
  const retry = integerField(data, 'retry', 0xffff_ffff);
  const expire = integerField(data, 'expire', 0xffff_ffff);
  const minimum = integerField(data, 'minimum', 0xffff_ffff);
  if (
    mname === null ||
    rname === null ||
    serial === null ||
    refresh === null ||
    retry === null ||
    expire === null ||
    minimum === null
  )
    return null;
  try {
    return join([
      canonicalName(mname),
      canonicalName(rname),
      uint32(serial),
      uint32(refresh),
      uint32(retry),
      uint32(expire),
      uint32(minimum),
    ]);
  } catch {
    return null;
  }
}

function canonicalSrvRdata(data: unknown): Uint8Array | null {
  if (!isObject(data)) return null;
  const priority = integerField(data, 'priority', 0xffff);
  const weight = integerField(data, 'weight', 0xffff);
  const port = integerField(data, 'port', 0xffff);
  const target = stringField(data, 'target');
  if (priority === null || weight === null || port === null || target === null) return null;
  try {
    return join([uint16(priority), uint16(weight), uint16(port), canonicalName(target)]);
  } catch {
    return null;
  }
}

function canonicalSvcbRdata(raw: Uint8Array): Uint8Array | null {
  if (raw.length < 3) return null;
  const value = raw.slice();
  let offset = 2;
  let wireLength = 1;
  while (offset < value.length) {
    const length = value[offset];
    if (length === undefined || length > 63 || (length & 0xc0) !== 0) return null;
    offset += 1;
    if (length === 0) return value;
    if (offset + length > value.length || wireLength + length + 1 > 255) return null;
    for (let index = offset; index < offset + length; index += 1) {
      const byte = value[index];
      if (byte === undefined) return null;
      if (byte >= 0x41 && byte <= 0x5a) value[index] = byte + 0x20;
    }
    wireLength += length + 1;
    offset += length;
  }
  return null;
}

function validOpaqueRdata(record: DnsRecord): boolean {
  if (record.type === 'A') return record.rawRdata.length === 4;
  if (record.type === 'AAAA') return record.rawRdata.length === 16;
  if (record.type === 'TLSA') return record.rawRdata.length >= 3;
  if (record.type === 'CAA') {
    const tagLength = record.rawRdata[1];
    return tagLength !== undefined && tagLength > 0 && tagLength + 2 <= record.rawRdata.length;
  }
  if (record.type === 'TXT') {
    let offset = 0;
    while (offset < record.rawRdata.length) {
      const length = record.rawRdata[offset];
      if (length === undefined || offset + 1 + length > record.rawRdata.length) return false;
      offset += length + 1;
    }
    return offset === record.rawRdata.length;
  }
  return false;
}

export function canonicalRdata(record: DnsRecord): Uint8Array | null {
  const bound = boundCanonicalRdata(record);
  if (bound !== undefined) return bound;
  if (
    record.type === 'DNSKEY' ||
    record.type === 'DS' ||
    record.type === 'NSEC' ||
    record.type === 'NSEC3'
  )
    return record.rawRdata;
  if (validOpaqueRdata(record)) return record.rawRdata;
  if (
    record.type === 'CNAME' ||
    record.type === 'DNAME' ||
    record.type === 'NS' ||
    record.type === 'PTR'
  )
    return canonicalTargetRdata(record.data);
  if (record.type === 'MX') return canonicalMxRdata(record.data);
  if (record.type === 'SOA') return canonicalSoaRdata(record.data);
  if (record.type === 'SRV') return canonicalSrvRdata(record.data);
  if (record.type === 'SVCB' || record.type === 'HTTPS')
    return canonicalSvcbRdata(record.rawRdata);
  return null;
}

export function rrsetSignedData(
  records: readonly DnsRecord[],
  signature: RrsigInfo,
): Uint8Array | null {
  const owner = ownerForSignature(signature.record.owner, signature.labels);
  if (owner === null || signature.record.class.toUpperCase() !== 'IN') return null;
  const canonicalRecords = records
    .filter(
      (record) =>
        record.type === signature.typeCovered &&
        record.class.toUpperCase() === 'IN' &&
        record.owner.toLowerCase() === signature.record.owner.toLowerCase(),
    )
    .map(canonicalRdata);
  if (canonicalRecords.length === 0 || canonicalRecords.some((rdata) => rdata === null))
    return null;
  try {
    const uniqueRdata = [
      ...new Map(
        (canonicalRecords as Uint8Array[]).map((rdata) => [bytesKey(rdata), rdata]),
      ).values(),
    ];
    const encodedRecords = uniqueRdata
      .sort(compareBytes)
      .map((rdata) =>
        join([
          canonicalName(owner),
          uint16(recordTypeCode(signature.typeCovered)),
          uint16(1),
          uint32(signature.originalTtl),
          uint16(rdata.length),
          rdata,
        ]),
      );
    return join([signaturePrefix(signature), ...encodedRecords]);
  } catch {
    return null;
  }
}

export function dnskeyRrsetSignedData(
  records: readonly DnsRecord[],
  signature: RrsigInfo,
): Uint8Array {
  const data = rrsetSignedData(records, signature);
  if (data === null) throw new Error('DNSKEY RRset could not be canonicalised.');
  return data;
}

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function rsaParts(key: Uint8Array): { exponent: Uint8Array; modulus: Uint8Array } | null {
  const first = key[0];
  if (first === undefined) return null;
  const exponentLength = first === 0 ? ((key[1] ?? 0) << 8) | (key[2] ?? 0) : first;
  const lengthBytes = first === 0 ? 3 : 1;
  if (exponentLength === 0 || lengthBytes + exponentLength >= key.length) return null;
  const exponent = key.slice(lengthBytes, lengthBytes + exponentLength);
  const modulus = key.slice(lengthBytes + exponentLength);
  const exponentBits = bitLength(exponent);
  if (
    exponentBits < 2 ||
    exponentBits > 64 ||
    exponent[0] === 0 ||
    ((exponent.at(-1) ?? 0) & 1) === 0 ||
    modulus[0] === 0
  )
    return null;
  return { exponent, modulus };
}

function bitLength(bytes: Uint8Array): number {
  const firstIndex = bytes.findIndex((byte) => byte !== 0);
  if (firstIndex < 0) return 0;
  const first = bytes[firstIndex];
  if (first === undefined) return 0;
  return (bytes.length - firstIndex - 1) * 8 + (32 - Math.clz32(first));
}

function verificationAlgorithmSupported(algorithm: number): boolean {
  return canVerifyRrsigAlgorithm(algorithm);
}

async function importVerificationKey(key: DnskeyInfo): Promise<CryptoKey | null> {
  if (
    key.algorithm === 5 ||
    key.algorithm === 7 ||
    key.algorithm === 8 ||
    key.algorithm === 10
  ) {
    const parts = rsaParts(key.key);
    if (parts === null) return null;
    const modulusBits = bitLength(parts.modulus);
    if (modulusBits > 4096 || (key.algorithm === 10 ? modulusBits < 1024 : modulusBits < 512))
      return null;
    const hash = key.algorithm === 8 ? 'SHA-256' : key.algorithm === 10 ? 'SHA-512' : 'SHA-1';
    return crypto.subtle.importKey(
      'jwk',
      {
        alg: key.algorithm === 8 ? 'RS256' : key.algorithm === 10 ? 'RS512' : 'RS1',
        e: base64Url(parts.exponent),
        ext: true,
        kty: 'RSA',
        n: base64Url(parts.modulus),
      },
      { hash, name: 'RSASSA-PKCS1-v1_5' },
      false,
      ['verify'],
    );
  }
  if (key.algorithm === 13 || key.algorithm === 14) {
    const expected = key.algorithm === 13 ? 64 : 96;
    if (key.key.length !== expected) return null;
    const raw = join([new Uint8Array([4]), key.key]);
    return crypto.subtle.importKey(
      'raw',
      asArrayBuffer(raw),
      { name: 'ECDSA', namedCurve: key.algorithm === 13 ? 'P-256' : 'P-384' },
      false,
      ['verify'],
    );
  }
  if (key.algorithm === 15) {
    if (key.key.length !== 32) return null;
    return crypto.subtle.importKey('raw', asArrayBuffer(key.key), { name: 'Ed25519' }, false, [
      'verify',
    ]);
  }
  return null;
}

async function verifyWithKey(
  key: DnskeyInfo,
  signature: RrsigInfo,
  data: Uint8Array,
): Promise<boolean | null> {
  if (key.algorithm === 16) {
    if (key.key.length !== 57 || signature.signature.length !== 114) return false;
    const { ed448 } = await import('@noble/curves/ed448.js');
    return ed448.verify(signature.signature, data, key.key);
  }
  const cryptoKey = await importVerificationKey(key);
  if (cryptoKey === null) return null;
  if (key.algorithm === 13 || key.algorithm === 14) {
    return crypto.subtle.verify(
      {
        hash: key.algorithm === 13 ? 'SHA-256' : 'SHA-384',
        name: 'ECDSA',
      },
      cryptoKey,
      asArrayBuffer(signature.signature),
      asArrayBuffer(data),
    );
  }
  if (key.algorithm === 15) {
    return crypto.subtle.verify(
      'Ed25519',
      cryptoKey,
      asArrayBuffer(signature.signature),
      asArrayBuffer(data),
    );
  }
  return crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    cryptoKey,
    asArrayBuffer(signature.signature),
    asArrayBuffer(data),
  );
}

export async function verifyRrset(
  records: readonly DnsRecord[],
  typeCovered: string,
  keys: readonly DnskeyInfo[],
  now = Math.floor(Date.now() / 1000),
  budget = new DnssecWorkBudget(),
): Promise<readonly SignatureVerification[]> {
  if (
    records.length > MAX_RRSET_RECORDS ||
    keys.length > MAX_VERIFICATION_KEYS ||
    !budget.consume('records', records.length) ||
    !budget.consume('keys', keys.length)
  )
    return [
      {
        algorithm: 0,
        keyTag: 0,
        message: 'The RRset exceeds the local cryptographic work bound.',
        status: 'resource-limit',
      },
    ];
  const signatures = records.flatMap((record) => {
    const signature = parseRrsig(record, now);
    return signature?.typeCovered === typeCovered ? [signature] : [];
  });
  if (
    signatures.length > MAX_RRSET_SIGNATURES ||
    !budget.consume('signatures', signatures.length)
  )
    return [
      {
        algorithm: 0,
        keyTag: 0,
        message: 'The RRset contains too many signatures for one local validation step.',
        status: 'resource-limit',
      },
    ];
  const results: SignatureVerification[] = [];

  for (const signature of signatures) {
    const signatureIdentity = {
      algorithm: signature.algorithm,
      expiration: signature.expiration,
      inception: signature.inception,
      keyTag: signature.keyTag,
    } as const;
    if (signature.timeState !== 'current') {
      results.push({
        ...signatureIdentity,
        message: `The signature is ${signature.timeState.replaceAll('-', ' ')}.`,
        status: 'outside-validity',
      });
      continue;
    }
    if (!nameIsAtOrBelow(signature.record.owner, signature.signerName)) {
      results.push({
        ...signatureIdentity,
        message: 'The RRSIG signer does not contain the signed RRset owner.',
        status: 'invalid',
      });
      continue;
    }
    const candidates = keys.filter(
      (key) =>
        key.keyTag === signature.keyTag &&
        key.algorithm === signature.algorithm &&
        key.protocol === 3 &&
        key.zoneKey &&
        !key.revoked &&
        (key.flags & ~0x0181) === 0 &&
        key.record.owner.toLowerCase() === signature.signerName.toLowerCase(),
    );
    if (candidates.length === 0) {
      results.push({
        ...signatureIdentity,
        message: 'No matching DNSKEY was returned for this signature.',
        status: 'missing-key',
      });
      continue;
    }

    const data = rrsetSignedData(records, signature);
    if (data === null) {
      results.push({
        ...signatureIdentity,
        message: `The ${signature.typeCovered} RRset could not be canonicalised safely.`,
        status: 'invalid',
      });
      continue;
    }
    let supported = false;
    let verified = false;
    for (const key of candidates) {
      if (!verificationAlgorithmSupported(key.algorithm)) continue;
      if (!budget.consume('cryptographicVerifications')) {
        results.push({
          ...signatureIdentity,
          message: budget.explanation,
          status: 'resource-limit',
        });
        return results;
      }
      if (key.algorithm === 16 && !budget.consume('ed448Verifications')) {
        results.push({
          ...signatureIdentity,
          message: budget.explanation,
          status: 'resource-limit',
        });
        return results;
      }
      try {
        const result = await verifyWithKey(key, signature, data);
        if (budget.cancelled) {
          results.push({
            ...signatureIdentity,
            message: budget.explanation,
            status: 'resource-limit',
          });
          return results;
        }
        supported = true;
        if (result === true) verified = true;
      } catch (cause) {
        if (!(cause instanceof DOMException && cause.name === 'NotSupportedError'))
          supported = true;
        // Another matching key or signature can still establish this RRset.
      }
    }
    results.push({
      ...signatureIdentity,
      message: verified
        ? `The ${signature.typeCovered} RRset signature verified locally.`
        : supported
          ? `The ${signature.typeCovered} RRset signature did not verify with the trusted key.`
          : 'This validator cannot verify this DNSSEC signature algorithm.',
      status: verified ? 'verified' : supported ? 'invalid' : 'unsupported',
    });
  }
  return results;
}

export async function verifyDnskeyRrset(
  records: readonly DnsRecord[],
  now = Math.floor(Date.now() / 1000),
  budget = new DnssecWorkBudget(),
): Promise<readonly SignatureVerification[]> {
  const keys = records.flatMap((record) => {
    const key = parseDnskey(record);
    return key === null ? [] : [key];
  });
  return verifyRrset(records, 'DNSKEY', keys, now, budget);
}
