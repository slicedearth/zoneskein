import { toType } from '@dnsquery/dns-packet/types.js';

import type { DnsRecord } from '../dns/types';
import { parseDnskey, parseRrsig } from './records';
import type { DnskeyInfo, RrsigInfo, SignatureVerification } from './types';

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

function canonicalName(name: string): Uint8Array {
  const normalized = name.endsWith('.') ? name.slice(0, -1) : name;
  if (normalized === '') return new Uint8Array([0]);
  const encoder = new TextEncoder();
  const parts: number[] = [];
  for (const label of normalized.toLowerCase().split('.')) {
    const bytes = encoder.encode(label);
    parts.push(bytes.length, ...bytes);
  }
  parts.push(0);
  return new Uint8Array(parts);
}

function ownerForSignature(owner: string, labels: number): string {
  const ownerLabels = owner.replace(/\.$/u, '').split('.').filter(Boolean);
  if (ownerLabels.length <= labels) return owner;
  return `*.${ownerLabels.slice(-labels).join('.')}.`;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function signaturePrefix(signature: RrsigInfo): Uint8Array {
  return join([
    uint16(toType(signature.typeCovered)),
    new Uint8Array([signature.algorithm, signature.labels]),
    uint32(signature.originalTtl),
    uint32(signature.expiration),
    uint32(signature.inception),
    uint16(signature.keyTag),
    canonicalName(signature.signerName),
  ]);
}

export function dnskeyRrsetSignedData(
  records: readonly DnsRecord[],
  signature: RrsigInfo,
): Uint8Array {
  const owner = ownerForSignature(signature.record.owner, signature.labels);
  const canonicalRecords = records
    .filter(
      (record) =>
        record.type === 'DNSKEY' &&
        record.owner.toLowerCase() === signature.record.owner.toLowerCase(),
    )
    .map((record) => record.rawRdata)
    .sort(compareBytes)
    .map((rdata) =>
      join([
        canonicalName(owner),
        uint16(48),
        uint16(1),
        uint32(signature.originalTtl),
        uint16(rdata.length),
        rdata,
      ]),
    );
  return join([signaturePrefix(signature), ...canonicalRecords]);
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
  return {
    exponent: key.slice(lengthBytes, lengthBytes + exponentLength),
    modulus: key.slice(lengthBytes + exponentLength),
  };
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

export async function verifyDnskeyRrset(
  records: readonly DnsRecord[],
  now = Math.floor(Date.now() / 1000),
): Promise<readonly SignatureVerification[]> {
  const keys = records.flatMap((record) => {
    const key = parseDnskey(record);
    return key === null ? [] : [key];
  });
  const signatures = records.flatMap((record) => {
    const signature = parseRrsig(record, now);
    return signature?.typeCovered === 'DNSKEY' ? [signature] : [];
  });
  const results: SignatureVerification[] = [];

  for (const signature of signatures) {
    if (signature.timeState !== 'current') {
      results.push({
        algorithm: signature.algorithm,
        keyTag: signature.keyTag,
        message: `The signature is ${signature.timeState.replaceAll('-', ' ')}.`,
        status: 'outside-validity',
      });
      continue;
    }
    const candidates = keys.filter(
      (key) => key.keyTag === signature.keyTag && key.algorithm === signature.algorithm,
    );
    if (candidates.length === 0) {
      results.push({
        algorithm: signature.algorithm,
        keyTag: signature.keyTag,
        message: 'No matching DNSKEY was returned for this signature.',
        status: 'missing-key',
      });
      continue;
    }

    const data = dnskeyRrsetSignedData(records, signature);
    let supported = false;
    let verified = false;
    for (const key of candidates) {
      try {
        const result = await verifyWithKey(key, signature, data);
        if (result !== null) supported = true;
        if (result === true) verified = true;
      } catch {
        supported = false;
      }
    }
    results.push({
      algorithm: signature.algorithm,
      keyTag: signature.keyTag,
      message: verified
        ? 'The DNSKEY RRset signature verified locally.'
        : supported
          ? 'The DNSKEY RRset signature did not verify with the returned key.'
          : 'This browser cannot verify this DNSSEC signature algorithm.',
      status: verified ? 'verified' : supported ? 'invalid' : 'unsupported',
    });
  }
  return results;
}
