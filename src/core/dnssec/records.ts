import type { DnsRecord } from '../dns/types';
import type { DnskeyInfo, DsInfo, RrsigInfo, SignatureTimeState } from './types';

function readUint16(bytes: Uint8Array, offset: number): number | null {
  const high = bytes[offset];
  const low = bytes[offset + 1];
  return high === undefined || low === undefined ? null : (high << 8) | low;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object';
}

function numberField(value: Record<string, unknown>, name: string): number | null {
  const field = value[name];
  return typeof field === 'number' && Number.isInteger(field) && field >= 0 ? field : null;
}

function signatureTimeState(
  inception: number,
  expiration: number,
  now: number,
): SignatureTimeState {
  if (now < inception) return 'not-yet-valid';
  if (now > expiration) return 'expired';
  return 'current';
}

export function dnskeyKeyTag(rdata: Uint8Array): number {
  if (rdata.length < 4) throw new Error('DNSKEY RDATA is too short.');
  if (rdata[3] === 1) {
    const penultimate = rdata.at(-3);
    const last = rdata.at(-2);
    if (penultimate === undefined || last === undefined) {
      throw new Error('RSA/MD5 DNSKEY RDATA is too short.');
    }
    return (penultimate << 8) | last;
  }

  let accumulator = 0;
  for (let index = 0; index < rdata.length; index += 1) {
    const byte = rdata[index];
    if (byte === undefined) throw new Error('DNSKEY RDATA is malformed.');
    accumulator += index % 2 === 0 ? byte << 8 : byte;
  }
  accumulator += (accumulator >> 16) & 0xffff;
  return accumulator & 0xffff;
}

export function parseDnskey(record: DnsRecord): DnskeyInfo | null {
  if (record.type !== 'DNSKEY' || record.rawRdata.length < 4) return null;
  const flags = readUint16(record.rawRdata, 0);
  const protocol = record.rawRdata[2];
  const algorithm = record.rawRdata[3];
  if (flags === null || protocol === undefined || algorithm === undefined) return null;
  return {
    algorithm,
    flags,
    key: record.rawRdata.slice(4),
    keyTag: dnskeyKeyTag(record.rawRdata),
    protocol,
    record,
    revoked: Boolean(flags & 0x0080),
    secureEntryPoint: Boolean(flags & 0x0001),
    zoneKey: Boolean(flags & 0x0100),
  };
}

export function parseDs(record: DnsRecord): DsInfo | null {
  if (record.type !== 'DS' || record.rawRdata.length < 5) return null;
  const keyTag = readUint16(record.rawRdata, 0);
  const algorithm = record.rawRdata[2];
  const digestType = record.rawRdata[3];
  if (keyTag === null || algorithm === undefined || digestType === undefined) return null;
  return {
    algorithm,
    digest: record.rawRdata.slice(4),
    digestType,
    keyTag,
    record,
  };
}

export function parseRrsig(
  record: DnsRecord,
  now = Math.floor(Date.now() / 1000),
): RrsigInfo | null {
  if (record.type !== 'RRSIG' || !isObject(record.data)) return null;
  const algorithm = numberField(record.data, 'algorithm');
  const labels = numberField(record.data, 'labels');
  const originalTtl = numberField(record.data, 'originalTTL');
  const expiration = numberField(record.data, 'expiration');
  const inception = numberField(record.data, 'inception');
  const keyTag = numberField(record.data, 'keyTag');
  const typeCovered = record.data['typeCovered'];
  const signerName = record.data['signersName'];
  const signature = record.data['signature'];
  if (
    algorithm === null ||
    labels === null ||
    originalTtl === null ||
    expiration === null ||
    inception === null ||
    keyTag === null ||
    typeof typeCovered !== 'string' ||
    typeof signerName !== 'string' ||
    !(signature instanceof Uint8Array)
  ) {
    return null;
  }
  return {
    algorithm,
    expiration,
    inception,
    keyTag,
    labels,
    originalTtl,
    record,
    signature,
    signerName,
    timeState: signatureTimeState(inception, expiration, now),
    typeCovered,
  };
}

export function dnssecAlgorithmName(algorithm: number): string {
  const names: Readonly<Record<number, string>> = {
    1: 'RSA/MD5',
    3: 'DSA/SHA-1',
    5: 'RSA/SHA-1',
    6: 'DSA-NSEC3-SHA1',
    7: 'RSASHA1-NSEC3-SHA1',
    8: 'RSA/SHA-256',
    10: 'RSA/SHA-512',
    12: 'GOST R 34.10-2001',
    13: 'ECDSA P-256/SHA-256',
    14: 'ECDSA P-384/SHA-384',
    15: 'Ed25519',
    16: 'Ed448',
  };
  return names[algorithm] ?? `Algorithm ${String(algorithm)}`;
}

export function digestTypeName(digestType: number): string {
  const names: Readonly<Record<number, string>> = {
    1: 'SHA-1',
    2: 'SHA-256',
    3: 'GOST R 34.11-94',
    4: 'SHA-384',
  };
  return names[digestType] ?? `Digest type ${String(digestType)}`;
}
