import type { DnskeyInfo, DsInfo, DsMatch } from './types';

function canonicalNameWire(name: string): Uint8Array {
  const normalized = name.endsWith('.') ? name.slice(0, -1) : name;
  if (normalized === '') return new Uint8Array([0]);
  const encoder = new TextEncoder();
  const parts: number[] = [];
  for (const label of normalized.toLowerCase().split('.')) {
    const bytes = encoder.encode(label);
    if (bytes.length === 0 || bytes.length > 63) throw new Error('Invalid DNS owner name.');
    parts.push(bytes.length, ...bytes);
  }
  parts.push(0);
  return new Uint8Array(parts);
}

function concatenate(left: Uint8Array, right: Uint8Array): Uint8Array {
  const value = new Uint8Array(left.length + right.length);
  value.set(left);
  value.set(right, left.length);
  return value;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

export function hex(bytes: Uint8Array): string {
  return [...bytes]
    .map((value) => value.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

export async function dnskeyDigest(
  owner: string,
  rdata: Uint8Array,
  digestType: 2 | 4,
): Promise<Uint8Array> {
  const algorithm = digestType === 2 ? 'SHA-256' : 'SHA-384';
  const input = concatenate(canonicalNameWire(owner), rdata);
  return new Uint8Array(await crypto.subtle.digest(algorithm, asArrayBuffer(input)));
}

export async function compareDsToDnskeys(
  owner: string,
  dsRecords: readonly DsInfo[],
  keys: readonly DnskeyInfo[],
): Promise<readonly DsMatch[]> {
  const matches: DsMatch[] = [];
  for (const ds of dsRecords) {
    if (ds.digestType !== 2 && ds.digestType !== 4) continue;
    for (const dnskey of keys) {
      if (dnskey.keyTag !== ds.keyTag || dnskey.algorithm !== ds.algorithm) continue;
      const calculated = await dnskeyDigest(owner, dnskey.record.rawRdata, ds.digestType);
      matches.push({
        digestType: ds.digestType,
        dnskey,
        ds,
        matches: equalBytes(calculated, ds.digest),
      });
    }
  }
  return matches;
}
