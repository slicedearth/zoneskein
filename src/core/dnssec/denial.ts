import { toType } from '@dnsquery/dns-packet/types.js';

import type { DnsRecord } from '../dns/types';
import type { DnskeyInfo, SignatureVerification } from './types';
import { canonicalName, verifyRrset } from './verify';
import { DnssecWorkBudget } from './work-budget';

export type DsDenialState =
  | 'insecure'
  | 'not-delegated'
  | 'alias-boundary'
  | 'opt-out'
  | 'bogus'
  | 'unsupported'
  | 'incomplete';

export interface DsDenialResult {
  readonly explanation: string;
  readonly proofType?: 'NSEC' | 'NSEC3';
  readonly proofVerifications?: readonly (readonly SignatureVerification[])[];
  readonly state: DsDenialState;
  readonly verifications: readonly SignatureVerification[];
}

const MAX_NSEC3_ITERATIONS = 500;
const MAX_NSEC3_HASH_ROUNDS = 20_000;
const MAX_PROOF_RECORDS = 64;
const MAX_PROOF_RRSETS = 32;

function normalized(name: string): string {
  const lower = name.toLowerCase();
  return lower.endsWith('.') ? lower : `${lower}.`;
}

function readUint16(bytes: Uint8Array, offset: number): number | null {
  const high = bytes[offset];
  const low = bytes[offset + 1];
  return high === undefined || low === undefined ? null : (high << 8) | low;
}

function readName(
  bytes: Uint8Array,
  initialOffset = 0,
): { labels: readonly Uint8Array[]; offset: number } | null {
  const labels: Uint8Array[] = [];
  let offset = initialOffset;
  let wireLength = 1;
  while (offset < bytes.length) {
    const length = bytes[offset];
    if (length === undefined || length > 63 || (length & 0xc0) !== 0) return null;
    offset += 1;
    if (length === 0) return wireLength <= 255 ? { labels, offset } : null;
    if (offset + length > bytes.length) return null;
    labels.push(bytes.slice(offset, offset + length));
    wireLength += length + 1;
    offset += length;
  }
  return null;
}

function parseTypeBitmap(bytes: Uint8Array, offset: number): ReadonlySet<number> | null {
  const types = new Set<number>();
  let previousWindow = -1;
  while (offset < bytes.length) {
    const window = bytes[offset];
    const length = bytes[offset + 1];
    if (
      window === undefined ||
      length === undefined ||
      window <= previousWindow ||
      length < 1 ||
      length > 32 ||
      offset + 2 + length > bytes.length
    )
      return null;
    const bitmap = bytes.slice(offset + 2, offset + 2 + length);
    if (bitmap.at(-1) === 0) return null;
    for (let octetIndex = 0; octetIndex < bitmap.length; octetIndex += 1) {
      const octet = bitmap[octetIndex];
      if (octet === undefined) return null;
      for (let bit = 0; bit < 8; bit += 1) {
        if ((octet & (1 << (7 - bit))) !== 0) types.add(window * 256 + octetIndex * 8 + bit);
      }
    }
    previousWindow = window;
    offset += 2 + length;
  }
  return types;
}

type DelegationBitmap = 'alias-boundary' | 'contradiction' | 'delegation' | 'other';

function delegationBitmap(types: ReadonlySet<number>): DelegationBitmap {
  if (types.has(toType('DS')) || types.has(toType('CNAME'))) return 'contradiction';
  if (types.has(toType('DNAME'))) return 'alias-boundary';
  return types.has(toType('NS')) && !types.has(toType('SOA')) ? 'delegation' : 'other';
}

function safeClosestEncloserBitmap(types: ReadonlySet<number>): boolean {
  if (types.has(toType('DNAME'))) return false;
  return !types.has(toType('NS')) || types.has(toType('SOA'));
}

function foldAscii(byte: number): number {
  return byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte;
}

function dnsNameLabels(name: string): readonly Uint8Array[] | null {
  const value = name.endsWith('.') ? name.slice(0, -1) : name;
  if (value === '.') return [];
  if (value === '') return [];
  const labels: Uint8Array[] = [];
  for (const label of value.split('.')) {
    if (label.length === 0 || label.length > 63) return null;
    const bytes = new Uint8Array(label.length);
    for (let index = 0; index < label.length; index += 1) {
      const code = label.charCodeAt(index);
      if (code > 0x7f) return null;
      bytes[index] = code;
    }
    labels.push(bytes);
  }
  return labels;
}

function compareLabels(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = foldAscii(left[index] ?? 0) - foldAscii(right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function canonicalDnsNameCompare(
  leftLabels: readonly Uint8Array[],
  rightLabels: readonly Uint8Array[],
): number {
  const canonicalLeft = leftLabels.toReversed();
  const canonicalRight = rightLabels.toReversed();
  const length = Math.min(canonicalLeft.length, canonicalRight.length);
  for (let index = 0; index < length; index += 1) {
    const leftLabel = canonicalLeft[index];
    const rightLabel = canonicalRight[index];
    if (leftLabel === undefined || rightLabel === undefined) break;
    const difference = compareLabels(leftLabel, rightLabel);
    if (difference !== 0) return difference;
  }
  return canonicalLeft.length - canonicalRight.length;
}

function labelsEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && compareLabels(left, right) === 0;
}

function isStrictSubdomain(
  name: readonly Uint8Array[],
  ancestor: readonly Uint8Array[],
): boolean {
  if (name.length <= ancestor.length) return false;
  return ancestor.every((label, index) =>
    labelsEqual(name[name.length - ancestor.length + index] ?? new Uint8Array(), label),
  );
}

function nsecProvesEmptyNonTerminal(
  owner: string,
  next: readonly Uint8Array[],
  target: string,
  bitmap: ReadonlySet<number>,
): boolean {
  const ownerLabels = dnsNameLabels(owner);
  const targetLabels = dnsNameLabels(target);
  if (ownerLabels === null || targetLabels === null) return false;
  if (canonicalDnsNameCompare(targetLabels, ownerLabels) <= 0) return false;
  if (
    isStrictSubdomain(targetLabels, ownerLabels) &&
    ((bitmap.has(toType('NS')) && !bitmap.has(toType('SOA'))) || bitmap.has(toType('DNAME')))
  )
    return false;
  const ownerBeforeNext = canonicalDnsNameCompare(ownerLabels, next) < 0;
  if (ownerBeforeNext && canonicalDnsNameCompare(targetLabels, next) >= 0) return false;
  if (!ownerBeforeNext && !isStrictSubdomain(targetLabels, next)) return false;
  return isStrictSubdomain(next, targetLabels);
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const value = new Uint8Array(left.length + right.length);
  value.set(left);
  value.set(right, left.length);
  return value;
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.length);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

async function sha1(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-1', asArrayBuffer(bytes)));
}

async function nsec3Hash(
  name: string,
  salt: Uint8Array,
  iterations: number,
  budget: DnssecWorkBudget,
): Promise<Uint8Array | null> {
  if (iterations > MAX_NSEC3_ITERATIONS) return null;
  let hash = await sha1(concat(canonicalName(name), salt));
  if (budget.cancelled) return null;
  for (let iteration = 0; iteration < iterations; iteration += 1) {
    hash = await sha1(concat(hash, salt));
    if (!budget.consume('nsec3HashRounds', 0)) return null;
  }
  return hash;
}

const BASE32HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

function base32hex(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      const symbol = BASE32HEX[(value >>> (bits - 5)) & 31];
      if (symbol === undefined) throw new Error('Base32hex encoding failed.');
      output += symbol;
      bits -= 5;
    }
  }
  if (bits > 0) {
    const symbol = BASE32HEX[(value << (5 - bits)) & 31];
    if (symbol === undefined) throw new Error('Base32hex encoding failed.');
    output += symbol;
  }
  return output;
}

function intervalCovers(owner: string, next: string, target: string): boolean {
  if (owner < next) return owner < target && target < next;
  return target > owner || target < next;
}

interface ParsedNsec3 {
  readonly bitmap: ReadonlySet<number>;
  readonly flags: number;
  readonly hashAlgorithm: number;
  readonly iterations: number;
  readonly nextHash: string;
  readonly salt: Uint8Array;
}

function parseNsec3(record: DnsRecord): ParsedNsec3 | null {
  const bytes = record.rawRdata;
  const hashAlgorithm = bytes[0];
  const flags = bytes[1];
  const iterations = readUint16(bytes, 2);
  const saltLength = bytes[4];
  if (
    hashAlgorithm === undefined ||
    flags === undefined ||
    iterations === null ||
    saltLength === undefined
  )
    return null;
  const saltStart = 5;
  const saltEnd = saltStart + saltLength;
  const hashLength = bytes[saltEnd];
  if (hashLength === undefined || (flags & ~1) !== 0 || saltEnd + 1 + hashLength > bytes.length)
    return null;
  const nextStart = saltEnd + 1;
  const nextEnd = nextStart + hashLength;
  const bitmap = parseTypeBitmap(bytes, nextEnd);
  if (bitmap === null || bitmap.has(toType('NSEC3'))) return null;
  return {
    bitmap,
    flags,
    hashAlgorithm,
    iterations,
    nextHash: base32hex(bytes.slice(nextStart, nextEnd)),
    salt: bytes.slice(saltStart, saltEnd),
  };
}

function recordsForProofRrset(
  authorities: readonly DnsRecord[],
  proof: DnsRecord,
): readonly DnsRecord[] {
  const owner = proof.owner.toLowerCase();
  return authorities.filter((record) => {
    if (record.owner.toLowerCase() !== owner || record.class.toUpperCase() !== 'IN')
      return false;
    if (record.type === proof.type)
      return (
        record.rawRdata.length === proof.rawRdata.length &&
        record.rawRdata.every((byte, index) => proof.rawRdata[index] === byte)
      );
    if (record.type !== 'RRSIG' || record.data === null || typeof record.data !== 'object')
      return false;
    return (record.data as Record<string, unknown>)['typeCovered'] === proof.type;
  });
}

function bytesIdentity(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function signerZone(keys: readonly DnskeyInfo[]): string | null {
  const zones = new Set(keys.map((key) => normalized(key.record.owner)));
  return zones.size === 1 ? ([...zones][0] ?? null) : null;
}

function nsec3OwnerHash(record: DnsRecord, zone: string, supported: boolean): string | null {
  const ownerLabels = normalized(record.owner).slice(0, -1).split('.').filter(Boolean);
  const zoneLabels = zone === '.' ? [] : zone.slice(0, -1).split('.');
  if (
    ownerLabels.length !== zoneLabels.length + 1 ||
    !zoneLabels.every(
      (label, index) => ownerLabels[index + 1]?.toLowerCase() === label.toLowerCase(),
    )
  )
    return null;
  const hash = ownerLabels[0]?.toUpperCase();
  if (hash === undefined || !/^[0-9A-V]+$/u.test(hash)) return null;
  if (supported && hash.length !== 32) return null;
  return hash;
}

function sameNsec3Parameters(left: ParsedNsec3, right: ParsedNsec3): boolean {
  if (
    left.hashAlgorithm !== right.hashAlgorithm ||
    left.iterations !== right.iterations ||
    left.salt.length !== right.salt.length
  )
    return false;
  return left.salt.every((byte, index) => right.salt[index] === byte);
}

interface VerifiedNsec3 {
  readonly ownerHash: string;
  readonly parsed: ParsedNsec3;
  readonly record: DnsRecord;
  readonly verifications: readonly SignatureVerification[];
}

function ancestors(name: string, zone: string): readonly string[] {
  const nameLabels = normalized(name).slice(0, -1).split('.').filter(Boolean);
  const zoneLabels = zone === '.' ? [] : zone.slice(0, -1).split('.').filter(Boolean);
  const values: string[] = [];
  for (let start = 0; start <= nameLabels.length - zoneLabels.length; start += 1) {
    const candidate = normalized(nameLabels.slice(start).join('.'));
    if (candidate === zone || candidate.endsWith(`.${zone}`) || zone === '.')
      values.push(candidate);
  }
  return values;
}

export async function validateDsDenial(
  name: string,
  authorities: readonly DnsRecord[],
  parentKeys: readonly DnskeyInfo[],
  now = Math.floor(Date.now() / 1000),
  budget = new DnssecWorkBudget(),
): Promise<DsDenialResult> {
  const target = normalized(name);
  const allVerifications: SignatureVerification[] = [];
  const zone = signerZone(parentKeys);
  if (zone === null)
    return {
      explanation: 'The trusted parent DNSKEY set does not identify one signer zone.',
      state: 'incomplete',
      verifications: [],
    };
  if (authorities.length > MAX_PROOF_RECORDS || !budget.consume('records', authorities.length))
    return {
      explanation: `The response exceeds the ${String(MAX_PROOF_RECORDS)}-record authenticated-denial work bound.`,
      state: 'incomplete',
      verifications: [],
    };

  const proofGroups = new Map<string, DnsRecord[]>();
  for (const proof of authorities.filter(
    (record) =>
      (record.type === 'NSEC' || record.type === 'NSEC3') &&
      record.class.toUpperCase() === 'IN',
  )) {
    const key = `${proof.type}|${normalized(proof.owner)}|${bytesIdentity(proof.rawRdata)}`;
    const group = proofGroups.get(key) ?? [];
    group.push(proof);
    proofGroups.set(key, group);
  }
  if (proofGroups.size > MAX_PROOF_RRSETS)
    return {
      explanation: `The response exceeds the ${String(MAX_PROOF_RRSETS)}-RRset authenticated-denial work bound.`,
      state: 'incomplete',
      verifications: [],
    };

  let sawProof = false;
  let sawUnsupported = false;
  let sawInvalid = false;
  let sawIncompleteOptOut = false;
  let sawResourceLimit = false;
  const verifiedNsec3: VerifiedNsec3[] = [];
  const hashCache = new Map<string, Promise<Uint8Array | null>>();
  const boundedNsec3Hash = (
    originalName: string,
    salt: Uint8Array,
    iterations: number,
  ): Promise<Uint8Array | null> => {
    const key = `${normalized(originalName)}|${String(iterations)}|${bytesIdentity(salt)}`;
    const existing = hashCache.get(key);
    if (existing !== undefined) return existing;
    const rounds = iterations + 1;
    if (!budget.consume('nsec3HashRounds', rounds)) {
      sawResourceLimit = true;
      return Promise.resolve(null);
    }
    const pending = nsec3Hash(originalName, salt, iterations, budget);
    hashCache.set(key, pending);
    return pending;
  };

  for (const proofs of proofGroups.values()) {
    const proof = proofs[0];
    if (proof === undefined) continue;
    sawProof = true;
    const verifications = await verifyRrset(
      recordsForProofRrset(authorities, proof),
      proof.type,
      parentKeys,
      now,
      budget,
    );
    allVerifications.push(...verifications);
    if (!verifications.some((verification) => verification.status === 'verified')) {
      if (verifications.some((verification) => verification.status === 'resource-limit'))
        sawResourceLimit = true;
      else if (verifications.some((verification) => verification.status === 'unsupported'))
        sawUnsupported = true;
      else sawInvalid = true;
      continue;
    }

    for (const member of proofs) {
      if (member.type === 'NSEC') {
        const next = readName(member.rawRdata);
        const bitmap = next === null ? null : parseTypeBitmap(member.rawRdata, next.offset);
        if (next === null || bitmap === null) {
          sawInvalid = true;
          continue;
        }
        if (normalized(member.owner) !== target) {
          if (nsecProvesEmptyNonTerminal(member.owner, next.labels, target, bitmap))
            return {
              explanation:
                'A locally verified NSEC interval proves that this intermediate name is an empty non-terminal rather than a delegation.',
              proofType: 'NSEC',
              proofVerifications: [verifications],
              state: 'not-delegated',
              verifications: allVerifications,
            };
          continue;
        }
        const kind = delegationBitmap(bitmap);
        if (kind === 'contradiction') {
          return {
            explanation:
              'The authenticated NSEC bitmap contradicts the claimed absence of the DS RRset.',
            proofType: 'NSEC',
            state: 'bogus',
            verifications: allVerifications,
          };
        }
        return {
          explanation:
            kind === 'delegation'
              ? 'A locally verified NSEC bitmap proves that the parent publishes NS but no DS or SOA at this delegation.'
              : kind === 'alias-boundary'
                ? 'A locally verified NSEC bitmap proves that a DNAME alias boundary exists at this name.'
                : 'A locally verified NSEC bitmap proves that DS is absent, but this name is not an unsigned delegation point.',
          proofType: 'NSEC',
          proofVerifications: [verifications],
          state:
            kind === 'delegation'
              ? 'insecure'
              : kind === 'alias-boundary'
                ? 'alias-boundary'
                : 'not-delegated',
          verifications: allVerifications,
        };
      }

      const nsec3 = parseNsec3(member);
      if (nsec3 === null) {
        sawInvalid = true;
        continue;
      }
      const supported = nsec3.hashAlgorithm === 1;
      const ownerHash = nsec3OwnerHash(member, zone, supported);
      if (ownerHash === null || (supported && member.rawRdata[5 + nsec3.salt.length] !== 20)) {
        sawInvalid = true;
        continue;
      }
      if (!supported || nsec3.iterations > MAX_NSEC3_ITERATIONS) {
        sawUnsupported = true;
        continue;
      }
      verifiedNsec3.push({ ownerHash, parsed: nsec3, record: member, verifications });
    }
  }

  for (const proof of verifiedNsec3) {
    const targetHashBytes = await boundedNsec3Hash(
      target,
      proof.parsed.salt,
      proof.parsed.iterations,
    );
    if (targetHashBytes === null) {
      if (!sawResourceLimit) sawUnsupported = true;
      continue;
    }
    const targetHash = base32hex(targetHashBytes);
    if (proof.ownerHash === targetHash) {
      const kind = delegationBitmap(proof.parsed.bitmap);
      if (kind === 'contradiction')
        return {
          explanation:
            'The authenticated NSEC3 bitmap contradicts the claimed absence of the DS RRset.',
          proofType: 'NSEC3',
          state: 'bogus',
          verifications: allVerifications,
        };
      return {
        explanation:
          kind === 'delegation'
            ? 'A locally verified exact-match NSEC3 bitmap proves that the parent publishes NS but no DS or SOA at this delegation.'
            : kind === 'alias-boundary'
              ? 'A locally verified exact-match NSEC3 bitmap proves that a DNAME alias boundary exists at this name.'
              : 'A locally verified exact-match NSEC3 bitmap proves that DS is absent, but this name is not an unsigned delegation point.',
        proofType: 'NSEC3',
        proofVerifications: [proof.verifications],
        state:
          kind === 'delegation'
            ? 'insecure'
            : kind === 'alias-boundary'
              ? 'alias-boundary'
              : 'not-delegated',
        verifications: allVerifications,
      };
    }
    if (proof.parsed.flags !== 1) continue;

    let closestEncloser: { name: string; proof: VerifiedNsec3 } | undefined;
    for (const candidateName of ancestors(target, zone)) {
      const hashBytes = await boundedNsec3Hash(
        candidateName,
        proof.parsed.salt,
        proof.parsed.iterations,
      );
      if (hashBytes === null) break;
      const hash = base32hex(hashBytes);
      const match = verifiedNsec3.find(
        (candidate) =>
          candidate.ownerHash === hash &&
          sameNsec3Parameters(candidate.parsed, proof.parsed) &&
          safeClosestEncloserBitmap(candidate.parsed.bitmap),
      );
      if (match !== undefined) {
        closestEncloser = { name: candidateName, proof: match };
        break;
      }
    }
    if (closestEncloser === undefined) {
      sawIncompleteOptOut = true;
      continue;
    }
    const targetLabels = target.slice(0, -1).split('.').filter(Boolean);
    const encloserLabels = closestEncloser.name.slice(0, -1).split('.').filter(Boolean);
    const nextCloser = normalized(
      targetLabels.slice(targetLabels.length - encloserLabels.length - 1).join('.'),
    );
    const nextHashBytes = await boundedNsec3Hash(
      nextCloser,
      proof.parsed.salt,
      proof.parsed.iterations,
    );
    if (
      nextHashBytes === null ||
      !intervalCovers(proof.ownerHash, proof.parsed.nextHash, base32hex(nextHashBytes))
    ) {
      sawIncompleteOptOut = true;
      continue;
    }
    return {
      explanation:
        'Locally verified NSEC3 records prove an Opt-Out interval, but they do not authenticate whether this covered name exists as an insecure delegation.',
      proofType: 'NSEC3',
      proofVerifications:
        closestEncloser.proof.record === proof.record
          ? [proof.verifications]
          : [proof.verifications, closestEncloser.proof.verifications],
      state: 'opt-out',
      verifications: allVerifications,
    };
  }

  if (sawResourceLimit)
    return {
      explanation: `The NSEC3 proof exceeds the ${String(MAX_NSEC3_HASH_ROUNDS)}-round local hashing work bound.`,
      state: 'incomplete',
      verifications: allVerifications,
    };
  if (sawUnsupported)
    return {
      explanation:
        'The parent returned an authenticated-denial form or parameters that this browser validator cannot safely evaluate.',
      state: 'unsupported',
      verifications: allVerifications,
    };
  if (sawInvalid)
    return {
      explanation:
        'The returned DS denial proof did not validate with the trusted parent keys.',
      state: 'bogus',
      verifications: allVerifications,
    };
  return {
    explanation: sawIncompleteOptOut
      ? 'The opt-out interval lacked a matching, locally verified closest-provable-encloser record.'
      : sawProof
        ? 'No returned authenticated denial proof established the DS result for this exact name.'
        : 'The response did not contain an NSEC or NSEC3 proof for the absent DS RRset.',
    state: 'incomplete',
    verifications: allVerifications,
  };
}
