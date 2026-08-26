import { toType } from '@dnsquery/dns-packet/types.js';

import type { DnsRecord } from '../dns/types';
import { parseRrsig } from './records';
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

export type ApplicationDenialState = 'secure' | 'bogus' | 'unsupported' | 'incomplete';

export type ApplicationDenialKind =
  'nodata' | 'name-error' | 'wildcard-nodata' | 'wildcard-answer' | 'compact-name-error';

export interface ApplicationDenialResult {
  readonly explanation: string;
  readonly kind?: ApplicationDenialKind;
  readonly proofType?: 'NSEC' | 'NSEC3';
  readonly state: ApplicationDenialState;
  readonly verificationGroups: readonly (readonly SignatureVerification[])[];
  readonly verifications: readonly SignatureVerification[];
  readonly wildcardSignatureLabels: number | null;
}

const MAX_NSEC3_ITERATIONS = 500;
const MAX_NSEC3_HASH_ROUNDS = 20_000;
const MAX_PROOF_RECORDS = 64;
const MAX_PROOF_RRSETS = 32;
const NXNAME_TYPE = 128;

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

function isAtOrBelow(name: readonly Uint8Array[], ancestor: readonly Uint8Array[]): boolean {
  if (name.length < ancestor.length) return false;
  return ancestor.every((label, index) =>
    labelsEqual(name[name.length - ancestor.length + index] ?? new Uint8Array(), label),
  );
}

function namesEqual(left: readonly Uint8Array[], right: readonly Uint8Array[]): boolean {
  return (
    left.length === right.length &&
    left.every((label, index) => labelsEqual(label, right[index] ?? new Uint8Array()))
  );
}

function nameIsInZone(name: string, zone: string): boolean {
  const nameLabels = dnsNameLabels(name);
  const zoneLabels = dnsNameLabels(zone);
  return nameLabels !== null && zoneLabels !== null && isAtOrBelow(nameLabels, zoneLabels);
}

function wildcardName(closestEncloser: string): string {
  return closestEncloser === '.' ? '*.' : `*.${normalized(closestEncloser)}`;
}

function nextCloserName(name: string, closestEncloser: string): string | null {
  const nameLabels = normalized(name).slice(0, -1).split('.').filter(Boolean);
  const encloserLabels = normalized(closestEncloser).slice(0, -1).split('.').filter(Boolean);
  if (
    nameLabels.length <= encloserLabels.length ||
    !encloserLabels.every(
      (label, index) => nameLabels[nameLabels.length - encloserLabels.length + index] === label,
    )
  )
    return null;
  return normalized(nameLabels.slice(nameLabels.length - encloserLabels.length - 1).join('.'));
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

type DenialRecordType = 'NSEC' | 'NSEC3';

interface ReceivedProofRrset {
  readonly owner: string;
  readonly proofs: DnsRecord[];
  readonly type: DenialRecordType;
}

function nsecIsFromOtherAuthoritySide(
  proof: DnsRecord,
  authorities: readonly DnsRecord[],
  zone: string,
  now: number,
): boolean {
  const owner = normalized(proof.owner);
  if (!nameIsInZone(owner, zone)) return false;
  const next = readName(proof.rawRdata);
  const bitmap = next === null ? null : parseTypeBitmap(proof.rawRdata, next.offset);
  if (bitmap === null) return false;
  const signerNames = authorities.flatMap((record) => {
    if (normalized(record.owner) !== owner) return [];
    const signature = parseRrsig(record, now);
    return signature?.typeCovered === 'NSEC' ? [normalized(signature.signerName)] : [];
  });
  if (owner !== zone)
    return bitmap.has(toType('SOA')) && signerNames.some((signer) => signer === owner);
  return (
    !bitmap.has(toType('SOA')) &&
    signerNames.some((signer) => signer !== zone && nameIsInZone(owner, signer))
  );
}

function recordsForProofRrset(
  authorities: readonly DnsRecord[],
  group: ReceivedProofRrset,
  zone: string,
  now: number,
): readonly DnsRecord[] {
  const signatures = authorities.filter((record) => {
    if (
      normalized(record.owner) !== group.owner ||
      record.class.toUpperCase() !== 'IN' ||
      record.type !== 'RRSIG'
    )
      return false;
    const signature = parseRrsig(record, now);
    return signature?.typeCovered === group.type && normalized(signature.signerName) === zone;
  });
  return [...group.proofs, ...signatures];
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

interface VerifiedNsec {
  readonly bitmap: ReadonlySet<number>;
  readonly next: readonly Uint8Array[];
  readonly owner: readonly Uint8Array[];
  readonly record: DnsRecord;
  readonly verifications: readonly SignatureVerification[];
}

interface DenialEvidenceStatus {
  resourceExplanation?: string;
  sawInvalid: boolean;
  sawProof: boolean;
  sawResourceLimit: boolean;
  sawUnsupported: boolean;
}

interface DenialEvidence {
  readonly budget: DnssecWorkBudget;
  readonly hashCache: Map<string, Promise<Uint8Array | null>>;
  readonly nsec: readonly VerifiedNsec[];
  readonly nsec3: readonly VerifiedNsec3[];
  readonly status: DenialEvidenceStatus;
  readonly verifications: readonly SignatureVerification[];
  readonly zone: string | null;
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

async function collectDenialEvidence(
  authorities: readonly DnsRecord[],
  keys: readonly DnskeyInfo[],
  now: number,
  budget: DnssecWorkBudget,
): Promise<DenialEvidence> {
  const status: DenialEvidenceStatus = {
    sawInvalid: false,
    sawProof: false,
    sawResourceLimit: false,
    sawUnsupported: false,
  };
  const verifications: SignatureVerification[] = [];
  const nsec: VerifiedNsec[] = [];
  const nsec3: VerifiedNsec3[] = [];
  const zone = signerZone(keys);
  const evidence = {
    budget,
    hashCache: new Map<string, Promise<Uint8Array | null>>(),
    nsec,
    nsec3,
    status,
    verifications,
    zone,
  } satisfies DenialEvidence;
  if (zone === null) return evidence;
  if (
    authorities.length > MAX_PROOF_RECORDS ||
    !budget.consume('records', authorities.length)
  ) {
    status.sawResourceLimit = true;
    status.resourceExplanation =
      authorities.length > MAX_PROOF_RECORDS
        ? `The response exceeds the ${String(MAX_PROOF_RECORDS)}-record authenticated-denial work bound.`
        : budget.explanation;
    return evidence;
  }

  const proofGroups = new Map<string, ReceivedProofRrset>();
  for (const proof of authorities) {
    if ((proof.type !== 'NSEC' && proof.type !== 'NSEC3') || proof.class.toUpperCase() !== 'IN')
      continue;
    status.sawProof = true;
    if (proof.type === 'NSEC' && nsecIsFromOtherAuthoritySide(proof, authorities, zone, now))
      continue;
    const owner = normalized(proof.owner);
    const key = `${proof.type}|${owner}`;
    const group = proofGroups.get(key) ?? { owner, proofs: [], type: proof.type };
    if (
      !group.proofs.some(
        (member) => bytesIdentity(member.rawRdata) === bytesIdentity(proof.rawRdata),
      )
    )
      group.proofs.push(proof);
    proofGroups.set(key, group);
  }
  if (proofGroups.size > MAX_PROOF_RRSETS) {
    status.sawResourceLimit = true;
    status.resourceExplanation = `The response exceeds the ${String(MAX_PROOF_RRSETS)}-RRset authenticated-denial work bound.`;
    return evidence;
  }

  const zoneLabels = dnsNameLabels(zone);
  if (zoneLabels === null) {
    status.sawInvalid = true;
    return evidence;
  }
  for (const group of proofGroups.values()) {
    const proofRrset = recordsForProofRrset(authorities, group, zone, now);
    const proofVerifications = await verifyRrset(proofRrset, group.type, keys, now, budget);
    verifications.push(...proofVerifications);
    if (!proofVerifications.some((verification) => verification.status === 'verified')) {
      if (proofVerifications.some((verification) => verification.status === 'resource-limit')) {
        status.sawResourceLimit = true;
        status.resourceExplanation ??= budget.explanation;
      } else if (
        proofVerifications.some((verification) => verification.status === 'unsupported')
      )
        status.sawUnsupported = true;
      else status.sawInvalid = true;
      continue;
    }

    const expectedLabels = dnsNameLabels(group.owner)?.length;
    const proofSignatures = proofRrset.flatMap((record) => {
      const signature = parseRrsig(record, now);
      return signature?.typeCovered === group.type ? [signature] : [];
    });
    if (
      !proofSignatures.some(
        (signature, index) =>
          signature.labels === expectedLabels &&
          proofVerifications[index]?.status === 'verified',
      )
    ) {
      status.sawInvalid = true;
      continue;
    }

    for (const proof of group.proofs) {
      if (proof.type === 'NSEC') {
        const next = readName(proof.rawRdata);
        const bitmap = next === null ? null : parseTypeBitmap(proof.rawRdata, next.offset);
        const owner = dnsNameLabels(proof.owner);
        if (
          next === null ||
          bitmap === null ||
          owner === null ||
          !isAtOrBelow(owner, zoneLabels) ||
          !isAtOrBelow(next.labels, zoneLabels)
        ) {
          status.sawInvalid = true;
          continue;
        }
        const verified = {
          bitmap,
          next: next.labels,
          owner,
          record: proof,
          verifications: proofVerifications,
        } satisfies VerifiedNsec;
        if (bitmap.has(NXNAME_TYPE) && !validCompactNsec(verified)) {
          status.sawInvalid = true;
          continue;
        }
        nsec.push(verified);
        continue;
      }

      const parsed = parseNsec3(proof);
      if (parsed === null) {
        status.sawInvalid = true;
        continue;
      }
      const supported = parsed.hashAlgorithm === 1;
      const ownerHash = nsec3OwnerHash(proof, zone, supported);
      if (ownerHash === null || (supported && proof.rawRdata[5 + parsed.salt.length] !== 20)) {
        status.sawInvalid = true;
        continue;
      }
      if (!supported || parsed.iterations > MAX_NSEC3_ITERATIONS) {
        status.sawUnsupported = true;
        continue;
      }
      const verified = {
        ownerHash,
        parsed,
        record: proof,
        verifications: proofVerifications,
      } satisfies VerifiedNsec3;
      if (parsed.bitmap.has(NXNAME_TYPE) && !validCompactNsec3(verified)) {
        status.sawInvalid = true;
        continue;
      }
      nsec3.push(verified);
    }
  }
  return evidence;
}

async function nsec3NameHash(
  evidence: DenialEvidence,
  name: string,
  parameters: ParsedNsec3,
): Promise<string | null> {
  const key = `${normalized(name)}|${String(parameters.iterations)}|${bytesIdentity(parameters.salt)}`;
  let pending = evidence.hashCache.get(key);
  if (pending === undefined) {
    if (!evidence.budget.consume('nsec3HashRounds', parameters.iterations + 1)) {
      evidence.status.sawResourceLimit = true;
      evidence.status.resourceExplanation ??= evidence.budget.explanation;
      return null;
    }
    pending = nsec3Hash(
      normalized(name),
      parameters.salt,
      parameters.iterations,
      evidence.budget,
    ).catch(() => {
      evidence.status.sawInvalid = true;
      return null;
    });
    evidence.hashCache.set(key, pending);
  }
  const hash = await pending;
  if (hash === null) {
    evidence.status.sawResourceLimit = true;
    evidence.status.resourceExplanation ??= evidence.budget.explanation;
    return null;
  }
  return base32hex(hash);
}

function nsecCoversName(proof: VerifiedNsec, name: string): boolean {
  const target = dnsNameLabels(name);
  if (target === null || namesEqual(proof.owner, target)) return false;
  if (
    isStrictSubdomain(target, proof.owner) &&
    ((proof.bitmap.has(toType('NS')) && !proof.bitmap.has(toType('SOA'))) ||
      proof.bitmap.has(toType('DNAME')))
  )
    return false;
  const ownerToNext = canonicalDnsNameCompare(proof.owner, proof.next);
  const ownerToTarget = canonicalDnsNameCompare(proof.owner, target);
  const targetToNext = canonicalDnsNameCompare(target, proof.next);
  if (ownerToNext < 0) return ownerToTarget < 0 && targetToNext < 0;
  if (ownerToNext > 0) return ownerToTarget < 0 || targetToNext < 0;
  return true;
}

function nsecExactName(proof: VerifiedNsec, name: string): boolean {
  const target = dnsNameLabels(name);
  return target !== null && namesEqual(proof.owner, target);
}

function nsecDeniesName(proof: VerifiedNsec, name: string): boolean {
  return (
    nsecCoversName(proof, name) ||
    (nsecExactName(proof, name) && proof.bitmap.has(NXNAME_TYPE) && validCompactNsec(proof))
  );
}

function nsecNameExists(evidence: DenialEvidence, name: string): boolean {
  if (name === evidence.zone) return true;
  return nsecNameExistenceProof(evidence, name) !== undefined;
}

function nsecNameExistenceProof(
  evidence: DenialEvidence,
  name: string,
): VerifiedNsec | undefined {
  return evidence.nsec.find(
    (proof) =>
      (nsecExactName(proof, name) && !proof.bitmap.has(NXNAME_TYPE)) ||
      nsecProvesEmptyNonTerminal(proof.record.owner, proof.next, name, proof.bitmap),
  );
}

function closestNsecEncloser(evidence: DenialEvidence, name: string): string | null {
  if (evidence.zone === null) return null;
  for (const candidate of ancestors(name, evidence.zone).slice(1)) {
    if (nsecNameExists(evidence, candidate)) return candidate;
  }
  return null;
}

function nsec3ParameterKey(parameters: ParsedNsec3): string {
  return `${String(parameters.hashAlgorithm)}|${String(parameters.iterations)}|${bytesIdentity(parameters.salt)}`;
}

function nsec3Groups(evidence: DenialEvidence): readonly (readonly VerifiedNsec3[])[] {
  const groups = new Map<string, VerifiedNsec3[]>();
  for (const proof of evidence.nsec3) {
    const key = nsec3ParameterKey(proof.parsed);
    const values = groups.get(key) ?? [];
    values.push(proof);
    groups.set(key, values);
  }
  return [...groups.values()];
}

async function matchingNsec3(
  evidence: DenialEvidence,
  proofs: readonly VerifiedNsec3[],
  name: string,
): Promise<VerifiedNsec3 | null> {
  const parameters = proofs[0]?.parsed;
  if (parameters === undefined) return null;
  const hash = await nsec3NameHash(evidence, name, parameters);
  if (hash === null) return null;
  return proofs.find((proof) => proof.ownerHash === hash) ?? null;
}

async function coveringNsec3(
  evidence: DenialEvidence,
  proofs: readonly VerifiedNsec3[],
  name: string,
): Promise<VerifiedNsec3 | null> {
  const parameters = proofs[0]?.parsed;
  if (parameters === undefined) return null;
  const hash = await nsec3NameHash(evidence, name, parameters);
  if (hash === null) return null;
  return (
    proofs.find((proof) => intervalCovers(proof.ownerHash, proof.parsed.nextHash, hash)) ?? null
  );
}

function immediateNsecSuccessor(proof: VerifiedNsec): boolean {
  const first = proof.next[0];
  return (
    proof.next.length === proof.owner.length + 1 &&
    first?.length === 1 &&
    first[0] === 0 &&
    proof.owner.every((label, index) =>
      labelsEqual(label, proof.next[index + 1] ?? new Uint8Array()),
    )
  );
}

function compactNsecBitmap(bitmap: ReadonlySet<number>): boolean {
  return (
    bitmap.size === 3 &&
    bitmap.has(toType('RRSIG')) &&
    bitmap.has(toType('NSEC')) &&
    bitmap.has(NXNAME_TYPE)
  );
}

function compactNsec3Bitmap(bitmap: ReadonlySet<number>): boolean {
  return bitmap.size === 1 && bitmap.has(NXNAME_TYPE);
}

function validCompactNsec(proof: VerifiedNsec): boolean {
  return compactNsecBitmap(proof.bitmap) && immediateNsecSuccessor(proof);
}

function immediateNsec3Successor(proof: VerifiedNsec3): boolean {
  if (proof.ownerHash.length !== proof.parsed.nextHash.length) return false;
  const successor: number[] = [];
  for (let index = 0; index < proof.ownerHash.length; index += 1)
    successor.push(BASE32HEX.indexOf(proof.ownerHash.charAt(index)));
  if (successor.some((value) => value < 0)) return false;
  for (let index = successor.length - 1; index >= 0; index -= 1) {
    const value = successor[index];
    if (value === undefined) return false;
    successor[index] = (value + 1) & 31;
    if (value !== 31) break;
  }
  return successor.map((value) => BASE32HEX[value] ?? '').join('') === proof.parsed.nextHash;
}

function validCompactNsec3(proof: VerifiedNsec3): boolean {
  return compactNsec3Bitmap(proof.parsed.bitmap) && immediateNsec3Successor(proof);
}

function closestEncloserFromSignatureLabels(name: string, labels: number): string | null {
  const values = normalized(name).slice(0, -1).split('.').filter(Boolean);
  if (!Number.isSafeInteger(labels) || labels < 0 || labels >= values.length) return null;
  return normalized(values.slice(values.length - labels).join('.'));
}

function secureResult(
  evidence: DenialEvidence,
  kind: ApplicationDenialKind,
  proofType: 'NSEC' | 'NSEC3',
  explanation: string,
  proofs: readonly (VerifiedNsec | VerifiedNsec3)[],
  wildcardSignatureLabels: number | null = null,
): ApplicationDenialResult {
  const verificationGroups: (readonly SignatureVerification[])[] = [];
  for (const proof of proofs)
    if (!verificationGroups.includes(proof.verifications))
      verificationGroups.push(proof.verifications);
  return {
    explanation,
    kind,
    proofType,
    state: 'secure',
    verificationGroups,
    verifications: evidence.verifications,
    wildcardSignatureLabels,
  };
}

function bogusResult(
  evidence: DenialEvidence,
  proofType: 'NSEC' | 'NSEC3',
  explanation: string,
): ApplicationDenialResult {
  return {
    explanation,
    proofType,
    state: 'bogus',
    verificationGroups: [],
    verifications: evidence.verifications,
    wildcardSignatureLabels: null,
  };
}

interface Nsec3ClosestEncloserProof {
  readonly closestEncloser: string;
  readonly closestMatch: VerifiedNsec3;
  readonly nextCloserCover: VerifiedNsec3;
}

interface Nsec3ClosestEncloserSearch {
  readonly contradiction?: string;
  readonly proof?: Nsec3ClosestEncloserProof;
}

async function findNsec3ClosestEncloser(
  evidence: DenialEvidence,
  proofs: readonly VerifiedNsec3[],
  name: string,
): Promise<Nsec3ClosestEncloserSearch> {
  if (evidence.zone === null) return {};
  for (const candidate of ancestors(name, evidence.zone).slice(1)) {
    const match = await matchingNsec3(evidence, proofs, candidate);
    if (match === null) continue;
    if (match.parsed.bitmap.has(NXNAME_TYPE)) {
      if (!validCompactNsec3(match))
        return { contradiction: 'The signed NSEC3 NXNAME proof is malformed.' };
      continue;
    }
    if (!safeClosestEncloserBitmap(match.parsed.bitmap))
      return {
        contradiction:
          'The longest matching NSEC3 ancestor is a delegation or DNAME boundary and cannot establish the closest encloser.',
      };
    const nextCloser = nextCloserName(name, candidate);
    if (nextCloser === null)
      return { contradiction: 'The NSEC3 closest-encloser relationship is malformed.' };
    const cover = await coveringNsec3(evidence, proofs, nextCloser);
    if (cover === null) return {};
    return {
      proof: {
        closestEncloser: candidate,
        closestMatch: match,
        nextCloserCover: cover,
      },
    };
  }
  return {};
}

function failureResult(evidence: DenialEvidence, explanation: string): ApplicationDenialResult {
  if (evidence.zone === null)
    return {
      explanation: 'The authenticated DNSKEY set does not identify one signer zone.',
      state: 'incomplete',
      verificationGroups: [],
      verifications: evidence.verifications,
      wildcardSignatureLabels: null,
    };
  if (evidence.status.sawResourceLimit)
    return {
      explanation: evidence.status.resourceExplanation ?? evidence.budget.explanation,
      state: 'incomplete',
      verificationGroups: [],
      verifications: evidence.verifications,
      wildcardSignatureLabels: null,
    };
  if (evidence.nsec.length === 0 && evidence.nsec3.length === 0) {
    if (evidence.status.sawUnsupported)
      return {
        explanation:
          'The response uses authenticated-denial parameters unavailable to this browser validator.',
        state: 'unsupported',
        verificationGroups: [],
        verifications: evidence.verifications,
        wildcardSignatureLabels: null,
      };
    if (evidence.status.sawInvalid)
      return {
        explanation:
          'No returned authenticated-denial RRset validated with the trusted zone keys.',
        state: 'bogus',
        verificationGroups: [],
        verifications: evidence.verifications,
        wildcardSignatureLabels: null,
      };
  }
  return {
    explanation,
    state: 'incomplete',
    verificationGroups: [],
    verifications: evidence.verifications,
    wildcardSignatureLabels: null,
  };
}

function applicationTypeCode(type: string): number {
  if (type === 'ZONEMD') return 63;
  if (type === 'SVCB') return 64;
  if (type === 'HTTPS') return 65;
  return toType(type);
}

export async function validateApplicationDenial(
  name: string,
  type: string,
  responseCode: string,
  authorities: readonly DnsRecord[],
  zoneKeys: readonly DnskeyInfo[],
  now = Math.floor(Date.now() / 1000),
  budget = new DnssecWorkBudget(),
): Promise<ApplicationDenialResult> {
  const target = normalized(name);
  const queriedType = applicationTypeCode(type);
  const cnameType = toType('CNAME');
  const evidence = await collectDenialEvidence(authorities, zoneKeys, now, budget);
  if (evidence.zone !== null && !nameIsInZone(target, evidence.zone))
    return failureResult(
      evidence,
      'The authenticated zone keys are not authoritative for the queried name.',
    );
  if (responseCode !== 'NOERROR' && responseCode !== 'NXDOMAIN')
    return failureResult(
      evidence,
      `The ${type} question returned ${responseCode}, which is not an authenticated NODATA or name-error form.`,
    );

  let compactProof:
    | {
        readonly proof: VerifiedNsec | VerifiedNsec3;
        readonly proofType: 'NSEC' | 'NSEC3';
        readonly valid: boolean;
      }
    | undefined;
  let exactNodataProof:
    | { readonly proof: VerifiedNsec | VerifiedNsec3; readonly proofType: 'NSEC' | 'NSEC3' }
    | undefined;
  let exactOrdinaryExists = false;
  let exactContradiction:
    { readonly proofType: 'NSEC' | 'NSEC3'; readonly reason: string } | undefined;

  for (const proof of evidence.nsec.filter((candidate) => nsecExactName(candidate, target))) {
    if (proof.bitmap.has(NXNAME_TYPE)) {
      compactProof ??= { proof, proofType: 'NSEC', valid: validCompactNsec(proof) };
      if (!validCompactNsec(proof))
        exactContradiction ??= {
          proofType: 'NSEC',
          reason:
            'The exact-owner NSEC NXNAME proof does not use the required compact bitmap and immediate successor.',
        };
      continue;
    }
    exactOrdinaryExists = true;
    if (proof.bitmap.has(queriedType) || proof.bitmap.has(cnameType))
      exactContradiction ??= {
        proofType: 'NSEC',
        reason: `The authenticated NSEC bitmap says that ${type} or CNAME data exists at the queried name.`,
      };
    else exactNodataProof ??= { proof, proofType: 'NSEC' };
  }

  for (const proofs of nsec3Groups(evidence)) {
    const proof = await matchingNsec3(evidence, proofs, target);
    if (proof === null) continue;
    if (proof.parsed.bitmap.has(NXNAME_TYPE)) {
      compactProof ??= { proof, proofType: 'NSEC3', valid: validCompactNsec3(proof) };
      if (!validCompactNsec3(proof))
        exactContradiction ??= {
          proofType: 'NSEC3',
          reason:
            'The exact-match NSEC3 NXNAME proof does not use the required compact bitmap and immediate hash successor.',
        };
      continue;
    }
    exactOrdinaryExists = true;
    if (proof.parsed.bitmap.has(queriedType) || proof.parsed.bitmap.has(cnameType))
      exactContradiction ??= {
        proofType: 'NSEC3',
        reason: `The authenticated NSEC3 bitmap says that ${type} or CNAME data exists at the queried name.`,
      };
    else exactNodataProof ??= { proof, proofType: 'NSEC3' };
  }

  if (evidence.status.sawResourceLimit)
    return failureResult(evidence, 'The authenticated-denial work bound was exhausted.');

  if (exactContradiction !== undefined)
    return bogusResult(evidence, exactContradiction.proofType, exactContradiction.reason);
  if (compactProof !== undefined && exactOrdinaryExists)
    return bogusResult(
      evidence,
      compactProof.proofType,
      'Authenticated denial RRsets conflict about whether the queried name exists.',
    );
  if (compactProof?.valid === true)
    return secureResult(
      evidence,
      'compact-name-error',
      compactProof.proofType,
      responseCode === 'NXDOMAIN'
        ? 'An RFC 9824 NXNAME proof authenticates the compact name error and is consistent with the restored NXDOMAIN response code.'
        : 'An RFC 9824 NXNAME proof authenticates that the queried name does not exist despite the compact NOERROR response code.',
      [compactProof.proof],
    );

  const nsecEmptyNonTerminal = evidence.nsec.find(
    (proof) =>
      !nsecExactName(proof, target) &&
      nsecProvesEmptyNonTerminal(proof.record.owner, proof.next, target, proof.bitmap),
  );
  if (
    responseCode === 'NXDOMAIN' &&
    (exactOrdinaryExists || nsecEmptyNonTerminal !== undefined)
  )
    return bogusResult(
      evidence,
      exactNodataProof?.proofType ?? 'NSEC',
      'The authenticated denial evidence proves that the queried name exists, contradicting NXDOMAIN.',
    );
  if (responseCode === 'NOERROR' && exactNodataProof !== undefined)
    return secureResult(
      evidence,
      'nodata',
      exactNodataProof.proofType,
      `An authenticated exact-owner ${exactNodataProof.proofType} bitmap proves NODATA by omitting both ${type} and CNAME.`,
      [exactNodataProof.proof],
    );
  if (responseCode === 'NOERROR' && nsecEmptyNonTerminal !== undefined)
    return secureResult(
      evidence,
      'nodata',
      'NSEC',
      `An authenticated NSEC interval proves that the queried name is an empty non-terminal with no ${type} or CNAME RRset.`,
      [nsecEmptyNonTerminal],
    );

  if (responseCode === 'NXDOMAIN') {
    const closestEncloser = closestNsecEncloser(evidence, target);
    if (closestEncloser !== null) {
      const closestEncloserProof = nsecNameExistenceProof(evidence, closestEncloser);
      const nextCloser = nextCloserName(target, closestEncloser);
      const nextCloserProof =
        nextCloser === null
          ? undefined
          : evidence.nsec.find((proof) => nsecDeniesName(proof, nextCloser));
      if (nextCloserProof !== undefined) {
        const wildcard = wildcardName(closestEncloser);
        const exactWildcard = evidence.nsec.find((proof) => nsecExactName(proof, wildcard));
        if (exactWildcard !== undefined) {
          if (exactWildcard.bitmap.has(NXNAME_TYPE) && validCompactNsec(exactWildcard))
            return secureResult(
              evidence,
              'name-error',
              'NSEC',
              'Authenticated NSEC records cover the queried name and use NXNAME to deny the closest-encloser wildcard.',
              [
                ...(closestEncloserProof === undefined ? [] : [closestEncloserProof]),
                nextCloserProof,
                exactWildcard,
              ],
            );
          return bogusResult(
            evidence,
            'NSEC',
            'An authenticated NSEC record proves that the closest-encloser wildcard exists, contradicting NXDOMAIN.',
          );
        }
        if (nsecNameExists(evidence, wildcard))
          return bogusResult(
            evidence,
            'NSEC',
            'Authenticated NSEC evidence proves that the closest-encloser wildcard exists as an empty non-terminal.',
          );
        const wildcardCover = evidence.nsec.find((proof) => nsecCoversName(proof, wildcard));
        if (wildcardCover !== undefined)
          return secureResult(
            evidence,
            'name-error',
            'NSEC',
            'Authenticated NSEC intervals prove the NXDOMAIN name error by denying the next closer name and closest-encloser wildcard.',
            [
              ...(closestEncloserProof === undefined ? [] : [closestEncloserProof]),
              nextCloserProof,
              wildcardCover,
            ],
          );
      }
    }

    let sawOptOut = false;
    for (const proofs of nsec3Groups(evidence)) {
      const closest = await findNsec3ClosestEncloser(evidence, proofs, target);
      if (closest.contradiction !== undefined)
        return bogusResult(evidence, 'NSEC3', closest.contradiction);
      if (closest.proof === undefined) continue;
      if (closest.proof.nextCloserCover.parsed.flags === 1) {
        sawOptOut = true;
        continue;
      }
      const wildcard = wildcardName(closest.proof.closestEncloser);
      const wildcardMatch = await matchingNsec3(evidence, proofs, wildcard);
      if (wildcardMatch !== null) {
        if (wildcardMatch.parsed.bitmap.has(NXNAME_TYPE) && validCompactNsec3(wildcardMatch))
          return secureResult(
            evidence,
            'name-error',
            'NSEC3',
            'Authenticated NSEC3 records prove the closest encloser and next closer while NXNAME denies its wildcard.',
            [closest.proof.closestMatch, closest.proof.nextCloserCover, wildcardMatch],
          );
        return bogusResult(
          evidence,
          'NSEC3',
          'An authenticated NSEC3 match proves that the closest-encloser wildcard exists, contradicting NXDOMAIN.',
        );
      }
      const wildcardCover = await coveringNsec3(evidence, proofs, wildcard);
      if (wildcardCover !== null)
        return secureResult(
          evidence,
          'name-error',
          'NSEC3',
          'Authenticated NSEC3 records prove the NXDOMAIN name error by establishing the closest encloser, covering the next closer, and denying its wildcard.',
          [closest.proof.closestMatch, closest.proof.nextCloserCover, wildcardCover],
        );
    }
    return failureResult(
      evidence,
      sawOptOut
        ? 'The NSEC3 next-closer proof uses Opt-Out, so it cannot authenticate whether the queried name exists.'
        : 'The response lacks a complete authenticated closest-encloser, next-closer, and wildcard name-error proof.',
    );
  }

  const closestEncloser = closestNsecEncloser(evidence, target);
  if (closestEncloser !== null) {
    const closestEncloserProof = nsecNameExistenceProof(evidence, closestEncloser);
    const nextCloser = nextCloserName(target, closestEncloser);
    const nextCloserProof =
      nextCloser === null
        ? undefined
        : evidence.nsec.find((proof) => nsecDeniesName(proof, nextCloser));
    if (nextCloserProof !== undefined) {
      const wildcard = wildcardName(closestEncloser);
      const exactWildcard = evidence.nsec.find((proof) => nsecExactName(proof, wildcard));
      if (exactWildcard !== undefined && !exactWildcard.bitmap.has(NXNAME_TYPE)) {
        if (exactWildcard.bitmap.has(queriedType) || exactWildcard.bitmap.has(cnameType))
          return bogusResult(
            evidence,
            'NSEC',
            `The authenticated wildcard NSEC bitmap says that ${type} or CNAME data exists.`,
          );
        return secureResult(
          evidence,
          'wildcard-nodata',
          'NSEC',
          `Authenticated NSEC records prove wildcard NODATA for ${type} and deny the next closer name.`,
          [
            ...(closestEncloserProof === undefined ? [] : [closestEncloserProof]),
            nextCloserProof,
            exactWildcard,
          ],
        );
      }
      const wildcardExistenceProof = nsecNameExistenceProof(evidence, wildcard);
      if (wildcardExistenceProof !== undefined)
        return secureResult(
          evidence,
          'wildcard-nodata',
          'NSEC',
          `Authenticated NSEC records prove that an empty non-terminal wildcard matches but owns no ${type} or CNAME RRset.`,
          [
            ...(closestEncloserProof === undefined ? [] : [closestEncloserProof]),
            nextCloserProof,
            wildcardExistenceProof,
          ],
        );
    }
  }

  let sawOptOut = false;
  for (const proofs of nsec3Groups(evidence)) {
    const closest = await findNsec3ClosestEncloser(evidence, proofs, target);
    if (closest.contradiction !== undefined)
      return bogusResult(evidence, 'NSEC3', closest.contradiction);
    if (closest.proof === undefined) continue;
    if (closest.proof.nextCloserCover.parsed.flags === 1) {
      sawOptOut = true;
      continue;
    }
    const wildcard = wildcardName(closest.proof.closestEncloser);
    const wildcardMatch = await matchingNsec3(evidence, proofs, wildcard);
    if (wildcardMatch === null || wildcardMatch.parsed.bitmap.has(NXNAME_TYPE)) continue;
    if (
      wildcardMatch.parsed.bitmap.has(queriedType) ||
      wildcardMatch.parsed.bitmap.has(cnameType)
    )
      return bogusResult(
        evidence,
        'NSEC3',
        `The authenticated wildcard NSEC3 bitmap says that ${type} or CNAME data exists.`,
      );
    return secureResult(
      evidence,
      'wildcard-nodata',
      'NSEC3',
      `Authenticated NSEC3 records prove wildcard NODATA for ${type} with a complete closest-encloser proof.`,
      [closest.proof.closestMatch, closest.proof.nextCloserCover, wildcardMatch],
    );
  }
  return failureResult(
    evidence,
    sawOptOut
      ? 'The NSEC3 next-closer proof uses Opt-Out, so it cannot authenticate wildcard NODATA.'
      : `No complete authenticated NODATA proof was returned for ${type}.`,
  );
}

export async function validateWildcardAnswerDenial(
  name: string,
  signatureLabels: readonly number[],
  authorities: readonly DnsRecord[],
  zoneKeys: readonly DnskeyInfo[],
  now = Math.floor(Date.now() / 1000),
  budget = new DnssecWorkBudget(),
): Promise<ApplicationDenialResult> {
  const target = normalized(name);
  const evidence = await collectDenialEvidence(authorities, zoneKeys, now, budget);
  if (evidence.zone !== null && !nameIsInZone(target, evidence.zone))
    return failureResult(
      evidence,
      'The authenticated zone keys are not authoritative for the queried name.',
    );
  if (evidence.status.sawResourceLimit)
    return failureResult(evidence, 'The authenticated-denial work bound was exhausted.');
  const candidates = [...new Set(signatureLabels)].flatMap((labels) => {
    const closestEncloser = closestEncloserFromSignatureLabels(target, labels);
    return closestEncloser === null ? [] : [{ closestEncloser, labels }];
  });
  if (candidates.length === 0)
    return bogusResult(
      evidence,
      'NSEC',
      'The verified wildcard signature does not identify a valid closest encloser.',
    );

  if (nsecNameExists(evidence, target))
    return bogusResult(
      evidence,
      'NSEC',
      'Authenticated NSEC evidence says that the queried name exists, so wildcard synthesis was not permitted.',
    );
  for (const candidate of candidates) {
    const { closestEncloser } = candidate;
    if (
      evidence.zone === null ||
      !(
        closestEncloser === evidence.zone ||
        closestEncloser.endsWith(`.${evidence.zone}`) ||
        evidence.zone === '.'
      )
    )
      continue;
    const nextCloser = nextCloserName(target, closestEncloser);
    if (nextCloser === null) continue;
    if (nsecNameExists(evidence, nextCloser))
      return bogusResult(
        evidence,
        'NSEC',
        'Authenticated NSEC evidence proves that a closer name existed than the wildcard signature permits.',
      );
    const nextCloserProof = evidence.nsec.find((proof) => nsecDeniesName(proof, nextCloser));
    if (nextCloserProof !== undefined)
      return secureResult(
        evidence,
        'wildcard-answer',
        'NSEC',
        'The wildcard-expanded RRset signature and an authenticated NSEC next-closer denial both verified.',
        [nextCloserProof],
        candidate.labels,
      );
  }

  let sawOptOut = false;
  for (const proofs of nsec3Groups(evidence)) {
    const targetMatch = await matchingNsec3(evidence, proofs, target);
    if (
      targetMatch !== null &&
      !(targetMatch.parsed.bitmap.has(NXNAME_TYPE) && validCompactNsec3(targetMatch))
    )
      return bogusResult(
        evidence,
        'NSEC3',
        'An authenticated NSEC3 match says that the queried name exists, so wildcard synthesis was not permitted.',
      );
    for (const candidate of candidates) {
      const { closestEncloser } = candidate;
      if (
        evidence.zone === null ||
        !(
          closestEncloser === evidence.zone ||
          closestEncloser.endsWith(`.${evidence.zone}`) ||
          evidence.zone === '.'
        )
      )
        continue;
      const closestEncloserMatch = await matchingNsec3(evidence, proofs, closestEncloser);
      if (closestEncloserMatch === null || closestEncloserMatch.parsed.bitmap.has(NXNAME_TYPE))
        continue;
      if (!safeClosestEncloserBitmap(closestEncloserMatch.parsed.bitmap))
        return bogusResult(
          evidence,
          'NSEC3',
          'The authenticated NSEC3 closest-encloser match is a delegation or DNAME boundary and cannot authorise wildcard synthesis.',
        );
      const nextCloser = nextCloserName(target, closestEncloser);
      if (nextCloser === null) continue;
      const nextCloserMatch = await matchingNsec3(evidence, proofs, nextCloser);
      if (nextCloserMatch !== null) {
        if (
          nextCloserMatch.parsed.bitmap.has(NXNAME_TYPE) &&
          validCompactNsec3(nextCloserMatch)
        )
          return secureResult(
            evidence,
            'wildcard-answer',
            'NSEC3',
            'The wildcard-expanded RRset signature verified and an RFC 9824 NXNAME proof denies its next closer name.',
            [closestEncloserMatch, nextCloserMatch],
            candidate.labels,
          );
        return bogusResult(
          evidence,
          'NSEC3',
          'An authenticated NSEC3 match proves that a closer name existed than the wildcard signature permits.',
        );
      }
      const cover = await coveringNsec3(evidence, proofs, nextCloser);
      if (cover === null) continue;
      if (cover.parsed.flags === 1) {
        sawOptOut = true;
        continue;
      }
      return secureResult(
        evidence,
        'wildcard-answer',
        'NSEC3',
        'The wildcard-expanded RRset signature verified with authenticated NSEC3 closest-encloser and next-closer proofs.',
        [closestEncloserMatch, cover],
        candidate.labels,
      );
    }
  }
  return failureResult(
    evidence,
    sawOptOut
      ? 'The wildcard next-closer proof uses NSEC3 Opt-Out and cannot authenticate wildcard synthesis.'
      : 'The wildcard-expanded RRset lacks an authenticated closer-match denial proof.',
  );
}

export async function validateDsDenial(
  name: string,
  authorities: readonly DnsRecord[],
  parentKeys: readonly DnskeyInfo[],
  now = Math.floor(Date.now() / 1000),
  budget = new DnssecWorkBudget(),
): Promise<DsDenialResult> {
  const target = normalized(name);
  const evidence = await collectDenialEvidence(authorities, parentKeys, now, budget);
  const allVerifications = evidence.verifications;
  const zone = evidence.zone;
  if (zone === null)
    return {
      explanation: 'The trusted parent DNSKEY set does not identify one signer zone.',
      state: 'incomplete',
      verifications: allVerifications,
    };
  if (!nameIsInZone(target, zone))
    return {
      explanation: 'The trusted parent DNSKEY set is not authoritative for this DS name.',
      state: 'incomplete',
      verifications: allVerifications,
    };
  let sawIncompleteOptOut = false;

  for (const proof of evidence.nsec) {
    if (normalized(proof.record.owner) !== target) {
      if (nsecProvesEmptyNonTerminal(proof.record.owner, proof.next, target, proof.bitmap))
        return {
          explanation:
            'A locally verified NSEC interval proves that this intermediate name is an empty non-terminal rather than a delegation.',
          proofType: 'NSEC',
          proofVerifications: [proof.verifications],
          state: 'not-delegated',
          verifications: allVerifications,
        };
      continue;
    }
    const kind = delegationBitmap(proof.bitmap);
    if (kind === 'contradiction')
      return {
        explanation:
          'The authenticated NSEC bitmap contradicts the claimed absence of the DS RRset.',
        proofType: 'NSEC',
        state: 'bogus',
        verifications: allVerifications,
      };
    return {
      explanation:
        kind === 'delegation'
          ? 'A locally verified NSEC bitmap proves that the parent publishes NS but no DS or SOA at this delegation.'
          : kind === 'alias-boundary'
            ? 'A locally verified NSEC bitmap proves that a DNAME alias boundary exists at this name.'
            : 'A locally verified NSEC bitmap proves that DS is absent, but this name is not an unsigned delegation point.',
      proofType: 'NSEC',
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

  for (const proofs of nsec3Groups(evidence)) {
    const proof = await matchingNsec3(evidence, proofs, target);
    if (proof === null) continue;
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

  for (const proof of evidence.nsec3.filter((candidate) => candidate.parsed.flags === 1)) {
    let closestEncloser: { name: string; proof: VerifiedNsec3 } | undefined;
    for (const candidateName of ancestors(target, zone)) {
      const hash = await nsec3NameHash(evidence, candidateName, proof.parsed);
      if (hash === null) break;
      const match = evidence.nsec3.find(
        (candidate) =>
          candidate.ownerHash === hash &&
          sameNsec3Parameters(candidate.parsed, proof.parsed) &&
          !candidate.parsed.bitmap.has(NXNAME_TYPE) &&
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
    const nextCloser = nextCloserName(target, closestEncloser.name);
    const nextHash =
      nextCloser === null ? null : await nsec3NameHash(evidence, nextCloser, proof.parsed);
    if (
      nextHash === null ||
      !intervalCovers(proof.ownerHash, proof.parsed.nextHash, nextHash)
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

  if (evidence.status.sawResourceLimit)
    return {
      explanation:
        evidence.status.resourceExplanation ??
        `The NSEC3 proof exceeds the ${String(MAX_NSEC3_HASH_ROUNDS)}-round local hashing work bound.`,
      state: 'incomplete',
      verifications: allVerifications,
    };
  if (evidence.status.sawUnsupported)
    return {
      explanation:
        'The parent returned an authenticated-denial form or parameters that this browser validator cannot safely evaluate.',
      state: 'unsupported',
      verifications: allVerifications,
    };
  if (evidence.status.sawInvalid)
    return {
      explanation:
        'The returned DS denial proof did not validate with the trusted parent keys.',
      state: 'bogus',
      verifications: allVerifications,
    };
  return {
    explanation: sawIncompleteOptOut
      ? 'The opt-out interval lacked a matching, locally verified closest-provable-encloser record.'
      : evidence.status.sawProof
        ? 'No returned authenticated denial proof established the DS result for this exact name.'
        : 'The response did not contain an NSEC or NSEC3 proof for the absent DS RRset.',
    state: 'incomplete',
    verifications: allVerifications,
  };
}
