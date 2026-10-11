import { canonicalMasterName } from './master-name';
import type { ZoneRecord } from './types';
import { canonicalRecordRdata } from './zonemd';

export function recordTarget(record: ZoneRecord, index: number, fallbackOrigin?: string) {
  return canonicalMasterName(record.rdata[index]?.raw ?? '', record.origin ?? fallbackOrigin);
}

export function opaqueRecordKey(record: ZoneRecord): string {
  // Raw token boundaries preserve quoted whitespace, escaped octets and unknown grammars.
  return JSON.stringify(record.rdata.map((token) => [token.quoted, token.raw]));
}

export function canonicalRdataKey(record: ZoneRecord, fallbackOrigin?: string): string | null {
  const encoded = canonicalRecordRdata(record, fallbackOrigin);
  return encoded.ok
    ? Array.from(encoded.bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
    : null;
}

export type ComparisonConfidence =
  | 'canonical-wire-equal'
  | 'application-equivalent'
  | 'opaque-data-equal'
  | 'unsupported'
  | 'different';

export function compareRecordConfidence(
  before: ZoneRecord,
  after: ZoneRecord,
): {
  readonly state: ComparisonConfidence;
  readonly txtChunksDiffer: boolean;
} {
  const left = canonicalRdataKey(before);
  const right = canonicalRdataKey(after);
  const sameType = before.type === after.type && before.className === after.className;
  const beforeOwner = canonicalMasterName(before.owner);
  const afterOwner = canonicalMasterName(after.owner);
  const sameOwner =
    beforeOwner !== null && afterOwner !== null && beforeOwner.absolute === afterOwner.absolute;
  const boundaries = (record: ZoneRecord) =>
    JSON.stringify(record.rdata.map((token) => new TextEncoder().encode(token.value).length));
  const txtChunksDiffer =
    sameType && before.type === 'TXT' && boundaries(before) !== boundaries(after);
  const text = before.rdata.map((token) => token.value).join('');
  const state: ComparisonConfidence =
    !sameType || !sameOwner || before.ttl !== after.ttl
      ? 'different'
      : before.ttl === undefined || after.ttl === undefined
        ? 'unsupported'
        : left !== null && right !== null && left === right
          ? /^TYPE\d+$/u.test(before.type)
            ? 'opaque-data-equal'
            : 'canonical-wire-equal'
          : left !== null &&
              right !== null &&
              before.type === 'TXT' &&
              /^v=spf1(?: |$)/iu.test(text) &&
              text === after.rdata.map((token) => token.value).join('')
            ? 'application-equivalent'
            : txtChunksDiffer && text === after.rdata.map((token) => token.value).join('')
              ? 'unsupported'
              : left === null || right === null
                ? 'unsupported'
                : 'different';
  return { state, txtChunksDiffer };
}
