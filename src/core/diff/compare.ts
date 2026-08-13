import ipaddr from 'ipaddr.js';

import type { ZoneDocument, ZoneRecord } from '../zone/types';
import type { DiffReport, DnsChange } from './types';

interface IndexedRecord {
  readonly index: number;
  readonly record: ZoneRecord;
  readonly semantic: string;
}

function absoluteTarget(value: string, origin: string | undefined): string {
  if (value === '@') return origin ?? '@';
  if (value.endsWith('.')) return value.toLowerCase();
  return origin === undefined
    ? value.toLowerCase()
    : `${value.toLowerCase()}.${origin}`.replace('..', '.');
}

function normalizedAddress(value: string): string {
  try {
    return ipaddr.parse(value).toNormalizedString();
  } catch {
    return value.toLowerCase();
  }
}

function semanticRdata(record: ZoneRecord, origin: string | undefined): string {
  const values = record.rdata.map((token) => token.value);
  if (record.type === 'TXT') return values.join('');
  if (record.type === 'A' || record.type === 'AAAA') return normalizedAddress(values[0] ?? '');
  if (record.type === 'MX') {
    return `${String(Number(values[0] ?? 0))} ${absoluteTarget(values[1] ?? '', origin)}`;
  }
  if (record.type === 'SRV') {
    return [
      String(Number(values[0] ?? 0)),
      String(Number(values[1] ?? 0)),
      String(Number(values[2] ?? 0)),
      absoluteTarget(values[3] ?? '', origin),
    ].join(' ');
  }
  if (record.type === 'CNAME' || record.type === 'NS' || record.type === 'PTR') {
    return absoluteTarget(values[0] ?? '', origin);
  }
  if (record.type === 'SOA') {
    return [
      absoluteTarget(values[0] ?? '', origin),
      absoluteTarget(values[1] ?? '', origin),
      ...values.slice(2).map((value) => String(Number(value))),
    ].join(' ');
  }
  if (record.type === 'CAA') {
    return [
      String(Number(values[0] ?? 0)),
      (values[1] ?? '').toLowerCase(),
      ...values.slice(2),
    ].join(' ');
  }
  return values.join(' ').replaceAll(/\s+/gu, ' ').trim();
}

function indexed(document: ZoneDocument): IndexedRecord[] {
  return document.records.map((record, index) => ({
    index,
    record,
    semantic: semanticRdata(record, document.origin),
  }));
}

function pairKey(record: IndexedRecord): string {
  return `${record.record.owner}|${record.record.type}`;
}

function disruptive(type: string, category: DnsChange['category']): boolean {
  if (category === 'formatting-only' || category === 'ttl-only') return false;
  return type === 'NS' || type === 'MX' || type === 'CNAME' || category === 'removed';
}

function change(
  category: DnsChange['category'],
  before: ZoneRecord | undefined,
  after: ZoneRecord | undefined,
  explanation: string,
): DnsChange {
  const representative = after ?? before;
  if (representative === undefined) throw new Error('A DNS change requires a record.');
  return {
    ...(after === undefined ? {} : { after }),
    ...(before === undefined ? {} : { before }),
    category,
    disruptive: disruptive(representative.type, category),
    explanation,
    owner: representative.owner,
    type: representative.type,
  };
}

function mxExchange(record: IndexedRecord): string {
  return record.semantic.split(' ').slice(1).join(' ');
}

export function compareZoneDocuments(before: ZoneDocument, after: ZoneDocument): DiffReport {
  const left = indexed(before);
  const right = indexed(after);
  const leftUsed = new Set<number>();
  const rightUsed = new Set<number>();
  const changes: DnsChange[] = [];

  for (const prior of left) {
    const exact = right.find(
      (candidate) =>
        !rightUsed.has(candidate.index) &&
        pairKey(candidate) === pairKey(prior) &&
        candidate.semantic === prior.semantic &&
        candidate.record.ttl === prior.record.ttl,
    );
    if (exact === undefined) continue;
    leftUsed.add(prior.index);
    rightUsed.add(exact.index);
    if (prior.record.original.trim() !== exact.record.original.trim()) {
      changes.push(
        change(
          'formatting-only',
          prior.record,
          exact.record,
          'Presentation changed while owner, type, TTL, and semantic RDATA remained equivalent.',
        ),
      );
    }
  }

  for (const prior of left.filter((record) => !leftUsed.has(record.index))) {
    const sameValue = right.find(
      (candidate) =>
        !rightUsed.has(candidate.index) &&
        pairKey(candidate) === pairKey(prior) &&
        candidate.semantic === prior.semantic,
    );
    if (sameValue === undefined) continue;
    leftUsed.add(prior.index);
    rightUsed.add(sameValue.index);
    changes.push(
      change(
        'ttl-only',
        prior.record,
        sameValue.record,
        `TTL changed from ${String(prior.record.ttl ?? 'unspecified')} to ${String(sameValue.record.ttl ?? 'unspecified')}.`,
      ),
    );
  }

  for (const prior of left.filter(
    (record) => !leftUsed.has(record.index) && record.record.type === 'MX',
  )) {
    const priority = right.find(
      (candidate) =>
        !rightUsed.has(candidate.index) &&
        pairKey(candidate) === pairKey(prior) &&
        mxExchange(candidate) === mxExchange(prior),
    );
    if (priority === undefined) continue;
    leftUsed.add(prior.index);
    rightUsed.add(priority.index);
    changes.push(
      change(
        'priority-changed',
        prior.record,
        priority.record,
        `MX preference changed for ${mxExchange(prior)}.`,
      ),
    );
  }

  const groups = new Set([
    ...left.filter((record) => !leftUsed.has(record.index)).map(pairKey),
    ...right.filter((record) => !rightUsed.has(record.index)).map(pairKey),
  ]);
  for (const key of groups) {
    const remainingLeft = left.filter(
      (record) => !leftUsed.has(record.index) && pairKey(record) === key,
    );
    const remainingRight = right.filter(
      (record) => !rightUsed.has(record.index) && pairKey(record) === key,
    );
    const pairs = Math.min(remainingLeft.length, remainingRight.length);
    for (let index = 0; index < pairs; index += 1) {
      const prior = remainingLeft[index];
      const next = remainingRight[index];
      if (prior === undefined || next === undefined) continue;
      leftUsed.add(prior.index);
      rightUsed.add(next.index);
      changes.push(
        change(
          'value-changed',
          prior.record,
          next.record,
          'The record value changed after semantic normalization.',
        ),
      );
    }
  }

  for (const prior of left.filter((record) => !leftUsed.has(record.index))) {
    changes.push(
      change(
        'removed',
        prior.record,
        undefined,
        'The record is absent from the proposed snapshot.',
      ),
    );
  }
  for (const next of right.filter((record) => !rightUsed.has(record.index))) {
    changes.push(
      change('added', undefined, next.record, 'The record is new in the proposed snapshot.'),
    );
  }

  const guidance = new Set<string>();
  if (changes.some((item) => item.type === 'NS' && item.disruptive)) {
    guidance.add(
      'Nameserver changes must be coordinated between the parent delegation and the authoritative zone. Keep old service available while previously cached NS data can still be used.',
    );
  }
  if (changes.some((item) => item.type === 'MX' && item.disruptive)) {
    guidance.add(
      'Stage and test new mail targets before removing old MX routes. Preference changes can redirect new delivery immediately while old answers remain cached.',
    );
  }
  if (changes.some((item) => item.type === 'CNAME' && item.disruptive)) {
    guidance.add(
      'Verify the replacement target exists before changing or removing a CNAME, and check that no incompatible data will coexist at that owner.',
    );
  }
  if (changes.some((item) => item.category === 'removed')) {
    guidance.add(
      'Create and verify replacements before deleting records where continuity matters. A cached old answer can outlive the change according to its previous TTL.',
    );
  }
  const ttlChanges = changes.filter((item) => item.category === 'ttl-only');
  if (ttlChanges.length > 0) {
    guidance.add(
      'For a planned migration, reduce TTL early enough for the previous higher TTL to age out. Restore the normal TTL after the change is stable.',
    );
  }
  if (changes.some((item) => item.disruptive)) {
    guidance.add(
      'There is no universal propagation-complete time. Recursive caches, negative caching, and TTLs observed before publication affect what users see.',
    );
  }
  return { changes, guidance: [...guidance] };
}
