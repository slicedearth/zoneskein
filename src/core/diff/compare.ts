import ipaddr from 'ipaddr.js';

import { ZONE_ANALYSIS_LIMITS } from '../zone/parser';
import type { ZoneDocument, ZoneRecord } from '../zone/types';
import type { DiffReport, DnsChange } from './types';

interface IndexedRecord {
  readonly index: number;
  readonly mxExchange?: string;
  readonly pair: string;
  readonly record: ZoneRecord;
  readonly semantic: string;
}

interface RecordQueue {
  next: number;
  readonly records: IndexedRecord[];
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
  const rawValues = record.rdata.map((token) => token.raw);
  if (record.type === 'TXT') return values.join('');
  if (record.type === 'A' || record.type === 'AAAA') return normalizedAddress(values[0] ?? '');
  if (record.type === 'MX') {
    return `${String(Number(values[0] ?? 0))} ${absoluteTarget(rawValues[1] ?? '', origin)}`;
  }
  if (record.type === 'SRV') {
    return [
      String(Number(values[0] ?? 0)),
      String(Number(values[1] ?? 0)),
      String(Number(values[2] ?? 0)),
      absoluteTarget(rawValues[3] ?? '', origin),
    ].join(' ');
  }
  if (
    record.type === 'CNAME' ||
    record.type === 'DNAME' ||
    record.type === 'NS' ||
    record.type === 'PTR'
  ) {
    return absoluteTarget(rawValues[0] ?? '', origin);
  }
  if (record.type === 'SOA') {
    return [
      absoluteTarget(rawValues[0] ?? '', origin),
      absoluteTarget(rawValues[1] ?? '', origin),
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
  return document.records.map((record, index) => {
    const semantic = semanticRdata(record, document.origin);
    const separator = semantic.indexOf(' ');
    return {
      index,
      ...(record.type === 'MX'
        ? { mxExchange: separator < 0 ? '' : semantic.slice(separator + 1) }
        : {}),
      pair: `${record.owner}|${record.type}`,
      record,
      semantic,
    };
  });
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

function keyedQueues(
  records: readonly IndexedRecord[],
  key: (record: IndexedRecord) => string,
): Map<string, RecordQueue> {
  const queues = new Map<string, RecordQueue>();
  for (const record of records) {
    const identity = key(record);
    const queue = queues.get(identity);
    if (queue === undefined) queues.set(identity, { next: 0, records: [record] });
    else queue.records.push(record);
  }
  return queues;
}

function takeQueued(
  queues: ReadonlyMap<string, RecordQueue>,
  identity: string,
  used: ReadonlySet<number>,
): IndexedRecord | undefined {
  const queue = queues.get(identity);
  if (queue === undefined) return undefined;
  while (queue.next < queue.records.length) {
    const candidate = queue.records[queue.next];
    queue.next += 1;
    if (candidate !== undefined && !used.has(candidate.index)) return candidate;
  }
  return undefined;
}

function exactKey(record: IndexedRecord): string {
  return JSON.stringify([record.pair, record.semantic, record.record.ttl ?? null]);
}

function semanticKey(record: IndexedRecord): string {
  return JSON.stringify([record.pair, record.semantic]);
}

function mxKey(record: IndexedRecord): string {
  return JSON.stringify([record.pair, record.mxExchange ?? '']);
}

function incompleteReport(reasons: readonly string[]): DiffReport {
  return {
    changes: [],
    guidance: [],
    incompleteReasons: [...new Set(reasons)],
    status: 'incomplete',
  };
}

function completeReport(changes: readonly DnsChange[]): DiffReport {
  return {
    changes,
    guidance: guidanceFor(changes),
    incompleteReasons: [],
    status: 'complete',
  };
}

function documentResourceReason(document: ZoneDocument, label: string): string | null {
  if (document.incomplete !== undefined) return `${label}: ${document.incomplete.message}`;
  if (document.source.length > ZONE_ANALYSIS_LIMITS.characters)
    return `${label} exceeds the ${String(ZONE_ANALYSIS_LIMITS.characters)}-character safety limit.`;
  if (document.records.length > ZONE_ANALYSIS_LIMITS.records)
    return `${label} exceeds the ${String(ZONE_ANALYSIS_LIMITS.records)}-record safety limit.`;
  if (document.diagnostics.length > ZONE_ANALYSIS_LIMITS.diagnostics)
    return `${label} exceeds the ${String(ZONE_ANALYSIS_LIMITS.diagnostics)}-diagnostic safety limit.`;
  let tokens = 0;
  for (const record of document.records) {
    tokens += record.rdata.length;
    if (tokens > ZONE_ANALYSIS_LIMITS.tokens)
      return `${label} exceeds the ${String(ZONE_ANALYSIS_LIMITS.tokens)}-token safety limit.`;
  }
  return null;
}

function guidanceFor(changes: readonly DnsChange[]): readonly string[] {
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
  if (changes.some((item) => item.category === 'ttl-only')) {
    guidance.add(
      'For a planned migration, reduce TTL early enough for the previous higher TTL to age out. Restore the normal TTL after the change is stable.',
    );
  }
  if (changes.some((item) => item.disruptive)) {
    guidance.add(
      'There is no universal propagation-complete time. Recursive caches, negative caching, and TTLs observed before publication affect what users see.',
    );
  }
  return [...guidance];
}

export function omitIncompleteRecordTypes(
  report: DiffReport,
  incompleteTypes: readonly string[],
): DiffReport {
  if (report.status === 'incomplete') return report;
  const excluded = new Set(incompleteTypes.map((type) => type.toUpperCase()));
  const changes = report.changes.filter((change) => !excluded.has(change.type.toUpperCase()));
  return completeReport(changes);
}

export function isDefinitiveDnsObservation(responseCode: string): boolean {
  return responseCode === 'NOERROR' || responseCode === 'NXDOMAIN';
}

export function compareZoneDocuments(before: ZoneDocument, after: ZoneDocument): DiffReport {
  const inputReasons = [
    documentResourceReason(before, 'Earlier snapshot'),
    documentResourceReason(after, 'Later snapshot'),
  ].flatMap((reason) => (reason === null ? [] : [reason]));
  if (inputReasons.length > 0) return incompleteReport(inputReasons);

  const left = indexed(before);
  const right = indexed(after);
  const leftUsed = new Set<number>();
  const rightUsed = new Set<number>();
  const changes: DnsChange[] = [];
  const exactRight = keyedQueues(right, exactKey);
  const semanticRight = keyedQueues(right, semanticKey);
  const mxRight = keyedQueues(
    right.filter((record) => record.record.type === 'MX'),
    mxKey,
  );
  const append = (value: DnsChange): boolean => {
    if (changes.length >= ZONE_ANALYSIS_LIMITS.changes) return false;
    changes.push(value);
    return true;
  };
  const changeLimit = () =>
    incompleteReport([
      `Comparison exceeded the ${String(ZONE_ANALYSIS_LIMITS.changes)}-change safety limit. No partial change set was retained.`,
    ]);

  for (const prior of left) {
    const exact = takeQueued(exactRight, exactKey(prior), rightUsed);
    if (exact === undefined) continue;
    leftUsed.add(prior.index);
    rightUsed.add(exact.index);
    if (prior.record.original.trim() !== exact.record.original.trim()) {
      if (
        !append(
          change(
            'formatting-only',
            prior.record,
            exact.record,
            'Presentation changed while owner, type, TTL, and semantic RDATA remained equivalent.',
          ),
        )
      )
        return changeLimit();
    }
  }

  for (const prior of left) {
    if (leftUsed.has(prior.index)) continue;
    const sameValue = takeQueued(semanticRight, semanticKey(prior), rightUsed);
    if (sameValue === undefined) continue;
    leftUsed.add(prior.index);
    rightUsed.add(sameValue.index);
    if (
      !append(
        change(
          'ttl-only',
          prior.record,
          sameValue.record,
          `TTL changed from ${String(prior.record.ttl ?? 'unspecified')} to ${String(sameValue.record.ttl ?? 'unspecified')}.`,
        ),
      )
    )
      return changeLimit();
  }

  for (const prior of left) {
    if (leftUsed.has(prior.index) || prior.record.type !== 'MX') continue;
    const priority = takeQueued(mxRight, mxKey(prior), rightUsed);
    if (priority === undefined) continue;
    leftUsed.add(prior.index);
    rightUsed.add(priority.index);
    if (
      !append(
        change(
          'priority-changed',
          prior.record,
          priority.record,
          `MX preference changed for ${prior.mxExchange ?? ''}.`,
        ),
      )
    )
      return changeLimit();
  }

  const groups = new Map<
    string,
    { readonly left: IndexedRecord[]; readonly right: IndexedRecord[] }
  >();
  const group = (identity: string) => {
    const existing = groups.get(identity);
    if (existing !== undefined) return existing;
    const created = { left: [], right: [] };
    groups.set(identity, created);
    return created;
  };
  for (const record of left)
    if (!leftUsed.has(record.index)) group(record.pair).left.push(record);
  for (const record of right)
    if (!rightUsed.has(record.index)) group(record.pair).right.push(record);
  for (const records of groups.values()) {
    if (records.left.length === 1 && records.right.length === 1) {
      const prior = records.left[0];
      const next = records.right[0];
      if (prior === undefined || next === undefined) continue;
      leftUsed.add(prior.index);
      rightUsed.add(next.index);
      if (
        !append(
          change(
            'value-changed',
            prior.record,
            next.record,
            'The record value changed after semantic normalisation.',
          ),
        )
      )
        return changeLimit();
    }
  }

  for (const prior of left) {
    if (leftUsed.has(prior.index)) continue;
    if (
      !append(
        change(
          'removed',
          prior.record,
          undefined,
          'The record is absent from the proposed snapshot.',
        ),
      )
    )
      return changeLimit();
  }
  for (const next of right) {
    if (rightUsed.has(next.index)) continue;
    if (
      !append(
        change('added', undefined, next.record, 'The record is new in the proposed snapshot.'),
      )
    )
      return changeLimit();
  }

  return completeReport(changes);
}
