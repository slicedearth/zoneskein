import { validateDnsName } from './names';
import type { DnsRecord } from './types';

const MAX_ALIAS_RECORDS = 64;

export interface ReachableAnswerRecords {
  readonly aliases: readonly DnsRecord[];
  readonly error?: string;
  readonly ignoredRecords: number;
  readonly records: readonly DnsRecord[];
}

function canonicalName(value: string): string | null {
  if (value !== value.trim() || value.includes('://') || /[^\x21-\x7e]/u.test(value))
    return null;
  const parsed = validateDnsName(value);
  return parsed.ok ? parsed.value.ascii : null;
}

function aliasTarget(record: DnsRecord): string | null {
  return typeof record.data === 'string' ? canonicalName(record.data) : null;
}

function result(
  matchingCount: number,
  aliases: readonly DnsRecord[],
  records: readonly DnsRecord[],
  error?: string,
): ReachableAnswerRecords {
  return {
    aliases,
    ...(error === undefined ? {} : { error }),
    ignoredRecords: matchingCount - records.length,
    records,
  };
}

export function reachableAnswerRecords(
  questionName: string,
  answers: readonly DnsRecord[],
  type: string,
): ReachableAnswerRecords {
  const matchingType = answers.filter(
    (record) => record.class.toUpperCase() === 'IN' && record.type === type,
  );
  const start = canonicalName(questionName);
  if (start === null) return result(matchingType.length, [], []);
  if (type === 'CNAME') {
    const records = matchingType.filter((record) => canonicalName(record.owner) === start);
    return result(matchingType.length, [], records);
  }

  const recordsByOwner = new Map<string, DnsRecord[]>();
  for (const record of answers) {
    if (record.class.toUpperCase() !== 'IN') continue;
    const recordOwner = canonicalName(record.owner);
    if (recordOwner === null) continue;
    const ownerRecords = recordsByOwner.get(recordOwner);
    if (ownerRecords === undefined) recordsByOwner.set(recordOwner, [record]);
    else ownerRecords.push(record);
  }
  const aliases: DnsRecord[] = [];
  const visited = new Set<string>();
  let owner = start;

  for (let depth = 0; ; depth += 1) {
    if (visited.has(owner))
      return result(matchingType.length, aliases, [], 'The DNS answer contains an alias loop.');
    visited.add(owner);

    const ownerRecords = recordsByOwner.get(owner) ?? [];
    const records = ownerRecords.filter((record) => record.type === type);
    const cnames = ownerRecords.filter((record) => record.type === 'CNAME');
    if (cnames.length > 0) {
      if (records.length > 0)
        return result(
          matchingType.length,
          aliases,
          [],
          'The DNS answer contains both CNAME and requested-type data at one owner.',
        );
      const targets = new Set(cnames.map(aliasTarget));
      if (targets.has(null) || targets.size !== 1)
        return result(
          matchingType.length,
          aliases,
          [],
          'The DNS answer contains an invalid or ambiguous CNAME RRset.',
        );
      const target = [...targets][0];
      if (target === null || target === undefined)
        return result(
          matchingType.length,
          aliases,
          [],
          'The DNS answer contains an invalid CNAME target.',
        );
      if (depth >= MAX_ALIAS_RECORDS)
        return result(
          matchingType.length,
          aliases,
          [],
          `The DNS answer exceeds the ${String(MAX_ALIAS_RECORDS)}-alias safety limit.`,
        );
      aliases.push(...cnames);
      owner = target;
      continue;
    }
    if (records.length > 0) return result(matchingType.length, aliases, records);

    const ownerLabels = owner.split('.');
    const applicableDnames = ownerLabels.slice(1).flatMap((_, labelIndex) => {
      const aliasOwner = ownerLabels.slice(labelIndex + 1).join('.');
      return (recordsByOwner.get(aliasOwner) ?? []).flatMap((record) => {
        if (record.type !== 'DNAME') return [];
        const target = aliasTarget(record);
        return target === null ? [] : [{ aliasOwner, record, target }];
      });
    });
    if (applicableDnames.length === 0) return result(matchingType.length, aliases, []);
    const longest = Math.max(
      ...applicableDnames.map((candidate) => candidate.aliasOwner.split('.').length),
    );
    const closest = applicableDnames.filter(
      (candidate) => candidate.aliasOwner.split('.').length === longest,
    );
    const rewrites = new Set(
      closest.map((candidate) => {
        const prefix = owner.slice(0, -(candidate.aliasOwner.length + 1));
        return canonicalName(`${prefix}.${candidate.target}`);
      }),
    );
    if (rewrites.has(null) || rewrites.size !== 1)
      return result(
        matchingType.length,
        aliases,
        [],
        'The DNS answer contains an invalid or ambiguous DNAME RRset.',
      );
    const rewritten = [...rewrites][0];
    if (rewritten === null || rewritten === undefined)
      return result(
        matchingType.length,
        aliases,
        [],
        'The DNS answer contains an invalid DNAME target.',
      );
    if (depth >= MAX_ALIAS_RECORDS)
      return result(
        matchingType.length,
        aliases,
        [],
        `The DNS answer exceeds the ${String(MAX_ALIAS_RECORDS)}-alias safety limit.`,
      );
    aliases.push(...closest.map((candidate) => candidate.record));
    owner = rewritten;
  }
}
