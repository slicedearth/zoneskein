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

  const aliasCandidates = answers
    .filter(
      (record) =>
        record.class.toUpperCase() === 'IN' &&
        (record.type === 'CNAME' || record.type === 'DNAME'),
    )
    .slice(0, MAX_ALIAS_RECORDS);
  const aliases: DnsRecord[] = [];
  const visited = new Set<string>();
  let owner = start;

  for (let depth = 0; depth <= MAX_ALIAS_RECORDS; depth += 1) {
    if (visited.has(owner))
      return result(matchingType.length, aliases, [], 'The DNS answer contains an alias loop.');
    visited.add(owner);

    const records = matchingType.filter((record) => canonicalName(record.owner) === owner);
    const cnames = aliasCandidates.filter(
      (record) => record.type === 'CNAME' && canonicalName(record.owner) === owner,
    );
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
      aliases.push(...cnames);
      owner = target;
      continue;
    }
    if (records.length > 0) return result(matchingType.length, aliases, records);

    const applicableDnames = aliasCandidates.flatMap((record) => {
      if (record.type !== 'DNAME') return [];
      const aliasOwner = canonicalName(record.owner);
      const target = aliasTarget(record);
      if (aliasOwner === null || target === null || !owner.endsWith(`.${aliasOwner}`))
        return [];
      return [{ aliasOwner, record, target }];
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
    aliases.push(...closest.map((candidate) => candidate.record));
    owner = rewritten;
  }
  return result(
    matchingType.length,
    aliases,
    [],
    `The DNS answer exceeds the ${String(MAX_ALIAS_RECORDS)}-alias safety limit.`,
  );
}
