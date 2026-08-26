import { validateDnsName } from '../dns/names';
import { txtRecordValue } from '../dns/records';
import type { DnsRecord } from '../dns/types';

export interface BoundDkimKeyAnswer {
  readonly error?: string;
  readonly ttl?: number;
  readonly values: readonly string[];
}

const MAX_DKIM_CNAME_HOPS = 64;

function canonicalName(value: string): string | null {
  if (value !== value.trim() || value.includes('://') || /[^\x21-\x7e]/u.test(value))
    return null;
  const parsed = validateDnsName(value);
  return parsed.ok ? parsed.value.absolute : null;
}

interface IndexedDkimRecords {
  readonly aliases: DnsRecord[];
  readonly keys: DnsRecord[];
}

function indexAnswers(answers: readonly DnsRecord[]): ReadonlyMap<string, IndexedDkimRecords> {
  const owners = new Map<string, IndexedDkimRecords>();
  for (const record of answers) {
    if (
      record.class.toUpperCase() !== 'IN' ||
      (record.type !== 'TXT' && record.type !== 'CNAME')
    )
      continue;
    const owner = canonicalName(record.owner);
    if (owner === null) continue;
    let records = owners.get(owner);
    if (records === undefined) {
      records = { aliases: [], keys: [] };
      owners.set(owner, records);
    }
    (record.type === 'CNAME' ? records.aliases : records.keys).push(record);
  }
  return owners;
}

/** Resolve only the unique IN/CNAME chain rooted at the selector question. */
export function bindDkimKeyAnswer(
  answers: readonly DnsRecord[],
  question: string,
): BoundDkimKeyAnswer {
  const parsedQuestion = validateDnsName(question);
  if (!parsedQuestion.ok) return { error: parsedQuestion.error.message, values: [] };

  const owners = indexAnswers(answers);
  const visited = new Set<string>();
  const ttlRecords: DnsRecord[] = [];
  let owner = parsedQuestion.value.absolute;
  let aliasHops = 0;

  while (!visited.has(owner)) {
    visited.add(owner);
    const owned = owners.get(owner);
    const records = owned?.keys ?? [];
    const aliases = owned?.aliases ?? [];
    if (aliases.length === 0) {
      const values: string[] = [];
      for (const record of records) {
        const value = txtRecordValue(record);
        if (value === null)
          return { error: 'The selector answer contains malformed TXT data.', values: [] };
        values.push(value);
      }
      const ttls = [...ttlRecords, ...records]
        .map((record) => record.ttl)
        .filter((ttl) => ttl >= 0);
      return {
        ...(ttls.length === 0 ? {} : { ttl: Math.min(...ttls) }),
        values: [...new Set(values)],
      };
    }
    if (records.length > 0)
      return {
        error: 'The selector answer contains both CNAME and TXT data at one owner.',
        values: [],
      };

    if (aliasHops >= MAX_DKIM_CNAME_HOPS)
      return {
        error: `The selector answer exceeds the ${String(MAX_DKIM_CNAME_HOPS)}-alias safety limit.`,
        values: [],
      };
    const targets = aliases.map((record) =>
      typeof record.data === 'string' ? canonicalName(record.data) : null,
    );
    const uniqueTargets = new Set(targets);
    if (uniqueTargets.has(null) || uniqueTargets.size !== 1)
      return {
        error: 'The selector answer contains an invalid or ambiguous CNAME chain.',
        values: [],
      };
    ttlRecords.push(...aliases);
    const target = uniqueTargets.values().next().value;
    if (target === undefined || target === null)
      return { error: 'The selector answer contains an invalid CNAME target.', values: [] };
    aliasHops += 1;
    owner = target;
  }

  return { error: 'The selector answer contains a CNAME loop.', values: [] };
}
