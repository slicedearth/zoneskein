import type { PolicyQueryResult } from '../dns/policy-query';
import { reachableAnswerRecords } from '../dns/answer-chain';
import type { DnsRecord } from '../dns/types';
import type { CaaInput } from './parser';

export interface CaaAliasEvidence {
  readonly owner: string;
  readonly target: string;
  readonly type: 'CNAME' | 'DNAME';
}

export interface CaaDiscoveryReport {
  readonly aliases: readonly CaaAliasEvidence[];
  readonly errors: readonly string[];
  readonly foundFor?: string;
  readonly queried: readonly string[];
  readonly records: readonly CaaInput[];
  readonly requested: string;
  readonly source?: string;
  readonly ttl?: number;
}

function caaInput(record: DnsRecord): CaaInput | null {
  if (record.data === null || typeof record.data !== 'object') return null;
  const value = record.data as Record<string, unknown>;
  const tag = value['tag'];
  const content = value['value'];
  const flags = value['flags'];
  const critical = value['issuerCritical'];
  if (typeof tag !== 'string' || typeof content !== 'string') return null;
  return {
    flags: typeof flags === 'number' ? flags : critical === true ? 128 : 0,
    tag,
    value: content,
  };
}

function reachableAnswerData(
  requested: string,
  result: PolicyQueryResult,
): {
  readonly aliases: readonly CaaAliasEvidence[];
  readonly records: readonly DnsRecord[];
} {
  const relevant = reachableAnswerRecords(requested, result.answers, 'CAA');
  return {
    aliases: relevant.aliases.flatMap((record) =>
      typeof record.data === 'string'
        ? [
            {
              owner: record.owner.replace(/\.$/u, ''),
              target: record.data.replace(/\.$/u, ''),
              type: record.type as 'CNAME' | 'DNAME',
            },
          ]
        : [],
    ),
    records: relevant.records,
  };
}

export async function discoverCaaPolicy(
  names: readonly string[],
  query: (name: string) => Promise<PolicyQueryResult>,
  cancelled: () => boolean = () => false,
): Promise<CaaDiscoveryReport> {
  const requested = names[0] ?? '';
  const queried: string[] = [];
  const errors: string[] = [];
  const aliases: CaaAliasEvidence[] = [];

  for (const name of names) {
    if (cancelled()) break;
    queried.push(name);
    const result = await query(name);
    const relevant = reachableAnswerData(name, result);
    aliases.push(...relevant.aliases);
    const queryError =
      result.error ??
      (result.responseCode === 'NOERROR' || result.responseCode === 'NXDOMAIN'
        ? undefined
        : `resolver returned ${result.responseCode}`);
    if (queryError !== undefined) {
      errors.push(`${name}: ${queryError}`);
      break;
    }
    if (result.responseCode !== 'NOERROR' && relevant.records.length > 0) {
      errors.push(`${name}: resolver returned positive CAA data with ${result.responseCode}`);
      break;
    }
    const records = relevant.records.flatMap((record) => {
      const value = caaInput(record);
      return value === null ? [] : [value];
    });
    if (records.length > 0) {
      const source = relevant.records[0]?.owner.replace(/\.$/u, '') ?? name;
      return {
        aliases,
        errors,
        foundFor: name,
        queried,
        records,
        requested,
        source,
        ...(result.ttl === undefined ? {} : { ttl: result.ttl }),
      };
    }
  }

  return { aliases, errors, queried, records: [], requested };
}
