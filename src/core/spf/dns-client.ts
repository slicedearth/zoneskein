import { validateDnsName } from '../dns/names';
import { txtRecordValue } from '../dns/records';
import { reverseNameFromAddress } from '../dns/reverse';
import { DnsQueryError, type DnsRecord, type DnsResolver } from '../dns/types';
import { DnsQueryRun } from '../doh/query-run';
import { SPF_WORK_LIMITS } from './limits';
import type { SpfSenderDnsClient } from './sender-evaluator';
import type { SpfLookupResult, SpfLookupType, SpfMxRecord } from './types';

const MAX_CNAME_HOPS = 64;

interface BoundAnswerRecords {
  readonly error?: string;
  readonly matching: readonly DnsRecord[];
  readonly ttlRecords: readonly DnsRecord[];
}

function canonicalName(value: string): string | null {
  const parsed = validateDnsName(value);
  return parsed.ok ? parsed.value.absolute : null;
}

/**
 * A DNS message can legally carry unrelated answer records. Follow only the
 * unique IN/CNAME chain rooted at the original question before consuming data.
 */
function bindAnswerRecords(
  answers: readonly DnsRecord[],
  question: string,
  type: SpfLookupType | 'PTR',
): BoundAnswerRecords {
  const recordsByOwner = new Map<string, DnsRecord[]>();
  for (const record of answers) {
    if (record.class.toUpperCase() !== 'IN') continue;
    const recordOwner = canonicalName(record.owner);
    if (recordOwner === null) continue;
    const records = recordsByOwner.get(recordOwner);
    if (records === undefined) recordsByOwner.set(recordOwner, [record]);
    else records.push(record);
  }

  const visited = new Set<string>();
  const ttlRecords: DnsRecord[] = [];
  let owner = question;
  let cnameHops = 0;

  for (;;) {
    if (visited.has(owner)) {
      return {
        error: 'The DNS answer contains a CNAME loop.',
        matching: [],
        ttlRecords,
      };
    }
    visited.add(owner);
    const owned = recordsByOwner.get(owner) ?? [];
    const matching = owned.filter((record) => record.type === type);
    const aliases = owned.filter((record) => record.type === 'CNAME');
    if (aliases.length === 0) return { matching, ttlRecords: [...ttlRecords, ...matching] };
    if (matching.length > 0)
      return {
        error: 'The DNS answer contains both CNAME and requested-type data at one owner.',
        matching: [],
        ttlRecords,
      };

    let target: string | null = null;
    for (const alias of aliases) {
      const candidate = typeof alias.data === 'string' ? canonicalName(alias.data) : null;
      if (candidate === null || (target !== null && candidate !== target)) {
        return {
          error: 'The DNS answer contains an invalid or ambiguous CNAME chain.',
          matching: [],
          ttlRecords,
        };
      }
      target = candidate;
    }
    if (target === null) {
      return {
        error: 'The DNS answer contains an invalid or ambiguous CNAME chain.',
        matching: [],
        ttlRecords,
      };
    }
    if (cnameHops >= MAX_CNAME_HOPS) {
      return {
        error: `The DNS answer exceeds ${String(MAX_CNAME_HOPS)} reachable CNAME hops.`,
        matching: [],
        ttlRecords,
      };
    }

    ttlRecords.push(...aliases);
    cnameHops += 1;
    owner = target;
  }
}

function mxRecord(value: unknown): SpfMxRecord | null {
  if (value === null || typeof value !== 'object') return null;
  const fields = value as Record<string, unknown>;
  const exchange = fields['exchange'];
  const preference = fields['preference'];
  if (
    typeof exchange !== 'string' ||
    typeof preference !== 'number' ||
    !Number.isInteger(preference) ||
    preference < 0 ||
    preference > 65_535
  ) {
    return null;
  }
  const parsed = validateDnsName(exchange);
  if (!parsed.ok) return null;
  return {
    exchange: parsed.value.ascii === '' ? '.' : parsed.value.ascii,
    preference,
  };
}

function distinctMxRecords(records: readonly DnsRecord[]): readonly SpfMxRecord[] {
  const distinct = new Map<string, SpfMxRecord>();
  for (const record of records) {
    const parsed = mxRecord(record.data);
    if (parsed === null) continue;
    const key = `${String(parsed.preference)}\u0000${parsed.exchange}`;
    if (!distinct.has(key)) distinct.set(key, parsed);
  }
  return [...distinct.values()];
}

function statusFromCode(code: string): SpfLookupResult['status'] {
  if (code === 'NXDOMAIN') return 'nxdomain';
  if (code === 'SERVFAIL') return 'servfail';
  return code === 'NOERROR' ? 'nodata' : 'error';
}

function absoluteExpiry(receivedAt: string, ttl: number): string | undefined {
  const observed = Date.parse(receivedAt);
  if (!Number.isFinite(observed)) return undefined;
  const expires = observed + ttl * 1000;
  return Number.isFinite(expires) ? new Date(expires).toISOString() : undefined;
}

export class WireSpfDnsClient implements SpfSenderDnsClient {
  readonly #resolver: DnsResolver;
  readonly #run: DnsQueryRun;

  constructor(resolver: DnsResolver, run: DnsQueryRun) {
    this.#resolver = resolver;
    this.#run = run;
  }

  async lookup(domain: string, type: SpfLookupType): Promise<SpfLookupResult> {
    return await this.#lookupName(domain, type);
  }

  async lookupPtr(ip: string): Promise<SpfLookupResult> {
    const reverse = reverseNameFromAddress(ip);
    if (!reverse.ok) {
      return { error: reverse.error, messageBytes: 0, status: 'error', values: [] };
    }
    return await this.#lookupName(reverse.value.name, 'PTR');
  }

  async #lookupName(domain: string, type: SpfLookupType | 'PTR'): Promise<SpfLookupResult> {
    const parsed = validateDnsName(domain);
    if (!parsed.ok) {
      return { error: parsed.error.message, messageBytes: 0, status: 'error', values: [] };
    }
    try {
      const response = await this.#run.query(
        this.#resolver,
        { name: parsed.value, type },
        { checkingDisabled: false, dnssecOk: false },
      );
      const bound = bindAnswerRecords(response.message.answers, parsed.value.absolute, type);
      if (bound.error !== undefined) {
        return {
          error: bound.error,
          messageBytes: response.message.messageBytes,
          status: 'error',
          values: [],
        };
      }
      const matching = response.message.responseCode === 'NOERROR' ? bound.matching : [];
      if (matching.length > SPF_WORK_LIMITS.lookupAnswerValues) {
        return {
          error: `The DNS answer exceeds the ${String(SPF_WORK_LIMITS.lookupAnswerValues)}-value SPF safety limit.`,
          messageBytes: response.message.messageBytes,
          status: 'error',
          values: [],
        };
      }
      const mxRecords = type === 'MX' ? distinctMxRecords(matching) : undefined;
      const txtValues = type === 'TXT' ? matching.map(txtRecordValue) : [];
      const malformedText = txtValues.some((value) => value === null);
      const values =
        type === 'TXT'
          ? txtValues.filter((value): value is string => value !== null)
          : type === 'MX'
            ? []
            : matching.flatMap((record) =>
                typeof record.data === 'string' ? [record.data] : [],
              );
      const uniqueValues =
        mxRecords === undefined
          ? [...new Set(values)]
          : [...new Set(mxRecords.map((record) => record.exchange))];
      if (malformedText) {
        return {
          error: 'The DNS answer contains TXT data that is not valid UTF-8.',
          messageBytes: response.message.messageBytes,
          status: 'error',
          values: [],
        };
      }
      const ttlValues = bound.ttlRecords.map((record) => record.ttl).filter((ttl) => ttl >= 0);
      const ttl =
        uniqueValues.length === 0 || ttlValues.length === 0
          ? undefined
          : Math.min(...ttlValues);
      const expiresAt =
        ttl === undefined ? undefined : absoluteExpiry(response.receivedAt, ttl);
      return {
        messageBytes: response.message.messageBytes,
        status:
          uniqueValues.length > 0 ? 'answer' : statusFromCode(response.message.responseCode),
        ...(expiresAt === undefined ? {} : { expiresAt }),
        ...(ttl === undefined ? {} : { ttl }),
        ...(mxRecords === undefined ? {} : { mxRecords }),
        values: uniqueValues,
      };
    } catch (cause) {
      if (
        cause instanceof DnsQueryError &&
        (cause.code === 'aborted' || cause.code === 'budget-exhausted')
      )
        throw cause;
      const message =
        cause instanceof DnsQueryError
          ? cause.message
          : cause instanceof Error
            ? cause.message
            : 'DNS lookup failed.';
      return { error: message, messageBytes: 0, status: 'error', values: [] };
    }
  }
}
