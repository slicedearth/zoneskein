import { validateDnsName } from '../dns/names';
import { parseRecordView } from '../dns/records';
import { reverseNameFromAddress } from '../dns/reverse';
import { DnsQueryError, type DnsRecord, type DnsResolver } from '../dns/types';
import { DnsQueryRun } from '../doh/query-run';
import type { SpfSenderDnsClient } from './sender-evaluator';
import type { SpfLookupResult, SpfLookupType, SpfMxRecord } from './types';

const MAX_PTR_VALUES = 256;
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
      const mxRecords = type === 'MX' ? distinctMxRecords(matching) : undefined;
      const values = matching.flatMap((record) => {
        if (type === 'TXT') {
          const view = parseRecordView(record);
          return view.txtChunks === undefined
            ? []
            : [view.txtChunks.map((chunk) => chunk.text).join('')];
        }
        if (type === 'MX') {
          return [];
        }
        return typeof record.data === 'string' ? [record.data] : [];
      });
      const uniqueValues =
        mxRecords === undefined
          ? [...new Set(values)]
          : [...new Set(mxRecords.map((record) => record.exchange))];
      const boundedValues =
        type === 'PTR' ? uniqueValues.slice(0, MAX_PTR_VALUES) : uniqueValues;
      const ttlValues = bound.ttlRecords.map((record) => record.ttl).filter((ttl) => ttl >= 0);
      return {
        messageBytes: response.message.messageBytes,
        status:
          boundedValues.length > 0 ? 'answer' : statusFromCode(response.message.responseCode),
        ...(ttlValues.length === 0 ? {} : { ttl: Math.min(...ttlValues) }),
        ...(mxRecords === undefined ? {} : { mxRecords }),
        values: boundedValues,
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
