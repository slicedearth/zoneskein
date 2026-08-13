import { validateDnsName } from '../dns/names';
import { parseRecordView } from '../dns/records';
import { DnsQueryError, type DnsResolver } from '../dns/types';
import { DnsQueryRun } from '../doh/query-run';
import type { SpfDnsClient, SpfLookupResult, SpfLookupType } from './types';

function mxExchange(value: unknown): string | null {
  if (value === null || typeof value !== 'object') return null;
  const exchange = (value as Record<string, unknown>)['exchange'];
  return typeof exchange === 'string' ? exchange : null;
}

function statusFromCode(code: string): SpfLookupResult['status'] {
  if (code === 'NXDOMAIN') return 'nxdomain';
  if (code === 'SERVFAIL') return 'servfail';
  return code === 'NOERROR' ? 'nodata' : 'error';
}

export class WireSpfDnsClient implements SpfDnsClient {
  readonly #resolver: DnsResolver;
  readonly #run: DnsQueryRun;

  constructor(resolver: DnsResolver, run: DnsQueryRun) {
    this.#resolver = resolver;
    this.#run = run;
  }

  async lookup(domain: string, type: SpfLookupType): Promise<SpfLookupResult> {
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
      const matching = response.message.answers.filter((record) => record.type === type);
      const values = matching.flatMap((record) => {
        if (type === 'TXT') {
          const view = parseRecordView(record);
          return view.txtChunks === undefined
            ? []
            : [view.txtChunks.map((chunk) => chunk.text).join('')];
        }
        if (type === 'MX') {
          const exchange = mxExchange(record.data);
          return exchange === null ? [] : [exchange];
        }
        return typeof record.data === 'string' ? [record.data] : [];
      });
      const ttlValues = matching.map((record) => record.ttl).filter((ttl) => ttl >= 0);
      return {
        messageBytes: response.message.messageBytes,
        status: values.length > 0 ? 'answer' : statusFromCode(response.message.responseCode),
        ...(ttlValues.length === 0 ? {} : { ttl: Math.min(...ttlValues) }),
        values,
      };
    } catch (cause) {
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
