import { validateDnsName } from './names';
import { parseRecordView } from './records';
import { DnsQueryError, type DnsRecord, type DnsRecordType, type DnsResolver } from './types';
import { DnsQueryRun } from '../doh/query-run';

export interface PolicyQueryResult {
  readonly answers: readonly DnsRecord[];
  readonly error?: string;
  readonly messageBytes: number;
  readonly records: readonly DnsRecord[];
  readonly responseCode: string;
  readonly ttl?: number;
  readonly values: readonly string[];
}

export async function queryPolicyRecords(
  resolver: DnsResolver,
  run: DnsQueryRun,
  name: string,
  type: DnsRecordType,
): Promise<PolicyQueryResult> {
  const parsed = validateDnsName(name);
  if (!parsed.ok) {
    return {
      answers: [],
      error: parsed.error.message,
      messageBytes: 0,
      records: [],
      responseCode: 'LOCAL_ERROR',
      values: [],
    };
  }
  try {
    const response = await run.query(
      resolver,
      { name: parsed.value, type },
      { checkingDisabled: false, dnssecOk: true },
    );
    const records = response.message.answers.filter((record) => record.type === type);
    const ttlValues = records.map((record) => record.ttl);
    const values =
      type === 'TXT'
        ? records.flatMap((record) => {
            const view = parseRecordView(record);
            return view.txtChunks === undefined
              ? []
              : [view.txtChunks.map((chunk) => chunk.text).join('')];
          })
        : [];
    return {
      answers: response.message.answers,
      messageBytes: response.message.messageBytes,
      records,
      responseCode: response.message.responseCode,
      ...(ttlValues.length === 0 ? {} : { ttl: Math.min(...ttlValues) }),
      values,
    };
  } catch (cause) {
    const message =
      cause instanceof DnsQueryError
        ? cause.message
        : cause instanceof Error
          ? cause.message
          : 'DNS policy lookup failed.';
    return {
      answers: [],
      error: message,
      messageBytes: 0,
      records: [],
      responseCode: 'QUERY_ERROR',
      values: [],
    };
  }
}
