import { validateDnsName } from './names';
import { reachableAnswerRecords } from './answer-chain';
import { txtRecordValue } from './records';
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
    const bound =
      response.message.responseCode === 'NOERROR'
        ? reachableAnswerRecords(parsed.value.ascii, response.message.answers, type)
        : { aliases: [], ignoredRecords: 0, records: [] };
    const records = bound.records;
    const ttlValues = [...bound.aliases, ...records].map((record) => record.ttl);
    const txtValues = type === 'TXT' ? records.map(txtRecordValue) : [];
    const malformedText = txtValues.some((value) => value === null);
    const values = txtValues.filter((value): value is string => value !== null);
    return {
      answers: response.message.answers,
      ...(bound.error !== undefined
        ? { error: bound.error }
        : malformedText
          ? { error: 'The policy answer contains TXT data that is not valid UTF-8.' }
          : {}),
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
