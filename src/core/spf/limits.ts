import type { SpfLookupResult } from './types';

export const SPF_WORK_LIMITS = Object.freeze({
  aggregateAnswerValues: 2_048,
  analysisNetworkValues: 1_024,
  dependencyVisits: 128,
  graphEdges: 256,
  lookupAnswerValues: 256,
  outputOctets: 65_000,
  provenanceEntries: 1_024,
  provenanceOctets: 1_048_576,
  responseBytes: 1_048_576,
  termExpansions: 512,
});

export const MAX_SPF_DNS_VALUE_CHARACTERS = 8_192;
export const MAX_SPF_DNS_MESSAGE_BYTES = 65_535;

const LOOKUP_STATUSES = new Set(['answer', 'nodata', 'nxdomain', 'servfail', 'error']);

function canonicalTimestamp(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

/** Apply the same bounded runtime contract to every SPF DNS consumer. */
export function spfLookupShapeError(result: SpfLookupResult): string | null {
  if (
    !Number.isInteger(result.messageBytes) ||
    result.messageBytes < 0 ||
    result.messageBytes > MAX_SPF_DNS_MESSAGE_BYTES
  ) {
    return 'The resolver reported an invalid DNS message size.';
  }
  if (!Array.isArray(result.values)) return 'The resolver returned an invalid value list.';
  if (result.values.length > SPF_WORK_LIMITS.lookupAnswerValues) {
    return `The resolver returned more than ${String(SPF_WORK_LIMITS.lookupAnswerValues)} values in one answer.`;
  }
  if (
    result.values.some(
      (value) => typeof value !== 'string' || value.length > MAX_SPF_DNS_VALUE_CHARACTERS,
    )
  ) {
    return 'The resolver returned an invalid or overlong DNS value.';
  }
  if (!LOOKUP_STATUSES.has(result.status)) return 'The resolver returned an unknown status.';
  if (result.status !== 'answer' && result.values.length > 0) {
    return 'The resolver returned answer values with a non-answer status.';
  }
  if (
    result.ttl !== undefined &&
    (!Number.isInteger(result.ttl) || result.ttl < 0 || result.ttl > 0xffff_ffff)
  ) {
    return 'The resolver returned an invalid TTL.';
  }
  if (result.expiresAt !== undefined && !canonicalTimestamp(result.expiresAt)) {
    return 'The resolver returned an invalid absolute expiry.';
  }
  if (result.mxRecords !== undefined) {
    const rawMxRecords: unknown = result.mxRecords;
    if (
      !Array.isArray(rawMxRecords) ||
      rawMxRecords.length > SPF_WORK_LIMITS.lookupAnswerValues
    ) {
      return `The resolver returned more than ${String(SPF_WORK_LIMITS.lookupAnswerValues)} MX values in one answer.`;
    }
    const mxRecords = rawMxRecords as readonly unknown[];
    if (
      mxRecords.some((candidate) => {
        if (candidate === null || typeof candidate !== 'object') return true;
        const record = candidate as Readonly<Record<string, unknown>>;
        const preference = record['preference'];
        return (
          typeof record['exchange'] !== 'string' ||
          typeof preference !== 'number' ||
          !Number.isInteger(preference) ||
          preference < 0 ||
          preference > 65_535
        );
      })
    ) {
      return 'The resolver returned invalid MX values.';
    }
    if (result.status !== 'answer' && mxRecords.length > 0) {
      return 'The resolver returned MX values with a non-answer status.';
    }
  }
  return null;
}
