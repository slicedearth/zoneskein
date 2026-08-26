import {
  DnsQueryError,
  type DnsQueryErrorCode,
  type DnsRecord,
  type DnsResponse,
} from '../dns/types';
import { reachableAnswerRecords } from '../dns/answer-chain';

export type DnsCacheClassification =
  'positive' | 'resolver-ad-negative' | 'ordinary-negative' | 'resolution-failure';

export type DnsCacheHit =
  | {
      readonly classification: DnsCacheClassification;
      readonly response: DnsResponse;
    }
  | {
      readonly classification: 'resolution-failure';
      readonly error: DnsQueryError;
    };

type CacheableFailureCode = Extract<
  DnsQueryErrorCode,
  'http-error' | 'invalid-response' | 'timeout' | 'transport-error'
>;

interface ResponseCacheEntry {
  readonly classification: DnsCacheClassification;
  readonly expiresAt: number;
  readonly response: DnsResponse;
}

interface FailureCacheEntry {
  readonly classification: 'resolution-failure';
  readonly errorCode: CacheableFailureCode;
  readonly expiresAt: number;
}

type CacheEntry = FailureCacheEntry | ResponseCacheEntry;

interface FailureHistory {
  readonly attempts: number;
  readonly lastFailureAt: number;
}

const MAX_CACHE_ENTRIES = 256;
const MAX_CACHE_TTL_SECONDS = 86_400;
const MAX_NEGATIVE_CACHE_TTL_SECONDS = 10_800;
// RFC 9520 requires at least one second and no more than five minutes for
// resolution failures. Start at five seconds and double repeated failures.
const INITIAL_FAILURE_CACHE_TTL_SECONDS = 5;
const MAX_FAILURE_CACHE_TTL_SECONDS = 300;
const MAX_FAILURE_ATTEMPTS = 7;

const CACHEABLE_FAILURE_CODES = new Set<DnsQueryErrorCode>([
  'http-error',
  'invalid-response',
  'timeout',
  'transport-error',
]);

function isCacheableFailureCode(code: DnsQueryErrorCode): code is CacheableFailureCode {
  return CACHEABLE_FAILURE_CODES.has(code);
}

function cachedFailureMessage(code: CacheableFailureCode): string {
  if (code === 'timeout')
    return 'A recent DNS request timed out. Retry after the short backoff.';
  if (code === 'http-error')
    return 'A recent resolver HTTP request failed. Retry after the short backoff.';
  if (code === 'invalid-response')
    return 'A recent resolver response was invalid. Retry after the short backoff.';
  return 'A recent DNS transport request failed. Retry after the short backoff.';
}

function minimum(values: readonly number[], maximum: number): number {
  return values.length === 0 ? 0 : Math.min(maximum, ...values);
}

function recordTtlCandidates(records: readonly DnsRecord[]): readonly number[] {
  return records.flatMap((record) => {
    const values = [record.ttl];
    if (record.type !== 'RRSIG' || record.data === null || typeof record.data !== 'object')
      return values;
    const originalTtl = (record.data as Record<string, unknown>)['originalTTL'];
    if (typeof originalTtl === 'number' && Number.isInteger(originalTtl) && originalTtl >= 0)
      values.push(originalTtl);
    return values;
  });
}

function capBySignatureExpiration(
  ttl: number,
  records: readonly DnsRecord[],
  response: DnsResponse,
): number {
  const receivedAt = Date.parse(response.receivedAt);
  if (!Number.isFinite(receivedAt)) return 0;
  const receivedSeconds = Math.floor(receivedAt / 1000) >>> 0;
  let result = ttl;
  for (const signature of records.filter((record) => record.type === 'RRSIG')) {
    if (signature.data === null || typeof signature.data !== 'object') continue;
    const expiration = (signature.data as Record<string, unknown>)['expiration'];
    if (typeof expiration !== 'number' || !Number.isInteger(expiration)) continue;
    const lifetime = ((expiration >>> 0) - receivedSeconds) >>> 0;
    result = lifetime < 0x8000_0000 ? Math.min(result, lifetime) : 0;
  }
  return result;
}

function remainingTtl(ttl: number, response: DnsResponse, now: number): number {
  const receivedAt = Date.parse(response.receivedAt);
  if (!Number.isFinite(receivedAt)) return 0;
  const ageSeconds = Math.max(0, (now - receivedAt) / 1000);
  return Math.max(0, ttl - ageSeconds);
}

function negativeClassification(response: DnsResponse): DnsCacheClassification {
  const denialTypes = new Set(['NSEC', 'NSEC3']);
  const hasDenial = response.message.authorities.some((record) => denialTypes.has(record.type));
  const hasSignature = response.message.authorities.some((record) => record.type === 'RRSIG');
  // This classification only controls cache lifetime. It does not replace
  // ZoneSkein's independent DNSSEC validation or turn the resolver AD bit
  // into an application trust conclusion.
  return response.message.flags.authenticatedData && hasDenial && hasSignature
    ? 'resolver-ad-negative'
    : 'ordinary-negative';
}

function reachablePositiveRecords(response: DnsResponse): readonly DnsRecord[] {
  const reachable = reachableAnswerRecords(
    response.question.name.ascii,
    response.message.answers,
    response.question.type,
  );
  if (reachable.error !== undefined || reachable.records.length === 0) return [];
  const owners = new Set(
    [...reachable.aliases, ...reachable.records].map((record) =>
      record.owner.toLowerCase().replace(/\.$/u, ''),
    ),
  );
  const signatures = response.message.answers.filter(
    (record) =>
      record.type === 'RRSIG' && owners.has(record.owner.toLowerCase().replace(/\.$/u, '')),
  );
  return [...reachable.aliases, ...reachable.records, ...signatures];
}

function responseClassification(response: DnsResponse): DnsCacheClassification {
  if (
    response.message.responseCode !== 'NOERROR' &&
    response.message.responseCode !== 'NXDOMAIN'
  )
    return 'resolution-failure';
  if (
    response.message.responseCode === 'NXDOMAIN' ||
    reachablePositiveRecords(response).length === 0
  )
    return negativeClassification(response);
  return 'positive';
}

function positiveResponseTtl(response: DnsResponse, now: number): number {
  const records = reachablePositiveRecords(response);
  const ttl = minimum(recordTtlCandidates(records), MAX_CACHE_TTL_SECONDS);
  return remainingTtl(capBySignatureExpiration(ttl, records, response), response, now);
}

function negativeResponseTtl(
  response: DnsResponse,
  now: number,
  authenticated: boolean,
): number {
  const soa = response.message.authorities.find((record) => record.type === 'SOA');
  const soaMinimum =
    soa?.data !== null && typeof soa?.data === 'object'
      ? (soa.data as Record<string, unknown>)['minimum']
      : undefined;
  const derivedNegativeTtl =
    soa !== undefined &&
    typeof soaMinimum === 'number' &&
    Number.isInteger(soaMinimum) &&
    soaMinimum >= 0
      ? Math.min(soa.ttl, soaMinimum)
      : undefined;
  const negativeTtl = response.message.negativeCacheTtl ?? derivedNegativeTtl;
  if (negativeTtl === undefined) return 0;
  let ttl = Math.min(negativeTtl, MAX_NEGATIVE_CACHE_TTL_SECONDS);
  if (authenticated) {
    const denialRecords = response.message.authorities.filter(
      (record) =>
        record.type === 'SOA' ||
        record.type === 'NSEC' ||
        record.type === 'NSEC3' ||
        record.type === 'RRSIG',
    );
    ttl = Math.min(ttl, ...recordTtlCandidates(denialRecords));
    ttl = capBySignatureExpiration(ttl, denialRecords, response);
  }
  return remainingTtl(ttl, response, now);
}

export class DnsMemoryCache {
  readonly #entries = new Map<string, CacheEntry>();
  readonly #failureHistory = new Map<string, FailureHistory>();
  readonly #now: () => number;

  constructor(now: () => number = Date.now) {
    this.#now = now;
  }

  clear(): void {
    this.#entries.clear();
    this.#failureHistory.clear();
  }

  get(key: string): DnsCacheHit | null {
    const now = this.#now();
    this.#pruneFailureHistory(now);
    const entry = this.#entries.get(key);
    if (entry === undefined) return null;
    if (entry.expiresAt <= now) {
      this.#entries.delete(key);
      return null;
    }
    this.#entries.delete(key);
    this.#entries.set(key, entry);
    if ('response' in entry)
      return { classification: entry.classification, response: entry.response };
    return {
      classification: 'resolution-failure',
      error: new DnsQueryError(
        entry.errorCode,
        cachedFailureMessage(entry.errorCode),
        Math.max(1, Math.ceil(entry.expiresAt - now)),
      ),
    };
  }

  set(key: string, response: DnsResponse): void {
    this.#entries.delete(key);
    const now = this.#now();
    const classification = responseClassification(response);
    if (classification === 'resolution-failure') {
      this.#setResponse(key, response, classification, this.#nextFailureTtl(key, now), now);
      return;
    }

    this.#failureHistory.delete(key);
    const ttl =
      classification === 'positive'
        ? positiveResponseTtl(response, now)
        : negativeResponseTtl(response, now, classification === 'resolver-ad-negative');
    this.#setResponse(key, response, classification, ttl, now);
  }

  setFailure(key: string, error: DnsQueryError): void {
    if (!isCacheableFailureCode(error.code)) return;
    this.#entries.delete(key);
    const now = this.#now();
    const ttl = this.#nextFailureTtl(key, now);
    // Retain only a bounded error category. Transport exception text can be
    // implementation-defined and must not become cached application state.
    this.#entries.set(key, {
      classification: 'resolution-failure',
      errorCode: error.code,
      expiresAt: now + ttl * 1000,
    });
    this.#enforceEntryLimit();
  }

  #enforceEntryLimit(): void {
    while (this.#entries.size > MAX_CACHE_ENTRIES) {
      const oldest = this.#entries.keys().next().value;
      if (oldest === undefined) break;
      this.#entries.delete(oldest);
    }
  }

  #nextFailureTtl(key: string, now: number): number {
    this.#pruneFailureHistory(now);
    const previous = this.#failureHistory.get(key);
    const attempts = Math.min((previous?.attempts ?? 0) + 1, MAX_FAILURE_ATTEMPTS);
    this.#failureHistory.delete(key);
    this.#failureHistory.set(key, { attempts, lastFailureAt: now });
    while (this.#failureHistory.size > MAX_CACHE_ENTRIES) {
      const oldest = this.#failureHistory.keys().next().value;
      if (oldest === undefined) break;
      this.#failureHistory.delete(oldest);
    }
    return Math.min(
      INITIAL_FAILURE_CACHE_TTL_SECONDS * 2 ** (attempts - 1),
      MAX_FAILURE_CACHE_TTL_SECONDS,
    );
  }

  #pruneFailureHistory(now: number): void {
    for (const [key, value] of this.#failureHistory) {
      if (value.lastFailureAt + MAX_FAILURE_CACHE_TTL_SECONDS * 1000 <= now)
        this.#failureHistory.delete(key);
    }
  }

  #setResponse(
    key: string,
    response: DnsResponse,
    classification: DnsCacheClassification,
    ttl: number,
    now: number,
  ): void {
    if (ttl <= 0) return;
    this.#entries.set(key, {
      classification,
      expiresAt: now + ttl * 1000,
      response,
    });
    this.#enforceEntryLimit();
  }
}
