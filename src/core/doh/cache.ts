import type { DnsResponse } from '../dns/types';

interface CacheEntry {
  readonly expiresAt: number;
  readonly response: DnsResponse;
}

const MAX_CACHE_ENTRIES = 256;
const MAX_CACHE_TTL_SECONDS = 86_400;
const MAX_NEGATIVE_CACHE_TTL_SECONDS = 10_800;
function responseTtl(response: DnsResponse, now: number): number {
  const records = [...response.message.answers, ...response.message.authorities];
  const recordTtls = records.map((record) => record.ttl);
  const originalTtls = records.flatMap((record) => {
    if (record.type !== 'RRSIG' || record.data === null || typeof record.data !== 'object')
      return [];
    const originalTtl = (record.data as Record<string, unknown>)['originalTTL'];
    return typeof originalTtl === 'number' && Number.isInteger(originalTtl) && originalTtl >= 0
      ? [originalTtl]
      : [];
  });
  const ttlCandidates = [
    ...recordTtls,
    ...originalTtls,
    ...(response.message.negativeCacheTtl === undefined
      ? []
      : [response.message.negativeCacheTtl]),
  ];
  if (ttlCandidates.length === 0) return 0;
  let ttl = Math.min(MAX_CACHE_TTL_SECONDS, ...ttlCandidates);
  if (response.message.negativeCacheTtl !== undefined)
    ttl = Math.min(ttl, MAX_NEGATIVE_CACHE_TTL_SECONDS);
  const receivedAt = Date.parse(response.receivedAt);
  if (!Number.isFinite(receivedAt)) return 0;
  const receivedSeconds = Math.floor(receivedAt / 1000) >>> 0;
  for (const signature of [...response.message.answers, ...response.message.authorities].filter(
    (record) => record.type === 'RRSIG',
  )) {
    if (signature.data === null || typeof signature.data !== 'object') continue;
    const expiration = (signature.data as Record<string, unknown>)['expiration'];
    if (typeof expiration !== 'number' || !Number.isInteger(expiration)) continue;
    const lifetime = ((expiration >>> 0) - receivedSeconds) >>> 0;
    ttl = lifetime < 0x8000_0000 ? Math.min(ttl, lifetime) : 0;
  }
  const ageSeconds = Math.max(0, (now - receivedAt) / 1000);
  return Math.max(0, ttl - ageSeconds);
}

export class DnsMemoryCache {
  readonly #entries = new Map<string, CacheEntry>();
  readonly #now: () => number;

  constructor(now: () => number = Date.now) {
    this.#now = now;
  }

  clear(): void {
    this.#entries.clear();
  }

  get(key: string): DnsResponse | null {
    const entry = this.#entries.get(key);
    if (entry === undefined) return null;
    if (entry.expiresAt <= this.#now()) {
      this.#entries.delete(key);
      return null;
    }
    this.#entries.delete(key);
    this.#entries.set(key, entry);
    return entry.response;
  }

  set(key: string, response: DnsResponse): void {
    this.#entries.delete(key);
    const now = this.#now();
    const ttl = responseTtl(response, now);
    if (ttl <= 0) return;
    this.#entries.set(key, {
      expiresAt: now + ttl * 1000,
      response,
    });
    while (this.#entries.size > MAX_CACHE_ENTRIES) {
      const oldest = this.#entries.keys().next().value;
      if (oldest === undefined) break;
      this.#entries.delete(oldest);
    }
  }
}
