import type { DnsResponse } from '../dns/types';

interface CacheEntry {
  readonly expiresAt: number;
  readonly response: DnsResponse;
}

const MAX_CACHE_ENTRIES = 256;
const MAX_CACHE_TTL_SECONDS = 86_400;
const NEGATIVE_CACHE_SECONDS = 60;

function responseTtl(response: DnsResponse): number {
  const records = [
    ...response.message.answers,
    ...response.message.authorities,
    ...response.message.additionals,
  ].filter((record) => record.type !== 'OPT' && record.ttl > 0);
  if (records.length === 0) return NEGATIVE_CACHE_SECONDS;
  return Math.min(MAX_CACHE_TTL_SECONDS, ...records.map((record) => record.ttl));
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
    this.#entries.set(key, {
      expiresAt: this.#now() + responseTtl(response) * 1000,
      response,
    });
    while (this.#entries.size > MAX_CACHE_ENTRIES) {
      const oldest = this.#entries.keys().next().value;
      if (oldest === undefined) break;
      this.#entries.delete(oldest);
    }
  }
}
