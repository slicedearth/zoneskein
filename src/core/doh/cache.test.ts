import { encode } from '@dnsquery/dns-packet';
import { describe, expect, it } from 'vitest';

import { validateDnsName } from '../dns/names';
import { DnsQueryError, type DnsResponse } from '../dns/types';
import { decodeDnsMessage } from '../dns/wire';
import { DnsMemoryCache } from './cache';
import { resolverById } from './resolvers';

function response(ttl: number): DnsResponse {
  const parsed = validateDnsName('example.com');
  if (!parsed.ok) throw new Error(parsed.error.message);
  const message = decodeDnsMessage(
    encode({
      answers: [{ class: 'IN', data: '192.0.2.1', name: 'example.com.', ttl, type: 'A' }],
      flags: 0x8180,
      id: 0,
      questions: [{ class: 'IN', name: 'example.com.', type: 'A' }],
      type: 'response',
    }),
  );
  return {
    cache: 'miss',
    message,
    queryTimeMs: 1,
    question: { name: parsed.value, type: 'A' },
    receivedAt: '2026-08-13T00:00:00.000Z',
    resolver: resolverById('google'),
  };
}

function negativeResponse(soaTtl: number, minimum: number): DnsResponse {
  const parsed = validateDnsName('missing.example.com');
  if (!parsed.ok) throw new Error(parsed.error.message);
  const message = decodeDnsMessage(
    encode({
      authorities: [
        {
          class: 'IN',
          data: {
            expire: 604800,
            minimum,
            mname: 'ns1.example.com.',
            refresh: 3600,
            retry: 600,
            rname: 'hostmaster.example.com.',
            serial: 1,
          },
          name: 'example.com.',
          ttl: soaTtl,
          type: 'SOA',
        },
      ],
      flags: 0x8183,
      id: 0,
      questions: [{ class: 'IN', name: 'missing.example.com.', type: 'A' }],
      type: 'response',
    }),
  );
  return {
    cache: 'miss',
    message,
    queryTimeMs: 1,
    question: { name: parsed.value, type: 'A' },
    receivedAt: '2026-08-13T00:00:00.000Z',
    resolver: resolverById('google'),
  };
}

function unrelatedAnswerResponse(answerTtl: number, negativeTtl: number): DnsResponse {
  const parsed = validateDnsName('example.com');
  if (!parsed.ok) throw new Error(parsed.error.message);
  const message = decodeDnsMessage(
    encode({
      answers: [
        {
          class: 'IN',
          data: '192.0.2.1',
          name: 'unrelated.example.',
          ttl: answerTtl,
          type: 'A',
        },
      ],
      authorities: [
        {
          class: 'IN',
          data: {
            expire: 604800,
            minimum: negativeTtl,
            mname: 'ns1.example.',
            refresh: 3600,
            retry: 600,
            rname: 'hostmaster.example.',
            serial: 1,
          },
          name: 'example.',
          ttl: negativeTtl,
          type: 'SOA',
        },
      ],
      flags: 0x8180,
      id: 0,
      questions: [{ class: 'IN', name: 'example.com.', type: 'A' }],
      type: 'response',
    }),
  );
  return {
    cache: 'miss',
    message,
    queryTimeMs: 1,
    question: { name: parsed.value, type: 'A' },
    receivedAt: '2026-08-13T00:00:00.000Z',
    resolver: resolverById('google'),
  };
}

function cachedResponse(cache: DnsMemoryCache, key: string): DnsResponse | null {
  const hit = cache.get(key);
  return hit !== null && 'response' in hit ? hit.response : null;
}

describe('DNS memory cache', () => {
  it('expires entries using the lowest positive record TTL', () => {
    let now = 10_000;
    const cache = new DnsMemoryCache(() => now);
    const value = response(2);
    cache.set('answer', value);
    expect(cachedResponse(cache, 'answer')).toBe(value);
    now = 12_000;
    expect(cachedResponse(cache, 'answer')).toBeNull();
  });

  it('can be cleared without persisting query history', () => {
    const cache = new DnsMemoryCache();
    cache.set('answer', response(60));
    cache.clear();
    expect(cachedResponse(cache, 'answer')).toBeNull();
  });

  it('expires negative answers using min(SOA TTL, SOA minimum)', () => {
    let now = 10_000;
    const cache = new DnsMemoryCache(() => now);
    const value = negativeResponse(900, 2);
    cache.set('negative', value);
    expect(cachedResponse(cache, 'negative')).toBe(value);
    now = 12_000;
    expect(cachedResponse(cache, 'negative')).toBeNull();
  });

  it('does not classify unrelated answer data as a positive cache entry', () => {
    let now = 10_000;
    const cache = new DnsMemoryCache(() => now);
    const value = unrelatedAnswerResponse(86_400, 1);
    cache.set('unrelated', value);

    expect(cache.get('unrelated')).toMatchObject({ classification: 'ordinary-negative' });
    now = 11_000;
    expect(cache.get('unrelated')).toBeNull();
  });

  it('does not cache responses without a cacheable TTL', () => {
    const cache = new DnsMemoryCache();
    cache.set('zero', response(0));
    expect(cachedResponse(cache, 'zero')).toBeNull();
  });

  it('uses a bounded exponential backoff for sanitised resolution failures', () => {
    let now = 10_000;
    const cache = new DnsMemoryCache(() => now);
    const failure = new DnsQueryError(
      'transport-error',
      'private-query.example.test must not enter cached error state',
    );
    const lifetimes = [5, 10, 20, 40, 80, 160, 300];

    for (const lifetime of lifetimes) {
      cache.setFailure('opaque-cache-key', failure);
      const hit = cache.get('opaque-cache-key');
      expect(hit).not.toBeNull();
      if (hit === null || !('error' in hit)) throw new Error('Expected a cached failure.');
      expect(hit.classification).toBe('resolution-failure');
      expect(hit.error.code).toBe('transport-error');
      expect(hit.error.message).not.toContain('private-query.example.test');
      expect(hit.error.retryAfterMs).toBe(lifetime * 1000);
      now += lifetime * 1000;
      expect(cache.get('opaque-cache-key')).toBeNull();
    }
  });

  it.each(['aborted', 'budget-exhausted', 'cooldown', 'rate-limited'] as const)(
    'does not cache %s control-flow failures',
    (code) => {
      const cache = new DnsMemoryCache();
      cache.setFailure('control-flow', new DnsQueryError(code, 'Not a resolution failure.'));
      expect(cache.get('control-flow')).toBeNull();
    },
  );

  it('clears failure history and cached failures with the rest of the memory cache', () => {
    let now = 10_000;
    const cache = new DnsMemoryCache(() => now);
    const failure = new DnsQueryError('http-error', 'HTTP 503');
    cache.setFailure('failure', failure);
    cache.clear();
    expect(cache.get('failure')).toBeNull();

    cache.setFailure('failure', failure);
    const hit = cache.get('failure');
    if (hit === null || !('error' in hit)) throw new Error('Expected a cached failure.');
    expect(hit.error.retryAfterMs).toBe(5_000);
    now += 5_000;
  });
});
