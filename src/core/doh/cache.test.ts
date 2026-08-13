import { encode } from '@dnsquery/dns-packet';
import { describe, expect, it } from 'vitest';

import { validateDnsName } from '../dns/names';
import type { DnsResponse } from '../dns/types';
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

describe('DNS memory cache', () => {
  it('expires entries using the lowest positive record TTL', () => {
    let now = 10_000;
    const cache = new DnsMemoryCache(() => now);
    const value = response(2);
    cache.set('answer', value);
    expect(cache.get('answer')).toBe(value);
    now = 12_000;
    expect(cache.get('answer')).toBeNull();
  });

  it('can be cleared without persisting query history', () => {
    const cache = new DnsMemoryCache();
    cache.set('answer', response(60));
    cache.clear();
    expect(cache.get('answer')).toBeNull();
  });

  it('expires negative answers using min(SOA TTL, SOA minimum)', () => {
    let now = 10_000;
    const cache = new DnsMemoryCache(() => now);
    const value = negativeResponse(900, 2);
    cache.set('negative', value);
    expect(cache.get('negative')).toBe(value);
    now = 12_000;
    expect(cache.get('negative')).toBeNull();
  });

  it('does not cache responses without a cacheable TTL', () => {
    const cache = new DnsMemoryCache();
    cache.set('zero', response(0));
    expect(cache.get('zero')).toBeNull();
  });
});
