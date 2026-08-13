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
});
