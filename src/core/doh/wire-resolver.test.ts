import { encode } from '@dnsquery/dns-packet';
import { describe, expect, it, vi } from 'vitest';

import { validateDnsName } from '../dns/names';
import { DnsMemoryCache } from './cache';
import { resolverById } from './resolvers';
import { Semaphore } from './semaphore';
import { WireDnsResolver } from './wire-resolver';

function question() {
  const parsed = validateDnsName('example.com');
  if (!parsed.ok) throw new Error(parsed.error.message);
  return { name: parsed.value, type: 'A' as const };
}

function answerResponse(status = 200): Response {
  const body = encode({
    answers: [{ class: 'IN', data: '192.0.2.1', name: 'example.com.', ttl: 60, type: 'A' }],
    flags: 0x8180,
    id: 0,
    questions: [{ class: 'IN', name: 'example.com.', type: 'A' }],
    type: 'response',
  });
  const buffer = new ArrayBuffer(body.byteLength);
  new Uint8Array(buffer).set(body);
  return new Response(buffer, {
    headers: { 'Content-Type': 'application/dns-message' },
    status,
  });
}

function testDependencies(fetchMock: typeof fetch) {
  return {
    cache: new DnsMemoryCache(),
    fetch: fetchMock,
    limiter: { wait: vi.fn(), imposeCooldown: vi.fn() } as never,
    semaphore: new Semaphore(4),
  };
}

describe('wire DoH resolver', () => {
  it('uses fixed POST wire requests and TTL cache', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(answerResponse());
    const resolver = new WireDnsResolver(resolverById('google'), testDependencies(fetchMock));
    const options = { checkingDisabled: false, dnssecOk: true };

    const first = await resolver.query(question(), options);
    const second = await resolver.query(question(), options);

    expect(first.cache).toBe('miss');
    expect(second.cache).toBe('hit');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      'https://dns.google/dns-query',
      expect.objectContaining({ method: 'POST', credentials: 'omit' }),
    );
  });

  it('deduplicates identical in-flight requests', async () => {
    let resolveFetch: ((value: Response) => void) | undefined;
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveFetch = resolve;
        }),
    );
    const resolver = new WireDnsResolver(
      resolverById('cloudflare'),
      testDependencies(fetchMock),
    );
    const options = { checkingDisabled: false, dnssecOk: false };
    const first = resolver.query(question(), options);
    const second = resolver.query(question(), options);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    resolveFetch?.(answerResponse());

    expect((await first).cache).toBe('miss');
    expect((await second).cache).toBe('shared');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('opens a cooldown circuit after HTTP 429', async () => {
    const imposeCooldown = vi.fn();
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response('', { headers: { 'Retry-After': '12' }, status: 429 }));
    const resolver = new WireDnsResolver(resolverById('quad9'), {
      ...testDependencies(fetchMock),
      limiter: { wait: vi.fn(), imposeCooldown } as never,
    });

    await expect(
      resolver.query(question(), { checkingDisabled: false, dnssecOk: false }),
    ).rejects.toMatchObject({ code: 'rate-limited', retryAfterMs: 12_000 });
    expect(imposeCooldown).toHaveBeenCalledWith('quad9', 12_000);
  });
});
