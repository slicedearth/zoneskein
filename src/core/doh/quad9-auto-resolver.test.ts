import { encode } from '@dnsquery/dns-packet';
import { describe, expect, it, vi } from 'vitest';

import { validateDnsName } from '../dns/names';
import { DnsQueryError } from '../dns/types';
import { DnsMemoryCache } from './cache';
import { createDnsResolver } from './resolvers';
import { Semaphore } from './semaphore';

function question() {
  const parsed = validateDnsName('example.com');
  if (!parsed.ok) throw new Error(parsed.error.message);
  return { name: parsed.value, type: 'A' as const };
}

function answerResponse(): Response {
  const body = encode({
    answers: [{ class: 'IN', data: '192.0.2.1', name: 'example.com.', ttl: 60, type: 'A' }],
    flags: 0x8180,
    id: 0,
    questions: [{ class: 'IN', name: 'example.com.', type: 'A' }],
    type: 'response',
  });
  return new Response(Uint8Array.from(body), {
    headers: { 'Content-Type': 'application/dns-message' },
    status: 200,
  });
}

function dependencies(fetchMock: typeof fetch) {
  return {
    cache: new DnsMemoryCache(),
    fetch: fetchMock,
    limiter: { wait: vi.fn(), imposeCooldown: vi.fn() } as never,
    semaphore: new Semaphore(4),
  };
}

const options = { checkingDisabled: false, dnssecOk: true };

describe('automatic Quad9 resolver', () => {
  it('keeps a run on the direct path after its first valid answer', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(answerResponse());
    const resolver = createDnsResolver('quad9', dependencies(fetchMock));

    const response = await resolver.query(question(), options);

    expect(response.resolver.id).toBe('quad9');
    expect(resolver.definition.id).toBe('quad9');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toEqual(
      expect.stringMatching(/^https:\/\/dns\.quad9\.net\/dns-query\?dns=/u),
    );
  });

  it('falls back once after a direct transport failure and discloses relay provenance', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError('Direct transport unavailable.'))
      .mockResolvedValueOnce(answerResponse());
    const resolver = createDnsResolver('quad9', dependencies(fetchMock));

    const [first, shared] = await Promise.all([
      resolver.query(question(), options),
      resolver.query(question(), options),
    ]);

    expect(first.resolver).toMatchObject({
      endpoint: '/api/doh/quad9',
      id: 'quad9-relay',
      label: 'Quad9 (compatibility mode)',
      relay: { operator: 'Netlify', upstreamLabel: 'Quad9' },
    });
    expect(shared.resolver.id).toBe('quad9-relay');
    expect(shared.cache).toBe('hit');
    expect(resolver.definition.id).toBe('quad9-relay');
    expect(fetchMock.mock.calls.map(([target]) => target)).toEqual([
      expect.stringMatching(/^https:\/\/dns\.quad9\.net\/dns-query\?dns=/u),
      '/api/doh/quad9',
    ]);
  });

  it('does not bypass a direct rate limit through the compatibility relay', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response('', { headers: { 'Retry-After': '30' }, status: 429 }));
    const resolver = createDnsResolver('quad9', dependencies(fetchMock));

    await expect(resolver.query(question(), options)).rejects.toMatchObject({
      code: 'rate-limited',
      retryAfterMs: 30_000,
    });
    expect(resolver.definition.id).toBe('quad9');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('does not hide an invalid direct response behind the compatibility relay', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(new Uint8Array([0]), {
        headers: { 'Content-Type': 'application/dns-message' },
        status: 200,
      }),
    );
    const resolver = createDnsResolver('quad9', dependencies(fetchMock));

    await expect(resolver.query(question(), options)).rejects.toMatchObject({
      code: 'invalid-response',
    });
    expect(resolver.definition.id).toBe('quad9');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('reports both failures when compatibility mode also fails', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError('Direct transport unavailable.'))
      .mockRejectedValueOnce(new TypeError('Relay transport unavailable.'));
    const resolver = createDnsResolver('quad9', dependencies(fetchMock));

    let caught: unknown;
    try {
      await resolver.query(question(), options);
    } catch (cause) {
      caught = cause;
    }
    expect(caught).toBeInstanceOf(DnsQueryError);
    if (!(caught instanceof DnsQueryError)) throw new Error('Expected a DNS query error.');
    expect(caught.code).toBe('transport-error');
    expect(caught.message).toContain('Automatic compatibility mode also failed');
    expect(resolver.definition.id).toBe('quad9-relay');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
