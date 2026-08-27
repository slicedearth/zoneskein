import { encode } from '@dnsquery/dns-packet';
import { describe, expect, it, vi } from 'vitest';

import { validateDnsName } from '../dns/names';
import { DnsQueryError } from '../dns/types';
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

function resolutionFailureResponse(responseCode: 'FORMERR' | 'REFUSED' | 'SERVFAIL'): Response {
  const responseCodes = { FORMERR: 1, REFUSED: 5, SERVFAIL: 2 } as const;
  const body = encode({
    authorities: [
      {
        class: 'IN',
        data: {
          expire: 604_800,
          minimum: 86_400,
          mname: 'ns1.example.com.',
          refresh: 3_600,
          retry: 600,
          rname: 'hostmaster.example.com.',
          serial: 1,
        },
        name: 'example.com.',
        ttl: 86_400,
        type: 'SOA',
      },
    ],
    flags: 0x8180 | responseCodes[responseCode],
    id: 0,
    questions: [{ class: 'IN', name: 'example.com.', type: 'A' }],
    type: 'response',
  });
  const buffer = new ArrayBuffer(body.byteLength);
  new Uint8Array(buffer).set(body);
  return new Response(buffer, {
    headers: { 'Content-Type': 'application/dns-message' },
    status: 200,
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
  it('uses fixed browser-compatible GET wire requests and TTL cache', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockImplementation(() => Promise.resolve(answerResponse()));
    const resolver = new WireDnsResolver(resolverById('google'), testDependencies(fetchMock));
    const options = { checkingDisabled: false, dnssecOk: true };

    const first = await resolver.query(question(), options);
    const second = await resolver.query(question(), options);

    expect(first.cache).toBe('miss');
    expect(second.cache).toBe('hit');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [target, init] = fetchMock.mock.calls[0] ?? [];
    if (typeof target !== 'string') throw new Error('Expected a string resolver URL.');
    expect(target).toMatch(/^https:\/\/dns\.google\/dns-query\?dns=/u);
    expect(target).not.toContain('example.com');
    expect(init).toEqual(
      expect.objectContaining({ credentials: 'omit', method: 'GET', redirect: 'error' }),
    );
  });

  it('keeps recursive and recursion-disabled questions in separate cache entries', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockImplementation(() => Promise.resolve(answerResponse()));
    const resolver = new WireDnsResolver(resolverById('google'), testDependencies(fetchMock));
    const options = { checkingDisabled: false, dnssecOk: true };

    await expect(resolver.query(question(), options)).resolves.toMatchObject({ cache: 'miss' });
    await expect(
      resolver.query(question(), { ...options, recursionDesired: false }),
    ).resolves.toMatchObject({ cache: 'miss' });
    await expect(resolver.query(question(), options)).resolves.toMatchObject({ cache: 'hit' });
    await expect(
      resolver.query(question(), { ...options, recursionDesired: false }),
    ).resolves.toMatchObject({ cache: 'hit' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('uses a same-origin POST for the explicit Quad9 compatibility relay', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(answerResponse());
    const resolver = new WireDnsResolver(
      resolverById('quad9-relay'),
      testDependencies(fetchMock),
    );

    const response = await resolver.query(question(), {
      checkingDisabled: false,
      dnssecOk: true,
    });

    expect(response.resolver).toMatchObject({
      endpoint: '/api/doh/quad9',
      httpMethod: 'POST',
      id: 'quad9-relay',
      label: 'Quad9 (compatibility mode)',
      relay: {
        operator: 'Netlify',
        upstreamEndpoint: 'https://dns.quad9.net/dns-query',
        upstreamLabel: 'Quad9',
      },
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [target, init] = fetchMock.mock.calls[0] ?? [];
    expect(target).toBe('/api/doh/quad9');
    expect(init?.body).toBeInstanceOf(ArrayBuffer);
    expect(init).toEqual(
      expect.objectContaining({
        cache: 'no-store',
        credentials: 'omit',
        headers: {
          Accept: 'application/dns-message',
          'Content-Type': 'application/dns-message',
        },
        method: 'POST',
        mode: 'cors',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
      }),
    );
  });

  it('keeps direct and relayed Quad9 cache entries separate', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockImplementation(() => Promise.resolve(answerResponse()));
    const cache = new DnsMemoryCache();
    const dependencies = { ...testDependencies(fetchMock), cache };
    const direct = new WireDnsResolver(resolverById('quad9'), dependencies);
    const relayed = new WireDnsResolver(resolverById('quad9-relay'), dependencies);
    const options = { checkingDisabled: false, dnssecOk: true };

    expect((await direct.query(question(), options)).cache).toBe('miss');
    expect((await relayed.query(question(), options)).cache).toBe('miss');
    expect((await direct.query(question(), options)).cache).toBe('hit');
    expect((await relayed.query(question(), options)).cache).toBe('hit');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls.map(([target]) => target)).toEqual([
      expect.stringMatching(/^https:\/\/dns\.quad9\.net\/dns-query\?dns=/u),
      '/api/doh/quad9',
    ]);
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
    const [target, init] = fetchMock.mock.calls[0] ?? [];
    expect(target).toBe('https://cloudflare-dns.com/dns-query');
    expect(init?.method).toBe('POST');
    expect(init?.body).toBeInstanceOf(ArrayBuffer);
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

  it('opens only the relay cooldown circuit after a relay HTTP 429', async () => {
    const imposeCooldown = vi.fn();
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response('', { headers: { 'Retry-After': '7' }, status: 429 }));
    const resolver = new WireDnsResolver(resolverById('quad9-relay'), {
      ...testDependencies(fetchMock),
      limiter: { wait: vi.fn(), imposeCooldown } as never,
    });

    await expect(
      resolver.query(question(), { checkingDisabled: false, dnssecOk: false }),
    ).rejects.toMatchObject({
      code: 'rate-limited',
      message: 'The resolver rate-limited this browser.',
      retryAfterMs: 7_000,
    });
    expect(imposeCooldown).toHaveBeenCalledWith('quad9-relay', 7_000);
    const [target, init] = fetchMock.mock.calls[0] ?? [];
    expect(target).toBe('/api/doh/quad9');
    expect(init?.method).toBe('POST');
  });

  it('recovers from a transient SERVFAIL without inheriting its authority TTL', async () => {
    let now = Date.now();
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(resolutionFailureResponse('SERVFAIL'))
      .mockResolvedValueOnce(answerResponse());
    const resolver = new WireDnsResolver(resolverById('google'), {
      ...testDependencies(fetchMock),
      cache: new DnsMemoryCache(() => now),
    });
    const options = { checkingDisabled: false, dnssecOk: true };

    await expect(resolver.query(question(), options)).resolves.toMatchObject({
      cache: 'miss',
      message: { responseCode: 'SERVFAIL' },
    });
    await expect(resolver.query(question(), options)).resolves.toMatchObject({
      cache: 'hit',
      message: { responseCode: 'SERVFAIL' },
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    now += 5_000;
    await expect(resolver.query(question(), options)).resolves.toMatchObject({
      cache: 'miss',
      message: { responseCode: 'NOERROR' },
    });
    await expect(resolver.query(question(), options)).resolves.toMatchObject({
      cache: 'hit',
      message: { responseCode: 'NOERROR' },
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('briefly caches HTTP failures and retries after the bounded backoff', async () => {
    let now = Date.now();
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response('', { status: 503 }))
      .mockResolvedValueOnce(answerResponse());
    const resolver = new WireDnsResolver(resolverById('google'), {
      ...testDependencies(fetchMock),
      cache: new DnsMemoryCache(() => now),
    });
    const options = { checkingDisabled: false, dnssecOk: false };

    await expect(resolver.query(question(), options)).rejects.toMatchObject({
      code: 'http-error',
    });
    await expect(resolver.query(question(), options)).rejects.toMatchObject({
      code: 'http-error',
      retryAfterMs: 5_000,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    now += 5_000;
    await expect(resolver.query(question(), options)).resolves.toMatchObject({
      cache: 'miss',
      message: { responseCode: 'NOERROR' },
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('cancels a rejected response body before releasing the request boundary', async () => {
    let releaseCancellation: (() => void) | undefined;
    const cancel = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          releaseCancellation = resolve;
        }),
    );
    const body = new ReadableStream<Uint8Array>({ cancel });
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(body, { status: 503 }));
    const resolver = new WireDnsResolver(resolverById('google'), testDependencies(fetchMock));
    let settled = false;
    const pending = resolver
      .query(question(), { checkingDisabled: false, dnssecOk: false })
      .finally(() => {
        settled = true;
      });

    await vi.waitFor(() => expect(cancel).toHaveBeenCalledOnce());
    expect(settled).toBe(false);
    releaseCancellation?.();
    await expect(pending).rejects.toMatchObject({ code: 'http-error' });
  });

  it('sanitises cached transport failures and recovers after the bounded backoff', async () => {
    let now = Date.now();
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(
        new Error('private-query.example.test appeared in transport state'),
      )
      .mockResolvedValueOnce(answerResponse());
    const resolver = new WireDnsResolver(resolverById('cloudflare'), {
      ...testDependencies(fetchMock),
      cache: new DnsMemoryCache(() => now),
    });
    const options = { checkingDisabled: false, dnssecOk: false };

    const firstFailure = await resolver
      .query(question(), options)
      .catch((cause: unknown) => cause);
    expect(firstFailure).toBeInstanceOf(DnsQueryError);
    if (!(firstFailure instanceof DnsQueryError))
      throw new Error('Expected a DNS query error.');
    expect(firstFailure.code).toBe('transport-error');
    expect(firstFailure.message).not.toContain('private-query.example.test');

    const cachedFailure = await resolver
      .query(question(), options)
      .catch((cause: unknown) => cause);
    expect(cachedFailure).toBeInstanceOf(DnsQueryError);
    if (!(cachedFailure instanceof DnsQueryError))
      throw new Error('Expected a DNS query error.');
    expect(cachedFailure.code).toBe('transport-error');
    expect(cachedFailure.message).not.toContain('private-query.example.test');
    expect(cachedFailure.retryAfterMs).toBe(5_000);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    now += 5_000;
    await expect(resolver.query(question(), options)).resolves.toMatchObject({
      cache: 'miss',
      message: { responseCode: 'NOERROR' },
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('explains Quad9 HTTP version requirements without mislabelling a transport rejection', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockRejectedValue(new TypeError('Failed to fetch'));
    const resolver = new WireDnsResolver(resolverById('quad9'), testDependencies(fetchMock));

    const failure = await resolver
      .query(question(), { checkingDisabled: false, dnssecOk: true })
      .catch((cause: unknown) => cause);

    expect(resolver.definition.endpoint).toBe('https://dns.quad9.net/dns-query');
    expect(failure).toBeInstanceOf(DnsQueryError);
    if (!(failure instanceof DnsQueryError)) throw new Error('Expected a DNS query error.');
    expect(failure.code).toBe('transport-error');
    expect(failure.message).toContain('HTTPS transport failed');
    expect(failure.message).toContain('end-to-end HTTP/2 or HTTP/3');
    expect(failure.message).toContain('direct path unavailable');
    expect(failure.message).not.toContain('Failed to fetch');
    expect(failure.message).not.toContain('NXDOMAIN');
  });

  it('does not turn user cancellation into cached resolution failure state', async () => {
    let requests = 0;
    const fetchMock = vi.fn<typeof fetch>((_input, init) => {
      requests += 1;
      if (requests > 1) return Promise.resolve(answerResponse());
      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener(
          'abort',
          () => reject(new DOMException('Aborted', 'AbortError')),
          { once: true },
        );
      });
    });
    const resolver = new WireDnsResolver(resolverById('google'), testDependencies(fetchMock));
    const controller = new AbortController();
    const pending = resolver.query(question(), {
      checkingDisabled: false,
      dnssecOk: false,
      signal: controller.signal,
    });
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    controller.abort();

    await expect(pending).rejects.toMatchObject({ code: 'aborted' });
    await expect(
      resolver.query(question(), { checkingDisabled: false, dnssecOk: false }),
    ).resolves.toMatchObject({ cache: 'miss' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('aborts a stalled request after eight seconds', async () => {
    vi.useFakeTimers();
    try {
      const fetchMock = vi.fn<typeof fetch>(
        (_input, init) =>
          new Promise((_resolve, reject) => {
            init?.signal?.addEventListener(
              'abort',
              () => reject(new DOMException('Aborted', 'AbortError')),
              { once: true },
            );
          }),
      );
      const resolver = new WireDnsResolver(resolverById('google'), testDependencies(fetchMock));
      const pending = resolver.query(question(), {
        checkingDisabled: false,
        dnssecOk: false,
      });
      const rejection = expect(pending).rejects.toMatchObject({ code: 'timeout' });

      await vi.advanceTimersByTimeAsync(8_000);
      await rejection;
    } finally {
      vi.useRealTimers();
    }
  });
});
