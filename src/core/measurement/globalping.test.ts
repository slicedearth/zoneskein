import { afterEach, describe, expect, it, vi } from 'vitest';

import { reserveGlobalpingRun, runGlobalpingDns } from './globalping';

afterEach(() => vi.useRealTimers());

describe('Globalping measurement client', () => {
  it('applies the conservative browser-hour guardrail without storing targets', () => {
    const storage = new Map<string, string>();
    const adapter: Storage = {
      clear: () => storage.clear(),
      getItem: (key) => storage.get(key) ?? null,
      key: (index) => [...storage.keys()][index] ?? null,
      get length() {
        return storage.size;
      },
      removeItem: (key) => {
        storage.delete(key);
      },
      setItem: (key, value) => {
        storage.set(key, value);
      },
    };
    for (let index = 0; index < 6; index += 1)
      expect(reserveGlobalpingRun(adapter, 1_000 + index).ok).toBe(true);
    expect(reserveGlobalpingRun(adapter, 2_000).ok).toBe(false);
    expect([...storage.values()].join('')).not.toContain('example');
  });

  it('creates, polls, bounds, and decodes a DNS trace', async () => {
    vi.useFakeTimers();
    const fetcher = vi.fn<typeof fetch>();
    fetcher
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ id: 'measurement_1', probesCount: 1 }), {
          status: 202,
          headers: { 'content-type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            id: 'measurement_1',
            probesCount: 1,
            status: 'finished',
            target: 'example.com',
            results: [
              {
                probe: {
                  asn: 64500,
                  city: 'Melbourne',
                  country: 'AU',
                  network: 'Example Network',
                },
                result: {
                  status: 'finished',
                  rawOutput: 'trace output',
                  hops: [
                    {
                      resolver: 'a.root-servers.net',
                      answers: [
                        {
                          name: 'com.',
                          type: 'NS',
                          ttl: 172800,
                          class: 'IN',
                          value: 'a.gtld-servers.net.',
                        },
                      ],
                      timings: { total: 12.5 },
                    },
                  ],
                },
              },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      );
    const pending = runGlobalpingDns(
      {
        ipVersion: 4,
        location: 'Australia',
        probes: 1,
        protocol: 'UDP',
        target: 'example.com',
        trace: true,
        type: 'NS',
      },
      new AbortController().signal,
      fetcher,
    );
    await vi.advanceTimersByTimeAsync(700);
    const result = await pending;
    expect(result.results[0]?.hops[0]?.answers[0]?.value).toBe('a.gtld-servers.net.');
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('rejects an unrecognised measurement lifecycle state', async () => {
    vi.useFakeTimers();
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ id: 'measurement_2' }), { status: 202 }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            id: 'measurement_2',
            probesCount: 0,
            results: [],
            status: 'mystery',
            target: 'example.com',
          }),
          { status: 200 },
        ),
      );
    const pending = runGlobalpingDns(
      {
        ipVersion: 4,
        location: 'world',
        probes: 1,
        protocol: 'UDP',
        target: 'example.com',
        trace: false,
        type: 'NS',
      },
      new AbortController().signal,
      fetcher,
    );
    const assertion = expect(pending).rejects.toThrow(/invalid or mismatched shape/u);
    await vi.advanceTimersByTimeAsync(700);
    await assertion;
  });
});
