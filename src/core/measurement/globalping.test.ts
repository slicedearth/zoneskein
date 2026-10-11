import { afterEach, describe, expect, it, vi } from 'vitest';

import { MEASUREMENT_DEADLINE_MS, reserveGlobalpingRun, runGlobalpingDns } from './globalping';

afterEach(() => vi.useRealTimers());

describe('Globalping measurement client', () => {
  const request = {
    ipVersion: 4,
    location: 'world',
    probes: 1,
    protocol: 'UDP',
    target: 'example.com',
    trace: true,
    type: 'NS',
  } as const;

  it.each(['headers', 'create-body', 'poll-body'] as const)(
    'enforces one deadline across stalled %s and releases the reader',
    async (phase) => {
      vi.useFakeTimers();
      const cancel = vi.fn();
      const stream = new ReadableStream<Uint8Array>({ cancel });
      const fetcher = vi.fn<typeof fetch>();
      if (phase === 'headers') fetcher.mockReturnValue(new Promise<Response>(() => undefined));
      else if (phase === 'create-body')
        fetcher.mockResolvedValue(new Response(stream, { status: 202 }));
      else
        fetcher
          .mockResolvedValueOnce(new Response('{"id":"deadline"}', { status: 202 }))
          .mockResolvedValueOnce(new Response(stream));
      const controller = new AbortController();
      const add = vi.spyOn(controller.signal, 'addEventListener');
      const remove = vi.spyOn(controller.signal, 'removeEventListener');
      const pending = runGlobalpingDns(request, controller.signal, fetcher);
      const result = expect(pending).rejects.toMatchObject({
        name: 'TimeoutError',
      });
      await vi.advanceTimersByTimeAsync(MEASUREMENT_DEADLINE_MS);
      await result;
      const requestSignal = fetcher.mock.calls[0]?.[1]?.signal;
      expect(requestSignal?.aborted).toBe(true);
      expect(fetcher).toHaveBeenCalledTimes(phase === 'poll-body' ? 2 : 1);
      if (phase !== 'headers') expect(cancel).toHaveBeenCalledOnce();
      expect(stream.locked).toBe(false);
      expect(vi.getTimerCount()).toBe(0);
      expect(remove).toHaveBeenCalledWith('abort', add.mock.calls[0]?.[1]);
    },
  );

  it.each(['headers', 'body', 'delay'] as const)(
    'cancels stalled %s without waiting for the overall deadline',
    async (phase) => {
      vi.useFakeTimers();
      const cancel = vi.fn();
      const stream = new ReadableStream<Uint8Array>({ cancel });
      const fetcher = vi.fn<typeof fetch>();
      if (phase === 'headers') fetcher.mockReturnValue(new Promise<Response>(() => undefined));
      else
        fetcher.mockResolvedValue(
          new Response(phase === 'body' ? stream : '{"id":"cancel"}', { status: 202 }),
        );
      const controller = new AbortController();
      const pending = runGlobalpingDns(request, controller.signal, fetcher);
      const result = expect(pending).rejects.toMatchObject({ name: 'AbortError' });
      await vi.advanceTimersByTimeAsync(10);
      controller.abort();
      await result;
      if (phase === 'body') expect(cancel).toHaveBeenCalledOnce();
      expect(stream.locked).toBe(false);
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(vi.getTimerCount()).toBe(0);
    },
  );

  it('cancels a late response body and never sends an already-cancelled request', async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    controller.abort();
    const fetcher = vi.fn<typeof fetch>();
    await expect(runGlobalpingDns(request, controller.signal, fetcher)).rejects.toMatchObject({
      name: 'AbortError',
    });
    expect(fetcher).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
    let complete!: (value: Response) => void;
    fetcher.mockReturnValue(
      new Promise<Response>((resolve) => {
        complete = resolve;
      }),
    );
    const active = new AbortController();
    const pending = runGlobalpingDns(request, active.signal, fetcher);
    const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    active.abort();
    await rejected;
    const cancel = vi.fn();
    complete(new Response(new ReadableStream({ cancel }), { status: 202 }));
    await Promise.resolve();
    expect(cancel).toHaveBeenCalledOnce();
  });

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
