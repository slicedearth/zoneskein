import { afterEach, describe, expect, it, vi } from 'vitest';

import { BrowserRateLimiter } from './rate-limit';

class MemoryStorage {
  value: string | null;
  readonly writes: string[] = [];

  constructor(value: string | null = null) {
    this.value = value;
  }

  getItem(): string | null {
    return this.value;
  }

  setItem(_key: string, value: string): void {
    this.value = value;
    this.writes.push(value);
  }
}

class TestChannel {
  closed = false;
  listener: ((event: MessageEvent<unknown>) => void) | undefined;
  readonly posted: unknown[] = [];

  addEventListener(_type: 'message', listener: (event: MessageEvent<unknown>) => void): void {
    this.listener = listener;
  }

  close(): void {
    this.closed = true;
  }

  emit(data: unknown): void {
    this.listener?.(new MessageEvent('message', { data }));
  }

  postMessage(message: unknown): void {
    this.posted.push(message);
  }
}

function isolated(now: () => number): BrowserRateLimiter {
  return new BrowserRateLimiter(now, { channelFactory: () => null, storage: null });
}

function storedRequests(
  now: number,
  count: number,
  options: { readonly savedAt?: number; readonly timestamp?: number } = {},
): string {
  const timestamp = options.timestamp ?? now;
  return JSON.stringify({
    savedAt: options.savedAt ?? now,
    version: 1,
    windows: {
      google: {
        cooldownUntil: 0,
        requests: Array.from({ length: count }, (_, index) => ({
          id: `external-${String(index)}`,
          timestamp,
        })),
      },
    },
  });
}

describe('browser DNS rate limiter', () => {
  afterEach(() => vi.useRealTimers());

  it('allows a four-request burst then throttles to two requests per second', async () => {
    vi.useFakeTimers();
    let now = 0;
    const limiter = isolated(() => now);

    await Promise.all([
      limiter.wait('google'),
      limiter.wait('google'),
      limiter.wait('google'),
      limiter.wait('google'),
    ]);
    let fifthFinished = false;
    const fifth = limiter.wait('google').then(() => {
      fifthFinished = true;
    });
    await Promise.resolve();
    expect(fifthFinished).toBe(false);

    now = 500;
    await vi.advanceTimersByTimeAsync(500);
    await fifth;
    expect(fifthFinished).toBe(true);
    limiter.close();
  });

  it('honours resolver cooldowns without making another request', async () => {
    const limiter = isolated(() => 1_000);
    limiter.imposeCooldown('quad9', 12_000);
    await expect(limiter.wait('quad9')).rejects.toMatchObject({
      code: 'cooldown',
      retryAfterMs: 12_000,
    });
    limiter.close();
  });

  it('enforces the rolling per-resolver request ceiling', async () => {
    let now = 0;
    const limiter = isolated(() => now);
    for (let index = 0; index < 120; index += 1) {
      if (index >= 4) now += 500;
      await limiter.wait('cloudflare');
    }

    await expect(limiter.wait('cloudflare')).rejects.toMatchObject({
      code: 'rate-limited',
    });
    limiter.close();
  });

  it('serves concurrent waiters in first-in, first-out order', async () => {
    vi.useFakeTimers();
    let now = 0;
    const limiter = isolated(() => now);
    await Promise.all(Array.from({ length: 4 }, () => limiter.wait('google')));

    const order: string[] = [];
    const fifth = limiter.wait('google').then(() => order.push('fifth'));
    const sixth = limiter.wait('google').then(() => order.push('sixth'));
    const seventh = limiter.wait('google').then(() => order.push('seventh'));

    now = 500;
    await vi.advanceTimersByTimeAsync(500);
    expect(order).toEqual(['fifth']);
    now = 1_000;
    await vi.advanceTimersByTimeAsync(500);
    expect(order).toEqual(['fifth', 'sixth']);
    now = 1_500;
    await vi.advanceTimersByTimeAsync(500);
    await Promise.all([fifth, sixth, seventh]);
    expect(order).toEqual(['fifth', 'sixth', 'seventh']);
    limiter.close();
  });

  it('bounds each resolver queue and permits queued callers to cancel', async () => {
    vi.useFakeTimers();
    const limiter = isolated(() => 0);
    await Promise.all(Array.from({ length: 4 }, () => limiter.wait('google')));
    const controllers = Array.from({ length: 257 }, () => new AbortController());
    const pending = controllers.map((controller) => limiter.wait('google', controller.signal));

    await expect(limiter.wait('google')).rejects.toMatchObject({ code: 'rate-limited' });
    for (const controller of controllers) controller.abort();
    expect(
      (await Promise.allSettled(pending)).every((result) => result.status === 'rejected'),
    ).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
    limiter.close();
  });

  it('removes abort listeners after delayed and queued waits settle', async () => {
    vi.useFakeTimers();
    let now = 0;
    const limiter = isolated(() => now);
    await Promise.all(Array.from({ length: 4 }, () => limiter.wait('google')));

    const activeController = new AbortController();
    const activeAdd = vi.spyOn(activeController.signal, 'addEventListener');
    const activeRemove = vi.spyOn(activeController.signal, 'removeEventListener');
    const active = limiter.wait('google', activeController.signal);

    const queuedController = new AbortController();
    const queuedAdd = vi.spyOn(queuedController.signal, 'addEventListener');
    const queuedRemove = vi.spyOn(queuedController.signal, 'removeEventListener');
    const queued = limiter.wait('google', queuedController.signal);
    queuedController.abort();
    await expect(queued).rejects.toMatchObject({ code: 'aborted' });

    now = 500;
    await vi.advanceTimersByTimeAsync(500);
    await active;

    expect(activeRemove.mock.calls.filter(([event]) => event === 'abort')).toHaveLength(
      activeAdd.mock.calls.filter(([event]) => event === 'abort').length,
    );
    expect(queuedRemove.mock.calls.filter(([event]) => event === 'abort')).toHaveLength(
      queuedAdd.mock.calls.filter(([event]) => event === 'abort').length,
    );
    expect(vi.getTimerCount()).toBe(0);
    limiter.close();
  });

  it.each([
    [
      'a future save time',
      (now: number) => storedRequests(now, 120, { savedAt: now + 60_000 }),
    ],
    [
      'future request times',
      (now: number) => storedRequests(now, 120, { timestamp: now + 60_000 }),
    ],
    [
      'an expired save time',
      (now: number) => storedRequests(now, 120, { savedAt: now - 2_000_000 }),
    ],
  ])('ignores persisted state with %s', async (_, makeState) => {
    const now = 3_000_000;
    const storage = new MemoryStorage(makeState(now));
    const limiter = new BrowserRateLimiter(() => now, {
      channelFactory: () => null,
      storage,
    });

    await expect(limiter.wait('google')).resolves.toBeUndefined();
    limiter.close();
  });

  it.each([
    ['invalid JSON', '{not-json'],
    ['an oversized serialised value', 'x'.repeat(40_000)],
    ['too many request entries', storedRequests(1_000_000, 121)],
    [
      'a malformed request entry',
      JSON.stringify({
        savedAt: 1_000_000,
        version: 1,
        windows: {
          google: {
            cooldownUntil: 0,
            requests: [{ id: 'contains whitespace', timestamp: 1_000_000 }],
          },
        },
      }),
    ],
  ])('fails open locally for %s in cross-tab storage', async (_, value) => {
    const storage = new MemoryStorage(value);
    const limiter = new BrowserRateLimiter(() => 1_000_000, {
      channelFactory: () => null,
      storage,
    });

    await expect(limiter.wait('google')).resolves.toBeUndefined();
    limiter.close();
  });

  it('ignores malformed, oversized, and far-future channel messages', async () => {
    const now = 1_000_000;
    const channel = new TestChannel();
    const limiter = new BrowserRateLimiter(() => now, {
      channelFactory: () => channel,
      storage: null,
    });

    for (let index = 0; index < 120; index += 1) {
      channel.emit({
        id: `${'x'.repeat(97)}${String(index)}`,
        resolverId: 'google',
        timestamp: now,
        type: 'request',
      });
      channel.emit({
        extra: 'x'.repeat(10_000),
        id: `extra-${String(index)}`,
        resolverId: 'google',
        timestamp: now,
        type: 'request',
      });
      channel.emit({
        id: `future-${String(index)}`,
        resolverId: 'google',
        timestamp: now + 60_000,
        type: 'request',
      });
    }
    channel.emit({ requests: new Array(10_000).fill(now), type: 'state' });

    await expect(
      Promise.all(Array.from({ length: 4 }, () => limiter.wait('google'))),
    ).resolves.toEqual([undefined, undefined, undefined, undefined]);
    limiter.close();
    expect(channel.closed).toBe(true);
  });

  it('counts valid unique channel events towards the shared rolling ceiling', async () => {
    const now = 1_000_000;
    const channel = new TestChannel();
    const limiter = new BrowserRateLimiter(() => now, {
      channelFactory: () => channel,
      storage: null,
    });

    for (let index = 0; index < 120; index += 1)
      channel.emit({
        id: `peer-${String(index)}`,
        resolverId: 'quad9',
        timestamp: now,
        type: 'request',
      });

    await expect(limiter.wait('quad9')).rejects.toMatchObject({ code: 'rate-limited' });
    limiter.close();
  });

  it('stops persisting new shared events after the bounded ledger is full', () => {
    const now = 1_000_000;
    const channel = new TestChannel();
    const storage = new MemoryStorage();
    const limiter = new BrowserRateLimiter(() => now, {
      channelFactory: () => channel,
      storage,
    });

    for (let index = 0; index < 1_000; index += 1)
      channel.emit({
        id: `peer-${String(index)}`,
        resolverId: 'quad9',
        timestamp: now,
        type: 'request',
      });

    expect(storage.writes).toHaveLength(120);
    expect(storage.value?.match(/"timestamp":/gu)?.length).toBe(120);
    expect(storage.writes.every((value) => value.length <= 32_768)).toBe(true);
    limiter.close();
  });

  it('does not multiply a replayed valid channel event', async () => {
    const now = 1_000_000;
    const channel = new TestChannel();
    const limiter = new BrowserRateLimiter(() => now, {
      channelFactory: () => channel,
      storage: null,
    });
    const event = {
      id: 'peer-replayed-event',
      resolverId: 'cloudflare',
      timestamp: now,
      type: 'request',
    } as const;
    for (let replay = 0; replay < 1_000; replay += 1) channel.emit(event);

    await expect(
      Promise.all(Array.from({ length: 3 }, () => limiter.wait('cloudflare'))),
    ).resolves.toEqual([undefined, undefined, undefined]);
    limiter.close();
  });

  it('honours a bounded valid channel cooldown and ignores an excessive one', async () => {
    const now = 1_000_000;
    const channel = new TestChannel();
    const limiter = new BrowserRateLimiter(() => now, {
      channelFactory: () => channel,
      storage: null,
    });

    channel.emit({ resolverId: 'google', type: 'cooldown', until: now + 1_000_000 });
    await expect(limiter.wait('google')).resolves.toBeUndefined();
    channel.emit({ resolverId: 'quad9', type: 'cooldown', until: now + 12_000 });
    await expect(limiter.wait('quad9')).rejects.toMatchObject({
      code: 'cooldown',
      retryAfterMs: 12_000,
    });
    limiter.close();
  });

  it('loads a bounded shared ledger and keeps every persisted write bounded', async () => {
    let now = 1_000_000;
    const storage = new MemoryStorage();
    const limiter = new BrowserRateLimiter(() => now, {
      channelFactory: () => null,
      storage,
    });

    for (let index = 0; index < 120; index += 1) {
      if (index >= 4) now += 500;
      await limiter.wait('google');
    }
    expect(storage.writes.length).toBeGreaterThan(0);
    expect(storage.writes.every((value) => value.length <= 32_768)).toBe(true);
    expect(storage.value?.match(/"timestamp":/gu)?.length).toBe(120);

    const restored = new BrowserRateLimiter(() => now, {
      channelFactory: () => null,
      storage,
    });
    await expect(restored.wait('google')).rejects.toMatchObject({ code: 'rate-limited' });

    now += 60_001;
    await limiter.wait('google');
    expect(storage.value?.match(/"timestamp":/gu)?.length).toBe(1);
    limiter.close();
    restored.close();
  });
});
