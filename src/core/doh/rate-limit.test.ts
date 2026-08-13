import { afterEach, describe, expect, it, vi } from 'vitest';

import { BrowserRateLimiter } from './rate-limit';

describe('browser DNS rate limiter', () => {
  afterEach(() => vi.useRealTimers());

  it('allows a four-request burst then throttles to two requests per second', async () => {
    vi.useFakeTimers();
    let now = 0;
    const limiter = new BrowserRateLimiter(() => now);

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
    const limiter = new BrowserRateLimiter(() => 1_000);
    limiter.imposeCooldown('quad9', 12_000);
    await expect(limiter.wait('quad9')).rejects.toMatchObject({
      code: 'cooldown',
      retryAfterMs: 12_000,
    });
    limiter.close();
  });

  it('enforces the rolling per-resolver request ceiling', async () => {
    let now = 0;
    const limiter = new BrowserRateLimiter(() => now);
    for (let index = 0; index < 120; index += 1) {
      if (index >= 4) now += 500;
      await limiter.wait('cloudflare');
    }

    await expect(limiter.wait('cloudflare')).rejects.toMatchObject({
      code: 'rate-limited',
    });
    limiter.close();
  });
});
