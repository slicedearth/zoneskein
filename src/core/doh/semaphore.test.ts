import { describe, expect, it } from 'vitest';

import { Semaphore } from './semaphore';

describe('request semaphore', () => {
  it('never grants more than its configured concurrency', async () => {
    const semaphore = new Semaphore(2);
    const first = await semaphore.acquire();
    const second = await semaphore.acquire();
    let thirdGranted = false;
    const thirdPromise = semaphore.acquire().then((release) => {
      thirdGranted = true;
      return release;
    });

    await Promise.resolve();
    expect(thirdGranted).toBe(false);
    first();
    const third = await thirdPromise;
    expect(thirdGranted).toBe(true);

    second();
    third();
  });

  it('removes a cancelled request from the queue', async () => {
    const semaphore = new Semaphore(1);
    const release = await semaphore.acquire();
    const controller = new AbortController();
    const waiting = semaphore.acquire(controller.signal);
    controller.abort();

    await expect(waiting).rejects.toMatchObject({ code: 'aborted' });
    release();
    const next = await semaphore.acquire();
    next();
  });
});
