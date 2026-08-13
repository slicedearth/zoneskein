import { DnsQueryError } from '../dns/types';

interface QueueEntry {
  readonly reject: (error: DnsQueryError) => void;
  readonly resolve: (release: () => void) => void;
  readonly signal?: AbortSignal;
}

export class Semaphore {
  readonly #limit: number;
  #active = 0;
  readonly #queue: QueueEntry[] = [];

  constructor(limit: number) {
    if (!Number.isInteger(limit) || limit < 1)
      throw new Error('Semaphore limit must be positive.');
    this.#limit = limit;
  }

  acquire(signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) {
      return Promise.reject(new DnsQueryError('aborted', 'The DNS run was cancelled.'));
    }
    if (this.#active < this.#limit) {
      this.#active += 1;
      return Promise.resolve(this.#releaseOnce());
    }

    return new Promise((resolve, reject) => {
      const entry: QueueEntry =
        signal === undefined ? { reject, resolve } : { reject, resolve, signal };
      this.#queue.push(entry);
      signal?.addEventListener(
        'abort',
        () => {
          const index = this.#queue.indexOf(entry);
          if (index >= 0) this.#queue.splice(index, 1);
          reject(new DnsQueryError('aborted', 'The DNS run was cancelled.'));
        },
        { once: true },
      );
    });
  }

  #releaseOnce(): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.#active -= 1;
      this.#drain();
    };
  }

  #drain(): void {
    while (this.#active < this.#limit && this.#queue.length > 0) {
      const entry = this.#queue.shift();
      if (entry === undefined || entry.signal?.aborted) continue;
      this.#active += 1;
      entry.resolve(this.#releaseOnce());
    }
  }
}
