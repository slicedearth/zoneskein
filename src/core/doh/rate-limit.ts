import { DnsQueryError, type ResolverId } from '../dns/types';

interface SharedEvent {
  readonly resolverId: ResolverId;
  readonly timestamp: number;
  readonly type: 'request';
}

function isResolverId(value: unknown): value is ResolverId {
  return value === 'cloudflare' || value === 'google' || value === 'quad9';
}

function isSharedEvent(value: unknown): value is SharedEvent {
  if (value === null || typeof value !== 'object') return false;
  const candidate = value as Partial<Record<keyof SharedEvent, unknown>>;
  return (
    candidate.type === 'request' &&
    isResolverId(candidate.resolverId) &&
    typeof candidate.timestamp === 'number' &&
    Number.isFinite(candidate.timestamp)
  );
}

interface ResolverWindow {
  cooldownUntil: number;
  requests: number[];
  tokens: number;
  updatedAt: number;
}

const BURST = 4;
const REFILL_PER_SECOND = 2;
const WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 120;

export class BrowserRateLimiter {
  readonly #channel?: BroadcastChannel;
  readonly #now: () => number;
  readonly #windows = new Map<ResolverId, ResolverWindow>();

  constructor(now: () => number = Date.now) {
    this.#now = now;
    if (typeof BroadcastChannel !== 'undefined') {
      this.#channel = new BroadcastChannel('zoneskein-doh-rate-v1');
      this.#channel.addEventListener('message', (event: MessageEvent<unknown>) => {
        if (isSharedEvent(event.data))
          this.#record(event.data.resolverId, event.data.timestamp);
      });
    }
  }

  close(): void {
    this.#channel?.close();
  }

  imposeCooldown(resolverId: ResolverId, durationMs: number): void {
    const window = this.#window(resolverId);
    window.cooldownUntil = Math.max(window.cooldownUntil, this.#now() + durationMs);
  }

  async wait(resolverId: ResolverId, signal?: AbortSignal): Promise<void> {
    for (;;) {
      if (signal?.aborted) throw new DnsQueryError('aborted', 'The DNS run was cancelled.');
      const now = this.#now();
      const window = this.#window(resolverId);
      this.#prune(window, now);
      if (window.cooldownUntil > now) {
        throw new DnsQueryError(
          'cooldown',
          'The resolver is cooling down after a rate-limit response.',
          window.cooldownUntil - now,
        );
      }
      if (window.requests.length >= MAX_REQUESTS_PER_WINDOW) {
        const oldest = window.requests.at(0);
        if (oldest === undefined) continue;
        const retryAfter = WINDOW_MS - (now - oldest);
        throw new DnsQueryError(
          'rate-limited',
          'This browser tab has reached the rolling DNS request limit.',
          retryAfter,
        );
      }

      const elapsed = Math.max(0, now - window.updatedAt);
      window.tokens = Math.min(BURST, window.tokens + (elapsed / 1000) * REFILL_PER_SECOND);
      window.updatedAt = now;
      if (window.tokens >= 1) {
        window.tokens -= 1;
        this.#record(resolverId, now);
        this.#channel?.postMessage({
          resolverId,
          timestamp: now,
          type: 'request',
        } satisfies SharedEvent);
        return;
      }

      await this.#delay(Math.ceil(((1 - window.tokens) / REFILL_PER_SECOND) * 1000), signal);
    }
  }

  #delay(milliseconds: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      const timeout = window.setTimeout(resolve, milliseconds);
      signal?.addEventListener(
        'abort',
        () => {
          window.clearTimeout(timeout);
          reject(new DnsQueryError('aborted', 'The DNS run was cancelled.'));
        },
        { once: true },
      );
    });
  }

  #prune(window: ResolverWindow, now: number): void {
    window.requests = window.requests.filter((timestamp) => timestamp > now - WINDOW_MS);
  }

  #record(resolverId: ResolverId, timestamp: number): void {
    const window = this.#window(resolverId);
    window.requests.push(timestamp);
    this.#prune(window, this.#now());
  }

  #window(resolverId: ResolverId): ResolverWindow {
    let window = this.#windows.get(resolverId);
    if (window === undefined) {
      window = { cooldownUntil: 0, requests: [], tokens: BURST, updatedAt: this.#now() };
      this.#windows.set(resolverId, window);
    }
    return window;
  }
}
