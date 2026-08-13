import {
  DnsQueryError,
  type DnsQueryOptions,
  type DnsQuestion,
  type DnsResolver,
  type DnsResponse,
  type ResolverDefinition,
} from '../dns/types';
import { decodeDnsMessage, encodeDnsQuery } from '../dns/wire';
import { DnsMemoryCache } from './cache';
import { BrowserRateLimiter } from './rate-limit';
import { Semaphore } from './semaphore';

const REQUEST_TIMEOUT_MS = 8000;
const DEFAULT_COOLDOWN_MS = 60_000;

// These controls are shared by every resolver instance in the page. This keeps
// comparisons and nested policy checks inside the same four-request ceiling.
const sharedCache = new DnsMemoryCache();
const sharedLimiter = new BrowserRateLimiter();
const sharedSemaphore = new Semaphore(4);

function cacheKey(
  definition: ResolverDefinition,
  question: DnsQuestion,
  options: DnsQueryOptions,
) {
  return [
    definition.id,
    question.name.absolute,
    question.type,
    options.checkingDisabled ? 'cd1' : 'cd0',
    options.dnssecOk ? 'do1' : 'do0',
  ].join('|');
}

function retryAfterMilliseconds(response: Response): number {
  const value = response.headers.get('Retry-After');
  if (value === null) return DEFAULT_COOLDOWN_MS;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, 900_000);
  const date = Date.parse(value);
  return Number.isNaN(date) ? DEFAULT_COOLDOWN_MS : Math.max(0, date - Date.now());
}

function abortSignals(signal: AbortSignal | undefined, timeoutMs: number) {
  const controller = new AbortController();
  let timedOut = false;
  const timeout = window.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  return {
    controller,
    dispose() {
      window.clearTimeout(timeout);
      signal?.removeEventListener('abort', abort);
    },
    timedOut: () => timedOut,
  };
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

export interface WireResolverDependencies {
  readonly cache?: DnsMemoryCache;
  readonly fetch?: typeof fetch;
  readonly limiter?: BrowserRateLimiter;
  readonly now?: () => number;
  readonly semaphore?: Semaphore;
}

export class WireDnsResolver implements DnsResolver {
  readonly definition: ResolverDefinition;
  readonly #cache: DnsMemoryCache;
  readonly #fetch: typeof fetch;
  readonly #inFlight = new Map<string, Promise<DnsResponse>>();
  readonly #limiter: BrowserRateLimiter;
  readonly #now: () => number;
  readonly #semaphore: Semaphore;

  constructor(definition: ResolverDefinition, dependencies: WireResolverDependencies = {}) {
    this.definition = definition;
    this.#cache = dependencies.cache ?? sharedCache;
    this.#fetch = dependencies.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.#limiter = dependencies.limiter ?? sharedLimiter;
    this.#now = dependencies.now ?? performance.now.bind(performance);
    this.#semaphore = dependencies.semaphore ?? sharedSemaphore;
  }

  async query(question: DnsQuestion, options: DnsQueryOptions): Promise<DnsResponse> {
    const key = cacheKey(this.definition, question, options);
    const cached = this.#cache.get(key);
    if (cached !== null) return { ...cached, cache: 'hit' };

    const active = this.#inFlight.get(key);
    if (active !== undefined) return { ...(await active), cache: 'shared' };

    const promise = this.#request(question, options).finally(() => this.#inFlight.delete(key));
    this.#inFlight.set(key, promise);
    const response = await promise;
    this.#cache.set(key, response);
    return response;
  }

  async #request(question: DnsQuestion, options: DnsQueryOptions): Promise<DnsResponse> {
    await this.#limiter.wait(this.definition.id, options.signal);
    const release = await this.#semaphore.acquire(options.signal);
    const composed = abortSignals(options.signal, REQUEST_TIMEOUT_MS);
    const started = this.#now();

    try {
      const query = encodeDnsQuery(question, options);
      const useGet = this.definition.httpMethod === 'GET';
      const target = useGet
        ? `${this.definition.endpoint}?dns=${base64Url(query)}`
        : this.definition.endpoint;
      const response = await this.#fetch(target, {
        ...(useGet ? {} : { body: asArrayBuffer(query) }),
        cache: 'no-store',
        credentials: 'omit',
        headers: useGet
          ? { Accept: 'application/dns-message' }
          : {
              Accept: 'application/dns-message',
              'Content-Type': 'application/dns-message',
            },
        method: this.definition.httpMethod,
        mode: 'cors',
        referrerPolicy: 'no-referrer',
        signal: composed.controller.signal,
      });

      if (response.status === 429) {
        const retryAfter = retryAfterMilliseconds(response);
        this.#limiter.imposeCooldown(this.definition.id, retryAfter);
        throw new DnsQueryError(
          'rate-limited',
          'The resolver rate-limited this browser.',
          retryAfter,
        );
      }
      if (!response.ok) {
        throw new DnsQueryError(
          'http-error',
          `The resolver returned HTTP ${String(response.status)}.`,
        );
      }
      const contentType = response.headers.get('Content-Type')?.split(';')[0]?.trim();
      if (contentType !== 'application/dns-message') {
        throw new DnsQueryError(
          'invalid-response',
          'The resolver returned an unexpected media type.',
        );
      }

      const raw = new Uint8Array(await response.arrayBuffer());
      let message;
      try {
        message = decodeDnsMessage(raw);
      } catch (cause) {
        throw new DnsQueryError(
          'invalid-response',
          cause instanceof Error
            ? cause.message
            : 'The resolver response could not be decoded.',
        );
      }

      return {
        cache: 'miss',
        message,
        queryTimeMs: Math.max(0, this.#now() - started),
        question,
        receivedAt: new Date().toISOString(),
        resolver: this.definition,
      };
    } catch (cause) {
      if (cause instanceof DnsQueryError) throw cause;
      if (cause instanceof DOMException && cause.name === 'AbortError') {
        if (composed.timedOut())
          throw new DnsQueryError('timeout', 'The DNS query timed out after 8 seconds.');
        throw new DnsQueryError('aborted', 'The DNS run was cancelled.');
      }
      throw new DnsQueryError(
        'transport-error',
        cause instanceof Error ? cause.message : 'The DNS request failed.',
      );
    } finally {
      composed.dispose();
      release();
    }
  }
}
