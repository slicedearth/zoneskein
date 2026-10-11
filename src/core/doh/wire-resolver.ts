import {
  DnsQueryError,
  type DnsQueryOptions,
  type DnsQuestion,
  type DnsResolver,
  type DnsResponse,
  type ResolverDefinition,
} from '../dns/types';
import { decodeDnsMessage, encodeDnsQuery, MAX_DNS_MESSAGE_BYTES } from '../dns/wire';
import { dnsRecordTypeCode } from '../dns/record-types';
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
    dnsRecordTypeCode(question.type),
    options.checkingDisabled ? 'cd1' : 'cd0',
    options.dnssecOk ? 'do1' : 'do0',
    options.recursionDesired === false ? 'rd0' : 'rd1',
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

async function settleCancellation(
  cancel: () => Promise<void>,
  signal: AbortSignal,
): Promise<void> {
  let cancellation: Promise<undefined>;
  try {
    cancellation = cancel().then(
      () => undefined,
      () => undefined,
    );
  } catch {
    return;
  }
  if (signal.aborted) return;
  let stopWaiting: (() => void) | undefined;
  const aborted = new Promise<void>((resolve) => {
    const abort = () => resolve();
    stopWaiting = abort;
    signal.addEventListener('abort', abort, { once: true });
  });
  try {
    await Promise.race([cancellation, aborted]);
  } finally {
    if (stopWaiting !== undefined) signal.removeEventListener('abort', stopWaiting);
  }
}

async function rejectResponse(
  response: Response,
  signal: AbortSignal,
  error: DnsQueryError,
): Promise<never> {
  if (response.body !== null) {
    await settleCancellation(
      () =>
        response.body?.cancel('DNS response was rejected before consumption.') ??
        Promise.resolve(),
      signal,
    );
  }
  throw error;
}

async function boundedDnsBody(response: Response, signal: AbortSignal): Promise<Uint8Array> {
  const contentLength = response.headers.get('Content-Length');
  if (contentLength !== null) {
    if (!/^\d+$/u.test(contentLength) || Number(contentLength) > MAX_DNS_MESSAGE_BYTES) {
      return rejectResponse(
        response,
        signal,
        new DnsQueryError(
          'invalid-response',
          `The resolver response exceeds ${String(MAX_DNS_MESSAGE_BYTES)} DNS message octets.`,
        ),
      );
    }
  }

  const reader = response.body?.getReader();
  if (reader === undefined) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let length = 0;
  let complete = false;
  try {
    while (!complete) {
      const next = await reader.read();
      complete = next.done;
      if (next.done) continue;
      const { value } = next;
      length += value.byteLength;
      if (length > MAX_DNS_MESSAGE_BYTES) {
        await settleCancellation(
          () => reader.cancel('DNS response exceeds the message-size bound.'),
          signal,
        );
        throw new DnsQueryError(
          'invalid-response',
          `The resolver response exceeds ${String(MAX_DNS_MESSAGE_BYTES)} DNS message octets.`,
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function sameDnsName(left: string, right: string): boolean {
  return left.toLowerCase().replace(/\.$/u, '') === right.toLowerCase().replace(/\.$/u, '');
}

function canonicalQuestionWire(question: DnsQuestion): Uint8Array {
  const labels = question.name.ascii === '' ? [] : question.name.ascii.split('.');
  const length = labels.reduce((total, label) => total + label.length + 1, 1);
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const label of labels) {
    bytes[offset] = label.length;
    offset += 1;
    for (let index = 0; index < label.length; index += 1) {
      const code = label.charCodeAt(index);
      if (code > 0x7f) throw new Error('A validated DNS question must use ASCII labels.');
      bytes[offset] = code >= 0x41 && code <= 0x5a ? code + 0x20 : code;
      offset += 1;
    }
  }
  return bytes;
}

function equalWireName(left: Uint8Array | undefined, right: Uint8Array): boolean {
  if (left?.length !== right.length) return false;
  return left.every((byte, index) => byte === right[index]);
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
    if (cached !== null) {
      if ('error' in cached) throw cached.error;
      return { ...cached.response, cache: 'hit' };
    }

    const active = this.#inFlight.get(key);
    if (active !== undefined) return { ...(await active), cache: 'shared' };

    const promise = this.#request(question, options).finally(() => this.#inFlight.delete(key));
    this.#inFlight.set(key, promise);
    try {
      const response = await promise;
      this.#cache.set(key, response);
      return response;
    } catch (cause) {
      if (cause instanceof DnsQueryError) this.#cache.setFailure(key, cause);
      throw cause;
    }
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
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: composed.controller.signal,
      });

      if (response.status === 429) {
        const retryAfter = retryAfterMilliseconds(response);
        this.#limiter.imposeCooldown(this.definition.id, retryAfter);
        return await rejectResponse(
          response,
          composed.controller.signal,
          new DnsQueryError(
            'rate-limited',
            'The resolver rate-limited this browser.',
            retryAfter,
          ),
        );
      }
      if (!response.ok) {
        return await rejectResponse(
          response,
          composed.controller.signal,
          new DnsQueryError(
            'http-error',
            `The resolver returned HTTP ${String(response.status)}.`,
          ),
        );
      }
      const contentType = response.headers.get('Content-Type')?.split(';')[0]?.trim();
      if (contentType !== 'application/dns-message') {
        return await rejectResponse(
          response,
          composed.controller.signal,
          new DnsQueryError(
            'invalid-response',
            'The resolver returned an unexpected media type.',
          ),
        );
      }

      const raw = await boundedDnsBody(response, composed.controller.signal);
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
      const decodedQuestion = message.questions[0];
      const expectedQuestionWire = canonicalQuestionWire(question);
      if (
        message.id !== 0 ||
        message.questions.length !== 1 ||
        decodedQuestion?.class.toUpperCase() !== 'IN' ||
        !equalWireName(decodedQuestion.canonicalNameWire, expectedQuestionWire) ||
        !sameDnsName(decodedQuestion.name, question.name.absolute) ||
        dnsRecordTypeCode(question.type) === null ||
        dnsRecordTypeCode(decodedQuestion.type) !== dnsRecordTypeCode(question.type) ||
        message.flags.truncated
      ) {
        throw new DnsQueryError(
          'invalid-response',
          message.flags.truncated
            ? 'The resolver returned a truncated DNS response.'
            : 'The resolver response does not match the original DNS question.',
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
        [
          'The HTTPS transport failed before a valid resolver response was received.',
          this.definition.transportNote,
        ]
          .filter((part): part is string => part !== undefined)
          .join(' '),
      );
    } finally {
      composed.dispose();
      release();
    }
  }
}
