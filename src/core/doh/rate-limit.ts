import { DnsQueryError, type ResolverId } from '../dns/types';

interface RateLimitChannel {
  addEventListener(type: 'message', listener: (event: MessageEvent<unknown>) => void): void;
  close(): void;
  postMessage(message: unknown): void;
}

interface RateLimitStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

interface RateLimitLockManager {
  request<T>(name: string, callback: () => Promise<T> | T): Promise<T>;
}

interface RuntimeGlobal {
  readonly process?: { readonly release?: { readonly name?: unknown } };
}

export interface BrowserRateLimiterOptions {
  readonly channelFactory?: (name: string) => RateLimitChannel | null;
  readonly lockManager?: RateLimitLockManager | null;
  readonly storage?: RateLimitStorage | null;
}

interface RequestStamp {
  readonly id: string;
  readonly timestamp: number;
}

interface SharedRequestEvent extends RequestStamp {
  readonly resolverId: ResolverId;
  readonly type: 'request';
}

interface SharedCooldownEvent {
  readonly resolverId: ResolverId;
  readonly type: 'cooldown';
  readonly until: number;
}

type SharedEvent = SharedCooldownEvent | SharedRequestEvent;

interface PersistedWindow {
  readonly cooldownUntil: number;
  readonly requests: readonly RequestStamp[];
}

interface PersistedState {
  readonly savedAt: number;
  readonly version: 1;
  readonly windows: Partial<Record<ResolverId, PersistedWindow>>;
}

interface ResolverWindow {
  cooldownUntil: number;
  requests: RequestStamp[];
}

interface QueueEntry {
  readonly id: symbol;
  readonly onAbort?: () => void;
  readonly reject: (error: DnsQueryError) => void;
  readonly resolve: () => void;
  readonly signal?: AbortSignal;
}

const BURST = 4;
const REFILL_PER_SECOND = 2;
const WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 120;
const MAX_QUEUED_PER_RESOLVER = 256;
const MAX_COOLDOWN_MS = 900_000;
const MAX_FUTURE_SKEW_MS = 5_000;
const MAX_STATE_AGE_MS = MAX_COOLDOWN_MS + WINDOW_MS;
const MAX_PERSISTED_CHARACTERS = 32_768;
const MAX_EVENT_ID_CHARACTERS = 96;
const CHANNEL_NAME = 'zoneskein-doh-rate-v2';
const LOCK_NAME_PREFIX = 'zoneskein-doh-rate-reservation-v1';
const STORAGE_KEY = 'zoneskein-doh-rate-v2';
const RESOLVER_IDS = [
  'cloudflare',
  'google',
  'quad9',
  'quad9-relay',
] as const satisfies readonly ResolverId[];

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isResolverId(value: unknown): value is ResolverId {
  return (
    value === 'cloudflare' || value === 'google' || value === 'quad9' || value === 'quad9-relay'
  );
}

function isTimestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isEventId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_EVENT_ID_CHARACTERS &&
    /^[A-Za-z0-9:._-]+$/u.test(value)
  );
}

function isSharedEvent(value: unknown): value is SharedEvent {
  if (!isObject(value) || !isResolverId(value['resolverId'])) return false;
  if (value['type'] === 'request')
    return (
      Object.keys(value).length === 4 &&
      isEventId(value['id']) &&
      isTimestamp(value['timestamp'])
    );
  return (
    value['type'] === 'cooldown' &&
    Object.keys(value).length === 3 &&
    isTimestamp(value['until'])
  );
}

function defaultStorage(): RateLimitStorage | undefined {
  try {
    const runtime = globalThis as typeof globalThis & RuntimeGlobal;
    return typeof document === 'undefined' ||
      document.defaultView === null ||
      runtime.process?.release?.name === 'node'
      ? undefined
      : document.defaultView.localStorage;
  } catch {
    return undefined;
  }
}

function defaultChannel(): RateLimitChannel | undefined {
  try {
    return typeof BroadcastChannel === 'undefined'
      ? undefined
      : new BroadcastChannel(CHANNEL_NAME);
  } catch {
    return undefined;
  }
}

function defaultLockManager(): RateLimitLockManager | undefined {
  try {
    if (typeof navigator === 'undefined') return undefined;
    const manager = (navigator as unknown as { readonly locks?: LockManager }).locks;
    if (manager === undefined) return undefined;
    return {
      request<T>(name: string, callback: () => Promise<T> | T): Promise<T> {
        return manager.request(name, () => callback());
      },
    };
  } catch {
    return undefined;
  }
}

function instanceId(): string {
  try {
    return globalThis.crypto.randomUUID();
  } catch {
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  }
}

function requestTimestamp(timestamp: number, now: number): number | null {
  if (!isTimestamp(timestamp) || timestamp > now + MAX_FUTURE_SKEW_MS) return null;
  if (timestamp <= now - WINDOW_MS) return null;
  return Math.min(timestamp, now);
}

function persistedState(value: unknown, now: number): PersistedState | null {
  if (!isObject(value) || Object.keys(value).length !== 3) return null;
  if (
    value['version'] !== 1 ||
    !isTimestamp(value['savedAt']) ||
    value['savedAt'] > now + MAX_FUTURE_SKEW_MS ||
    value['savedAt'] < Math.max(0, now - MAX_STATE_AGE_MS) ||
    !isObject(value['windows'])
  )
    return null;

  const rawWindows = value['windows'];
  if (Object.keys(rawWindows).some((key) => !isResolverId(key))) return null;
  const windows: Partial<Record<ResolverId, PersistedWindow>> = {};
  for (const resolverId of RESOLVER_IDS) {
    const rawWindow = rawWindows[resolverId];
    if (rawWindow === undefined) continue;
    if (!isObject(rawWindow) || Object.keys(rawWindow).length !== 2) return null;
    const cooldownUntil = rawWindow['cooldownUntil'];
    const rawRequests = rawWindow['requests'];
    if (
      !isTimestamp(cooldownUntil) ||
      cooldownUntil > now + MAX_COOLDOWN_MS + MAX_FUTURE_SKEW_MS ||
      !Array.isArray(rawRequests) ||
      rawRequests.length > MAX_REQUESTS_PER_WINDOW
    )
      return null;

    const requests: RequestStamp[] = [];
    const ids = new Set<string>();
    for (const rawRequest of rawRequests) {
      if (
        !isObject(rawRequest) ||
        Object.keys(rawRequest).length !== 2 ||
        !isEventId(rawRequest['id']) ||
        !isTimestamp(rawRequest['timestamp']) ||
        rawRequest['timestamp'] > now + MAX_FUTURE_SKEW_MS ||
        ids.has(rawRequest['id'])
      )
        return null;
      ids.add(rawRequest['id']);
      const timestamp = requestTimestamp(rawRequest['timestamp'], now);
      if (timestamp !== null) requests.push({ id: rawRequest['id'], timestamp });
    }
    requests.sort(
      (left, right) => left.timestamp - right.timestamp || left.id.localeCompare(right.id),
    );
    windows[resolverId] = {
      cooldownUntil: cooldownUntil > now ? Math.min(cooldownUntil, now + MAX_COOLDOWN_MS) : 0,
      requests,
    };
  }
  return { savedAt: value['savedAt'], version: 1, windows };
}

export class BrowserRateLimiter {
  readonly #channel: RateLimitChannel | undefined;
  readonly #instanceId = instanceId();
  readonly #lockManager: RateLimitLockManager | undefined;
  readonly #now: () => number;
  readonly #queues = new Map<ResolverId, QueueEntry[]>();
  readonly #running = new Set<ResolverId>();
  readonly #storage: RateLimitStorage | undefined;
  readonly #windows = new Map<ResolverId, ResolverWindow>();
  #sequence = 0;

  constructor(now: () => number = Date.now, options: BrowserRateLimiterOptions = {}) {
    this.#now = now;
    this.#storage =
      options.storage === undefined ? defaultStorage() : (options.storage ?? undefined);
    this.#lockManager =
      options.lockManager === undefined
        ? defaultLockManager()
        : (options.lockManager ?? undefined);
    try {
      this.#channel =
        options.channelFactory === undefined
          ? defaultChannel()
          : (options.channelFactory(CHANNEL_NAME) ?? undefined);
    } catch {
      // Rate limiting remains local when cross-tab messaging is unavailable.
    }
    this.#channel?.addEventListener('message', (event: MessageEvent<unknown>) => {
      this.#receive(event.data);
    });
    this.#loadPersisted(this.#time());
  }

  close(): void {
    this.#channel?.close();
  }

  imposeCooldown(resolverId: ResolverId, durationMs: number): void {
    if (!Number.isFinite(durationMs) || durationMs <= 0) return;
    const now = this.#time();
    this.#loadPersisted(now);
    const until = now + Math.min(Math.floor(durationMs), MAX_COOLDOWN_MS);
    const resolverWindow = this.#window(resolverId);
    resolverWindow.cooldownUntil = Math.max(resolverWindow.cooldownUntil, until);
    this.#persist(now);
    this.#post({ resolverId, type: 'cooldown', until: resolverWindow.cooldownUntil });
  }

  wait(resolverId: ResolverId, signal?: AbortSignal): Promise<void> {
    if (signal?.aborted)
      return Promise.reject(new DnsQueryError('aborted', 'The DNS run was cancelled.'));
    if ((this.#queues.get(resolverId)?.length ?? 0) >= MAX_QUEUED_PER_RESOLVER)
      return Promise.reject(
        new DnsQueryError(
          'rate-limited',
          'This browser has too many DNS requests waiting for the resolver.',
        ),
      );

    return new Promise((resolve, reject) => {
      const id = Symbol();
      const onAbort = () => this.#cancelQueued(resolverId, id);
      const entry: QueueEntry = {
        id,
        reject,
        resolve,
        ...(signal === undefined ? {} : { onAbort, signal }),
      };
      const queue = this.#queues.get(resolverId) ?? [];
      queue.push(entry);
      this.#queues.set(resolverId, queue);
      signal?.addEventListener('abort', onAbort, { once: true });
      if (signal?.aborted) onAbort();
      else this.#startDrain(resolverId);
    });
  }

  #cancelQueued(resolverId: ResolverId, id: symbol): void {
    const queue = this.#queues.get(resolverId);
    const index = queue?.findIndex((entry) => entry.id === id) ?? -1;
    if (queue === undefined || index < 0) return;
    const [entry] = queue.splice(index, 1);
    if (entry === undefined) return;
    this.#detach(entry);
    entry.reject(new DnsQueryError('aborted', 'The DNS run was cancelled.'));
    if (queue.length === 0) this.#queues.delete(resolverId);
  }

  #delay(milliseconds: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error?: DnsQueryError) => {
        if (settled) return;
        settled = true;
        window.clearTimeout(timeout);
        signal?.removeEventListener('abort', abort);
        if (error === undefined) resolve();
        else reject(error);
      };
      const abort = () => finish(new DnsQueryError('aborted', 'The DNS run was cancelled.'));
      const timeout = window.setTimeout(() => finish(), milliseconds);
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) abort();
    });
  }

  #detach(entry: QueueEntry): void {
    if (entry.signal !== undefined && entry.onAbort !== undefined)
      entry.signal.removeEventListener('abort', entry.onAbort);
  }

  async #drain(resolverId: ResolverId): Promise<void> {
    try {
      for (;;) {
        const queue = this.#queues.get(resolverId);
        const entry = queue?.shift();
        if (entry === undefined) break;
        if (queue?.length === 0) this.#queues.delete(resolverId);
        this.#detach(entry);
        if (entry.signal?.aborted) {
          entry.reject(new DnsQueryError('aborted', 'The DNS run was cancelled.'));
          continue;
        }
        try {
          await this.#takeSlot(resolverId, entry.signal);
          entry.resolve();
        } catch (cause) {
          entry.reject(
            cause instanceof DnsQueryError
              ? cause
              : new DnsQueryError('transport-error', 'The DNS rate limiter failed.'),
          );
        }
      }
    } finally {
      this.#running.delete(resolverId);
      if ((this.#queues.get(resolverId)?.length ?? 0) > 0) this.#startDrain(resolverId);
    }
  }

  #loadPersisted(now: number): void {
    if (this.#storage === undefined) return;
    let serialised: string | null;
    try {
      serialised = this.#storage.getItem(STORAGE_KEY);
    } catch {
      return;
    }
    if (
      serialised === null ||
      serialised.length === 0 ||
      serialised.length > MAX_PERSISTED_CHARACTERS
    )
      return;
    let decoded: unknown;
    try {
      decoded = JSON.parse(serialised) as unknown;
    } catch {
      return;
    }
    const state = persistedState(decoded, now);
    if (state === null) return;
    for (const resolverId of RESOLVER_IDS) {
      const source = state.windows[resolverId];
      if (source === undefined) continue;
      const target = this.#window(resolverId);
      target.cooldownUntil = Math.max(target.cooldownUntil, source.cooldownUntil);
      const known = new Set(target.requests.map((request) => request.id));
      for (const request of source.requests) {
        if (!known.has(request.id)) {
          target.requests.push(request);
          known.add(request.id);
        }
      }
      this.#prune(target, now);
    }
  }

  #nextRequestId(): string {
    this.#sequence += 1;
    return `${this.#instanceId}:${String(this.#sequence)}`;
  }

  #persist(now: number): void {
    if (this.#storage === undefined) return;
    const windows: Partial<Record<ResolverId, PersistedWindow>> = {};
    for (const resolverId of RESOLVER_IDS) {
      const resolverWindow = this.#windows.get(resolverId);
      if (resolverWindow === undefined) continue;
      this.#prune(resolverWindow, now);
      if (resolverWindow.cooldownUntil <= now && resolverWindow.requests.length === 0) continue;
      windows[resolverId] = {
        cooldownUntil: resolverWindow.cooldownUntil > now ? resolverWindow.cooldownUntil : 0,
        requests: resolverWindow.requests,
      };
    }
    const serialised = JSON.stringify({
      savedAt: now,
      version: 1,
      windows,
    } satisfies PersistedState);
    if (serialised.length > MAX_PERSISTED_CHARACTERS) return;
    try {
      this.#storage.setItem(STORAGE_KEY, serialised);
    } catch {
      // Storage failure must not prevent an otherwise permitted DNS request.
    }
  }

  #post(event: SharedEvent): void {
    try {
      this.#channel?.postMessage(event);
    } catch {
      // Cross-tab coordination is an additional guard, not a query dependency.
    }
  }

  #prune(resolverWindow: ResolverWindow, now: number): void {
    resolverWindow.requests = resolverWindow.requests
      .filter(
        (request) =>
          request.timestamp > now - WINDOW_MS && request.timestamp <= now + MAX_FUTURE_SKEW_MS,
      )
      .map((request) => ({ ...request, timestamp: Math.min(request.timestamp, now) }))
      .sort(
        (left, right) => left.timestamp - right.timestamp || left.id.localeCompare(right.id),
      );
    if (resolverWindow.requests.length > MAX_REQUESTS_PER_WINDOW)
      resolverWindow.requests = resolverWindow.requests.slice(-MAX_REQUESTS_PER_WINDOW);
    if (resolverWindow.cooldownUntil <= now) resolverWindow.cooldownUntil = 0;
  }

  #receive(value: unknown): void {
    if (!isSharedEvent(value)) return;
    const now = this.#time();
    if (value.type === 'request') {
      const timestamp = requestTimestamp(value.timestamp, now);
      if (timestamp === null) return;
      this.#record(value.resolverId, { id: value.id, timestamp }, now, false);
      return;
    }
    if (value.until <= now || value.until > now + MAX_COOLDOWN_MS + MAX_FUTURE_SKEW_MS) return;
    const resolverWindow = this.#window(value.resolverId);
    resolverWindow.cooldownUntil = Math.max(
      resolverWindow.cooldownUntil,
      Math.min(value.until, now + MAX_COOLDOWN_MS),
    );
  }

  #record(resolverId: ResolverId, request: RequestStamp, now: number, persist = true): void {
    const resolverWindow = this.#window(resolverId);
    this.#prune(resolverWindow, now);
    if (resolverWindow.requests.some((candidate) => candidate.id === request.id)) return;
    if (resolverWindow.requests.length >= MAX_REQUESTS_PER_WINDOW) return;
    resolverWindow.requests.push(request);
    this.#prune(resolverWindow, now);
    if (persist) this.#persist(now);
  }

  #startDrain(resolverId: ResolverId): void {
    if (this.#running.has(resolverId)) return;
    this.#running.add(resolverId);
    void this.#drain(resolverId);
  }

  async #takeSlot(resolverId: ResolverId, signal?: AbortSignal): Promise<void> {
    for (;;) {
      if (signal?.aborted) throw new DnsQueryError('aborted', 'The DNS run was cancelled.');
      const decision = await this.#withReservationLock(resolverId, () => {
        if (signal?.aborted) throw new DnsQueryError('aborted', 'The DNS run was cancelled.');
        const now = this.#time();
        this.#loadPersisted(now);
        const resolverWindow = this.#window(resolverId);
        this.#prune(resolverWindow, now);
        if (resolverWindow.cooldownUntil > now) {
          throw new DnsQueryError(
            'cooldown',
            'The resolver is cooling down after a rate-limit response.',
            resolverWindow.cooldownUntil - now,
          );
        }
        if (resolverWindow.requests.length >= MAX_REQUESTS_PER_WINDOW) {
          const oldest = resolverWindow.requests.at(0);
          if (oldest === undefined) return { delayMs: 1, granted: false } as const;
          throw new DnsQueryError(
            'rate-limited',
            'This browser has reached the rolling DNS request limit.',
            Math.max(0, WINDOW_MS - (now - oldest.timestamp)),
          );
        }

        const tokens = this.#tokens(resolverWindow.requests, now);
        if (tokens < 1)
          return {
            delayMs: Math.max(1, Math.ceil(((1 - tokens) / REFILL_PER_SECOND) * 1000)),
            granted: false,
          } as const;
        const request: SharedRequestEvent = {
          id: this.#nextRequestId(),
          resolverId,
          timestamp: now,
          type: 'request',
        };
        this.#record(resolverId, { id: request.id, timestamp: request.timestamp }, now);
        this.#post(request);
        return { granted: true } as const;
      });
      if (decision.granted) return;
      await this.#delay(decision.delayMs, signal);
    }
  }

  async #withReservationLock<T>(resolverId: ResolverId, callback: () => T): Promise<T> {
    if (this.#lockManager === undefined) return callback();
    return this.#lockManager.request(`${LOCK_NAME_PREFIX}:${resolverId}`, callback);
  }

  #time(): number {
    const value = this.#now();
    return Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER
      ? Math.floor(value)
      : Date.now();
  }

  #tokens(requests: readonly RequestStamp[], now: number): number {
    const first = requests[0];
    if (first === undefined) return BURST;
    let tokens = BURST;
    let updatedAt = first.timestamp;
    for (const request of requests) {
      const timestamp = Math.max(updatedAt, Math.min(request.timestamp, now));
      tokens = Math.min(BURST, tokens + ((timestamp - updatedAt) / 1000) * REFILL_PER_SECOND);
      tokens = Math.max(0, tokens - 1);
      updatedAt = timestamp;
    }
    return Math.min(BURST, tokens + ((now - updatedAt) / 1000) * REFILL_PER_SECOND);
  }

  #window(resolverId: ResolverId): ResolverWindow {
    let resolverWindow = this.#windows.get(resolverId);
    if (resolverWindow === undefined) {
      resolverWindow = { cooldownUntil: 0, requests: [] };
      this.#windows.set(resolverId, resolverWindow);
    }
    return resolverWindow;
  }
}
