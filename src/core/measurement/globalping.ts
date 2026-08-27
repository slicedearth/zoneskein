const GLOBALPING_API = 'https://api.globalping.io/v1/measurements';
const MAX_RESPONSE_BYTES = 1_048_576;
const MAX_RESULTS = 3;
const MAX_HOPS = 48;
const MAX_ANSWERS_PER_HOP = 256;
const MAX_POLL_ATTEMPTS = 64;
const POLL_INTERVAL_MS = 600;
const LOCAL_WINDOW_MS = 60 * 60 * 1000;
const LOCAL_RUN_LIMIT = 6;
const LEDGER_KEY = 'zoneskein:globalping-runs:v1';

export type GlobalpingDnsProtocol = 'TCP' | 'UDP';
export type GlobalpingDnsType =
  | 'A'
  | 'AAAA'
  | 'CAA'
  | 'CNAME'
  | 'DNSKEY'
  | 'DS'
  | 'HTTPS'
  | 'MX'
  | 'NS'
  | 'SOA'
  | 'SRV'
  | 'SVCB'
  | 'TXT';

export interface GlobalpingDnsRequest {
  readonly ipVersion: 4 | 6;
  readonly location: string;
  readonly probes: 1 | 2 | 3;
  readonly protocol: GlobalpingDnsProtocol;
  readonly resolver?: string;
  readonly target: string;
  readonly trace: boolean;
  readonly type: GlobalpingDnsType;
}

export interface GlobalpingDnsAnswer {
  readonly className: string;
  readonly name: string;
  readonly ttl: number;
  readonly type: string;
  readonly value: string;
}

export interface GlobalpingDnsHop {
  readonly answers: readonly GlobalpingDnsAnswer[];
  readonly resolver: string;
  readonly totalMs: number | null;
}

export interface GlobalpingProbe {
  readonly asn: number | null;
  readonly city: string;
  readonly country: string;
  readonly network: string;
}

export interface GlobalpingDnsResult {
  readonly hops: readonly GlobalpingDnsHop[];
  readonly probe: GlobalpingProbe;
  readonly rawOutput: string;
  readonly status: 'finished' | 'failed' | 'offline' | 'in-progress';
}

export interface GlobalpingDnsMeasurement {
  readonly completedAt: string;
  readonly id: string;
  readonly probesCount: number;
  readonly results: readonly GlobalpingDnsResult[];
  readonly target: string;
}

function object(value: unknown): Readonly<Record<string, unknown>> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Readonly<Record<string, unknown>>)
    : null;
}

function stringValue(value: unknown, maximum = 16_384): string | null {
  return typeof value === 'string' && value.length <= maximum ? value : null;
}

function numberValue(value: unknown, minimum: number, maximum: number): number | null {
  return typeof value === 'number' &&
    Number.isFinite(value) &&
    value >= minimum &&
    value <= maximum
    ? value
    : null;
}

async function responseBytes(response: Response): Promise<Uint8Array> {
  const declared = response.headers.get('content-length');
  if (declared !== null && Number(declared) > MAX_RESPONSE_BYTES) {
    throw new Error('The measurement service response exceeded the local size limit.');
  }
  if (response.body === null) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > MAX_RESPONSE_BYTES)
      throw new Error('The measurement service response exceeded the local size limit.');
    return bytes;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const item = await reader.read();
      if (item.done) break;
      total += item.value.length;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error('The measurement service response exceeded the local size limit.');
      }
      chunks.push(item.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}

async function responseJson(response: Response): Promise<unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(await responseBytes(response)),
    );
  } catch (cause) {
    if (cause instanceof Error && cause.message.includes('size limit')) throw cause;
    throw new Error('The measurement service returned malformed JSON.', { cause });
  }
  return parsed;
}

function decodeAnswer(value: unknown): GlobalpingDnsAnswer | null {
  const item = object(value);
  if (item === null) return null;
  const name = stringValue(item['name'], 1_024);
  const type = stringValue(item['type'], 32);
  const className = stringValue(item['class'], 16);
  const ttl = numberValue(item['ttl'], 0, 0xffff_ffff);
  const answerValue = stringValue(item['value']);
  return name === null ||
    type === null ||
    className === null ||
    ttl === null ||
    answerValue === null
    ? null
    : { className, name, ttl, type, value: answerValue };
}

function decodeHop(value: unknown): GlobalpingDnsHop | null {
  const item = object(value);
  if (item === null) return null;
  const resolver = stringValue(item['resolver'], 1_024);
  const answersValue = item['answers'];
  const timings = object(item['timings']);
  if (
    resolver === null ||
    !Array.isArray(answersValue) ||
    answersValue.length > MAX_ANSWERS_PER_HOP
  )
    return null;
  const answers = answersValue.map(decodeAnswer);
  if (answers.some((answer) => answer === null)) return null;
  return {
    answers: answers as readonly GlobalpingDnsAnswer[],
    resolver,
    totalMs: numberValue(timings?.['total'], 0, 120_000),
  };
}

function decodeProbe(value: unknown): GlobalpingProbe | null {
  const item = object(value);
  if (item === null) return null;
  const city = stringValue(item['city'], 256);
  const country = stringValue(item['country'], 128);
  const network = stringValue(item['network'], 512);
  const asn = item['asn'] === null ? null : numberValue(item['asn'], 1, 0xffff_ffff);
  return city === null || country === null || network === null
    ? null
    : { asn, city, country, network };
}

function decodeResult(value: unknown): GlobalpingDnsResult | null {
  const item = object(value);
  const probeValue = object(item?.['probe']);
  const resultValue = object(item?.['result']);
  const probe = decodeProbe(probeValue);
  const status = stringValue(resultValue?.['status'], 32);
  const rawOutput = stringValue(resultValue?.['rawOutput'], 65_536);
  if (
    probe === null ||
    rawOutput === null ||
    (status !== 'finished' &&
      status !== 'failed' &&
      status !== 'offline' &&
      status !== 'in-progress')
  )
    return null;
  const rawHops = resultValue?.['hops'];
  const simpleHop = decodeHop(resultValue);
  let hops: readonly GlobalpingDnsHop[];
  if (Array.isArray(rawHops)) {
    if (rawHops.length > MAX_HOPS) return null;
    const decoded = rawHops.map(decodeHop);
    if (decoded.some((hop) => hop === null)) return null;
    hops = decoded as readonly GlobalpingDnsHop[];
  } else hops = simpleHop === null ? [] : [simpleHop];
  return { hops, probe, rawOutput, status };
}

function decodeMeasurement(
  value: unknown,
  expectedId: string,
): Omit<GlobalpingDnsMeasurement, 'completedAt'> & { readonly final: boolean } {
  const item = object(value);
  if (item === null) throw new Error('The measurement response has an invalid shape.');
  const id = stringValue(item['id'], 128);
  const target = stringValue(item['target'], 2_048);
  const status = stringValue(item['status'], 32);
  const probesCount = numberValue(item['probesCount'], 0, MAX_RESULTS);
  const rawResults = item['results'];
  if (
    id !== expectedId ||
    target === null ||
    (status !== 'in-progress' && status !== 'finished') ||
    probesCount === null ||
    !Array.isArray(rawResults) ||
    rawResults.length > MAX_RESULTS
  )
    throw new Error('The measurement response has an invalid or mismatched shape.');
  const results = rawResults.map(decodeResult);
  if (results.some((result) => result === null))
    throw new Error('The measurement response contains an invalid probe result.');
  return {
    final: status !== 'in-progress',
    id,
    probesCount,
    results: results as readonly GlobalpingDnsResult[],
    target,
  };
}

function delay(signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException('The measurement was cancelled.', 'AbortError'));
      return;
    }
    const complete = () => {
      signal.removeEventListener('abort', abort);
      resolve();
    };
    const timeout = window.setTimeout(complete, POLL_INTERVAL_MS);
    const abort = () => {
      window.clearTimeout(timeout);
      signal.removeEventListener('abort', abort);
      reject(new DOMException('The measurement was cancelled.', 'AbortError'));
    };
    signal.addEventListener('abort', abort, { once: true });
  });
}

export function reserveGlobalpingRun(
  storage: Storage | null,
  now = Date.now(),
): { readonly ok: true } | { readonly ok: false; readonly retryAfterMs: number } {
  if (storage === null) return { ok: true };
  let values: number[] = [];
  try {
    const raw = storage.getItem(LEDGER_KEY);
    const parsed: unknown = raw === null ? [] : JSON.parse(raw);
    if (Array.isArray(parsed))
      values = parsed.filter(
        (value): value is number =>
          typeof value === 'number' &&
          Number.isFinite(value) &&
          value > now - LOCAL_WINDOW_MS &&
          value <= now,
      );
    values.sort((left, right) => left - right);
  } catch {
    values = [];
  }
  if (values.length >= LOCAL_RUN_LIMIT) {
    const first = values[0] ?? now;
    return { ok: false, retryAfterMs: Math.max(1, first + LOCAL_WINDOW_MS - now) };
  }
  try {
    storage.setItem(LEDGER_KEY, JSON.stringify([...values, now]));
  } catch {
    // The service retains its own rate limit when browser storage is unavailable.
  }
  return { ok: true };
}

export async function runGlobalpingDns(
  request: GlobalpingDnsRequest,
  signal: AbortSignal,
  fetcher: typeof fetch = fetch,
): Promise<GlobalpingDnsMeasurement> {
  const body = {
    inProgressUpdates: false,
    limit: request.probes,
    locations: request.location === 'world' ? [] : [{ magic: request.location }],
    measurementOptions: {
      ipVersion: request.ipVersion,
      protocol: request.protocol,
      query: { type: request.type },
      trace: request.trace,
      ...(request.resolver === undefined ? {} : { resolver: request.resolver }),
    },
    target: request.target,
    timeout: 12,
    type: 'dns',
  };
  const createdResponse = await fetcher(GLOBALPING_API, {
    body: JSON.stringify(body),
    cache: 'no-store',
    credentials: 'omit',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    method: 'POST',
    referrerPolicy: 'no-referrer',
    signal,
  });
  if (createdResponse.status !== 202) {
    const retry = createdResponse.headers.get('retry-after');
    throw new Error(
      createdResponse.status === 429
        ? `The measurement service rate limit was reached${retry === null ? '.' : `; retry after ${retry} seconds.`}`
        : `The measurement service rejected the request with HTTP ${String(createdResponse.status)}.`,
    );
  }
  const created = object(await responseJson(createdResponse));
  const id = stringValue(created?.['id'], 128);
  if (id === null || !/^[A-Za-z0-9_-]+$/u.test(id))
    throw new Error('The measurement service did not return a valid measurement identifier.');

  for (let attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt += 1) {
    await delay(signal);
    const response = await fetcher(`${GLOBALPING_API}/${id}`, {
      cache: 'no-store',
      credentials: 'omit',
      headers: { Accept: 'application/json' },
      method: 'GET',
      referrerPolicy: 'no-referrer',
      signal,
    });
    if (!response.ok)
      throw new Error(
        `The measurement result request failed with HTTP ${String(response.status)}.`,
      );
    const decoded = decodeMeasurement(await responseJson(response), id);
    if (decoded.final)
      return {
        completedAt: new Date().toISOString(),
        id: decoded.id,
        probesCount: decoded.probesCount,
        results: decoded.results,
        target: decoded.target,
      };
  }
  throw new Error('The measurement did not finish within the bounded polling window.');
}
