// @vitest-environment node

import { describe, expect, it, vi } from 'vitest';

import {
  MAX_RELAY_QUERY_BYTES,
  MAX_RELAY_RESPONSE_BYTES,
  QUAD9_DOH_URL,
  QUAD9_RELAY_TIMEOUT_MS,
  config,
  createQuad9RelayHandler,
  type Quad9Forwarder,
} from '../../netlify/functions/quad9-doh';

const MEDIA_TYPE = 'application/dns-message';

function writeUint16(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value >>> 8;
  bytes[offset + 1] = value & 0xff;
}

function dnsName(name: string): Uint8Array {
  if (name === '.') return new Uint8Array([0]);
  const bytes: number[] = [];
  for (const label of name.replace(/\.$/u, '').split('.')) {
    bytes.push(label.length);
    for (let index = 0; index < label.length; index += 1) {
      bytes.push(label.charCodeAt(index));
    }
  }
  bytes.push(0);
  return new Uint8Array(bytes);
}

function concatenate(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function dnsQuery({
  classCode = 1,
  dnssecOk = false,
  flags = 0x0100,
  id = 0,
  name = 'example.com.',
  typeCode = 1,
}: {
  readonly classCode?: number;
  readonly dnssecOk?: boolean;
  readonly flags?: number;
  readonly id?: number;
  readonly name?: string;
  readonly typeCode?: number;
} = {}): Uint8Array {
  const header = new Uint8Array(12);
  writeUint16(header, 0, id);
  writeUint16(header, 2, flags);
  writeUint16(header, 4, 1);
  writeUint16(header, 10, 1);
  const questionTail = new Uint8Array(4);
  writeUint16(questionTail, 0, typeCode);
  writeUint16(questionTail, 2, classCode);
  const optHeader = new Uint8Array([0, 0, 41, 4, 208, 0, 0, dnssecOk ? 128 : 0, 0, 0, 0]);
  const clientSubnet = new Uint8Array([0, 8, 0, 4, 0, 1, 0, 0]);
  const withoutPadding = concatenate(
    header,
    dnsName(name),
    questionTail,
    optHeader,
    clientSubnet,
  );
  const paddingLength = (128 - ((withoutPadding.length + 4) % 128)) % 128;
  const padding = new Uint8Array(4 + paddingLength);
  writeUint16(padding, 0, 12);
  writeUint16(padding, 2, paddingLength);
  writeUint16(optHeader, 9, clientSubnet.length + padding.length);
  return concatenate(header, dnsName(name), questionTail, optHeader, clientSubnet, padding);
}

function questionEnd(query: Uint8Array): number {
  let offset = 12;
  while (offset < query.length) {
    const length = query[offset];
    if (length === undefined) throw new Error('Test query is truncated.');
    offset += 1;
    if (length === 0) return offset + 4;
    offset += length;
  }
  throw new Error('Test query has no terminating root label.');
}

function dnsResponse(
  query: Uint8Array,
  {
    answer = false,
    flags = 0x8180,
    id = 0,
    questionType,
    trailing = false,
  }: {
    readonly answer?: boolean;
    readonly flags?: number;
    readonly id?: number;
    readonly questionType?: number;
    readonly trailing?: boolean;
  } = {},
): Uint8Array {
  const end = questionEnd(query);
  const question = query.slice(12, end);
  if (questionType !== undefined) writeUint16(question, question.length - 4, questionType);
  const answerRecord = answer
    ? new Uint8Array([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1])
    : new Uint8Array();
  const header = new Uint8Array(12);
  writeUint16(header, 0, id);
  writeUint16(header, 2, flags);
  writeUint16(header, 4, 1);
  writeUint16(header, 6, answer ? 1 : 0);
  return concatenate(
    header,
    question,
    answerRecord,
    trailing ? new Uint8Array([0xff]) : new Uint8Array(),
  );
}

function bodyBuffer(bytes: Uint8Array): ArrayBuffer {
  const output = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(output).set(bytes);
  return output;
}

function relayRequest(
  query: Uint8Array,
  {
    contentLength,
    headers = {},
    method = 'POST',
    search = '',
  }: {
    readonly contentLength?: number;
    readonly headers?: Readonly<Record<string, string>>;
    readonly method?: string;
    readonly search?: string;
  } = {},
): Request {
  return new Request(`https://zoneskein.test/api/doh/quad9${search}`, {
    ...(method === 'GET' ? {} : { body: bodyBuffer(query) }),
    headers: {
      'Content-Type': MEDIA_TYPE,
      ...(contentLength === undefined ? {} : { 'Content-Length': String(contentLength) }),
      ...headers,
    },
    method,
  });
}

describe('Quad9 compatibility relay', () => {
  it('exports one fixed, rate-limited POST route', () => {
    expect(QUAD9_DOH_URL.href).toBe('https://dns.quad9.net/dns-query');
    expect(config).toEqual({
      method: 'POST',
      path: '/api/doh/quad9',
      rateLimit: {
        action: 'rate_limit',
        aggregateBy: ['ip', 'domain'],
        windowLimit: 120,
        windowSize: 60,
      },
    });
  });

  it('forwards a bounded wire query and returns a bound DNS response without caching', async () => {
    const query = dnsQuery({ dnssecOk: true, flags: 0x0110 });
    const upstream = dnsResponse(query, { answer: true });
    const forward = vi.fn<Quad9Forwarder>((observed) => {
      expect(observed).toEqual(query);
      return Promise.resolve(upstream);
    });
    const response = await createQuad9RelayHandler(forward)(relayRequest(query));

    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toBe(MEDIA_TYPE);
    expect(response.headers.get('Cache-Control')).toBe('no-store, max-age=0');
    expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull();
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(upstream);
    expect(forward).toHaveBeenCalledOnce();
  });

  it('rejects methods, query strings, cross-origin use, encodings and media types before forwarding', async () => {
    const query = dnsQuery();
    const forward = vi.fn<Quad9Forwarder>(() => Promise.resolve(dnsResponse(query)));
    const handler = createQuad9RelayHandler(forward);
    const cases = [
      relayRequest(query, { method: 'GET' }),
      relayRequest(query, { search: '?target=https://attacker.test' }),
      relayRequest(query, { headers: { Origin: 'https://attacker.test' } }),
      relayRequest(query, { headers: { 'Sec-Fetch-Site': 'cross-site' } }),
      relayRequest(query, { headers: { 'Content-Encoding': 'gzip' } }),
      relayRequest(query, { headers: { 'Content-Type': 'text/plain' } }),
    ];

    const responses = await Promise.all(cases.map((request) => handler(request)));
    expect(responses.map((response) => response.status)).toEqual([
      405, 400, 403, 403, 415, 415,
    ]);
    expect(responses[0]?.headers.get('Allow')).toBe('POST');
    expect(forward).not.toHaveBeenCalled();
  });

  it('bounds declared, streamed and mismatched request lengths before forwarding', async () => {
    const query = dnsQuery();
    const forward = vi.fn<Quad9Forwarder>(() => Promise.resolve(dnsResponse(query)));
    const handler = createQuad9RelayHandler(forward);
    const declared = await handler(
      relayRequest(query, { contentLength: MAX_RELAY_QUERY_BYTES + 1 }),
    );
    const mismatch = await handler(relayRequest(query, { contentLength: query.length + 1 }));
    const oversized = await handler(
      relayRequest(new Uint8Array(MAX_RELAY_QUERY_BYTES + 1).fill(1)),
    );

    expect(declared.status).toBe(413);
    expect(mismatch.status).toBe(400);
    expect(oversized.status).toBe(413);
    expect(forward).not.toHaveBeenCalled();
  });

  it('accepts only the application query profile and supported QTYPEs', async () => {
    const baseline = dnsQuery();
    const compressed = baseline.slice();
    compressed[12] = 0xc0;
    compressed[13] = 0x0c;
    const badLabel = baseline.slice();
    badLabel[13] = 0x20;
    const badEcs = baseline.slice();
    const ecsStart = questionEnd(baseline) + 11;
    badEcs[ecsStart] = 0;
    badEcs[ecsStart + 1] = 10;
    const badPadding = baseline.slice();
    badPadding[badPadding.length - 1] = 1;
    const unpadded = baseline.slice(0, baseline.length - 1);
    const noOpt = baseline.slice();
    writeUint16(noOpt, 10, 0);
    const cases = [
      dnsQuery({ id: 1 }),
      dnsQuery({ flags: 0 }),
      dnsQuery({ classCode: 3 }),
      dnsQuery({ typeCode: 255 }),
      dnsQuery({ typeCode: 251 }),
      compressed,
      badLabel,
      badEcs,
      badPadding,
      unpadded,
      noOpt,
    ];
    const forward = vi.fn<Quad9Forwarder>(() => Promise.resolve(dnsResponse(baseline)));
    const handler = createQuad9RelayHandler(forward);

    for (const query of cases) expect((await handler(relayRequest(query))).status).toBe(400);
    expect(forward).not.toHaveBeenCalled();
  });

  it('allows every ZoneSkein live QTYPE including root DNSKEY', async () => {
    const supported = [1, 2, 5, 6, 12, 15, 16, 28, 33, 43, 46, 47, 48, 50, 52, 63, 64, 65, 257];
    for (const typeCode of supported) {
      const query = dnsQuery({ name: typeCode === 48 ? '.' : 'example.com.', typeCode });
      const response = await createQuad9RelayHandler(() => Promise.resolve(dnsResponse(query)))(
        relayRequest(query),
      );
      expect(response.status).toBe(200);
    }
  });

  it('rejects mismatched, truncated, malformed and oversized upstream responses', async () => {
    const query = dnsQuery();
    const tooManyRecords = dnsResponse(query);
    writeUint16(tooManyRecords, 6, 513);
    const malformedRecord = dnsResponse(query, { answer: true });
    writeUint16(malformedRecord, malformedRecord.length - 6, 32);
    const cases = [
      dnsResponse(query, { id: 1 }),
      dnsResponse(query, { questionType: 28 }),
      dnsResponse(query, { flags: 0x8380 }),
      dnsResponse(query, { trailing: true }),
      tooManyRecords,
      malformedRecord,
      new Uint8Array(MAX_RELAY_RESPONSE_BYTES + 1),
    ];

    for (const upstream of cases) {
      const response = await createQuad9RelayHandler(() => Promise.resolve(upstream))(
        relayRequest(query),
      );
      expect(response.status).toBe(502);
      expect(response.headers.get('Cache-Control')).toBe('no-store, max-age=0');
    }
  });

  it('maps upstream failures and the bounded timeout without exposing internals', async () => {
    const query = dnsQuery();
    const failed = await createQuad9RelayHandler(() =>
      Promise.reject(new Error('secret upstream detail')),
    )(relayRequest(query));
    expect(failed.status).toBe(502);
    expect(await failed.text()).not.toContain('secret');

    vi.useFakeTimers();
    try {
      const pending = createQuad9RelayHandler(
        (_query, signal) =>
          new Promise((_resolve, reject) => {
            signal.addEventListener(
              'abort',
              () => {
                reject(new DOMException('aborted', 'AbortError'));
              },
              { once: true },
            );
          }),
      )(relayRequest(query));
      await vi.advanceTimersByTimeAsync(QUAD9_RELAY_TIMEOUT_MS);
      const timedOut = await pending;
      expect(timedOut.status).toBe(504);
    } finally {
      vi.useRealTimers();
    }
  });
});
