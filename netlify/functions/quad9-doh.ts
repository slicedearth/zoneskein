import {
  connect,
  constants,
  type ClientHttp2Session,
  type ClientHttp2Stream,
  type IncomingHttpHeaders,
} from 'node:http2';

export const QUAD9_DOH_URL = new URL('https://dns.quad9.net/dns-query');
export const MAX_RELAY_QUERY_BYTES = 4_096;
export const MAX_RELAY_RESPONSE_BYTES = 65_535;
export const QUAD9_RELAY_TIMEOUT_MS = 7_000;

const MAX_BODY_CHUNKS = 256;
const MAX_DNS_NAME_OPERATIONS = 32_768;
const MAX_DNS_NAME_POINTERS = 128;
const MAX_DNS_RECORDS = 512;
const DNS_QUERY_PADDING_BLOCK_BYTES = 128;
const DNS_MESSAGE_MEDIA_TYPE = 'application/dns-message';
const SUPPORTED_QUERY_TYPES = new Set([
  1, // A
  2, // NS
  5, // CNAME
  6, // SOA
  12, // PTR
  15, // MX
  16, // TXT
  28, // AAAA
  33, // SRV
  43, // DS
  46, // RRSIG
  47, // NSEC
  48, // DNSKEY
  50, // NSEC3
  52, // TLSA
  63, // ZONEMD
  64, // SVCB
  65, // HTTPS
  257, // CAA
]);
const EXPECTED_EDNS_CLIENT_SUBNET = new Uint8Array([0, 8, 0, 4, 0, 1, 0, 0]);
const EDNS_PADDING_OPTION_CODE = 12;

export const config = {
  method: 'POST',
  path: '/api/doh/quad9',
  rateLimit: {
    action: 'rate_limit',
    aggregateBy: ['ip', 'domain'],
    windowLimit: 120,
    windowSize: 60,
  },
};

interface NameBudget {
  operations: number;
}

interface ParsedName {
  readonly canonicalWire: Uint8Array;
  readonly endOffset: number;
}

interface QuestionBinding {
  readonly canonicalName: Uint8Array;
  readonly classCode: number;
  readonly typeCode: number;
}

export type Quad9Forwarder = (query: Uint8Array, signal: AbortSignal) => Promise<Uint8Array>;

class RelayRequestError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'RelayRequestError';
    this.status = status;
  }
}

function readUint16(bytes: Uint8Array, offset: number): number {
  const high = bytes[offset];
  const low = bytes[offset + 1];
  if (high === undefined || low === undefined) throw new Error('Truncated DNS integer.');
  return (high << 8) | low;
}

function readUint32(bytes: Uint8Array, offset: number): number {
  const high = readUint16(bytes, offset);
  const low = readUint16(bytes, offset + 2);
  return high * 65_536 + low;
}

function asciiLower(byte: number): number {
  return byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte;
}

function isAllowedQueryLabelByte(byte: number): boolean {
  return (
    (byte >= 0x30 && byte <= 0x39) ||
    (byte >= 0x41 && byte <= 0x5a) ||
    (byte >= 0x61 && byte <= 0x7a) ||
    byte === 0x2a ||
    byte === 0x2d ||
    byte === 0x5f
  );
}

function readDnsName(
  message: Uint8Array,
  start: number,
  budget: NameBudget,
  allowCompression: boolean,
  restrictLabelBytes: boolean,
): ParsedName {
  let offset = start;
  let endOffset: number | undefined;
  let expandedOctets = 1;
  let pointerCount = 0;
  const canonical: number[] = [];
  const visitedPointers = new Set<number>();

  while (offset < message.length) {
    budget.operations += 1;
    if (budget.operations > MAX_DNS_NAME_OPERATIONS)
      throw new Error('DNS message exceeds the name-work limit.');
    const length = message[offset];
    if (length === undefined) throw new Error('Truncated DNS name.');

    if ((length & 0xc0) === 0xc0) {
      if (!allowCompression) throw new Error('Compressed query names are not accepted.');
      const low = message[offset + 1];
      if (low === undefined) throw new Error('Truncated DNS compression pointer.');
      const pointer = ((length & 0x3f) << 8) | low;
      if (pointer >= offset) throw new Error('DNS compression pointer must point backwards.');
      if (visitedPointers.has(pointer)) throw new Error('DNS compression pointer loop.');
      visitedPointers.add(pointer);
      pointerCount += 1;
      if (pointerCount > MAX_DNS_NAME_POINTERS)
        throw new Error('DNS name exceeds the compression-pointer limit.');
      endOffset ??= offset + 2;
      offset = pointer;
      continue;
    }
    if ((length & 0xc0) !== 0) throw new Error('Unsupported DNS label encoding.');
    offset += 1;
    if (length === 0) {
      canonical.push(0);
      return { canonicalWire: new Uint8Array(canonical), endOffset: endOffset ?? offset };
    }
    if (length > 63 || offset + length > message.length) throw new Error('Malformed DNS name.');
    expandedOctets += length + 1;
    if (expandedOctets > 255) throw new Error('DNS name exceeds 255 wire octets.');
    canonical.push(length);
    for (let index = 0; index < length; index += 1) {
      const byte = message[offset + index];
      if (byte === undefined) throw new Error('Truncated DNS label.');
      if (restrictLabelBytes && !isAllowedQueryLabelByte(byte))
        throw new Error('DNS query labels must use the supported ASCII subset.');
      canonical.push(asciiLower(byte));
    }
    offset += length;
  }
  throw new Error('Truncated DNS name.');
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function parseQuestion(
  message: Uint8Array,
  offset: number,
  budget: NameBudget,
  allowCompression: boolean,
  restrictLabelBytes: boolean,
): { readonly binding: QuestionBinding; readonly endOffset: number } {
  const name = readDnsName(message, offset, budget, allowCompression, restrictLabelBytes);
  if (name.endOffset + 4 > message.length) throw new Error('Truncated DNS question.');
  return {
    binding: {
      canonicalName: name.canonicalWire,
      classCode: readUint16(message, name.endOffset + 2),
      typeCode: readUint16(message, name.endOffset),
    },
    endOffset: name.endOffset + 4,
  };
}

function validateRelayQuery(message: Uint8Array): QuestionBinding {
  if (message.length < 12) throw new Error('DNS query is shorter than its header.');
  if (message.length % DNS_QUERY_PADDING_BLOCK_BYTES !== 0)
    throw new Error('DNS query does not match the padded ZoneSkein profile.');
  const flags = readUint16(message, 2);
  if ((flags & 0x0100) === 0 || (flags & ~(0x0100 | 0x0010)) !== 0)
    throw new Error('DNS query flags are not permitted.');
  if (
    readUint16(message, 4) !== 1 ||
    readUint16(message, 6) !== 0 ||
    readUint16(message, 8) !== 0 ||
    readUint16(message, 10) !== 1
  ) {
    throw new Error('The relay accepts one question and one OPT record only.');
  }
  if (readUint16(message, 0) !== 0) throw new Error('DNS query ID must be zero.');

  const budget: NameBudget = { operations: 0 };
  const question = parseQuestion(message, 12, budget, false, true);
  if (question.binding.classCode !== 1) throw new Error('DNS query class must be IN.');
  if (!SUPPORTED_QUERY_TYPES.has(question.binding.typeCode))
    throw new Error('DNS query type is not supported by ZoneSkein.');

  const optName = readDnsName(message, question.endOffset, budget, false, false);
  if (!equalBytes(optName.canonicalWire, new Uint8Array([0])))
    throw new Error('EDNS OPT owner must be the root name.');
  if (optName.endOffset + 10 > message.length) throw new Error('Truncated EDNS OPT record.');
  const typeCode = readUint16(message, optName.endOffset);
  const udpPayloadSize = readUint16(message, optName.endOffset + 2);
  const ttl = readUint32(message, optName.endOffset + 4);
  const dataLength = readUint16(message, optName.endOffset + 8);
  const dataStart = optName.endOffset + 10;
  const dataEnd = dataStart + dataLength;
  if (typeCode !== 41 || udpPayloadSize !== 1_232 || (ttl !== 0 && ttl !== 0x8000))
    throw new Error('EDNS OPT parameters do not match the ZoneSkein query profile.');
  if (dataEnd !== message.length)
    throw new Error('DNS query contains trailing or truncated data.');
  const paddingHeader = dataStart + EXPECTED_EDNS_CLIENT_SUBNET.length;
  if (
    !equalBytes(message.slice(dataStart, paddingHeader), EXPECTED_EDNS_CLIENT_SUBNET) ||
    paddingHeader + 4 > dataEnd ||
    readUint16(message, paddingHeader) !== EDNS_PADDING_OPTION_CODE
  ) {
    throw new Error('EDNS options do not match the zero-prefix privacy profile.');
  }
  const paddingLength = readUint16(message, paddingHeader + 2);
  const paddingStart = paddingHeader + 4;
  if (
    paddingLength > DNS_QUERY_PADDING_BLOCK_BYTES - 1 ||
    paddingStart + paddingLength !== dataEnd ||
    !message.slice(paddingStart, dataEnd).every((byte) => byte === 0)
  )
    throw new Error('EDNS padding does not match the ZoneSkein query profile.');
  return question.binding;
}

function validateRelayResponse(message: Uint8Array, question: QuestionBinding): void {
  if (message.length < 12) throw new Error('DNS response is shorter than its header.');
  if (readUint16(message, 0) !== 0) throw new Error('DNS response ID does not match.');
  const flags = readUint16(message, 2);
  if ((flags & 0x8000) === 0 || (flags & 0x7800) !== 0 || (flags & 0x0200) !== 0)
    throw new Error('DNS response flags are not permitted.');
  if ((flags & 0x0040) !== 0) throw new Error('DNS response reserved flag is set.');
  if (readUint16(message, 4) !== 1) throw new Error('DNS response must repeat one question.');
  const recordCount = readUint16(message, 6) + readUint16(message, 8) + readUint16(message, 10);
  if (recordCount > MAX_DNS_RECORDS) throw new Error('DNS response has too many records.');

  const budget: NameBudget = { operations: 0 };
  const responseQuestion = parseQuestion(message, 12, budget, true, false);
  if (
    responseQuestion.binding.classCode !== question.classCode ||
    responseQuestion.binding.typeCode !== question.typeCode ||
    !equalBytes(responseQuestion.binding.canonicalName, question.canonicalName)
  ) {
    throw new Error('DNS response question does not match the request.');
  }

  let offset = responseQuestion.endOffset;
  for (let index = 0; index < recordCount; index += 1) {
    const owner = readDnsName(message, offset, budget, true, false);
    offset = owner.endOffset;
    if (offset + 10 > message.length) throw new Error('Truncated DNS resource record.');
    const dataLength = readUint16(message, offset + 8);
    offset += 10 + dataLength;
    if (offset > message.length) throw new Error('DNS resource record exceeds the message.');
  }
  if (offset !== message.length) throw new Error('DNS response contains trailing data.');
}

function responseHeaders(contentType: string): Readonly<Record<string, string>> {
  return {
    'Cache-Control': 'no-store, max-age=0',
    'Content-Type': contentType,
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
  };
}

function errorResponse(
  status: number,
  message: string,
  additionalHeaders: Readonly<Record<string, string>> = {},
): Response {
  return new Response(message, {
    headers: { ...responseHeaders('text/plain; charset=utf-8'), ...additionalHeaders },
    status,
  });
}

function mediaType(value: string | null): string | null {
  return value?.split(';', 1)[0]?.trim().toLowerCase() ?? null;
}

async function boundedRequestBody(request: Request): Promise<Uint8Array> {
  const declaredLength = request.headers.get('Content-Length');
  let expectedLength: number | null = null;
  if (declaredLength !== null) {
    if (!/^\d+$/u.test(declaredLength))
      throw new RelayRequestError(400, 'The request Content-Length is invalid.');
    expectedLength = Number(declaredLength);
    if (expectedLength > MAX_RELAY_QUERY_BYTES)
      throw new RelayRequestError(413, 'The DNS query exceeds the relay size limit.');
  }
  const reader = request.body?.getReader();
  if (reader === undefined) throw new RelayRequestError(400, 'A DNS wire query is required.');
  const chunks: Uint8Array[] = [];
  let chunkCount = 0;
  let total = 0;
  try {
    for (let next = await reader.read(); !next.done; next = await reader.read()) {
      chunkCount += 1;
      total += next.value.byteLength;
      if (chunkCount > MAX_BODY_CHUNKS || total > MAX_RELAY_QUERY_BYTES) {
        try {
          await reader.cancel('DNS relay request exceeded its bounds.');
        } catch {
          // The original bound remains authoritative if cancellation also fails.
        }
        throw new RelayRequestError(413, 'The DNS query exceeds the relay size limit.');
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  if (total === 0) throw new RelayRequestError(400, 'A DNS wire query is required.');
  if (expectedLength !== null && expectedLength !== total)
    throw new RelayRequestError(400, 'The DNS query length does not match Content-Length.');
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

function headerText(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) return value[0] ?? null;
  return value ?? null;
}

export function forwardQuad9OverHttp2(
  query: Uint8Array,
  signal: AbortSignal,
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let stream: ClientHttp2Stream | undefined;
    let responseHeadersReceived = false;
    let responseLength: number | null = null;
    let total = 0;
    const chunks: Uint8Array[] = [];
    const session: ClientHttp2Session = connect(QUAD9_DOH_URL.origin, {
      ALPNProtocols: ['h2'],
      rejectUnauthorized: true,
      servername: QUAD9_DOH_URL.hostname,
    });

    const finish = (error: Error | null, value?: Uint8Array): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', abort);
      stream?.removeAllListeners();
      session.removeAllListeners();
      stream?.close(constants.NGHTTP2_CANCEL);
      session.destroy();
      if (error !== null) reject(error);
      else if (value !== undefined) resolve(value);
      else reject(new Error('Quad9 HTTP/2 request ended without a response.'));
    };
    const abort = (): void => {
      finish(new DOMException('The Quad9 request was aborted.', 'AbortError'));
    };
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) {
      abort();
      return;
    }

    session.once('error', (error: Error) => {
      finish(error);
    });
    session.once('connect', () => {
      if (session.alpnProtocol !== 'h2') {
        finish(new Error('Quad9 did not negotiate HTTP/2.'));
        return;
      }
      stream = session.request({
        ':method': 'POST',
        ':path': `${QUAD9_DOH_URL.pathname}${QUAD9_DOH_URL.search}`,
        Accept: DNS_MESSAGE_MEDIA_TYPE,
        'Content-Length': String(query.byteLength),
        'Content-Type': DNS_MESSAGE_MEDIA_TYPE,
      });
      stream.once('response', (headers: IncomingHttpHeaders) => {
        responseHeadersReceived = true;
        if (Number(headers[':status']) !== 200) {
          finish(new Error('Quad9 returned a non-success HTTP status.'));
          return;
        }
        if (mediaType(headerText(headers['content-type'])) !== DNS_MESSAGE_MEDIA_TYPE) {
          finish(new Error('Quad9 returned an unexpected media type.'));
          return;
        }
        const declaredLength = headerText(headers['content-length']);
        if (declaredLength !== null) {
          if (!/^\d+$/u.test(declaredLength)) {
            finish(new Error('Quad9 returned an invalid Content-Length.'));
            return;
          }
          responseLength = Number(declaredLength);
          if (responseLength > MAX_RELAY_RESPONSE_BYTES) {
            finish(new Error('Quad9 response exceeds the DNS message limit.'));
          }
        }
      });
      stream.on('data', (chunk: Uint8Array) => {
        total += chunk.byteLength;
        if (total > MAX_RELAY_RESPONSE_BYTES) {
          finish(new Error('Quad9 response exceeds the DNS message limit.'));
          return;
        }
        chunks.push(new Uint8Array(chunk));
      });
      stream.once('aborted', () => {
        finish(new Error('Quad9 aborted the HTTP/2 stream.'));
      });
      stream.once('error', (error: Error) => {
        finish(error);
      });
      stream.once('end', () => {
        if (!responseHeadersReceived) {
          finish(new Error('Quad9 response headers were not received.'));
          return;
        }
        if (responseLength !== null && responseLength !== total) {
          finish(new Error('Quad9 response length does not match Content-Length.'));
          return;
        }
        const response = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) {
          response.set(chunk, offset);
          offset += chunk.byteLength;
        }
        finish(null, response);
      });
      stream.end(query);
    });
  });
}

export function createQuad9RelayHandler(forward: Quad9Forwarder = forwardQuad9OverHttp2) {
  return async function quad9RelayHandler(request: Request): Promise<Response> {
    if (request.method !== 'POST')
      return errorResponse(405, 'Only POST DNS wire queries are accepted.', { Allow: 'POST' });
    const requestUrl = new URL(request.url);
    if (requestUrl.search !== '')
      return errorResponse(400, 'DNS relay request query strings are not accepted.');
    const requestOrigin = requestUrl.origin;
    const origin = request.headers.get('Origin');
    if (origin !== null && origin !== requestOrigin)
      return errorResponse(403, 'Cross-origin relay requests are not accepted.');
    if (request.headers.get('Sec-Fetch-Site') === 'cross-site')
      return errorResponse(403, 'Cross-origin relay requests are not accepted.');
    const contentEncoding = request.headers.get('Content-Encoding')?.trim().toLowerCase();
    if (contentEncoding !== undefined && contentEncoding !== 'identity')
      return errorResponse(415, 'Encoded request bodies are not accepted.');
    if (mediaType(request.headers.get('Content-Type')) !== DNS_MESSAGE_MEDIA_TYPE)
      return errorResponse(415, 'Content-Type must be application/dns-message.');

    let query: Uint8Array;
    let question: QuestionBinding;
    try {
      query = await boundedRequestBody(request);
      question = validateRelayQuery(query);
    } catch (error) {
      if (error instanceof RelayRequestError) return errorResponse(error.status, error.message);
      return errorResponse(
        400,
        error instanceof Error ? error.message : 'The DNS query is invalid.',
      );
    }

    const controller = new AbortController();
    const timeoutState = { expired: false };
    const timeout = setTimeout(() => {
      timeoutState.expired = true;
      controller.abort();
    }, QUAD9_RELAY_TIMEOUT_MS);
    const abort = (): void => {
      controller.abort();
    };
    request.signal.addEventListener('abort', abort, { once: true });
    try {
      const upstreamResponse = await forward(query, controller.signal);
      if (upstreamResponse.byteLength > MAX_RELAY_RESPONSE_BYTES)
        throw new Error('Quad9 response exceeds the DNS message limit.');
      validateRelayResponse(upstreamResponse, question);
      const body = new Uint8Array(upstreamResponse.byteLength);
      body.set(upstreamResponse);
      return new Response(body, {
        headers: {
          ...responseHeaders(DNS_MESSAGE_MEDIA_TYPE),
          'Content-Length': String(body.byteLength),
        },
        status: 200,
      });
    } catch {
      return timeoutState.expired
        ? errorResponse(504, 'The fixed Quad9 upstream timed out.')
        : errorResponse(502, 'The fixed Quad9 upstream did not return a valid DNS response.');
    } finally {
      clearTimeout(timeout);
      request.signal.removeEventListener('abort', abort);
    }
  };
}

export default createQuad9RelayHandler();
