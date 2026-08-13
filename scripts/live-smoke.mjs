import { DNSSEC_OK, decode, encode } from '@dnsquery/dns-packet';

const resolvers = [
  ['Google Public DNS', 'https://dns.google/dns-query', 'GET'],
  ['Cloudflare 1.1.1.1', 'https://cloudflare-dns.com/dns-query', 'POST'],
  ['Quad9', 'https://dns.quad9.net/dns-query', 'GET'],
];

const query = encode({
  additionals: [
    {
      flags: DNSSEC_OK,
      name: '.',
      options: [
        {
          code: 'CLIENT_SUBNET',
          family: 1,
          ip: '0.0.0.0',
          scopePrefixLength: 0,
          sourcePrefixLength: 0,
        },
      ],
      type: 'OPT',
      udpPayloadSize: 1232,
    },
  ],
  flags: 0x0100,
  id: 0,
  questions: [{ class: 'IN', name: 'example.com.', type: 'A' }],
  type: 'query',
});

const encodedQuery = Buffer.from(query).toString('base64url');
let failed = false;
for (const [label, endpoint, method] of resolvers) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8_000);
  try {
    const response = await fetch(
      method === 'GET' ? `${endpoint}?dns=${encodedQuery}` : endpoint,
      {
        ...(method === 'POST' ? { body: query } : {}),
        cache: 'no-store',
        credentials: 'omit',
        headers: {
          Accept: 'application/dns-message',
          ...(method === 'POST' ? { 'Content-Type': 'application/dns-message' } : {}),
          Origin: 'http://127.0.0.1:4173',
        },
        method,
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: controller.signal,
      },
    );
    const mediaType = response.headers.get('content-type')?.split(';')[0]?.trim();
    if (!response.ok || mediaType !== 'application/dns-message') {
      throw new Error(
        `unexpected HTTP response ${String(response.status)} (${mediaType ?? 'no media type'})`,
      );
    }
    if (response.headers.get('access-control-allow-origin') !== '*') {
      throw new Error('resolver response does not permit browser CORS');
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    const message = decode(bytes);
    if (message.type !== 'response') throw new Error('resolver returned a query packet');
    console.log(
      `${label}: ${method}, ${message.rcode ?? 'NOERROR'}, ${String(bytes.length)} bytes`,
    );
  } catch (cause) {
    failed = true;
    console.error(`${label}: ${cause instanceof Error ? cause.message : 'request failed'}`);
  } finally {
    clearTimeout(timeout);
  }
}

if (failed) process.exitCode = 1;
