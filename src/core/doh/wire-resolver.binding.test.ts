import { encode, type Packet } from '@dnsquery/dns-packet';
import { describe, expect, it, vi } from 'vitest';

import { validateDnsName } from '../dns/names';
import { DnsMemoryCache } from './cache';
import { resolverById } from './resolvers';
import { Semaphore } from './semaphore';
import { WireDnsResolver } from './wire-resolver';

function question(value = 'example.com') {
  const parsed = validateDnsName(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return { name: parsed.value, type: 'A' as const };
}

function packet(overrides: Partial<Packet> = {}): Packet {
  return {
    answers: [{ class: 'IN', data: '192.0.2.1', name: 'example.com.', ttl: 60, type: 'A' }],
    flags: 0x8180,
    id: 0,
    questions: [{ class: 'IN', name: 'example.com.', type: 'A' }],
    type: 'response',
    ...overrides,
  };
}

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const output = new ArrayBuffer(bytes.length);
  new Uint8Array(output).set(bytes);
  return output;
}

function wireResponse(value: Packet): Response {
  return new Response(arrayBuffer(encode(value)), {
    headers: { 'Content-Type': 'application/dns-message' },
  });
}

function rawWireResponse(bytes: Uint8Array): Response {
  return new Response(arrayBuffer(bytes), {
    headers: { 'Content-Type': 'application/dns-message' },
  });
}

function resolver(response: Response) {
  const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(response);
  return new WireDnsResolver(resolverById('google'), {
    cache: new DnsMemoryCache(),
    fetch: fetchMock,
    limiter: { wait: vi.fn(), imposeCooldown: vi.fn() } as never,
    semaphore: new Semaphore(4),
  });
}

async function expectInvalidResponse(response: Response, dnsQuestion = question()) {
  await expect(
    resolver(response).query(dnsQuestion, { checkingDisabled: true, dnssecOk: true }),
  ).rejects.toMatchObject({ code: 'invalid-response' });
}

describe('wire DoH response binding', () => {
  it.each([
    ['a non-zero transaction ID', packet({ id: 1 })],
    [
      'a different question name',
      packet({ questions: [{ class: 'IN', name: 'elsewhere.example.', type: 'A' }] }),
    ],
    [
      'a different question type',
      packet({ questions: [{ class: 'IN', name: 'example.com.', type: 'AAAA' }] }),
    ],
    [
      'a different question class',
      packet({ questions: [{ class: 'CH', name: 'example.com.', type: 'A' }] }),
    ],
    ['no decoded question', packet({ questions: [] })],
    [
      'more than one decoded question',
      packet({
        questions: [
          { class: 'IN', name: 'example.com.', type: 'A' },
          { class: 'IN', name: 'elsewhere.example.', type: 'A' },
        ],
      }),
    ],
  ])('rejects %s', async (_, value) => {
    await expectInvalidResponse(wireResponse(value));
  });

  it('rejects a response carrying the TC flag', async () => {
    await expectInvalidResponse(wireResponse(packet({ flags: 0x8380 })));
  });

  it('rejects a lax UTF-8 question collision at the raw-wire boundary', async () => {
    const bytes = Uint8Array.from([
      0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 8, 0xc1, 0xa5, 0x78, 0x61, 0x6d, 0x70, 0x6c,
      0x65, 3, 0x63, 0x6f, 0x6d, 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192,
      0, 2, 1,
    ]);

    await expectInvalidResponse(rawWireResponse(bytes));
  });

  it('rejects a dot inside one raw question label that resembles two labels', async () => {
    const label = [...new TextEncoder().encode('example.com')];
    const bytes = Uint8Array.from([
      0,
      0,
      0x81,
      0x80,
      0,
      1,
      0,
      0,
      0,
      0,
      0,
      0,
      label.length,
      ...label,
      0,
      0,
      1,
      0,
      1,
    ]);

    await expectInvalidResponse(rawWireResponse(bytes));
  });

  it('accepts a valid IDNA A-label question using exact wire binding', async () => {
    const value = packet({
      answers: [
        {
          class: 'IN',
          data: '192.0.2.1',
          name: 'xn--bcher-kva.example.',
          ttl: 60,
          type: 'A',
        },
      ],
      questions: [{ class: 'IN', name: 'xn--bcher-kva.example.', type: 'A' }],
    });

    await expect(
      resolver(wireResponse(value)).query(question('bücher.example'), {
        checkingDisabled: true,
        dnssecOk: true,
      }),
    ).resolves.toMatchObject({ message: { responseCode: 'NOERROR' } });
  });

  it.each([
    ['question', 4, 2],
    ['answer', 6, 2],
    ['answer', 6, 0],
    ['authority', 8, 1],
    ['additional', 10, 1],
  ])('rejects a malformed declared %s count of %i', async (_, offset, count) => {
    const bytes = encode(packet());
    bytes[offset] = count >>> 8;
    bytes[offset + 1] = count & 0xff;
    await expectInvalidResponse(
      new Response(arrayBuffer(bytes), {
        headers: { 'Content-Type': 'application/dns-message' },
      }),
    );
  });

  it('rejects an oversized declared body before reading it', async () => {
    const response = wireResponse(packet());
    response.headers.set('Content-Length', '65536');
    const read = vi.spyOn(response, 'arrayBuffer');

    await expectInvalidResponse(response);
    expect(read).not.toHaveBeenCalled();
  });

  it('bounds an oversized streamed body instead of materialising it with arrayBuffer', async () => {
    const chunks = [new Uint8Array(32_768), new Uint8Array(32_768), new Uint8Array(32_768)];
    let index = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        const chunk = chunks[index];
        index += 1;
        if (chunk === undefined) controller.close();
        else controller.enqueue(chunk);
      },
    });
    const response = new Response(body, {
      headers: { 'Content-Type': 'application/dns-message' },
    });
    const read = vi.spyOn(response, 'arrayBuffer');

    await expectInvalidResponse(response);
    expect(read).not.toHaveBeenCalled();
  });
});
