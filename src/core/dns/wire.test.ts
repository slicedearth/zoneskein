import { DNSSEC_OK, decode, encode, type Packet } from '@dnsquery/dns-packet';
import { describe, expect, it } from 'vitest';

import { validateDnsName } from './names';
import { decodeDnsMessage, DNS_QUERY_PADDING_BLOCK_BYTES, encodeDnsQuery } from './wire';

function name(value: string) {
  const result = validateDnsName(value);
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

interface DecodedOpt {
  readonly flags?: number;
  readonly options?: readonly DecodedOption[];
  readonly type: 'OPT';
  readonly udpPayloadSize?: number;
}

interface DecodedOption {
  readonly code?: number | string;
  readonly data?: Uint8Array;
  readonly family?: number;
  readonly ip?: string;
  readonly scopePrefixLength?: number;
  readonly sourcePrefixLength?: number;
  readonly type?: string;
}

function queryOpt(bytes: Uint8Array): DecodedOpt {
  const answer = decode(bytes).additionals?.find((item) => item.type === 'OPT');
  if (answer === undefined) throw new Error('Expected one OPT record.');
  return answer;
}

function expectZeroPrefixEcs(opt: DecodedOpt): void {
  const clientSubnet = opt.options?.find(
    (option) => option.code === 8 || option.type === 'CLIENT_SUBNET',
  );
  expect(opt.udpPayloadSize).toBe(1232);
  expect(clientSubnet?.family).toBe(1);
  expect(clientSubnet?.ip).toBe('0.0.0.0');
  expect(clientSubnet?.scopePrefixLength).toBe(0);
  expect(clientSubnet?.sourcePrefixLength).toBe(0);
}

function expectQueryPadding(bytes: Uint8Array, opt: DecodedOpt): void {
  const padding = opt.options?.filter(
    (option) => option.code === 12 || option.type === 'PADDING',
  );
  expect(bytes.length % DNS_QUERY_PADDING_BLOCK_BYTES).toBe(0);
  expect(padding).toHaveLength(1);
  expect(padding?.[0]?.data).toBeInstanceOf(Uint8Array);
  expect(padding?.[0]?.data?.every((byte) => byte === 0)).toBe(true);
}

describe('DNS wire messages', () => {
  it('encodes a zero-ID DNSSEC query without ANY', () => {
    const bytes = encodeDnsQuery(
      { name: name('example.com'), type: 'DNSKEY' },
      { checkingDisabled: true, dnssecOk: true },
    );

    expect(bytes[0]).toBe(0);
    expect(bytes[1]).toBe(0);
    expect(bytes.length).toBeGreaterThan(40);
    expect(bytes.length).toBeLessThan(512);
    const opt = queryOpt(bytes);
    expect((opt.flags ?? 0) & DNSSEC_OK).toBe(DNSSEC_OK);
    expectZeroPrefixEcs(opt);
    expectQueryPadding(bytes, opt);
  });

  it('adds zero-prefix ECS without setting DO on an SPF-style query', () => {
    const bytes = encodeDnsQuery(
      { name: name('sender.example'), type: 'TXT' },
      { checkingDisabled: false, dnssecOk: false },
    );
    const opt = queryOpt(bytes);

    expect((opt.flags ?? 0) & DNSSEC_OK).toBe(0);
    expectZeroPrefixEcs(opt);
    expectQueryPadding(bytes, opt);
  });

  it('encodes an authoritative-style numeric question with recursion disabled', () => {
    const bytes = encodeDnsQuery(
      { name: name('resolver.arpa'), type: 'TYPE261' },
      { checkingDisabled: false, dnssecOk: false, recursionDesired: false },
    );
    const packet = decode(bytes);

    expect((bytes[2] ?? 0) & 0x01).toBe(0);
    expect(packet.questions?.[0]?.type).toBe('UNKNOWN_261');
  });

  it('pads different valid query lengths to 128-octet blocks', () => {
    const questions = [
      { name: name('a.test'), type: 'A' as const },
      {
        name: name(`${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.example`),
        type: 'TXT' as const,
      },
    ];

    for (const question of questions) {
      const bytes = encodeDnsQuery(question, { checkingDisabled: false, dnssecOk: false });
      expectQueryPadding(bytes, queryOpt(bytes));
    }
  });

  it('decodes flags, exact wire size, TXT chunks, and raw RDATA', () => {
    const packet: Packet = {
      answers: [
        {
          class: 'IN',
          data: ['v=spf1 ', '-all'],
          name: 'example.com.',
          ttl: 300,
          type: 'TXT',
        },
      ],
      flags: 0x8180,
      id: 0,
      questions: [{ class: 'IN', name: 'example.com.', type: 'TXT' }],
      type: 'response',
    };
    const bytes = encode(packet);
    const result = decodeDnsMessage(bytes);

    expect(result.messageBytes).toBe(bytes.length);
    expect(result.flags.recursionAvailable).toBe(true);
    expect(result.answers[0]?.rawRdata.length).toBeGreaterThan(0);
    expect(result.answers[0]?.data).toHaveLength(2);
  });

  it('encodes and decodes the numeric wire type used for complete-zone digests', () => {
    const query = encodeDnsQuery(
      { name: name('example.com'), type: 'ZONEMD' },
      { checkingDisabled: true, dnssecOk: true },
    );
    expect(decode(query).questions?.[0]?.type).toBe('UNKNOWN_63');

    const rdata = Uint8Array.from([0, 0, 0, 1, 1, 1, ...new Uint8Array(48).fill(0xaa)]);
    const response = encode({
      answers: [
        {
          class: 'IN',
          data: rdata,
          name: 'example.com.',
          ttl: 300,
          type: 'UNKNOWN_63',
        } as never,
      ],
      flags: 0x8180,
      id: 0,
      questions: [{ class: 'IN', name: 'example.com.', type: 'UNKNOWN_63' }],
      type: 'response',
    });
    const message = decodeDnsMessage(response);
    expect(message.questions[0]?.type).toBe('ZONEMD');
    expect(message.answers[0]).toMatchObject({ type: 'ZONEMD', typeCode: 63 });
    expect(message.answers[0]?.rawRdata).toEqual(rdata);
  });

  it('rejects malformed and non-response messages', () => {
    expect(() => decodeDnsMessage(new Uint8Array([0, 1]))).toThrow(/shorter/);
    const query = encode({
      id: 0,
      questions: [{ name: 'example.com.', type: 'A' }],
      type: 'query',
    });
    expect(() => decodeDnsMessage(query)).toThrow(/query instead/);
  });

  it('rejects response shapes that exceed semantic allocation budgets', () => {
    const twoQuestions = encode({
      flags: 0x8180,
      id: 0,
      questions: [
        { class: 'IN', name: 'example.com.', type: 'A' },
        { class: 'IN', name: 'example.net.', type: 'A' },
      ],
      type: 'response',
    });
    expect(() => decodeDnsMessage(twoQuestions)).toThrow(/exactly one question/iu);

    const tooManyRecords = encode({
      answers: Array.from({ length: 513 }, () => ({
        class: 'IN' as const,
        data: '192.0.2.1',
        name: 'example.com.',
        ttl: 60,
        type: 'A' as const,
      })),
      flags: 0x8180,
      id: 0,
      questions: [{ class: 'IN', name: 'example.com.', type: 'A' }],
      type: 'response',
    });
    expect(() => decodeDnsMessage(tooManyRecords)).toThrow(/512-record safety limit/iu);

    const tooManyTxtChunks = encode({
      answers: [
        {
          class: 'IN',
          data: Array.from({ length: 257 }, () => ''),
          name: 'example.com.',
          ttl: 60,
          type: 'TXT',
        },
      ],
      flags: 0x8180,
      id: 0,
      questions: [{ class: 'IN', name: 'example.com.', type: 'TXT' }],
      type: 'response',
    });
    expect(() => decodeDnsMessage(tooManyTxtChunks)).toThrow(/256-chunk safety limit/iu);

    const tooManyOptions = encode({
      additionals: [
        {
          class: 'IN',
          name: '.',
          options: Array.from({ length: 257 }, () => ({ code: 'PADDING', length: 0 })),
          type: 'OPT',
          udpPayloadSize: 1232,
        } as never,
      ],
      flags: 0x8180,
      id: 0,
      questions: [{ class: 'IN', name: 'example.com.', type: 'A' }],
      type: 'response',
    });
    expect(() => decodeDnsMessage(tooManyOptions)).toThrow(/256-option safety limit/iu);

    const typeBitmap = Uint8Array.from([
      0,
      32,
      ...new Uint8Array(32).fill(0xff),
      1,
      32,
      ...new Uint8Array(32).fill(0xff),
      2,
      1,
      0x80,
    ]);
    const nsecRdata = Uint8Array.from([0, ...typeBitmap]);
    const excessiveTypeBitmap = Uint8Array.from([
      0,
      0,
      0x81,
      0x80,
      0,
      1,
      0,
      1,
      0,
      0,
      0,
      0,
      0,
      0,
      47,
      0,
      1,
      0xc0,
      0x0c,
      0,
      47,
      0,
      1,
      0,
      0,
      0,
      60,
      nsecRdata.length >>> 8,
      nsecRdata.length & 0xff,
      ...nsecRdata,
    ]);
    expect(() => decodeDnsMessage(excessiveTypeBitmap)).toThrow(/512-type safety limit/iu);
  });

  it('decodes extended DNS errors from EDNS options', () => {
    const text = new TextEncoder().encode('validation failed');
    const data = new Uint8Array(2 + text.length);
    data[1] = 6;
    data.set(text, 2);
    const bytes = encode({
      additionals: [
        {
          class: 'IN',
          name: '.',
          options: [{ code: 'PADDING', length: data.length }],
          type: 'OPT',
          udpPayloadSize: 1232,
        } as never,
      ],
      flags: 0x8182,
      id: 0,
      questions: [{ class: 'IN', name: 'broken.example.', type: 'A' }],
      type: 'response',
    });
    const optionOffset = bytes.length - data.length - 4;
    bytes[optionOffset] = 0;
    bytes[optionOffset + 1] = 15;
    bytes.set(data, optionOffset + 4);
    const result = decodeDnsMessage(bytes);
    expect(result.edns?.extendedErrors).toEqual([
      {
        code: 6,
        name: 'DNSSEC Bogus',
        rawText: {
          encoding: 'base64',
          octets: 17,
          value: 'dmFsaWRhdGlvbiBmYWlsZWQ=',
        },
        text: 'validation failed',
        textEncoding: 'utf-8',
      },
    ]);
    expect(result.additionals[0]?.data).toEqual(
      expect.objectContaining({ udpPayloadSize: 1232 }),
    );
  });

  it('preserves and visibly escapes hostile or malformed extended-error text bytes', () => {
    const assertText = (text: Uint8Array, display: string, encoding: 'binary' | 'utf-8') => {
      const data = new Uint8Array(2 + text.length);
      data[1] = 6;
      data.set(text, 2);
      const bytes = encode({
        additionals: [
          {
            class: 'IN',
            name: '.',
            options: [{ code: 'PADDING', length: data.length }],
            type: 'OPT',
            udpPayloadSize: 1232,
          } as never,
        ],
        flags: 0x8182,
        id: 0,
        questions: [{ class: 'IN', name: 'broken.example.', type: 'A' }],
        type: 'response',
      });
      const optionOffset = bytes.length - data.length - 4;
      bytes[optionOffset] = 0;
      bytes[optionOffset + 1] = 15;
      bytes.set(data, optionOffset + 4);
      const error = decodeDnsMessage(bytes).edns?.extendedErrors[0];
      expect(error).toMatchObject({
        rawText: { encoding: 'base64', octets: text.length },
        text: display,
        textEncoding: encoding,
      });
    };

    assertText(
      new TextEncoder().encode('bad\u0000\u202e\u2066\u2028text'),
      'bad\\u{0000}\\u{202E}\\u{2066}\\u{2028}text',
      'utf-8',
    );
    assertText(Uint8Array.from([0x66, 0x80]), '\\x66\\x80', 'binary');
    assertText(Uint8Array.from([0x66, 0x81]), '\\x66\\x81', 'binary');
  });

  it('derives the negative cache TTL from the SOA TTL and minimum', () => {
    const bytes = encode({
      authorities: [
        {
          class: 'IN',
          data: {
            expire: 604800,
            minimum: 300,
            mname: 'ns1.example.',
            refresh: 3600,
            retry: 600,
            rname: 'hostmaster.example.',
            serial: 1,
          },
          name: 'example.',
          ttl: 900,
          type: 'SOA',
        },
      ],
      flags: 0x8183,
      id: 0,
      questions: [{ class: 'IN', name: 'missing.example.', type: 'A' }],
      type: 'response',
    });
    expect(decodeDnsMessage(bytes).negativeCacheTtl).toBe(300);
  });
});
