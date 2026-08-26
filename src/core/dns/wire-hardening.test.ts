import { encode } from '@dnsquery/dns-packet';
import { describe, expect, it } from 'vitest';

import { recordDataText } from './presentation';
import { decodeDnsMessage } from './wire';

function concat(...parts: readonly (readonly number[] | Uint8Array)[]): Uint8Array {
  return Uint8Array.from(parts.flatMap((part) => [...part]));
}

function ascii(value: string): readonly number[] {
  return [...new TextEncoder().encode(value)];
}

function name(value: string): readonly number[] {
  return value
    .split('.')
    .flatMap((label) => [label.length, ...ascii(label)])
    .concat(0);
}

function rawResponse(
  questionName: readonly number[],
  answer?: {
    readonly data: readonly number[];
    readonly owner: readonly number[];
    readonly type: number;
  },
): Uint8Array {
  return concat(
    [0, 0, 0x81, 0x80, 0, 1, 0, answer === undefined ? 0 : 1, 0, 0, 0, 0],
    questionName,
    [0, 1, 0, 1],
    answer === undefined
      ? []
      : [
          ...answer.owner,
          answer.type >>> 8,
          answer.type & 0xff,
          0,
          1,
          0,
          0,
          0,
          60,
          answer.data.length >>> 8,
          answer.data.length & 0xff,
          ...answer.data,
        ],
  );
}

describe('DNS wire hardening', () => {
  it('combines the EDNS upper RCODE octet with the header RCODE nibble', () => {
    const bytes = encode({
      additionals: [
        {
          extendedRcode: 1,
          name: '.',
          type: 'OPT',
          udpPayloadSize: 1232,
        } as never,
      ],
      flags: 0x8183,
      id: 0,
      questions: [{ class: 'IN', name: 'example.com.', type: 'A' }],
      type: 'response',
    });

    const message = decodeDnsMessage(bytes);

    expect(message.edns?.extendedResponseCode).toBe(1);
    expect(message.responseCode).toBe('EXTENDED_RCODE_19');
  });

  it('keeps hostile owner octets distinct from their lax UTF-8 rendering', () => {
    const bytes = rawResponse(name('example.com'), {
      data: [192, 0, 2, 1],
      // C1 A5 is an overlong encoding that the dependency decoder renders as "e".
      owner: [8, 0xc1, 0xa5, ...ascii('xample'), 3, ...ascii('com'), 0],
      type: 1,
    });

    const message = decodeDnsMessage(bytes);

    expect(message.answers[0]?.owner).toBe('\\193\\165xample.com');
    expect(message.answers[0]?.owner).not.toBe(message.questions[0]?.name);
    expect(message.answers[0]?.canonicalOwnerWire).toEqual(
      Uint8Array.from([8, 0xc1, 0xa5, ...ascii('xample'), 3, ...ascii('com'), 0]),
    );
  });

  it('escapes an in-label dot in an alias target instead of treating it as a separator', () => {
    const bytes = rawResponse(name('example.com'), {
      data: [11, ...ascii('target.test'), 0],
      owner: [0xc0, 0x0c],
      type: 5,
    });

    expect(decodeDnsMessage(bytes).answers[0]?.data).toBe('target\\046test');
  });

  it('escapes URL delimiters before a policy binder can reinterpret the presentation', () => {
    const bytes = rawResponse(name('example.com'), {
      data: [14, ...ascii('target?ignored'), 0],
      owner: [0xc0, 0x0c],
      type: 5,
    });

    expect(decodeDnsMessage(bytes).answers[0]?.data).toBe('target\\063ignored');
  });

  it('accepts valid backward compression while preserving canonical wire names', () => {
    const bytes = rawResponse(name('example.com'), {
      data: [0xc0, 0x0c],
      owner: [0xc0, 0x0c],
      type: 5,
    });
    const message = decodeDnsMessage(bytes);

    expect(message.answers[0]?.data).toBe('example.com');
    expect(message.answers[0]?.canonicalOwnerWire).toEqual(
      Uint8Array.from(name('example.com')),
    );
  });

  it('preserves master-file field order for reparsed name-bearing data', () => {
    const message = decodeDnsMessage(
      encode({
        answers: [
          {
            class: 'IN',
            data: { exchange: 'mail.example.', preference: 10 },
            name: 'example.',
            ttl: 60,
            type: 'MX',
          },
          {
            class: 'IN',
            data: { port: 443, priority: 1, target: 'service.example.', weight: 2 },
            name: '_service._tcp.example.',
            ttl: 60,
            type: 'SRV',
          },
        ],
        authorities: [
          {
            class: 'IN',
            data: {
              expire: 86_400,
              minimum: 300,
              mname: 'ns.example.',
              refresh: 3_600,
              retry: 600,
              rname: 'hostmaster.example.',
              serial: 1,
            },
            name: 'example.',
            ttl: 60,
            type: 'SOA',
          },
        ],
        flags: 0x8180,
        id: 0,
        questions: [{ class: 'IN', name: 'example.', type: 'MX' }],
        type: 'response',
      }),
    );

    const mx = message.answers[0];
    const srv = message.answers[1];
    const soa = message.authorities[0];
    if (mx === undefined || srv === undefined || soa === undefined)
      throw new Error('Structured record fixture did not decode completely.');
    expect(recordDataText(mx)).toBe('10 mail.example.');
    expect(recordDataText(srv)).toBe('1 2 443 service.example.');
    expect(recordDataText(soa)).toBe('ns.example. hostmaster.example. 1 3600 600 86400 300');
  });

  it('rejects forward compression pointers and overlong expanded names', () => {
    expect(() => decodeDnsMessage(rawResponse([0xc0, 0x0e]))).toThrow(/pointer/iu);
    const overlong = [
      ...Array.from({ length: 4 }, (_, index) => [
        63,
        ...ascii(String(index).repeat(63)),
      ]).flat(),
      0,
    ];
    expect(() => decodeDnsMessage(rawResponse(overlong))).toThrow(/too long/iu);
  });

  it('bounds compression-pointer expansion work', () => {
    const question = name('example.com');
    const firstOwner = [0xc0, 0x0c];
    const firstHeader = [...firstOwner, 0xff, 0, 0, 1, 0, 0, 0, 60];
    const rdataStart = 12 + question.length + 4 + firstHeader.length + 2;
    const chain: number[] = [0];
    const pointerOffsets: number[] = [];
    for (let index = 0; index < 129; index += 1) {
      const target = index === 0 ? rdataStart : pointerOffsets[index - 1];
      if (target === undefined) throw new Error('Compression fixture target is missing.');
      pointerOffsets.push(rdataStart + chain.length);
      chain.push(0xc0 | (target >>> 8), target & 0xff);
    }
    const lastPointer = pointerOffsets.at(-1);
    if (lastPointer === undefined) throw new Error('Compression fixture pointer is missing.');
    const second = [
      0xc0 | (lastPointer >>> 8),
      lastPointer & 0xff,
      0,
      1,
      0,
      1,
      0,
      0,
      0,
      60,
      0,
      4,
      192,
      0,
      2,
      1,
    ];
    const bytes = concat(
      [0, 0, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0],
      question,
      [0, 1, 0, 1],
      firstHeader,
      [chain.length >>> 8, chain.length & 0xff],
      chain,
      second,
    );

    expect(() => decodeDnsMessage(bytes)).toThrow(/compression-pointer limit/iu);
  });

  it('bounds aggregate name-decoding work across the whole message', () => {
    const question = name('example.com');
    const firstOwner = [0xc0, 0x0c];
    const firstHeader = [...firstOwner, 0xff, 0, 0, 1, 0, 0, 0, 60];
    const rdataStart = 12 + question.length + 4 + firstHeader.length + 2;
    const chain: number[] = [0];
    const pointerOffsets: number[] = [];
    for (let index = 0; index < 120; index += 1) {
      const target = index === 0 ? rdataStart : pointerOffsets[index - 1];
      if (target === undefined) throw new Error('Compression fixture target is missing.');
      pointerOffsets.push(rdataStart + chain.length);
      chain.push(0xc0 | (target >>> 8), target & 0xff);
    }
    const lastPointer = pointerOffsets.at(-1);
    if (lastPointer === undefined) throw new Error('Compression fixture pointer is missing.');
    const repeatedRecord = [
      0xc0 | (lastPointer >>> 8),
      lastPointer & 0xff,
      0,
      1,
      0,
      1,
      0,
      0,
      0,
      60,
      0,
      4,
      192,
      0,
      2,
      1,
    ];
    const repeatedCount = 550;
    const answerCount = repeatedCount + 1;
    const bytes = concat(
      [0, 0, 0x81, 0x80, 0, 1, answerCount >>> 8, answerCount & 0xff, 0, 0, 0, 0],
      question,
      [0, 1, 0, 1],
      firstHeader,
      [chain.length >>> 8, chain.length & 0xff],
      chain,
      Array.from({ length: repeatedCount }, () => repeatedRecord).flat(),
    );

    expect(() => decodeDnsMessage(bytes)).toThrow(/aggregate name-decoding work/iu);
  });

  it('rejects bytes outside the declared DNS message structure', () => {
    expect(() => decodeDnsMessage(concat(rawResponse(name('example.com')), [0]))).toThrow(
      /trailing bytes/iu,
    );
  });

  it.each([
    ['A', 1, [192, 0, 2]],
    ['A', 1, [192, 0, 2, 1, 99]],
    ['AAAA', 28, new Array(15).fill(0)],
    ['AAAA', 28, new Array(17).fill(0)],
  ])('rejects %s RDATA that does not have its exact wire length', (_type, type, data) => {
    const bytes = rawResponse(name('example.com'), {
      data,
      owner: [0xc0, 0x0c],
      type,
    });

    expect(() => decodeDnsMessage(bytes)).toThrow(/RDATA/iu);
  });

  it('rebuilds CAA policy fields from bounded wire octets', () => {
    const bytes = rawResponse(name('example.com'), {
      data: [0x80, 5, ...ascii('issue'), ...ascii('ca.example')],
      owner: [0xc0, 0x0c],
      type: 257,
    });

    expect(decodeDnsMessage(bytes).answers[0]?.data).toEqual({
      flags: 128,
      issuerCritical: true,
      tag: 'issue',
      value: 'ca.example',
    });
  });

  it('rejects a CAA tag length that crosses the declared RDATA boundary', () => {
    const bytes = rawResponse(name('example.com'), {
      data: [0, 8, ...ascii('issue')],
      owner: [0xc0, 0x0c],
      type: 257,
    });

    expect(() => decodeDnsMessage(bytes)).toThrow(/CAA RDATA/iu);
  });

  it('keeps escaped and non-ASCII CAA value octets distinguishable', () => {
    const caa = (value: readonly number[]) =>
      decodeDnsMessage(
        rawResponse(name('example.com'), {
          data: [0, 5, ...ascii('issue'), ...value],
          owner: [0xc0, 0x0c],
          type: 257,
        }),
      ).answers[0]?.data as { readonly value: string };

    expect(caa(ascii('\\128')).value).toBe('\\092128');
    expect(caa([128]).value).toBe('\\128');
  });
});
