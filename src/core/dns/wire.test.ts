import { encode, type Packet } from '@dnsquery/dns-packet';
import { describe, expect, it } from 'vitest';

import { validateDnsName } from './names';
import { decodeDnsMessage, encodeDnsQuery } from './wire';

function name(value: string) {
  const result = validateDnsName(value);
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
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

  it('rejects malformed and non-response messages', () => {
    expect(() => decodeDnsMessage(new Uint8Array([0, 1]))).toThrow(/shorter/);
    const query = encode({
      id: 0,
      questions: [{ name: 'example.com.', type: 'A' }],
      type: 'query',
    });
    expect(() => decodeDnsMessage(query)).toThrow(/query instead/);
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
      { code: 6, name: 'DNSSEC Bogus', text: 'validation failed' },
    ]);
    expect(result.additionals[0]?.data).toEqual(
      expect.objectContaining({ udpPayloadSize: 1232 }),
    );
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
