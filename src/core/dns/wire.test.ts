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
});
