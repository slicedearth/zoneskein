import { encode } from '@dnsquery/dns-packet';
import { describe, expect, it } from 'vitest';

import { decodeDnsMessage } from './wire';

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
});
