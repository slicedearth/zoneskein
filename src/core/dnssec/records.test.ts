import { describe, expect, it } from 'vitest';

import type { DnsRecord } from '../dns/types';
import { parseRrsig, signatureTimeState } from './records';

function signature(inception: number, expiration: number): DnsRecord {
  return {
    class: 'IN',
    data: {
      algorithm: 8,
      expiration,
      inception,
      keyTag: 1,
      labels: 1,
      originalTTL: 300,
      signature: new Uint8Array([1]),
      signersName: 'example.',
      typeCovered: 'DNSKEY',
    },
    owner: 'example.',
    rawRdata: new Uint8Array(),
    section: 'answer',
    ttl: 300,
    type: 'RRSIG',
    typeCode: 46,
  };
}

describe('RRSIG serial-time intervals', () => {
  it.each([
    ['a zero-length interval', 100, 100],
    ['an exactly half-range interval', 100, (100 + 0x8000_0000) >>> 0],
    ['an interval longer than half the serial space', 100, 99],
  ])('rejects %s as ambiguous', (_, inception, expiration) => {
    expect(signatureTimeState(inception, expiration, inception)).toBeNull();
    expect(parseRrsig(signature(inception, expiration), inception)).toBeNull();
  });

  it('accepts a short interval that crosses the 32-bit serial origin', () => {
    expect(signatureTimeState(0xffff_fff0, 0x20, 0x10)).toBe('current');
    expect(parseRrsig(signature(0xffff_fff0, 0x20), 0x10)?.timeState).toBe('current');
  });
});
