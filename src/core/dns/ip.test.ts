import { describe, expect, it } from 'vitest';

import { normaliseStrictIpAddress, parseStrictIpAddress, processStrictIpAddress } from './ip';

describe('strict IP address grammar', () => {
  it('accepts canonical decimal IPv4 and standards-conforming IPv6 text', () => {
    expect(normaliseStrictIpAddress('192.0.2.10')).toBe('192.0.2.10');
    expect(normaliseStrictIpAddress('2001:0db8::1')).toBe('2001:db8:0:0:0:0:0:1');
    expect(parseStrictIpAddress('::ffff:192.0.2.10')?.kind()).toBe('ipv6');
    expect(processStrictIpAddress('::ffff:192.0.2.10')?.kind()).toBe('ipv4');
  });

  it.each(['127.1', '0x7f000001', '010.0.0.1', '192.168.001.1', 'fe80::1%eth0'])(
    'rejects non-canonical or scoped input %s',
    (value) => {
      expect(parseStrictIpAddress(value)).toBeNull();
      expect(normaliseStrictIpAddress(value)).toBeNull();
    },
  );

  it('rejects ambiguous embedded IPv4 while accepting its canonical form', () => {
    expect(parseStrictIpAddress('::ffff:192.168.001.1')).toBeNull();
    expect(parseStrictIpAddress('::ffff:192.168.1.1')?.kind()).toBe('ipv6');
  });
});
