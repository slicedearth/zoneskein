import { describe, expect, it } from 'vitest';

import { reverseNameFromAddress } from './reverse';

describe('reverse DNS names', () => {
  it('creates IPv4 and IPv6 reverse names', () => {
    expect(reverseNameFromAddress('192.0.2.5')).toMatchObject({
      ok: true,
      value: { family: 4, name: '5.2.0.192.in-addr.arpa.' },
    });
    const ipv6 = reverseNameFromAddress('2001:db8::1');
    expect(ipv6.ok).toBe(true);
    if (ipv6.ok) {
      expect(ipv6.value.family).toBe(6);
      expect(ipv6.value.name).toMatch(/ip6\.arpa\.$/);
    }
  });

  it('rejects non-address input', () => {
    expect(reverseNameFromAddress('example.com')).toEqual({
      error: 'Enter a valid IPv4 or IPv6 address.',
      ok: false,
    });
  });

  it.each(['127.1', '010.0.0.1', '0x7f000001', 'fe80::1%eth0'])(
    'rejects ambiguous or scoped address input %s',
    (address) => {
      expect(reverseNameFromAddress(address)).toMatchObject({ ok: false });
    },
  );
});
