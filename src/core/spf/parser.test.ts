import { describe, expect, it } from 'vitest';

import { parseSpfRecord } from './parser';

describe('SPF parser', () => {
  it('preserves order, qualifiers, dual CIDRs, and locations', () => {
    const policy = parseSpfRecord(
      'v=spf1 ip4:192.0.2.0/24 a:mail.example/28//64 -include:blocked.example ~all',
      'example.com',
    );
    expect(policy.terms.map((term) => term.original)).toEqual([
      'ip4:192.0.2.0/24',
      'a:mail.example/28//64',
      '-include:blocked.example',
      '~all',
    ]);
    expect(policy.terms[1]).toMatchObject({
      cidr: { ipv4: 28, ipv6: 64 },
      kind: 'mechanism',
      qualifier: '+',
    });
    expect(policy.terms[2]).toMatchObject({ kind: 'mechanism', qualifier: '-' });
    expect(policy.terms[0]).toMatchObject({ cidr: { ipv4: 24 } });
  });

  it('assigns CIDR lengths by mechanism family', () => {
    const policy = parseSpfRecord(
      'v=spf1 ip4:192.0.2.0/16 ip6:2001:db8::/32 a//64 mx:mail.example/24//96 -all',
      'example.com',
    );

    expect(policy.terms[0]).toMatchObject({ cidr: { ipv4: 16 }, name: 'ip4' });
    expect(policy.terms[1]).toMatchObject({ cidr: { ipv6: 32 }, name: 'ip6' });
    expect(policy.terms[2]).toMatchObject({ cidr: { ipv6: 64 }, name: 'a' });
    expect(policy.terms[3]).toMatchObject({
      cidr: { ipv4: 24, ipv6: 96 },
      name: 'mx',
    });
    expect(policy.diagnostics.map((item) => item.code)).not.toContain('invalid-cidr');
  });

  it('does not mistake a macro delimiter for a CIDR separator', () => {
    const policy = parseSpfRecord(
      'v=spf1 exists:%{l/}.sender.example a:%{l/}.sender.example//64 -all',
      'example.com',
    );

    expect(policy.terms[0]).toMatchObject({
      argument: '%{l/}.sender.example',
      name: 'exists',
    });
    expect(policy.terms[1]).toMatchObject({
      argument: '%{l/}.sender.example',
      cidr: { ipv6: 64 },
      name: 'a',
    });
    expect(policy.diagnostics.map((item) => item.code)).not.toContain('cidr-not-allowed');
  });

  it('rejects CIDR on ineligible mechanisms and dual CIDR on address literals', () => {
    const policy = parseSpfRecord(
      'v=spf1 include:child.example/24 exists:host.example/24 ptr/24 all/24 ip4:192.0.2.0/24//64 ip6:2001:db8::/32//64 a/33 mx//129 -all',
      'example.com',
    );
    const codes = policy.diagnostics.map((item) => item.code);

    expect(codes.filter((code) => code === 'cidr-not-allowed')).toHaveLength(4);
    expect(codes.filter((code) => code === 'invalid-cidr')).toHaveLength(4);
  });

  it('detects macros, ptr, unreachable terms, and redirect conflicts', () => {
    const policy = parseSpfRecord(
      'v=spf1 ptr exists:%{i}.example -all a redirect=next.example',
      'example.com',
    );
    expect(policy.diagnostics.map((item) => item.code)).toEqual(
      expect.arrayContaining([
        'ptr-discouraged',
        'macro-present',
        'after-all',
        'all-with-redirect',
      ]),
    );
  });

  it('rejects invalid networks and multiple identical terms', () => {
    const policy = parseSpfRecord('v=spf1 ip4:999.2.3.4 ip6:192.0.2.1 a a -all', 'example.com');
    expect(policy.diagnostics.map((item) => item.code)).toEqual(
      expect.arrayContaining(['invalid-network', 'duplicate-term']),
    );
  });

  it.each([
    'v=spf1\u00a0ip4:192.0.2.0/24 -all',
    'v=spf1\tip4:192.0.2.0/24 -all',
    'v=spf1\nip4:192.0.2.0/24 -all',
    'v=spf1 ip4:192.0.2.0/24\t-all',
    'v=spf1 ip4:192.0.2.0/24\r-all',
    'v=spf1 ip4:192.0.2.0/24\n-all',
    'v=spf1 ip4:192.0.2.0/24\u00a0-all',
    'v=spf1 ip4:192.0.2.0/24\u2003-all',
  ])('rejects non-printable or non-ASCII term separators', (record) => {
    const policy = parseSpfRecord(record, 'example.com');
    expect(policy.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'invalid-character', severity: 'error' }),
      ]),
    );
  });

  it('accepts repeated ordinary spaces without treating them as empty terms', () => {
    const policy = parseSpfRecord('v=spf1   ip4:192.0.2.0/24    -all', 'example.com');

    expect(policy.diagnostics.filter((item) => item.severity === 'error')).toEqual([]);
    expect(policy.terms.map((term) => term.original)).toEqual(['ip4:192.0.2.0/24', '-all']);
  });

  it.each(['127.1', '0x7f000001', '010.0.0.1'])(
    'rejects ambiguous IPv4 mechanism input %s',
    (address) => {
      const policy = parseSpfRecord(`v=spf1 ip4:${address} -all`, 'example.com');
      expect(policy.diagnostics.map((item) => item.code)).toContain('invalid-network');
    },
  );

  it('preserves unknown modifiers but keeps unknown mechanisms erroneous', () => {
    const policy = parseSpfRecord(
      'v=spf1 vendor=value option=%{d} future:thing -all',
      'example.com',
    );

    expect(policy.terms.slice(0, 2)).toEqual([
      expect.objectContaining({ kind: 'unknown-modifier', name: 'vendor', value: 'value' }),
      expect.objectContaining({ kind: 'unknown-modifier', name: 'option', value: '%{d}' }),
    ]);
    const unknownModifiers = policy.diagnostics.filter(
      (item) => item.code === 'unknown-modifier',
    );
    expect(unknownModifiers).toHaveLength(2);
    expect(unknownModifiers.every((item) => item.severity === 'warning')).toBe(true);
    expect(policy.diagnostics.map((item) => item.code)).toContain('unknown-term');
    expect(policy.diagnostics.map((item) => item.code)).not.toContain('macro-present');
  });

  it('rejects duplicate known modifier names even when their values differ', () => {
    const policy = parseSpfRecord(
      'v=spf1 redirect=one.example redirect=two.example exp=first.example exp=second.example',
      'example.com',
    );
    const duplicates = policy.diagnostics.filter((item) => item.code === 'duplicate-modifier');

    expect(duplicates).toHaveLength(2);
    expect(duplicates.every((item) => item.severity === 'error')).toBe(true);
  });
});
