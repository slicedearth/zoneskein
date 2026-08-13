import { describe, expect, it } from 'vitest';

import { parseSpfRecord } from './parser';

describe('SPF parser', () => {
  it('preserves order, qualifiers, dual CIDRs, and locations', () => {
    const policy = parseSpfRecord(
      'v=spf1 ip4:192.0.2.0/24 a:mail.example/28/64 -include:blocked.example ~all',
      'example.com',
    );
    expect(policy.terms.map((term) => term.original)).toEqual([
      'ip4:192.0.2.0/24',
      'a:mail.example/28/64',
      '-include:blocked.example',
      '~all',
    ]);
    expect(policy.terms[1]).toMatchObject({
      cidr: { ipv4: 28, ipv6: 64 },
      kind: 'mechanism',
      qualifier: '+',
    });
    expect(policy.terms[2]).toMatchObject({ kind: 'mechanism', qualifier: '-' });
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
});
