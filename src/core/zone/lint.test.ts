import { describe, expect, it } from 'vitest';

import { lintZoneSnippet } from './lint';
import { parseZoneSnippet } from './parser';

describe('zone-snippet parser', () => {
  it('handles comments, directives, multiline records, relative names, and owner inheritance', () => {
    const document = parseZoneSnippet(`
$ORIGIN example.com.
$TTL 1h
@ IN SOA ns1.example.net. hostmaster.example.net. (
  2026081301 1h 15m 1w 1h
)
www 300 IN A 192.0.2.10 ; deployed address
    IN AAAA 2001:db8::10
@ IN TXT "part one" "part two"
`);

    expect(document.origin).toBe('example.com.');
    expect(document.records).toHaveLength(4);
    expect(document.records[0]).toMatchObject({
      owner: 'example.com.',
      ttl: 3600,
      type: 'SOA',
    });
    expect(document.records[2]).toMatchObject({ owner: 'www.example.com.', type: 'AAAA' });
    expect(document.records[3]?.rdata.map((token) => token.value)).toEqual([
      'part one',
      'part two',
    ]);
  });

  it('reports unterminated quotes and parentheses without discarding all records', () => {
    const quote = parseZoneSnippet('www IN A 192.0.2.1\n@ IN TXT "unfinished');
    const parenthesis = parseZoneSnippet('www IN A 192.0.2.1\n@ IN MX ( 10 mail');
    expect(quote.records.length).toBeGreaterThan(0);
    expect(parenthesis.records.length).toBeGreaterThan(0);
    expect(quote.diagnostics.map((item) => item.rule)).toContain('syntax-quote');
    expect(parenthesis.diagnostics.map((item) => item.rule)).toContain('syntax-parenthesis');
  });
});

describe('zone-snippet lint rules', () => {
  it('finds CNAME conflicts, invalid addresses, and malformed structured records', () => {
    const document = lintZoneSnippet(
      `
@ IN CNAME target.example.net.
@ IN A 999.1.1.1
mail IN MX high 192.0.2.4
_service._tcp IN SRV 1 2 nope target
@ IN CAA 999 "bad tag" "ca.example"
`,
      { origin: 'example.com' },
    );
    expect(document.diagnostics.map((item) => item.rule)).toEqual(
      expect.arrayContaining([
        'cname-conflict',
        'apex-cname',
        'address-invalid',
        'mx-malformed',
        'target-ip-literal',
        'srv-malformed',
        'caa-malformed',
      ]),
    );
  });

  it('detects duplicate SPF policies, unreachable terms, duplicate records, and long TXT chunks', () => {
    const longChunk = 'x'.repeat(256);
    const document = lintZoneSnippet(
      `
@ 300 IN TXT "v=spf1 -all include:late.example"
@ 300 IN TXT "v=spf1 ip4:192.0.2.0/24 -all"
www 60 IN A 192.0.2.1
www 60 IN A 192.0.2.1
long IN TXT "${longChunk}"
`,
      { maximumTtl: 86_400, minimumTtl: 300, origin: 'example.com' },
    );
    expect(document.diagnostics.map((item) => item.rule)).toEqual(
      expect.arrayContaining([
        'spf-multiple',
        'spf-after-all',
        'record-duplicate',
        'txt-chunk-too-long',
        'ttl-below-recommended',
      ]),
    );
  });

  it('warns when a relative target changes under the origin', () => {
    const document = lintZoneSnippet('@ IN MX 10 mail.example.net', {
      origin: 'example.com',
    });
    expect(document.diagnostics).toEqual([
      expect.objectContaining({
        rule: 'target-relative',
        suggestion: 'Use mail.example.net. if this target is intended to be absolute.',
      }),
    ]);
  });
});
