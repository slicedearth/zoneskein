import { describe, expect, it } from 'vitest';

import { lintZoneSnippet } from './lint';
import { parseZoneSnippet, ZONE_ANALYSIS_LIMITS } from './parser';

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

  it('does not confuse mnemonic-looking owner labels with omitted owners', () => {
    const document = parseZoneSnippet(
      'ns 300 IN A 192.0.2.1\nin 600 IN AAAA 2001:db8::1\n300 900 IN TXT "numeric owner"',
      { origin: 'example.com' },
    );

    expect(document.records).toEqual([
      expect.objectContaining({ owner: 'ns.example.com.', ttl: 300, type: 'A' }),
      expect.objectContaining({ owner: 'in.example.com.', ttl: 600, type: 'AAAA' }),
      expect.objectContaining({ owner: '300.example.com.', ttl: 900, type: 'TXT' }),
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

  it('decodes decimal octets and escaped literals in quoted and unquoted token data', () => {
    const document = parseZoneSnippet(
      String.raw`@ IN TXT "space\032inside" unquoted\032space literal\ space nul\000max\255 suffix\0659 escaped\;semicolon escaped\(parentheses\) escaped\"quote escaped\\slash ; ignored`,
    );

    expect(document.diagnostics).toEqual([]);
    expect(document.records).toHaveLength(1);
    const tokens = document.records[0]?.rdata;
    expect(tokens?.map((token) => token.value)).toEqual([
      'space inside',
      'unquoted space',
      'literal space',
      `nul\u0000max${String.fromCharCode(255)}`,
      'suffixA9',
      'escaped;semicolon',
      'escaped(parentheses)',
      'escaped"quote',
      'escaped\\slash',
    ]);
    expect(tokens?.[0]).toMatchObject({ quoted: true, raw: String.raw`"space\032inside"` });
  });

  it('diagnoses incomplete, out-of-range, and trailing master-file escapes', () => {
    const decimal = parseZoneSnippet(
      String.raw`@ IN TXT "one\1" "two\12" "mixed\12x" "high\256" "higher\999"`,
    );
    const trailing = parseZoneSnippet('@ IN TXT trailing\\');

    expect(decimal.records[0]?.rdata.map((token) => token.value)).toEqual([
      'one1',
      'two12',
      'mixed12x',
      'high256',
      'higher999',
    ]);
    expect(decimal.diagnostics.map((item) => item.rule)).toEqual([
      'escape-decimal-malformed',
      'escape-decimal-malformed',
      'escape-decimal-malformed',
      'escape-decimal-range',
      'escape-decimal-range',
    ]);
    expect(decimal.diagnostics.at(-1)?.message).toContain('octet range \\000–\\255');
    expect(trailing.records[0]?.rdata[0]?.value).toBe('trailing\\');
    expect(trailing.diagnostics).toEqual([
      expect.objectContaining({
        message: 'A trailing backslash does not escape a character.',
        rule: 'escape-malformed',
        severity: 'error',
      }),
    ]);
  });

  it('accepts exact parser work boundaries and fails closed beyond them', () => {
    const exactRecords = Array.from(
      { length: ZONE_ANALYSIS_LIMITS.records },
      (_, index) => `record-${String(index)} IN A 192.0.2.1`,
    ).join('\n');
    const withinRecordLimit = parseZoneSnippet(exactRecords, { origin: 'example.com' });
    const beyondRecordLimit = parseZoneSnippet(`${exactRecords}\noverflow IN A 192.0.2.2`, {
      origin: 'example.com',
    });

    expect(withinRecordLimit.incomplete).toBeUndefined();
    expect(withinRecordLimit.records).toHaveLength(ZONE_ANALYSIS_LIMITS.records);
    expect(beyondRecordLimit).toMatchObject({
      incomplete: { limit: ZONE_ANALYSIS_LIMITS.records, resource: 'records' },
      records: [],
    });
    expect(beyondRecordLimit.diagnostics.at(-1)).toMatchObject({
      rule: 'parser-resource-limit',
      severity: 'error',
    });

    const exactTokenFields = Array.from(
      { length: ZONE_ANALYSIS_LIMITS.tokens - 3 },
      () => 'x',
    ).join(' ');
    const withinTokenLimit = parseZoneSnippet(`@ IN TXT ${exactTokenFields}`);
    const beyondTokenLimit = parseZoneSnippet(`@ IN TXT ${exactTokenFields} overflow`);

    expect(withinTokenLimit.incomplete).toBeUndefined();
    expect(withinTokenLimit.records).toHaveLength(1);
    expect(beyondTokenLimit).toMatchObject({
      incomplete: { limit: ZONE_ANALYSIS_LIMITS.tokens, resource: 'tokens' },
      records: [],
    });
  });

  it('bounds parser diagnostics and logical statements without retaining prefixes', () => {
    const exactDiagnostics = ')'.repeat(ZONE_ANALYSIS_LIMITS.diagnostics);
    const withinDiagnosticLimit = parseZoneSnippet(exactDiagnostics);
    const beyondDiagnosticLimit = parseZoneSnippet(`${exactDiagnostics})`);

    expect(withinDiagnosticLimit.incomplete).toBeUndefined();
    expect(withinDiagnosticLimit.diagnostics).toHaveLength(ZONE_ANALYSIS_LIMITS.diagnostics);
    expect(beyondDiagnosticLimit).toMatchObject({
      incomplete: { limit: ZONE_ANALYSIS_LIMITS.diagnostics, resource: 'diagnostics' },
      records: [],
    });
    expect(beyondDiagnosticLimit.diagnostics).toHaveLength(ZONE_ANALYSIS_LIMITS.diagnostics);
    expect(beyondDiagnosticLimit.diagnostics.at(-1)?.rule).toBe('parser-resource-limit');

    const exactStatements = Array.from(
      { length: ZONE_ANALYSIS_LIMITS.statements },
      () => '$TTL 300',
    ).join('\n');
    expect(parseZoneSnippet(exactStatements).incomplete).toBeUndefined();
    expect(parseZoneSnippet(`${exactStatements}\n$TTL 60`)).toMatchObject({
      incomplete: { limit: ZONE_ANALYSIS_LIMITS.statements, resource: 'statements' },
      records: [],
    });
  });
});

describe('zone-snippet lint rules', () => {
  it('preserves case-sensitive TXT octets while canonicalising DNS-name fields', () => {
    const document = lintZoneSnippet(
      '@ 300 IN TXT "Foo"\n@ 300 IN TXT "foo"\nwww 300 IN CNAME Target.Example.\nwww 300 IN CNAME target.example.',
      { origin: 'example.com' },
    );
    const duplicates = document.diagnostics.filter(
      (diagnostic) => diagnostic.rule === 'record-duplicate',
    );

    expect(duplicates).toHaveLength(1);
    expect(duplicates[0]?.line).toBe(4);
  });

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

  it('rejects ambiguous address syntax in records and SVCB hints', () => {
    const document = lintZoneSnippet(
      '@ IN A 010.0.0.1\n@ IN AAAA fe80::1%eth0\nsvc IN HTTPS 1 . ipv4hint=127.1',
      { origin: 'example.com' },
    );

    expect(document.diagnostics.filter((item) => item.rule === 'address-invalid')).toHaveLength(
      2,
    );
    expect(document.diagnostics).toContainEqual(
      expect.objectContaining({ rule: 'svcb-hint-invalid', severity: 'error' }),
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

  it('validates security and service-binding record fields', () => {
    const document = lintZoneSnippet(`
key IN DNSKEY 257 2 13 !!!!
@ IN DS 70000 13 2 AA
host IN SSHFP 4 2 AABB
_443._tcp IN TLSA 3 1 1 AABB
service IN HTTPS 0 . alpn="h2" key1="h3"
`);

    expect(document.diagnostics.map((item) => item.rule)).toEqual(
      expect.arrayContaining([
        'dnskey-malformed',
        'ds-malformed',
        'sshfp-malformed',
        'tlsa-malformed',
        'svcb-key-duplicate',
        'svcb-alias-parameters',
        'svcb-alias-root-target',
      ]),
    );
  });

  it('rejects deprecated SHA-1 DNSSEC authoring while retaining syntactically valid input', () => {
    const document = lintZoneSnippet(`
key5 IN DNSKEY 257 3 5 AAAA
key7 IN DNSKEY 257 3 7 AAAA
@ IN DS 12345 5 2 ${'AA'.repeat(32)}
@ IN DS 12345 8 1 ${'BB'.repeat(20)}
@ IN RRSIG A 5 2 300 1800003600 1799996400 12345 example. AAAA
`);

    expect(document.records).toHaveLength(5);
    expect(document.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          rule: 'dnskey-algorithm-deprecated',
          severity: 'error',
        }),
        expect.objectContaining({ rule: 'ds-algorithm-deprecated', severity: 'error' }),
        expect.objectContaining({ rule: 'ds-digest-deprecated', severity: 'error' }),
        expect.objectContaining({ rule: 'rrsig-algorithm-deprecated', severity: 'error' }),
      ]),
    );
    expect(
      document.diagnostics.filter((item) => item.rule === 'dnskey-algorithm-deprecated'),
    ).toHaveLength(2);
  });

  it('validates NAPTR and URI presentation fields', () => {
    const document = lintZoneSnippet(`
naptr IN NAPTR 100 10 "u" "E2U+sip" "!^.*$!sip:info@example.com!" target.example.
uri IN URI 10 1 relative/path
`);

    expect(document.diagnostics.map((item) => item.rule)).toEqual(
      expect.arrayContaining(['naptr-regexp-replacement', 'uri-malformed']),
    );
  });

  it('warns about non-canonical SvcParam ordering', () => {
    const document = lintZoneSnippet(
      'service IN HTTPS 1 . port="443" alpn="h2" mandatory="alpn,port"',
    );
    expect(document.diagnostics.map((item) => item.rule)).toContain('svcb-parameter-order');
  });

  it('fails closed when a zone exceeds the shared record limit', () => {
    const source = Array.from(
      { length: ZONE_ANALYSIS_LIMITS.records + 1 },
      (_, index) => `@ IN TXT "value-${String(index)}"`,
    ).join('\n');

    const document = lintZoneSnippet(source, { origin: 'example.com' });

    expect(document.records).toEqual([]);
    expect(document.incomplete).toMatchObject({
      limit: ZONE_ANALYSIS_LIMITS.records,
      resource: 'records',
    });
    expect(document.diagnostics.at(-1)).toMatchObject({
      rule: 'parser-resource-limit',
      severity: 'error',
    });
  });

  it('caps emitted diagnostics for adversarial repeated invalid records', () => {
    const source = Array.from({ length: 3000 }, () => '@ IN A invalid extra').join('\n');

    const document = lintZoneSnippet(source, { origin: 'example.com' });

    expect(document.diagnostics).toHaveLength(4096);
    expect(document.diagnostics.at(-1)).toMatchObject({
      rule: 'lint-diagnostic-limit',
      severity: 'warning',
    });
  });

  it('stops record-specific work when one record has too many data fields', () => {
    const source = `@ IN TXT ${Array.from({ length: 257 }, () => 'unquoted').join(' ')}`;

    const document = lintZoneSnippet(source, { origin: 'example.com' });

    expect(document.diagnostics).toEqual([
      expect.objectContaining({ rule: 'record-field-limit', severity: 'error' }),
    ]);
  });
});
