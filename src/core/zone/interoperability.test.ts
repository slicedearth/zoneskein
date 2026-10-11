import { describe, expect, it } from 'vitest';

import { expandZoneBundle } from './bundle';
import { previewDomainConnectTemplate } from './domain-connect';
import { exportZoneInfrastructure } from './iac';
import { lintZoneSnippet } from './lint';
import { parseZoneSnippet } from './parser';
import { canonicalRecordRdata } from './zonemd';

describe('zone bundle expansion', () => {
  it('stops a repeated include DAG at one shared work budget without a partial result', () => {
    const files = Array.from({ length: 12 }, (_, depth) => ({
      name: `${String(depth)}.zone`,
      source:
        depth === 11
          ? ''
          : Array.from({ length: 8 }, () => `$INCLUDE ${String(depth + 1)}.zone`).join('\n'),
    }));
    const result = expandZoneBundle(files, '0.zone', 'example.com', { workLimit: 64 });
    expect(result).toMatchObject({ provenance: [], source: '', status: 'invalid' });
    expect(result.diagnostics).toHaveLength(1);
    expect(result.diagnostics[0]?.message).toContain('after 64 work steps');
  });

  it('bounds diagnostics while visiting invalid includes, not after traversal', () => {
    const result = expandZoneBundle(
      [{ name: 'main.zone', source: '$INCLUDE absent.zone\n'.repeat(100) }],
      'main.zone',
      'example.com',
      { diagnosticLimit: 3, workLimit: 20 },
    );
    expect(result).toMatchObject({ provenance: [], source: '', status: 'invalid' });
    expect(result.diagnostics).toHaveLength(3);
    expect(result.diagnostics[2]?.message).toContain('diagnostic safety limit');
    expect(result.diagnostics.some((item) => item.message.includes('work steps'))).toBe(false);
  });

  it('restores the caller owner across nested and repeated includes and origin changes', () => {
    const result = expandZoneBundle(
      [
        {
          name: 'main.zone',
          source: String.raw`$ORIGIN example.com.
before\046label 300 IN A 192.0.2.1
$INCLUDE child.zone child.example.
 300 IN TXT "parent"
$INCLUDE child.zone child.example.
 300 IN TXT "parent-again"`,
        },
        {
          name: 'child.zone',
          source: String.raw` 300 IN TXT "inherited"
other 300 IN A 192.0.2.2
$INCLUDE nested.zone
 300 IN TXT "child"`,
        },
        { name: 'nested.zone', source: '$ORIGIN nested.example.\nlast 300 IN A 192.0.2.3' },
      ],
      'main.zone',
    );
    const parsed = parseZoneSnippet(result.source);
    expect(result.status).toBe('complete');
    expect(parsed.diagnostics).toEqual([]);
    expect(
      parsed.records
        .filter((record) => record.type === 'TXT')
        .map((record) => [record.owner, record.rdata[0]?.value]),
    ).toEqual([
      ['before\\046label.example.com.', 'inherited'],
      ['other.child.example.', 'child'],
      ['before\\046label.example.com.', 'parent'],
      ['before\\046label.example.com.', 'inherited'],
      ['other.child.example.', 'child'],
      ['before\\046label.example.com.', 'parent-again'],
    ]);
    expect(
      result.provenance.find(
        (item) => item.sourceFile === 'main.zone' && item.sourceLine === 4,
      ),
    ).toBeDefined();
  });

  it('preserves generated TXT lexical bytes, character-string boundaries and escaped dollars', () => {
    const template = String.raw`$ORIGIN example.com.
$GENERATE 1-2 host$ 300 IN TXT "a;b" "" "two spaces" "\036" "\$" "\092$" plain$`;
    const result = expandZoneBundle([{ name: 'main.zone', source: template }], 'main.zone');
    const records = parseZoneSnippet(result.source).records;
    expect(result.status).toBe('complete');
    expect(records).toHaveLength(2);
    for (const [index, record] of records.entries()) {
      const number = index + 1;
      const expected = parseZoneSnippet(
        String.raw`host${number}.example.com. 300 IN TXT "a;b" "" "two spaces" "\036" "$" "\092${number}" plain${number}`,
      ).records[0];
      expect(expected).toBeDefined();
      if (expected === undefined) throw new Error('The reference record did not parse.');
      expect(canonicalRecordRdata(record)).toEqual(canonicalRecordRdata(expected));
      expect(record.rdata.map((token) => token.value)).toEqual([
        'a;b',
        '',
        'two spaces',
        '$',
        '$',
        `\\${String(number)}`,
        `plain${String(number)}`,
      ]);
    }
  });

  it('does not treat continuation lines as inherited records or directives', () => {
    const result = expandZoneBundle(
      [
        {
          name: 'main.zone',
          source:
            '$ORIGIN example.com.\nlong 300 IN TXT ( "one"\n "two" )\n 300 IN TXT "three"',
        },
      ],
      'main.zone',
    );
    const parsed = parseZoneSnippet(result.source);
    expect(result.status).toBe('complete');
    expect(parsed.records.map((record) => record.owner)).toEqual([
      'long.example.com.',
      'long.example.com.',
    ]);
    expect(parsed.records[0]?.rdata.map((token) => token.value)).toEqual(['one', 'two']);
  });

  it('expands local includes and bounded generate directives with provenance', () => {
    const result = expandZoneBundle(
      [
        {
          name: 'main.zone',
          source: [
            '$ORIGIN example.com.',
            '$INCLUDE parts/mail.zone mail.example.com.',
            '$GENERATE 1-3 host$ 300 IN A 192.0.2.$',
            'after 300 IN A 192.0.2.99',
          ].join('\n'),
        },
        {
          name: 'parts/mail.zone',
          source: '@ 300 IN MX 10 inbound.example.net.',
        },
      ],
      'main.zone',
    );

    expect(result.status).toBe('complete');
    expect(result.source).toContain('$ORIGIN mail.example.com.');
    expect(result.source).toContain('$ORIGIN example.com.');
    expect(result.source).toContain('host3 300 IN A 192.0.2.3');
    expect(result.provenance.filter((item) => item.generatedIndex !== null)).toHaveLength(3);
    expect(result.provenance.find((item) => item.generatedIndex === 2)).toMatchObject({
      sourceFile: 'main.zone',
      sourceLine: 3,
    });
  });

  it('rejects missing files, traversal, cycles, and oversized generation ranges', () => {
    expect(
      expandZoneBundle([{ name: 'main.zone', source: '$INCLUDE ../secret.zone' }], 'main.zone')
        .status,
    ).toBe('invalid');
    expect(
      expandZoneBundle(
        [
          { name: 'a.zone', source: '$INCLUDE b.zone' },
          { name: 'b.zone', source: '$INCLUDE a.zone' },
        ],
        'a.zone',
        'example.com',
      ).diagnostics.some((item) => item.message.includes('cycle')),
    ).toBe(true);
    expect(
      expandZoneBundle(
        [{ name: 'main.zone', source: '$GENERATE 0-5000 host$ A 192.0.2.1' }],
        'main.zone',
        'example.com',
      ).status,
    ).toBe('invalid');
    const invalidOrigin = expandZoneBundle(
      [{ name: 'main.zone', source: '$ORIGIN bad..example\n@ 300 IN A 192.0.2.1' }],
      'main.zone',
    );
    expect(invalidOrigin).toMatchObject({ provenance: [], source: '', status: 'invalid' });
    const unknownCallerOrigin = expandZoneBundle(
      [
        { name: 'main.zone', source: '$INCLUDE child.zone\nafter 300 IN A 192.0.2.2' },
        { name: 'child.zone', source: '$ORIGIN child.example.\n@ 300 IN A 192.0.2.1' },
      ],
      'main.zone',
    );
    expect(unknownCallerOrigin).toMatchObject({
      provenance: [],
      source: '',
      status: 'invalid',
    });
  });
});

describe('Domain Connect preview', () => {
  it.each(['CNAME', 'NS', 'MX', 'SRV'])(
    'resolves %s targets as fully qualified independently of a trailing dot',
    (type) => {
      const render = (pointsTo: string, variables = {}) =>
        previewDomainConnectTemplate(
          JSON.stringify({
            providerId: 'provider.example',
            providerName: 'Fixture',
            serviceId: 'fixture',
            serviceName: 'Fixture',
            records: [
              {
                type,
                host: 'host',
                name: '@',
                service: '_sip',
                protocol: '_tcp',
                priority: 10,
                weight: 20,
                port: 443,
                ttl: 300,
                pointsTo,
                target: pointsTo,
              },
            ],
          }),
          'user.example',
          variables,
        );
      const without = render('service.example.net');
      expect(without.status).toBe('ready');
      expect(without.source).toContain('service.example.net.');
      expect(without.source).not.toContain('service.example.net.user.example');
      expect(render('service.example.net.').source).toBe(without.source);
      expect(render('%destination%', { destination: 'service.example.net' }).source).toBe(
        without.source,
      );
      expect(render('@').source).toContain('user.example.');
      expect(render('bad..example')).toMatchObject({ source: '', status: 'invalid' });
    },
  );

  it('validates variables and renders portable DNS records without publishing', () => {
    const result = previewDomainConnectTemplate(
      JSON.stringify({
        providerId: 'service.example',
        providerName: 'Example Service',
        serviceId: 'mail',
        serviceName: 'Example Mail',
        records: [
          { host: '@', pointsTo: '%ipv4%', ttl: '%ttl%', type: 'A' },
          { host: '@', pointsTo: 'mail', priority: 10, ttl: 3600, type: 'MX' },
          { host: '@', spfRules: 'include:spf.example -all', type: 'SPFM' },
        ],
      }),
      'example.com',
      { ipv4: '192.0.2.10', ttl: 300 },
    );

    expect(result.status).toBe('ready');
    expect(result.source).toContain('@ 300 IN A 192.0.2.10');
    expect(result.source).toContain('@ 3600 IN MX 10 mail.');
    expect(result.source).toContain('"v=spf1 include:spf.example -all"');
    expect(result.unresolvedVariables).toEqual([]);
  });

  it('keeps provider actions and unresolved variables explicit', () => {
    const result = previewDomainConnectTemplate(
      JSON.stringify({
        providerId: 'service.example',
        providerName: 'Example Service',
        serviceId: 'web',
        serviceName: 'Example Web',
        records: [
          { host: '@', pointsTo: '%address%', ttl: 300, type: 'A' },
          { essential: true, pointsTo: 'target.example', ttl: 300, type: 'APEXCNAME' },
        ],
      }),
      'example.com',
      {},
    );

    expect(result.status).toBe('invalid');
    expect(result.unresolvedVariables).toEqual(['address']);
    expect(result.records[1]).toMatchObject({ essential: true, line: null });
  });

  it('does not resolve variable placeholders through inherited object properties', () => {
    const result = previewDomainConnectTemplate(
      JSON.stringify({
        providerId: 'service.example',
        providerName: 'Example Service',
        serviceId: 'web',
        serviceName: 'Example Web',
        records: [{ data: '%constructor%', host: '@', ttl: 300, type: 'TXT' }],
      }),
      'example.com',
      {},
    );

    expect(result).toMatchObject({ source: '', status: 'invalid' });
    expect(result.unresolvedVariables).toEqual(['constructor']);
  });

  it('withholds unsafe, out-of-zone, and oversized template output', () => {
    const base = {
      providerId: 'service.example',
      providerName: 'Example Service',
      serviceId: 'web',
      serviceName: 'Example Web',
    };
    const outside = previewDomainConnectTemplate(
      JSON.stringify({
        ...base,
        records: [{ host: 'outside.example.net.', pointsTo: '192.0.2.1', ttl: 300, type: 'A' }],
      }),
      'example.com',
      {},
    );
    const injected = previewDomainConnectTemplate(
      JSON.stringify({
        ...base,
        records: [
          { data: 'safe\n@ 300 IN A 192.0.2.9', host: '@', ttl: 300, type: 'TYPE65280' },
        ],
      }),
      'example.com',
      {},
    );
    const oversized = previewDomainConnectTemplate(
      JSON.stringify({
        ...base,
        records: Array.from({ length: 513 }, () => ({
          host: '@',
          pointsTo: '192.0.2.1',
          ttl: 300,
          type: 'A',
        })),
      }),
      'example.com',
      {},
    );

    expect(outside).toMatchObject({ source: '', status: 'invalid' });
    expect(injected).toMatchObject({ source: '', status: 'invalid' });
    expect(oversized).toMatchObject({ records: [], source: '', status: 'invalid' });
  });
});

describe('portable zone exports', () => {
  it('groups complete same-owner RRsets while retaining mixed types and every value', () => {
    const document = lintZoneSnippet(
      '$ORIGIN example.com.\n@ 300 IN A 192.0.2.1\n@ 300 IN A 192.0.2.2\n@ 300 IN MX 10 first.example.\n@ 300 IN MX 20 second.example.\n@ 300 IN TXT "Token=AbC"\n@ 300 IN TXT "Token=abc"',
    );
    const result = exportZoneInfrastructure(document);
    expect(result.supportedRecords).toBe(6);
    expect(result.omittedRecords).toBe(0);
    expect(result.octoDns).toBe(
      [
        '---',
        "'':",
        '  - ttl: 300',
        '    type: A',
        '    values:',
        "      - '192.0.2.1'",
        "      - '192.0.2.2'",
        '  - ttl: 300',
        '    type: MX',
        '    values:',
        "      - exchange: 'first.example.'",
        '        preference: 10',
        "      - exchange: 'second.example.'",
        '        preference: 20',
        '  - ttl: 300',
        '    type: TXT',
        '    values:',
        "      - 'Token=AbC'",
        "      - 'Token=abc'",
        '',
      ].join('\n'),
    );
  });

  it('withholds every member of an inconsistent-TTL RRset without choosing a winner', () => {
    const result = exportZoneInfrastructure(
      lintZoneSnippet(
        '$ORIGIN example.com.\n@ 300 IN A 192.0.2.1\n@ 600 IN A 192.0.2.2\nwww 300 IN A 192.0.2.3',
      ),
    );
    expect(result).toMatchObject({ supportedRecords: 1, omittedRecords: 2 });
    expect(
      result.diagnostics.filter((item) => item.message.includes('inconsistent TTLs')),
    ).toHaveLength(2);
    for (const output of [result.dnsControl, result.octoDns]) {
      expect(output).not.toContain('192.0.2.1');
      expect(output).not.toContain('192.0.2.2');
      expect(output).toContain('192.0.2.3');
    }
  });

  it('resolves every supported target using raw tokens and the effective record origin', () => {
    const result = exportZoneInfrastructure(
      lintZoneSnippet(String.raw`$ORIGIN example.com.
@ 300 IN NS ns
$ORIGIN sub.example.com.
www 300 IN CNAME mail
ptr 300 IN PTR @
@ 300 IN MX 10 mail\046label
_sip._tcp 300 IN SRV 1 2 443 .
absolute 300 IN CNAME other.example.net.`),
    );
    expect(result.supportedRecords).toBe(6);
    for (const output of [result.dnsControl, result.octoDns]) {
      expect(output).toContain('ns.example.com.');
      expect(output).toContain('mail.sub.example.com.');
      expect(output).toContain('sub.example.com.');
      expect(output).toContain('other.example.net.');
    }
    expect(result.dnsControl).toContain(
      'MX("sub", 10, "mail\\\\046label.sub.example.com.", TTL(300))',
    );
    expect(result.octoDns).toContain("exchange: 'mail\\046label.sub.example.com.'");
    expect(result.dnsControl).toContain('SRV("_sip._tcp.sub", 1, 2, 443, ".", TTL(300))');
    expect(result.octoDns).toContain("target: '.'");
  });

  it('renders a conservative common subset and reports omissions', () => {
    const document = lintZoneSnippet(
      [
        '$ORIGIN example.com.',
        '@ 300 IN A 192.0.2.1',
        '@ 300 IN MX 10 mail.example.com.',
        'www 300 IN CNAME @',
        '@ 300 IN TXT "hello" " world"',
        '@ 300 IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 300',
      ].join('\n'),
    );
    const output = exportZoneInfrastructure(document);

    expect(output.supportedRecords).toBe(4);
    expect(output.omittedRecords).toBe(1);
    expect(output.dnsControl).toContain('D("example.com", REG_NONE');
    expect(output.dnsControl).toContain('TXT("@", "hello world", TTL(300))');
    expect(output.octoDns).toContain("'':");
    expect(output.octoDns).toContain("exchange: 'mail.example.com.'");
  });

  it('accepts valid RFC 3597 generic data and diagnoses mismatched lengths', () => {
    const valid = lintZoneSnippet('$ORIGIN example.\nopaque 300 IN TYPE65280 \\# 4 DEADBEEF');
    const invalid = lintZoneSnippet('$ORIGIN example.\nopaque 300 IN TYPE65280 \\# 3 DEADBEEF');

    expect(valid.diagnostics.some((item) => item.rule === 'type-unsupported')).toBe(false);
    expect(valid.diagnostics.some((item) => item.rule === 'generic-rdata-malformed')).toBe(
      false,
    );
    expect(invalid.diagnostics.some((item) => item.rule === 'generic-rdata-malformed')).toBe(
      true,
    );
  });

  it('omits lint-invalid records from generated configuration', () => {
    const document = lintZoneSnippet(
      '$ORIGIN example.com.\n@ 300 IN MX not-a-number mail.example.com.\nwww 300 IN A 192.0.2.1',
    );
    const output = exportZoneInfrastructure(document);

    expect(output.supportedRecords).toBe(1);
    expect(output.omittedRecords).toBe(1);
    expect(output.dnsControl).not.toContain('not-a-number');
    expect(output.octoDns).not.toContain('not-a-number');
  });
});
