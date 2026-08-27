import { describe, expect, it } from 'vitest';

import { expandZoneBundle } from './bundle';
import { previewDomainConnectTemplate } from './domain-connect';
import { exportZoneInfrastructure } from './iac';
import { lintZoneSnippet } from './lint';

describe('zone bundle expansion', () => {
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
    expect(result.source).toContain('@ 3600 IN MX 10 mail.example.com.');
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
