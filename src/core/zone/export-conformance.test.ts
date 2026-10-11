import { describe, expect, it } from 'vitest';

import { authorRecord, chunkTxtValue } from './authoring';
import { intendedRdataTokens, verifyBindRecord } from './export-conformance';
import { previewDomainConnectTemplate } from './domain-connect';
import { expandZoneBundle } from './bundle';
import { parseZoneSnippet } from './parser';

describe('offline BIND export conformance', () => {
  it.each([
    ['A', ['192.0.2.1'], '192.0.2.1', '192.0.2.2'],
    ['AAAA', ['2001:db8::1'], '2001:db8::1', '2001:db8::2'],
    ...['CNAME', 'NS', 'PTR'].map(
      (type) => [type, ['target.example.'], 'TARGET.example.', 'other.example.'] as const,
    ),
    ['MX', [10, 'mail.example.'], '10 MAIL.example.', '20 mail.example.'],
    ['SRV', [1, 2, 443, '.'], '1 2 443 .', '1 2 8443 .'],
    [
      'SOA',
      ['ns.example.', 'hostmaster.example.', 1, 3600, 600, 86400, 300],
      'ns.example. hostmaster.example. 1 1h 10m 1d 300',
      'ns.example. hostmaster.example. 2 1h 10m 1d 300',
    ],
    [
      'CAA',
      [0, 'issue', { text: 'CA.EXAMPLE; validationmethods=dns-01' }],
      '0 issue "CA.EXAMPLE; validationmethods=dns-01"',
      '0 issue "ca.example; validationmethods=dns-01"',
    ],
    ['DNSKEY', [257, 3, 13, 'AAAA'], '257 3 13 AAAA', '256 3 13 AAAA'],
    [
      'DS',
      [123, 13, 2, 'AA'.repeat(32)],
      `123 13 2 ${'AA'.repeat(32)}`,
      `124 13 2 ${'AA'.repeat(32)}`,
    ],
    ['SSHFP', [4, 2, 'AA'.repeat(32)], `4 2 ${'AA'.repeat(32)}`, `4 2 ${'BB'.repeat(32)}`],
    [
      'TLSA',
      [3, 1, 1, 'AA'.repeat(32)],
      `3 1 1 ${'AA'.repeat(32)}`,
      `3 0 1 ${'AA'.repeat(32)}`,
    ],
    [
      'URI',
      [10, 1, { text: 'https://example.test/Path' }],
      '10 1 "https://example.test/Path"',
      '10 1 "https://example.test/path"',
    ],
    [
      'NAPTR',
      [10, 20, { text: 'S' }, { text: 'SIP+D2T' }, { text: 'a b' }, '.'],
      '10 20 "S" "SIP+D2T" "a b" .',
      '10 20 "S" "SIP+D2T" "ab" .',
    ],
    ...['SVCB', 'HTTPS'].map(
      (type) =>
        [
          type,
          [1, '.', 'alpn="h2,h3"', 'port="443"'],
          '1 . alpn="h2,h3" port=443',
          '1 . alpn="h2,h3" port=8443',
        ] as const,
    ),
  ] as const)(
    'checks intended canonical %s RDATA, not just syntactic validity',
    (type, fields, correct, wrong) => {
      const expected = {
        owner: 'example.test.',
        ttl: 300,
        type,
        rdata: intendedRdataTokens(fields),
      };
      expect(verifyBindRecord(`example.test. 300 IN ${type} ${correct}`, expected)).toBeNull();
      expect(verifyBindRecord(`example.test. 300 IN ${type} ${wrong}`, expected)).toMatch(
        /changed the intended canonical RDATA/u,
      );
    },
  );

  it('requires an independently supplied non-TXT expectation', () => {
    expect(verifyBindRecord('@ IN A 192.0.2.1', { owner: '@', type: 'A' })).toMatch(
      /Intended typed RDATA is required/u,
    );
  });

  it('checks absolute template targets and generated TXT using their own source semantics', () => {
    const template = previewDomainConnectTemplate(
      JSON.stringify({
        providerId: 'provider.example',
        serviceId: 'mail',
        version: 1,
        records: [
          { type: 'MX', host: '@', priority: 10, pointsTo: 'mail.provider.example', ttl: 300 },
        ],
      }),
      'example.test',
      {},
    );
    expect(
      verifyBindRecord(template.records[0]?.line ?? '', {
        owner: '@',
        ttl: 300,
        type: 'MX',
        rdata: intendedRdataTokens([10, 'mail.provider.example.']),
      }),
    ).toBeNull();
    const bundle = expandZoneBundle(
      [
        {
          name: 'main.zone',
          source: '$ORIGIN example.test.\n$GENERATE 1-1 host$ 300 IN TXT "a;b" "" "two words"',
        },
      ],
      'main.zone',
    );
    const record = parseZoneSnippet(bundle.source).records[0];
    expect(
      verifyBindRecord(record?.original ?? '', {
        owner: 'host1',
        ttl: 300,
        type: 'TXT',
        txtChunks: ['a;b', '', 'two words'],
        rdata: intendedRdataTokens([{ text: 'a;b' }, { text: '' }, { text: 'two words' }]),
      }),
    ).toBeNull();
  });

  it.each([0, 254, 255, 256, 510, 511, 1024])(
    'preserves %i TXT octets and every boundary',
    (length) => {
      const value = 'x'.repeat(length);
      const chunks = chunkTxtValue(value);
      expect(chunks.join('')).toBe(value);
      expect(chunks.every((chunk) => new TextEncoder().encode(chunk).length <= 255)).toBe(true);
      const output = authorRecord({ owner: '@', ttl: '300', type: 'TXT', fields: { value } });
      expect(output.valid).toBe(true);
      expect(
        verifyBindRecord(output.bind ?? '', {
          owner: '@',
          ttl: 300,
          type: 'TXT',
          txtValue: value,
          txtChunks: chunks,
        }),
      ).toBeNull();
    },
  );

  it.each([254, 255, 256, 510])('retains terminal SPF text across boundary %i', (boundary) => {
    const value = `v=spf1 ${' '.repeat(boundary - 7)}-all`;
    const chunks = chunkTxtValue(value);
    const bind = `example.test. IN TXT (${chunks.map((chunk) => JSON.stringify(chunk)).join(' ')})`;
    expect(chunks.join('')).toBe(value);
    expect(
      parseZoneSnippet(bind)
        .records[0]?.rdata.map((token) => token.value)
        .join(''),
    ).toBe(value);
    expect(
      verifyBindRecord(bind, { owner: 'example.test.', type: 'TXT', txtValue: value }),
    ).toBeNull();
  });

  it.each([
    '@ 300 IN TXT "unterminated',
    '@ 300 IN TXT "one"\n@ 300 IN TXT "two"',
    '@ 300 IN TXT "' + 'x'.repeat(256) + '"',
    '@ 300 IN A 999.1.1.1',
  ])('withholds malformed output: %s', (bind) => {
    expect(
      verifyBindRecord(bind, {
        owner: '@',
        ttl: 300,
        type: bind.includes(' IN A ') ? 'A' : 'TXT',
      }),
    ).not.toBeNull();
  });

  it('detects lost separators and changed TXT boundaries', () => {
    expect(
      verifyBindRecord('@ IN TXT "v=spf1" "-all"', {
        owner: '@',
        type: 'TXT',
        txtValue: 'v=spf1 -all',
      }),
    ).toMatch(/intended value/u);
    expect(
      verifyBindRecord('@ IN TXT "ab"', { owner: '@', type: 'TXT', txtChunks: ['a', 'b'] }),
    ).toMatch(/boundaries/u);
  });

  it('rejects a character that cannot survive UTF-8 roundtrip', () => {
    expect(
      authorRecord({ owner: '@', ttl: '300', type: 'TXT', fields: { value: '\ud800' } }).valid,
    ).toBe(false);
  });
});
