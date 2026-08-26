import { describe, expect, it } from 'vitest';

import { lintZoneSnippet } from './lint';
import { analyseZoneDigest } from './zonemd';

const SIMPLE_EXAMPLE_ZONE = `
$ORIGIN example.
example.      86400  IN  SOA     ns1 admin 2018031900 (
                                     1800 900 604800 86400 )
              86400  IN  NS      ns1
              86400  IN  NS      ns2
              86400  IN  ZONEMD  2018031900 1 1 (
                                     c68090d90a7aed71
                                     6bc459f9340e3d7c
                                     1370d4d24b7e2fc3
                                     a1ddc0b9a87153b9
                                     a9713b3c9ae5cc27
                                     777f98b8e730044c )
ns1           3600   IN  A       203.0.113.63
ns2           3600   IN  AAAA    2001:db8::63
`;

function generatedZone(record: string, soa?: string): string {
  return `$ORIGIN example.
${soa ?? '@ 300 IN SOA ns hostmaster 1 3600 600 86400 300'}
@ 300 IN NS ns
ns 300 IN A 192.0.2.1
${record}
`;
}

async function sha384(zone: string): Promise<string> {
  const report = await analyseZoneDigest(lintZoneSnippet(zone), true);
  expect(report.state, `${zone}\n${report.explanation}`).toBe('generated');
  const digest = report.digests[0]?.calculated;
  expect(digest).toBeDefined();
  return digest ?? '';
}

describe('RFC 8976 complete-zone digests', () => {
  it('verifies the published SIMPLE SHA-384 example', async () => {
    const document = lintZoneSnippet(SIMPLE_EXAMPLE_ZONE);
    const report = await analyseZoneDigest(document, true);

    expect(report).toMatchObject({
      duplicatesOmitted: 0,
      excludedApexRecords: 1,
      excludedOutOfZoneRecords: 0,
      includedRecords: 5,
      origin: 'example.',
      serial: 2_018_031_900,
      state: 'verified',
    });
    expect(report.digests[0]).toMatchObject({
      calculated:
        'C68090D90A7AED716BC459F9340E3D7C1370D4D24B7E2FC3A1DDC0B9A87153B9A9713B3C9AE5CC27777F98B8E730044C',
      hashAlgorithm: 1,
      publications: [expect.objectContaining({ matches: true })],
    });
  });

  it('canonicalises case, order, duplicate records, wildcards and non-apex digests', async () => {
    const document = lintZoneSnippet(`
$ORIGIN example.
example. 86400 IN SOA ns1 admin 2018031900 1800 900 604800 86400
        86400 IN NS ns1
        86400 IN NS ns2
        86400 IN ZONEMD 2018031900 1 1 (
          a3b69bad980a3504e1cffcb0fd6397f93848071c93151f55
          2ae2f6b1711d4bd2d8b39808226d7b9db71e34b72077f8fe )
ns1 3600 IN A 203.0.113.63
NS2 3600 IN AAAA 2001:db8::63
occluded.sub 7200 IN TXT "I'm occluded but must be digested"
sub 7200 IN NS ns1
duplicate 300 IN TXT "I must be digested just once"
duplicate 300 IN TXT "I must be digested just once"
foo.test. 555 IN TXT "out-of-zone data must be excluded"
UPPERCASE 3600 IN TXT "canonicalize uppercase owner names"
* 777 IN PTR dont-forget-about-wildcards
mail 3600 IN MX 20 MAIL1
mail 3600 IN MX 10 Mail2.Example.
sortme 3600 IN AAAA 2001:db8::5:61
sortme 3600 IN AAAA 2001:db8::3:62
sortme 3600 IN AAAA 2001:db8::4:63
sortme 3600 IN AAAA 2001:db8::1:65
sortme 3600 IN AAAA 2001:db8::2:64
non-apex 900 IN ZONEMD 2018031900 1 1 (
  616c6c6f776564206275742069676e6f7265642e20616c6c
  6f776564206275742069676e6f7265642e20616c6c6f7765 )
`);
    const report = await analyseZoneDigest(document, true);

    expect(report).toMatchObject({
      duplicatesOmitted: 1,
      excludedOutOfZoneRecords: 1,
      state: 'verified',
    });
    expect(report.digests[0]?.calculated).toBe(
      'A3B69BAD980A3504E1CFFCB0FD6397F93848071C93151F552AE2F6B1711D4BD2D8B39808226D7B9DB71E34B72077F8FE',
    );
  });

  it('verifies both published digest algorithms in the multiple-digest example', async () => {
    const document = lintZoneSnippet(`
$ORIGIN example.
@ 86400 IN SOA ns1 admin 2018031900 1800 900 604800 86400
@ 86400 IN NS ns1.example.
@ 86400 IN NS ns2.example.
@ 86400 IN ZONEMD 2018031900 1 1 (
  62e6cf51b02e54b9b5f967d547ce43136792901f9f88e637
  493daaf401c92c279dd10f0edb1c56f8080211f8480ee306 )
@ 86400 IN ZONEMD 2018031900 1 2 (
  08cfa1115c7b948c4163a901270395ea226a930cd2cbcf2f
  a9a5e6eb85f37c8a4e114d884e66f176eab121cb02db7d65
  2e0cc4827e7a3204f166b47e5613fd27 )
ns1 3600 IN A 203.0.113.63
ns2 86400 IN TXT "This example has multiple digests"
NS2 3600 IN AAAA 2001:db8::63
`);
    const report = await analyseZoneDigest(document, true);

    expect(report.state).toBe('verified');
    expect(report.digests).toEqual([
      expect.objectContaining({
        calculated:
          '62E6CF51B02E54B9B5F967D547CE43136792901F9F88E637493DAAF401C92C279DD10F0EDB1C56F8080211F8480EE306',
        publications: [expect.objectContaining({ matches: true })],
      }),
      expect.objectContaining({
        calculated:
          '08CFA1115C7B948C4163A901270395EA226A930CD2CBCF2FA9A5E6EB85F37C8A4E114D884E66F176EAB121CB02DB7D652E0CC4827E7A3204F166B47E5613FD27',
        publications: [expect.objectContaining({ matches: true })],
      }),
    ]);
  });

  it('does not calculate a digest for an undeclared snippet or incomplete canonical input', async () => {
    const snippet = lintZoneSnippet('$ORIGIN example.\n@ 300 IN A 192.0.2.1');
    await expect(analyseZoneDigest(snippet, false)).resolves.toMatchObject({
      state: 'unavailable',
    });
    const completeResult = await analyseZoneDigest(snippet, true);
    expect(completeResult.state).toBe('unavailable');
    expect(completeResult.explanation).toMatch(/exactly one SOA/iu);
  });

  it('generates both standard records and accepts generic numeric RDATA', async () => {
    const document = lintZoneSnippet(`
$ORIGIN example.
@ 300 IN SOA ns hostmaster 1 3600 600 86400 300
@ 300 IN NS ns
opaque 300 IN TYPE65280 \\# 4 DEADBEEF
`);
    const report = await analyseZoneDigest(document, true);

    expect(report.state).toBe('generated');
    expect(report.suggestedRecords).toHaveLength(2);
    expect(report.suggestedRecords[0]?.text).toMatch(
      /^example\. 300 IN ZONEMD 1 1 1 [0-9A-F]{96}$/u,
    );
    expect(report.suggestedRecords[1]?.text).toMatch(
      /^example\. 300 IN ZONEMD 1 1 2 [0-9A-F]{128}$/u,
    );
  });

  it('treats numeric ZONEMD records and covering signatures like their named forms', async () => {
    const named = lintZoneSnippet(SIMPLE_EXAMPLE_ZONE);
    const digest =
      'C68090D90A7AED716BC459F9340E3D7C1370D4D24B7E2FC3A1DDC0B9A87153B9A9713B3C9AE5CC27777F98B8E730044C';
    const generic = lintZoneSnippet(`
$ORIGIN example.
example. 86400 IN SOA ns1 admin 2018031900 1800 900 604800 86400
         86400 IN NS ns1
         86400 IN NS ns2
         86400 IN TYPE63 \\# 54 7848B91C0101${digest}
         86400 IN RRSIG TYPE63 15 1 86400 20300101000000 20200101000000 1 example. AA==
ns1      3600 IN A 203.0.113.63
ns2      3600 IN AAAA 2001:db8::63
`);

    const [namedReport, genericReport] = await Promise.all([
      analyseZoneDigest(named, true),
      analyseZoneDigest(generic, true),
    ]);
    expect(genericReport).toMatchObject({
      authentication: 'covering-signature-present-but-unvalidated',
      excludedApexRecords: 2,
      state: 'verified',
    });
    expect(genericReport.digests[0]?.calculated).toBe(namedReport.digests[0]?.calculated);
  });

  it('generates a digest for a minimal complete zone with explicit TTLs', async () => {
    const document = lintZoneSnippet(`$ORIGIN example.
@ 300 IN SOA ns hostmaster 1 3600 600 86400 300
@ 300 IN NS ns
ns 300 IN A 192.0.2.1`);

    expect(document.records.map((record) => record.ttl)).toEqual([300, 300, 300]);
    await expect(analyseZoneDigest(document, true)).resolves.toMatchObject({
      includedRecords: 3,
      state: 'generated',
    });
  });

  it('distinguishes structural owner dots from escaped data dots', async () => {
    const [structural, escaped, decimal] = await Promise.all([
      sha384(generatedZone('foo.bar 300 IN TXT "value"')),
      sha384(generatedZone(String.raw`foo\.bar 300 IN TXT "value"`)),
      sha384(generatedZone(String.raw`foo\046bar 300 IN TXT "value"`)),
    ]);

    expect(escaped).toBe(
      '3732F47F42803D722661125F56D2534BB88415B7535EFAD13251DF45A3352083A7F55A49FFECF43E48F73406F1E9467F',
    );
    expect(escaped).toBe(decimal);
    expect(structural).not.toBe(escaped);
  });

  it.each([
    ['CNAME', 'alias 300 IN CNAME foo.bar', String.raw`alias 300 IN CNAME foo\.bar`],
    ['DNAME', 'dname 300 IN DNAME foo.bar', String.raw`dname 300 IN DNAME foo\.bar`],
    ['NS', 'delegated 300 IN NS foo.bar', String.raw`delegated 300 IN NS foo\.bar`],
    ['PTR', 'ptr 300 IN PTR foo.bar', String.raw`ptr 300 IN PTR foo\.bar`],
    ['MX', 'mail 300 IN MX 10 foo.bar', String.raw`mail 300 IN MX 10 foo\.bar`],
    ['SRV', '_svc 300 IN SRV 1 2 443 foo.bar', String.raw`_svc 300 IN SRV 1 2 443 foo\.bar`],
    [
      'NAPTR',
      'naptr 300 IN NAPTR 1 2 "U" "E2U+sip" "!^.*$!sip:info@example.!" foo.bar',
      String.raw`naptr 300 IN NAPTR 1 2 "U" "E2U+sip" "!^.*$!sip:info@example.!" foo\.bar`,
    ],
    [
      'NSEC',
      'nsec 300 IN NSEC foo.bar A NS SOA',
      String.raw`nsec 300 IN NSEC foo\.bar A NS SOA`,
    ],
    [
      'RRSIG',
      'signed 300 IN RRSIG A 15 3 300 20300101000000 20200101000000 1 foo.bar AA==',
      String.raw`signed 300 IN RRSIG A 15 3 300 20300101000000 20200101000000 1 foo\.bar AA==`,
    ],
    [
      'SVCB',
      'svc 300 IN SVCB 1 foo.bar alpn=h2',
      String.raw`svc 300 IN SVCB 1 foo\.bar alpn=h2`,
    ],
  ])(
    'preserves escaped separators in %s embedded domain names',
    async (_type, plain, escaped) => {
      const [plainDigest, escapedDigest] = await Promise.all([
        sha384(generatedZone(plain)),
        sha384(generatedZone(escaped)),
      ]);

      expect(plainDigest).not.toBe(escapedDigest);
    },
  );

  it('preserves escaped separators in SOA domain names', async () => {
    const [plain, escaped] = await Promise.all([
      sha384(generatedZone('', '@ 300 IN SOA foo.bar hostmaster 1 3600 600 86400 300')),
      sha384(
        generatedZone('', String.raw`@ 300 IN SOA foo\.bar hostmaster 1 3600 600 86400 300`),
      ),
    ]);

    expect(plain).not.toBe(escaped);
  });

  it('uses each record origin and resolves nested relative origin directives', async () => {
    const relative = `$ORIGIN example.
@ 300 IN SOA ns hostmaster 1 3600 600 86400 300
@ 300 IN NS ns
ns 300 IN A 192.0.2.1
$ORIGIN child
www 300 IN CNAME target
$ORIGIN grand
mail 300 IN MX 10 exchanger
`;
    const absolute = `$ORIGIN example.
@ 300 IN SOA ns.example. hostmaster.example. 1 3600 600 86400 300
@ 300 IN NS ns.example.
ns.example. 300 IN A 192.0.2.1
www.child.example. 300 IN CNAME target.child.example.
mail.grand.child.example. 300 IN MX 10 exchanger.grand.child.example.
`;

    const [relativeDigest, absoluteDigest] = await Promise.all([
      sha384(relative),
      sha384(absolute),
    ]);
    expect(relativeDigest).toBe(absoluteDigest);
  });

  it('canonicalises known numeric aliases by semantic type identity', async () => {
    const named = generatedZone('@ 300 IN NS Ns.Example.');
    const generic = generatedZone('@ 300 IN TYPE2 \\# 12 024E73074578616D706C6500');

    const [namedDigest, genericDigest] = await Promise.all([sha384(named), sha384(generic)]);
    expect(namedDigest).toBe(genericDigest);
  });

  it('canonicalises embedded names in generic signature aliases', async () => {
    const named = generatedZone(
      'signed 300 IN RRSIG A 15 3 300 20300101000000 20200101000000 1 signer.example. AA==',
    );
    const generic = generatedZone(
      'signed 300 IN TYPE46 \\# 35 00010F030000012C70DBD8805E0BE1000001065369676E6572074578616D706C650000',
    );

    const [namedDigest, genericDigest] = await Promise.all([sha384(named), sha384(generic)]);
    expect(namedDigest).toBe(genericDigest);
  });

  it('excludes a generic outer signature that covers the apex digest record', async () => {
    const digest =
      'C68090D90A7AED716BC459F9340E3D7C1370D4D24B7E2FC3A1DDC0B9A87153B9A9713B3C9AE5CC27777F98B8E730044C';
    const document = lintZoneSnippet(`
$ORIGIN example.
example. 86400 IN SOA ns1 admin 2018031900 1800 900 604800 86400
         86400 IN NS ns1
         86400 IN NS ns2
         86400 IN TYPE63 \\# 54 7848B91C0101${digest}
         86400 IN TYPE46 \\# 28 003F0F010001518070DBD8805E0BE1000001076578616D706C650000
ns1      3600 IN A 203.0.113.63
ns2      3600 IN AAAA 2001:db8::63
`);

    await expect(analyseZoneDigest(document, true)).resolves.toMatchObject({
      authentication: 'covering-signature-present-but-unvalidated',
      excludedApexRecords: 2,
      state: 'verified',
    });
  });

  it('distinguishes an escaped ALPN comma from a list separator', async () => {
    const [list, literal, genericLiteral] = await Promise.all([
      sha384(generatedZone('svc 300 IN SVCB 1 target alpn="h2,h3"')),
      sha384(generatedZone(String.raw`svc 300 IN SVCB 1 target alpn="h2\092,h3"`)),
      sha384(
        generatedZone(
          'svc 300 IN TYPE64 \\# 28 000106746172676574076578616D706C6500000100060568322C6833',
        ),
      ),
    ]);

    expect(list).not.toBe(literal);
    expect(literal).toBe(genericLiteral);
  });

  it.each([
    String.raw`svc 300 IN SVCB 1 target alpn\061h2`,
    String.raw`svc 300 IN SVCB 1 target mandatory=alpn\044port alpn=h2 port=443`,
    'delegated 300 IN TYPE2 \\# 2 C000',
  ])('fails closed for ambiguous or non-canonical structural input', async (record) => {
    const report = await analyseZoneDigest(lintZoneSnippet(generatedZone(record)), true);

    expect(report.state).toBe('unavailable');
    expect(report.digests).toEqual([]);
    expect(report.suggestedRecords).toEqual([]);
  });
});
