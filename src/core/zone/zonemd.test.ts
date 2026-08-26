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
});
