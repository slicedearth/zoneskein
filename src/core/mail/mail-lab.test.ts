import { gzipSync, strToU8, Zip, ZipDeflate, zipSync } from 'fflate';
import { describe, expect, it } from 'vitest';

import { inspectArcChain } from './arc';
import { inspectBimiSvg, parseBimiRecord } from './bimi';
import { inspectCertificate, verifyTlsaAssociation } from './certificate';
import { parseDmarcAggregateXml } from './dmarc-aggregate';
import { authorMtaStsPolicy, mtaStsMxCoverage, parseMtaStsPolicy } from './mta-sts';
import {
  extractMailReportPayloads,
  MAIL_REPORT_MAX_FEED_OUTPUT,
  type MailArchiveProgress,
} from './report-archive';
import { parseTlsAggregateJson, parseTlsRptRecord } from './tlsrpt';

const DMARC_XML = `<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>Example Receiver</org_name>
    <report_id>report-42</report_id>
    <date_range><begin>1722470400</begin><end>1722556800</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>reject</p></policy_published>
  <record>
    <row>
      <source_ip>192.0.2.1</source_ip><count>7</count>
      <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from><envelope_from>mail.example.com</envelope_from></identifiers>
  </record>
</feedback>`;

describe('mail evidence parsers', () => {
  const svg = (body: string, attributes = '') =>
    `<s:svg xmlns:s="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" baseProfile="tiny-ps" viewBox="0 0 100 100" ${attributes}><s:title>Local fixture</s:title>${body}</s:svg>`;

  it.each([
    'script',
    'animate',
    'animateMotion',
    'animateTransform',
    'set',
    'foreignObject',
    'image',
    'a',
    'unknown',
  ])('rejects namespace-prefixed active or unsupported SVG element %s', (name) => {
    expect(inspectBimiSvg(svg(`<s:${name}/>`)).valid).toBe(false);
  });

  it.each(['fill', 'stroke', 'filter', 'clip-path', 'mask', 'marker-start', 'style'])(
    'rejects external references in %s and escaped CSS',
    (attribute) => {
      expect(
        inspectBimiSvg(svg(`<s:path ${attribute}="url(https://example.com/resource)"/>`)).valid,
      ).toBe(false);
      expect(
        inspectBimiSvg(svg(`<s:path ${attribute}="u\\72l(https://example.com/resource)"/>`))
          .valid,
      ).toBe(false);
    },
  );

  it('accepts prefixed static elements and literal local gradient and use references', () => {
    expect(
      inspectBimiSvg(
        svg(
          '<s:defs><s:linearGradient id="paint"><s:stop offset="0" stop-color="red"/></s:linearGradient><s:path id="shape" d="M0 0h10v10z"/></s:defs><s:use xlink:href="#shape" fill="url(#paint)"/>',
        ),
      ).valid,
    ).toBe(true);
  });

  it.each([
    '<path xmlns="urn:foreign"/>',
    '<s:path xmlns:x="urn:foreign" x:href="#local"/>',
    '<s:path onload="alert(1)"/>',
    '<s:use xlink:href="https://example.com/shape"/>',
    '<?xml-stylesheet href="https://example.com/style.css"?>',
  ])('rejects unsupported namespaces, events and indirect resources: %s', (body) => {
    expect(inspectBimiSvg(svg(body)).valid).toBe(false);
  });

  it('rejects foreign roots, namespace removal and redirected fragment bases', () => {
    expect(
      inspectBimiSvg(
        '<svg xmlns="urn:foreign" baseProfile="tiny-ps" viewBox="0 0 1 1"><title>X</title></svg>',
      ).valid,
    ).toBe(false);
    expect(inspectBimiSvg(svg('<g xmlns=""><script/></g>')).valid).toBe(false);
    expect(
      inspectBimiSvg(svg('<s:use xlink:href="#shape"/>', 'xml:base="https://example.com/"'))
        .valid,
    ).toBe(false);
  });

  it.each([0, 1, 9] as const)(
    'stops gzip expansion before consuming a large output at level %s',
    (level) => {
      const compressed = gzipSync(new Uint8Array(2 * 1024 * 1024).fill(65), { level });
      const observations: MailArchiveProgress[] = [];
      expect(() =>
        extractMailReportPayloads('report.xml.gz', compressed, {
          expandedOctets: 1024,
          onProgress: (value) => observations.push(value),
        }),
      ).toThrow(/safety limit/u);
      const last = observations.at(-1);
      expect(last?.inputOctets).toBeLessThan(compressed.length);
      expect(last?.retainedOctets).toBeLessThanOrEqual(1024);
      expect(last?.outputOctets).toBeLessThanOrEqual(1024 + MAIL_REPORT_MAX_FEED_OUTPUT);
      expect(last?.largestChunkOctets).toBeLessThanOrEqual(MAIL_REPORT_MAX_FEED_OUTPUT);
      expect(last?.pushes).toBeLessThanOrEqual(Math.ceil((last?.inputOctets ?? 0) / 128));
    },
  );

  it('bounds ZIP data-descriptor output without trusting missing header sizes', () => {
    const chunks: Uint8Array[] = [];
    const zip = new Zip((error, chunk) => {
      if (error !== null) throw error;
      chunks.push(chunk);
    });
    const file = new ZipDeflate('report.xml');
    zip.add(file);
    file.push(new Uint8Array(2 * 1024 * 1024).fill(65), true);
    zip.end();
    const bytes = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    expect((bytes[6] ?? 0) & 8).toBe(8);
    expect(new DataView(bytes.buffer).getUint32(22, true)).toBe(0);
    const observations: MailArchiveProgress[] = [];
    expect(() =>
      extractMailReportPayloads('report.zip', bytes, {
        expandedOctets: 2048,
        entryOctets: 1024,
        onProgress: (value) => observations.push(value),
      }),
    ).toThrow(/expanded|safety limit/u);
    const last = observations.at(-1);
    expect(last?.inputOctets).toBeLessThan(bytes.length);
    expect(last?.retainedOctets).toBeLessThanOrEqual(1024);
    expect(last?.outputOctets).toBeLessThanOrEqual(1024 + MAIL_REPORT_MAX_FEED_OUTPUT);
  });

  it('shares a cumulative budget across ZIP entries and honours a remaining bundle budget', () => {
    const bytes = zipSync({
      'one.xml': strToU8('a'.repeat(600)),
      'two.json': strToU8('b'.repeat(600)),
    });
    expect(() =>
      extractMailReportPayloads('report.zip', bytes, { expandedOctets: 1000 }),
    ).toThrow(/expanded|safety limit/u);
    expect(() =>
      extractMailReportPayloads('report.xml', strToU8('abcd'), { expandedOctets: 3 }),
    ).toThrow(/safety limit/u);
    expect(
      new TextDecoder().decode(
        extractMailReportPayloads('report.xml.gz', gzipSync(strToU8('abcd')), {
          expandedOctets: 4,
        })[0]?.bytes,
      ),
    ).toBe('abcd');
  });

  it('summarises bounded DMARC aggregate XML and rejects document types', () => {
    const report = parseDmarcAggregateXml(DMARC_XML);

    expect(report).toMatchObject({
      domain: 'example.com',
      organisation: 'Example Receiver',
      policy: 'reject',
      reportId: 'report-42',
      summary: { aligned: 7, quarantined: 0, rejected: 7, total: 7 },
    });
    expect(report.records).toHaveLength(1);
    expect(() => parseDmarcAggregateXml('<!DOCTYPE feedback><feedback/>')).toThrow(
      /document type/u,
    );
    expect(
      parseDmarcAggregateXml(DMARC_XML.replace('192.0.2.1', 'not-an-address')).errors,
    ).toContain('Record 1 has no valid source IP or count.');
  });

  it('summarises TLS aggregate JSON and validates report destinations', () => {
    const report = parseTlsAggregateJson(
      JSON.stringify({
        'organization-name': 'Example Receiver',
        'report-id': 'tls-42',
        policies: [
          {
            policy: { 'policy-domain': 'example.com', 'policy-type': 'sts' },
            summary: {
              'total-failure-session-count': 2,
              'total-successful-session-count': 11,
            },
            'failure-details': [
              {
                'failed-session-count': 2,
                'receiving-ip': '192.0.2.2',
                'result-type': 'certificate-host-mismatch',
                'sending-mta-ip': '198.51.100.3',
              },
            ],
          },
        ],
      }),
    );

    expect(report.summary).toEqual({ failed: 2, successful: 11 });
    expect(report.policies[0]?.failures[0]?.resultType).toBe('certificate-host-mismatch');
    expect(parseTlsRptRecord('v=TLSRPTv1; rua=mailto:tls@example.com').valid).toBe(true);
    expect(parseTlsRptRecord('v=TLSRPTv1; rua=http://example.com/report').valid).toBe(false);
    expect(parseTlsRptRecord('rua=mailto:tls@example.com; v=TLSRPTv1').valid).toBe(false);
    expect(parseTlsRptRecord('v=TLSRPTv1; rua=https://user@example.com/report').valid).toBe(
      false,
    );
  });

  it('expands bounded gzip and ZIP report files without accepting path traversal', () => {
    const xmlBytes = strToU8(DMARC_XML);
    const compressed = gzipSync(xmlBytes);
    const gzipPayload = extractMailReportPayloads('aggregate.xml.gz', compressed);
    const zipPayloads = extractMailReportPayloads(
      'reports.zip',
      zipSync({
        '../outside.xml': xmlBytes,
        'aggregate.xml': xmlBytes,
        'notes.txt': strToU8('ignored'),
      }),
    );

    expect(gzipPayload[0]?.name).toBe('aggregate.xml');
    expect(new TextDecoder().decode(gzipPayload[0]?.bytes)).toBe(DMARC_XML);
    expect(zipPayloads.map((payload) => payload.name)).toEqual(['aggregate.xml']);
  });

  it('parses, authors, and checks MTA-STS policy coverage', () => {
    const source = authorMtaStsPolicy('enforce', 604_800, [
      'mx1.example.com',
      '*.mail.example.net',
    ]);
    const policy = parseMtaStsPolicy(source);

    expect(policy.valid).toBe(true);
    expect(mtaStsMxCoverage(policy, ['mx1.example.com.', 'mx2.mail.example.net'])).toEqual([
      { covered: true, host: 'mx1.example.com.' },
      { covered: true, host: 'mx2.mail.example.net' },
    ]);
    expect(parseMtaStsPolicy('version: STSv1\nmode: enforce\nmax_age: 31557601').valid).toBe(
      false,
    );
  });

  it('matches exactly one non-empty wildcard label in MTA-STS policies', () => {
    const policy = parseMtaStsPolicy(
      'version: STSv1\nmode: enforce\nmx: *.example.com\nmx: exact.example.net\nmax_age: 300',
    );
    expect(
      mtaStsMxCoverage(policy, [
        'mail.example.com',
        'MAIL.EXAMPLE.COM.',
        'example.com',
        '.example.com',
        'foo.bar.example.com',
        'exact.EXAMPLE.net.',
        'other.example.net',
      ]).map((item) => item.covered),
    ).toEqual([true, true, false, false, false, true, false]);
  });

  it('keeps BIMI inspection static and treats ARC as structural evidence only', () => {
    const bimi = parseBimiRecord(
      'v=BIMI1; l=https://assets.example.com/logo.svg; a=https://assets.example.com/vmc.pem',
    );
    const svg = inspectBimiSvg(
      '<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 100 100"><title>Example</title><path d="M0 0h100v100z"/></svg>',
    );
    const unsafeSvg = inspectBimiSvg(
      '<svg baseProfile="tiny-ps" viewBox="0 0 1 1"><title>X</title><image href="https://example.com/a.png"/></svg>',
    );
    const arc = inspectArcChain(
      [
        'ARC-Seal: i=1; a=rsa-sha256; d=example.com; s=arc; cv=none; b=AA',
        'ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=arc; b=AA',
        'ARC-Authentication-Results: i=1; mx.example; dkim=pass',
        'From: sender@example.com',
        '',
        'Body',
      ].join('\r\n'),
    );

    expect(bimi.valid).toBe(true);
    expect(svg).toMatchObject({ elements: 3, title: 'Example', valid: true });
    expect(unsafeSvg.valid).toBe(false);
    expect(arc.state).toBe('structurally-valid');
    expect(arc.instances).toHaveLength(1);
    expect(
      inspectArcChain(
        [
          'ARC-Seal: i=1; i=1; a=rsa-sha256; d=example.com; s=arc; cv=none; b=AA',
          'ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=arc; b=AA',
          'ARC-Authentication-Results: i=1; mx.example; dkim=pass',
          '',
          'Body',
        ].join('\r\n'),
      ).state,
    ).toBe('invalid');
  });

  it('matches bounded TLSA associations without needing network access', async () => {
    const der = new Uint8Array([1, 2, 3, 4]);
    const spki = new Uint8Array([5, 6, 7, 8]);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', spki));
    const association = [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');

    await expect(
      verifyTlsaAssociation(`3 1 1 ${association}`, der, spki),
    ).resolves.toMatchObject({ matches: true });
    await expect(verifyTlsaAssociation('3 2 1 aabb', der, spki)).resolves.toMatchObject({
      matches: false,
    });
    await expect(verifyTlsaAssociation('3 1 1 aabb', der, spki)).resolves.toEqual({
      matches: false,
      reason: 'TLSA matching type 1 requires exactly 64 hexadecimal characters.',
    });
    await expect(
      inspectCertificate(
        '-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAg==\n-----END CERTIFICATE-----',
      ),
    ).rejects.toThrow(/exactly one PEM certificate/u);
  });
});
