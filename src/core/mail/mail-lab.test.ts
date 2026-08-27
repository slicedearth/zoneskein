import { gzipSync, strToU8, zipSync } from 'fflate';
import { describe, expect, it } from 'vitest';

import { inspectArcChain } from './arc';
import { inspectBimiSvg, parseBimiRecord } from './bimi';
import { inspectCertificate, verifyTlsaAssociation } from './certificate';
import { parseDmarcAggregateXml } from './dmarc-aggregate';
import { authorMtaStsPolicy, mtaStsMxCoverage, parseMtaStsPolicy } from './mta-sts';
import { extractMailReportPayloads } from './report-archive';
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
