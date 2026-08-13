import { describe, expect, it } from 'vitest';

import { dmarcDiscoveryNames, parseDmarcRecord } from './parser';

describe('DMARC policy parser', () => {
  it('parses policy tags and external report authorization names', () => {
    const policy = parseDmarcRecord(
      'v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc@reports.example.net!10m',
      'example.com',
    );
    expect(policy.valid).toBe(true);
    expect(policy.destinations).toEqual([
      expect.objectContaining({
        authorizationName: 'example.com._report._dmarc.reports.example.net',
        external: true,
      }),
    ]);
  });

  it('detects malformed and duplicate tags', () => {
    const policy = parseDmarcRecord(
      'p=invalid; v=DMARC1; p=reject; pct=101; adkim=x; fo=0:0',
      'example.com',
    );
    expect(policy.diagnostics.map((item) => item.code)).toEqual(
      expect.arrayContaining([
        'version-invalid',
        'tag-duplicate',
        'percentage-invalid',
        'alignment-invalid',
        'failure-options-invalid',
      ]),
    );
  });

  it('uses the public suffix list for fallback discovery', () => {
    expect(dmarcDiscoveryNames('mail.example.co.uk')).toEqual([
      '_dmarc.mail.example.co.uk',
      '_dmarc.example.co.uk',
    ]);
  });
});
