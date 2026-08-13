import { describe, expect, it } from 'vitest';

import {
  dmarcDiscoveryNames,
  isDmarcRecord,
  parseDmarcRecord,
  selectDmarcPolicy,
} from './parser';

describe('DMARC policy parser', () => {
  it('parses policy tags and external report authorisation names', () => {
    const policy = parseDmarcRecord(
      'v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc@reports.example.net!10m',
      'example.com',
    );
    expect(policy.valid).toBe(true);
    expect(policy.diagnostics.map((item) => item.code)).toContain('historic-tag');
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
        'historic-tag',
        'alignment-invalid',
        'failure-options-invalid',
      ]),
    );
  });

  it('builds the bounded DNS tree walk without a public suffix list', () => {
    expect(dmarcDiscoveryNames('mail.example.co.uk')).toEqual([
      '_dmarc.mail.example.co.uk',
      '_dmarc.example.co.uk',
      '_dmarc.co.uk',
      '_dmarc.uk',
    ]);
    expect(dmarcDiscoveryNames('a.b.c.d.e.f.g.h.i.example')).toEqual([
      '_dmarc.a.b.c.d.e.f.g.h.i.example',
      '_dmarc.d.e.f.g.h.i.example',
      '_dmarc.e.f.g.h.i.example',
      '_dmarc.f.g.h.i.example',
      '_dmarc.g.h.i.example',
      '_dmarc.h.i.example',
      '_dmarc.i.example',
      '_dmarc.example',
    ]);
  });

  it('requires the case-sensitive version marker and supports rua-only policy', () => {
    expect(isDmarcRecord('v=DMARC1; p=none')).toBe(true);
    expect(isDmarcRecord('V=DMARC1; p=none')).toBe(false);
    const policy = parseDmarcRecord('v=DMARC1; rua=mailto:reports@example.com', 'example.com');
    expect(policy.applicable).toBe(true);
    expect(policy.effectiveDisposition).toBe('none');
    expect(policy.diagnostics.map((item) => item.code)).toContain('policy-default-none');
  });

  it('selects organisational and public-suffix policies from tree-walk markers', () => {
    const organizational = parseDmarcRecord('v=DMARC1; p=reject; psd=n', 'example.com');
    const selection = selectDmarcPolicy('mail.example.com', [
      { domain: 'mail.example.com' },
      { domain: 'example.com', policy: organizational },
    ]);
    expect(selection).toEqual(
      expect.objectContaining({
        organizationalDomain: 'example.com',
        source: 'organizational',
      }),
    );

    const psd = parseDmarcRecord('v=DMARC1; p=none; psd=y', 'bank');
    const psdSelection = selectDmarcPolicy('login.example.bank', [
      { domain: 'login.example.bank' },
      { domain: 'example.bank' },
      { domain: 'bank', policy: psd },
    ]);
    expect(psdSelection).toEqual(
      expect.objectContaining({
        organizationalDomain: 'example.bank',
        source: 'public-suffix',
      }),
    );
  });

  it('uses the direct author-domain record before an inherited record', () => {
    const direct = parseDmarcRecord('v=DMARC1; p=quarantine', 'mail.example.co.uk');
    const parent = parseDmarcRecord('v=DMARC1; p=reject; psd=n', 'example.co.uk');
    const selection = selectDmarcPolicy('mail.example.co.uk', [
      { domain: 'mail.example.co.uk', policy: direct },
      { domain: 'example.co.uk', policy: parent },
      { domain: 'co.uk' },
      { domain: 'uk' },
    ]);
    expect(selection.source).toBe('direct');
    expect(selection.selected?.domain).toBe('mail.example.co.uk');
    expect(selection.organizationalDomain).toBe('example.co.uk');
  });
});
