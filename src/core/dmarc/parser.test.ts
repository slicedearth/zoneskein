import { describe, expect, it } from 'vitest';

import {
  assessDmarcPolicy,
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

  it('requires independent discovery before treating a descendant report host as internal', () => {
    const policy = parseDmarcRecord(
      'v=DMARC1; p=none; rua=mailto:dmarc@reports.example.com,mailto:dmarc@example.com',
      'example.com',
      'example.com',
    );

    expect(policy.destinations).toEqual([
      expect.objectContaining({
        authorizationName: 'example.com._report._dmarc.reports.example.com',
        domain: 'reports.example.com',
        external: true,
      }),
      expect.objectContaining({ domain: 'example.com', external: false }),
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

  it('requires the case-sensitive version value and supports rua-only policy', () => {
    expect(isDmarcRecord('v=DMARC1; p=none')).toBe(true);
    expect(isDmarcRecord('V = DMARC1; p=none')).toBe(true);
    expect(isDmarcRecord('v=dmarc1; p=none')).toBe(false);
    const policy = parseDmarcRecord('v=DMARC1; rua=mailto:reports@example.com', 'example.com');
    expect(policy.applicable).toBe(true);
    expect(policy.effectiveDisposition).toBe('none');
    expect(policy.diagnostics.map((item) => item.code)).toContain('policy-default-none');
  });

  it('defaults an otherwise valid record without p to none even when reporting is absent', () => {
    const policy = parseDmarcRecord('v=DMARC1; adkim=s', 'example.com');

    expect(policy.applicable).toBe(true);
    expect(policy.effectiveDisposition).toBe('none');
    expect(policy.fallbackToNone).toBe(false);
    expect(policy.valid).toBe(true);
  });

  it.each(['p', 'sp', 'np'] as const)(
    'applies the valid-rua p=none fallback when %s is invalid',
    (tag) => {
      const assessmentTag = tag === 'p' ? 'p=invalid' : `p=reject; ${tag}=invalid`;
      const policy = parseDmarcRecord(
        `v=DMARC1; ${assessmentTag}; rua=mailto:reports@example.com`,
        'example.com',
      );

      expect(policy.applicable).toBe(true);
      expect(policy.effectiveDisposition).toBe('none');
      expect(policy.fallbackToNone).toBe(true);
      expect(policy.valid).toBe(false);
      expect(policy.diagnostics.map((item) => item.code)).toContain(
        'assessment-policy-fallback',
      );
    },
  );

  it.each(['p', 'sp', 'np'] as const)(
    'does not apply DMARC when %s is invalid and rua has no valid URI',
    (tag) => {
      const assessmentTag = tag === 'p' ? 'p=invalid' : `p=reject; ${tag}=invalid`;
      for (const reporting of ['', '; rua=mailto:']) {
        const policy = parseDmarcRecord(
          `v=DMARC1; ${assessmentTag}${reporting}`,
          'example.com',
        );

        expect(policy.applicable).toBe(false);
        expect(policy.effectiveDisposition).toBeUndefined();
        expect(policy.fallbackToNone).toBe(false);
      }
    },
  );

  it('selects p, sp, and np for direct, existing inherited, and non-existent inherited use', () => {
    const policy = parseDmarcRecord(
      'v=DMARC1; p=reject; sp=quarantine; np=none',
      'example.com',
    );

    expect(assessDmarcPolicy(policy, 'direct-author-domain')).toEqual(
      expect.objectContaining({
        appliedDisposition: 'reject',
        declaredDisposition: 'reject',
        selectedTag: 'p',
      }),
    );
    expect(assessDmarcPolicy(policy, 'existing-inherited-subdomain')).toEqual(
      expect.objectContaining({
        appliedDisposition: 'quarantine',
        declaredDisposition: 'quarantine',
        selectedTag: 'sp',
      }),
    );
    expect(assessDmarcPolicy(policy, 'non-existent-inherited-subdomain')).toEqual(
      expect.objectContaining({
        appliedDisposition: 'none',
        declaredDisposition: 'none',
        selectedTag: 'np',
      }),
    );
  });

  it('falls back from missing np to sp and from missing subdomain tags to p', () => {
    const withSp = parseDmarcRecord('v=DMARC1; p=reject; sp=quarantine', 'example.com');
    const pOnly = parseDmarcRecord('v=DMARC1; p=reject', 'example.com');

    expect(assessDmarcPolicy(withSp, 'non-existent-inherited-subdomain')).toEqual(
      expect.objectContaining({ appliedDisposition: 'quarantine', selectedTag: 'sp' }),
    );
    expect(assessDmarcPolicy(pOnly, 'existing-inherited-subdomain')).toEqual(
      expect.objectContaining({ appliedDisposition: 'reject', selectedTag: 'p' }),
    );
    expect(assessDmarcPolicy(pOnly, 'non-existent-inherited-subdomain')).toEqual(
      expect.objectContaining({ appliedDisposition: 'reject', selectedTag: 'p' }),
    );
  });

  it.each([
    ['direct-author-domain', 'reject', 'quarantine', 'p'],
    ['existing-inherited-subdomain', 'quarantine', 'none', 'sp'],
    ['non-existent-inherited-subdomain', 'none', 'none', 'np'],
  ] as const)(
    'reduces %s policy by one level under t=y without changing reporting',
    (context, declared, applied, selectedTag) => {
      const policy = parseDmarcRecord(
        'v=DMARC1; p=reject; sp=quarantine; np=none; t=y; rua=mailto:reports@example.com',
        'example.com',
      );
      const assessment = assessDmarcPolicy(policy, context);

      expect(assessment).toEqual(
        expect.objectContaining({
          appliedDisposition: applied,
          declaredDisposition: declared,
          selectedTag,
          testing: true,
        }),
      );
      expect(policy.destinations).toHaveLength(1);
      expect(policy.destinations[0]?.uri).toBe('mailto:reports@example.com');
    },
  );

  it('preserves a valid declared tag while applying the record-wide rua fallback', () => {
    const policy = parseDmarcRecord(
      'v=DMARC1; p=reject; sp=invalid; rua=mailto:reports@example.com',
      'example.com',
    );
    const assessment = assessDmarcPolicy(policy, 'direct-author-domain');

    expect(assessment).toEqual(
      expect.objectContaining({
        appliedDisposition: 'none',
        declaredDisposition: 'reject',
        fallbackToNone: true,
        selectedTag: 'p',
      }),
    );
  });

  it('accepts only alphabetic tag names and ignores malformed trailing tags safely', () => {
    const policy = parseDmarcRecord(
      'V=DMARC1; p=reject; x-provider=ignored; x1=ignored; note=ok',
      'example.com',
    );

    expect(policy.applicable).toBe(true);
    expect(policy.valid).toBe(false);
    expect(policy.tags.map((tag) => tag.name)).toEqual(['v', 'p', 'note']);
    expect(policy.diagnostics.map((item) => item.code)).toEqual(
      expect.arrayContaining(['tag-name-invalid', 'tag-unknown']),
    );
  });

  it('bounds records and tags before parsing and catches malformed reporting escapes', () => {
    const overlong = parseDmarcRecord(
      `v=DMARC1; p=none; note=${'a'.repeat(8_193)}`,
      'example.com',
    );
    const tooManyTags = parseDmarcRecord(
      `v=DMARC1; p=none; ${Array.from(
        { length: 63 },
        (_, index) =>
          `x${String.fromCharCode(97 + Math.floor(index / 26))}${String.fromCharCode(97 + (index % 26))}=a`,
      ).join(';')}`,
      'example.com',
    );
    const malformedUri = parseDmarcRecord(
      'v=DMARC1; p=none; rua=mailto:dmarc@exa%mple.test',
      'example.com',
    );

    expect(overlong.applicable).toBe(false);
    expect(overlong.diagnostics[0]?.code).toBe('record-too-long');
    expect(tooManyTags.applicable).toBe(false);
    expect(tooManyTags.diagnostics[0]?.code).toBe('tag-limit');
    expect(malformedUri.valid).toBe(false);
    expect(malformedUri.diagnostics.map((item) => item.code)).toContain('report-uri-invalid');
  });

  it('rejects reporting URIs whose mailto query fields could add recipients', () => {
    const policy = parseDmarcRecord(
      'v=DMARC1; p=none; rua=mailto:reports@example.com?bcc=copy@attacker.test; ruf=mailto:forensic@example.com#fragment',
      'example.com',
    );

    expect(policy.valid).toBe(false);
    expect(policy.destinations).toHaveLength(2);
    expect(policy.destinations.every((destination) => destination.domain === undefined)).toBe(
      true,
    );
    expect(
      policy.diagnostics.filter((item) => item.code === 'report-uri-invalid'),
    ).toHaveLength(2);
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
