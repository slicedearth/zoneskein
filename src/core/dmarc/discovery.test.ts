import { describe, expect, it, vi } from 'vitest';

import {
  discoverDmarc,
  DmarcDiscoverySession,
  type DmarcTxtLookup,
  type DmarcTxtLookupResult,
} from './discovery';

function fixtureLookup(
  answers: Readonly<Record<string, DmarcTxtLookupResult>>,
): DmarcTxtLookup {
  return vi.fn((name: string) =>
    Promise.resolve<DmarcTxtLookupResult>(
      answers[name] ?? {
        status: 'nxdomain' as const,
        values: [],
      },
    ),
  );
}

function answer(...values: string[]): DmarcTxtLookupResult {
  return { status: values.length === 0 ? 'nodata' : 'answer', ttl: 300, values };
}

describe('bounded DMARC discovery', () => {
  it('selects a direct policy while independently deriving its parent boundary', async () => {
    const lookup = fixtureLookup({
      '_dmarc.mail.example.com': answer('v=DMARC1; p=reject'),
      '_dmarc.example.com': answer('v=DMARC1; p=none; psd=n'),
    });
    const result = await discoverDmarc('MAIL.EXAMPLE.COM.', lookup);

    expect(result).toEqual(
      expect.objectContaining({
        domain: 'mail.example.com',
        organizationalDomain: 'example.com',
        status: 'complete',
      }),
    );
    expect(result.selected).toEqual(
      expect.objectContaining({
        domain: 'mail.example.com',
        queryName: '_dmarc.mail.example.com',
      }),
    );
    expect(result.selection.source).toBe('direct');
    expect(result.authorDomainExistence).toBeUndefined();
    expect(result.selected?.assessment).toEqual(
      expect.objectContaining({ appliedDisposition: 'reject', selectedTag: 'p' }),
    );
    expect(lookup).toHaveBeenCalledTimes(2);
  });

  it('derives an organisational domain one label below a psd=y record', async () => {
    const result = await discoverDmarc(
      'login.example.bank',
      fixtureLookup({
        '_dmarc.bank': answer('v=DMARC1; p=none; psd=y'),
      }),
    );

    expect(result.status).toBe('complete');
    expect(result.organizationalDomain).toBe('example.bank');
    expect(result.selected?.domain).toBe('bank');
    expect(result.selection.source).toBe('public-suffix');
    expect(result.authorDomainExistence).toBe('non-existent');
    expect(result.selected?.assessment).toEqual(
      expect.objectContaining({ appliedDisposition: 'none', selectedTag: 'p' }),
    );
  });

  it('selects sp for an inherited policy when a NODATA response proves the author exists', async () => {
    const result = await discoverDmarc(
      'mail.example.com',
      fixtureLookup({
        '_dmarc.example.com': answer('v=DMARC1; p=reject; sp=quarantine; np=none; psd=n'),
        'mail.example.com': answer(),
      }),
    );

    expect(result.status).toBe('complete');
    expect(result.authorDomainExistence).toBe('existing');
    expect(result.selected?.assessment).toEqual(
      expect.objectContaining({
        appliedDisposition: 'quarantine',
        context: 'existing-inherited-subdomain',
        selectedTag: 'sp',
      }),
    );
    expect(result.questions.at(-1)).toEqual(
      expect.objectContaining({
        name: 'mail.example.com',
        purpose: 'domain-existence',
        status: 'nodata',
      }),
    );
  });

  it('selects np for an inherited policy when NXDOMAIN proves the author is non-existent', async () => {
    const result = await discoverDmarc(
      'missing.example.com',
      fixtureLookup({
        '_dmarc.example.com': answer('v=DMARC1; p=reject; sp=quarantine; np=none; psd=n'),
      }),
    );

    expect(result.status).toBe('complete');
    expect(result.authorDomainExistence).toBe('non-existent');
    expect(result.selected?.assessment).toEqual(
      expect.objectContaining({
        appliedDisposition: 'none',
        context: 'non-existent-inherited-subdomain',
        selectedTag: 'np',
      }),
    );
  });

  it('fails inherited assessment closed when author-domain existence is unresolved', async () => {
    const result = await discoverDmarc(
      'mail.example.com',
      fixtureLookup({
        '_dmarc.example.com': answer('v=DMARC1; p=reject; sp=quarantine; psd=n'),
        'mail.example.com': {
          error: 'The resolver returned SERVFAIL.',
          status: 'temperror',
          values: [],
        },
      }),
    );

    expect(result.status).toBe('temperror');
    expect(result.selected).toBeUndefined();
    expect(result.reason).toMatch(/cannot be selected safely/iu);
  });

  it('uses the initial domain as the boundary after a complete walk with no policy', async () => {
    const result = await discoverDmarc('signer.example.com', fixtureLookup({}));

    expect(result.status).toBe('complete');
    expect(result.organizationalDomain).toBe('signer.example.com');
    expect(result.selected).toBeUndefined();
    expect(result.questions).toHaveLength(3);
  });

  it('discards multiple records at one node and continues to a parent policy', async () => {
    const result = await discoverDmarc(
      'mail.example.com',
      fixtureLookup({
        '_dmarc.mail.example.com': answer('v=DMARC1; p=reject', 'v=DMARC1; p=quarantine'),
        '_dmarc.example.com': answer('v=DMARC1; p=none; psd=n'),
      }),
    );

    expect(result.status).toBe('complete');
    expect(result.selected?.domain).toBe('example.com');
    expect(result.questions[0]?.dmarcRecords).toBe(2);
    expect(result.questions[0]?.detail).toMatch(/discarded/iu);
  });

  it('does not inherit a parent policy after an invalid assessment tag without valid rua', async () => {
    const lookup = fixtureLookup({
      '_dmarc.mail.example.com': answer('v=DMARC1; p=invalid'),
      '_dmarc.example.com': answer('v=DMARC1; p=reject; psd=n'),
    });
    const result = await discoverDmarc('mail.example.com', lookup);

    expect(result.status).toBe('complete');
    expect(result.selected).toBeUndefined();
    expect(result.rejected?.domain).toBe('mail.example.com');
    expect(result.rejected?.policy.diagnostics.map((item) => item.code)).toContain(
      'policy-invalid',
    );
    expect(result.reason).toMatch(/no parent policy is inherited/iu);
    expect(lookup).toHaveBeenCalledOnce();
  });

  it('fails closed on a transient DNS error even after seeing a direct policy', async () => {
    const result = await discoverDmarc(
      'mail.example.com',
      fixtureLookup({
        '_dmarc.mail.example.com': answer('v=DMARC1; p=reject'),
        '_dmarc.example.com': {
          error: 'The resolver returned SERVFAIL.',
          status: 'temperror',
          values: [],
        },
      }),
    );

    expect(result.status).toBe('temperror');
    expect(result.selected).toBeUndefined();
    expect(result.organizationalDomain).toBeUndefined();
    expect(result.reason).toMatch(/boundary is incomplete/iu);
  });

  it('bounds hostile TXT sets and overlong records', async () => {
    const tooMany = await discoverDmarc(
      'example.com',
      fixtureLookup({
        '_dmarc.example.com': answer(
          ...Array.from({ length: 65 }, (_, index) => `unrelated-${String(index)}`),
        ),
      }),
    );
    const tooLong = await discoverDmarc(
      'example.net',
      fixtureLookup({
        '_dmarc.example.net': answer(`v=DMARC1; p=none; x=${'a'.repeat(8_193)}`),
      }),
    );

    expect(tooMany.status).toBe('indeterminate');
    expect(tooLong.status).toBe('indeterminate');
  });

  it('rejects malformed input before querying DNS', async () => {
    const lookup = fixtureLookup({});
    const result = await discoverDmarc('https://example.com', lookup);

    expect(result.status).toBe('permerror');
    expect(lookup).not.toHaveBeenCalled();
  });

  it('shares repeated questions and enforces one global session limit', async () => {
    const lookup = fixtureLookup({});
    const session = new DmarcDiscoverySession(lookup, 2);

    await expect(session.lookup('_dmarc.example.com')).resolves.toEqual(
      expect.objectContaining({ status: 'nxdomain' }),
    );
    await session.lookup('_dmarc.example.com');
    await session.lookup('_dmarc.example.net');
    await expect(session.lookup('_dmarc.example.org')).resolves.toEqual(
      expect.objectContaining({ status: 'limit' }),
    );

    expect(session.questionsUsed).toBe(2);
    expect(lookup).toHaveBeenCalledTimes(2);
  });

  it('fails a tree walk closed when its shared session is cancelled', async () => {
    let cancelled = false;
    const lookup: DmarcTxtLookup = vi.fn(() => {
      cancelled = true;
      return Promise.resolve(answer('v=DMARC1; p=none'));
    });
    const session = new DmarcDiscoverySession(lookup, 80, () => cancelled);

    const result = await session.discover('cancelled.example');

    expect(result.status).toBe('temperror');
    expect(result.reason).toMatch(/cancelled/iu);
    expect(session.questionsUsed).toBe(1);
  });
});
