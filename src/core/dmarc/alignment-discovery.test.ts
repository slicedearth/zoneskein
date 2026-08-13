import { describe, expect, it, vi } from 'vitest';

import { discoverAndEvaluateDmarcAlignment } from './alignment-discovery';
import type { DmarcTxtLookup, DmarcTxtLookupResult } from './discovery';

function lookupFixture(
  values: Readonly<Record<string, readonly string[] | DmarcTxtLookupResult>>,
): DmarcTxtLookup {
  return vi.fn((name: string) => {
    const value = values[name];
    if (value === undefined)
      return Promise.resolve<DmarcTxtLookupResult>({ status: 'nxdomain', values: [] });
    if (Array.isArray(value)) {
      const strings = value as readonly string[];
      return Promise.resolve<DmarcTxtLookupResult>({
        status: strings.length === 0 ? 'nodata' : 'answer',
        values: strings,
      });
    }
    return Promise.resolve(value as DmarcTxtLookupResult);
  });
}

const authorPolicy = {
  '_dmarc.mail.example.com': ['v=DMARC1; p=reject; adkim=r; aspf=r'],
  '_dmarc.example.com': ['v=DMARC1; p=none; psd=n'],
} as const;

describe('DMARC alignment discovery orchestration', () => {
  it('discovers an authenticated identifier boundary independently before relaxed pass', async () => {
    const lookup = lookupFixture({
      ...authorPolicy,
      '_dmarc.signer.example.com': [],
    });
    const result = await discoverAndEvaluateDmarcAlignment(
      {
        dkimDomains: ['signer.example.com'],
        fromDomain: 'mail.example.com',
        spf: { result: 'fail' },
      },
      lookup,
    );

    expect(result.result).toBe('pass');
    expect(result.identifierDiscoveries).toHaveLength(1);
    expect(result.identifierDiscoveries[0]?.discovery.organizationalDomain).toBe('example.com');
    expect(lookup).toHaveBeenCalledTimes(3);
  });

  it('does not relaxed-align through an authenticated identifier psd=n cut', async () => {
    const result = await discoverAndEvaluateDmarcAlignment(
      {
        dkimDomains: ['signer.marketing.example.com'],
        fromDomain: 'mail.example.com',
        spf: { result: 'fail' },
      },
      lookupFixture({
        ...authorPolicy,
        '_dmarc.signer.marketing.example.com': [],
        '_dmarc.marketing.example.com': ['v=DMARC1; p=none; psd=n'],
      }),
    );

    expect(result.result).toBe('fail');
    expect(result.evaluation?.evidence[0]).toEqual(
      expect.objectContaining({
        organizationalDomain: 'marketing.example.com',
        status: 'unaligned',
      }),
    );
  });

  it('propagates a temporary authenticated-boundary failure', async () => {
    const result = await discoverAndEvaluateDmarcAlignment(
      {
        dkimDomains: ['signer.example.com'],
        fromDomain: 'mail.example.com',
        spf: { result: 'fail' },
      },
      lookupFixture({
        ...authorPolicy,
        '_dmarc.signer.example.com': {
          error: 'SERVFAIL',
          status: 'temperror',
          values: [],
        },
      }),
    );

    expect(result.result).toBe('temperror');
    expect(result.evaluation?.evidence[0]?.status).toBe('temperror');
  });

  it('needs no authenticated-domain walk for an exact aligned identifier', async () => {
    const lookup = lookupFixture(authorPolicy);
    const result = await discoverAndEvaluateDmarcAlignment(
      {
        dkimDomains: ['mail.example.com'],
        fromDomain: 'mail.example.com',
        spf: { result: 'fail' },
      },
      lookup,
    );

    expect(result.result).toBe('pass');
    expect(result.identifierDiscoveries).toEqual([]);
    expect(lookup).toHaveBeenCalledTimes(2);
  });

  it('returns indeterminate rather than evaluating without an author policy', async () => {
    const result = await discoverAndEvaluateDmarcAlignment(
      {
        dkimDomains: ['example.com'],
        fromDomain: 'example.com',
        spf: { result: 'pass', domain: 'example.com' },
      },
      lookupFixture({}),
    );

    expect(result.result).toBe('indeterminate');
    expect(result.evaluation).toBeUndefined();
    expect(result.reason).toMatch(/No applicable DMARC policy/iu);
  });

  it('fails closed when the shared DNS question limit interrupts a needed walk', async () => {
    const result = await discoverAndEvaluateDmarcAlignment(
      {
        dkimDomains: ['signer.example.com'],
        fromDomain: 'mail.example.com',
        spf: { result: 'fail' },
      },
      lookupFixture(authorPolicy),
      2,
    );

    expect(result.result).toBe('indeterminate');
    expect(result.identifierDiscoveries[0]?.discovery.status).toBe('indeterminate');
    expect(result.questionsUsed).toBe(2);
  });
});
