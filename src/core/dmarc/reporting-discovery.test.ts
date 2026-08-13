import { describe, expect, it, vi } from 'vitest';

import {
  DmarcDiscoverySession,
  type DmarcTxtLookup,
  type DmarcTxtLookupResult,
} from './discovery';
import { discoverDmarcReportingAuthorization } from './reporting-discovery';

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

describe('DMARC reporting boundary discovery', () => {
  it('proves a same-boundary destination internal through an independent walk', async () => {
    const result = await discoverDmarcReportingAuthorization(
      'example.com',
      'example.com',
      'mailto:dmarc@reports.example.com',
      lookupFixture({
        '_dmarc.example.com': ['v=DMARC1; p=none; psd=n'],
      }),
    );

    expect(result.status).toBe('internal');
    expect(result.discovery?.organizationalDomain).toBe('example.com');
    expect(result.authorizationName).toBeUndefined();
  });

  it('requires authorisation when a deeper psd=n cut makes a same-suffix host external', async () => {
    const result = await discoverDmarcReportingAuthorization(
      'example.com',
      'example.com',
      'mailto:dmarc@reports.example.com',
      lookupFixture({
        '_dmarc.reports.example.com': ['v=DMARC1; p=none; psd=n'],
        'example.com._report._dmarc.reports.example.com': ['v=DMARC1; x=allowed'],
      }),
    );

    expect(result.status).toBe('authorized');
    expect(result.discovery?.organizationalDomain).toBe('reports.example.com');
    expect(result.authorizationName).toBe('example.com._report._dmarc.reports.example.com');
  });

  it('does not skip authorisation when same-suffix boundary discovery fails', async () => {
    const result = await discoverDmarcReportingAuthorization(
      'example.com',
      'example.com',
      'mailto:dmarc@reports.example.com',
      lookupFixture({
        '_dmarc.reports.example.com': {
          error: 'SERVFAIL',
          status: 'temperror',
          values: [],
        },
      }),
    );

    expect(result.status).toBe('temperror');
    expect(result.selectedUris).toEqual([]);
  });

  it('fails closed when the external authorisation record is absent', async () => {
    const result = await discoverDmarcReportingAuthorization(
      'example.com',
      'example.com',
      'mailto:dmarc@reports.example.net',
      lookupFixture({
        '_dmarc.example.net': ['v=DMARC1; p=none; psd=n'],
      }),
    );

    expect(result.status).toBe('unauthorized');
    expect(result.selectedUris).toEqual([]);
  });

  it('applies a same-host ruf override for a forensic destination', async () => {
    const result = await discoverDmarcReportingAuthorization(
      'example.com',
      'example.com',
      'mailto:old@reports.example.net',
      lookupFixture({
        '_dmarc.reports.example.net': ['v=DMARC1; p=none; psd=n'],
        'example.com._report._dmarc.reports.example.net': [
          'v=DMARC1; rua=mailto:ignored@attacker.example; ruf=mailto:new@reports.example.net',
        ],
      }),
      'ruf',
    );

    expect(result.status).toBe('authorized');
    expect(result.selectedUris).toEqual(['mailto:new@reports.example.net']);
  });

  it('shares one question cap across multiple destination walks', async () => {
    const session = new DmarcDiscoverySession(
      lookupFixture({
        '_dmarc.reports.one.test': ['v=DMARC1; p=none; psd=n'],
        'example.com._report._dmarc.reports.one.test': ['v=DMARC1'],
      }),
      2,
    );
    const first = await discoverDmarcReportingAuthorization(
      'example.com',
      'example.com',
      'mailto:dmarc@reports.one.test',
      session,
    );
    const second = await discoverDmarcReportingAuthorization(
      'example.com',
      'example.com',
      'mailto:dmarc@reports.two.test',
      session,
    );

    expect(first.status).toBe('authorized');
    expect(second.status).toBe('indeterminate');
    expect(session.questionsUsed).toBe(2);
  });
});
