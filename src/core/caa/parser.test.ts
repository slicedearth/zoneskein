import { describe, expect, it } from 'vitest';

import {
  authorCaaRecord,
  buildCaaRecord,
  caaParentNames,
  caaParentWalk,
  parseCaaPolicy,
} from './parser';

describe('CAA policy analysis', () => {
  it('walks from a host towards its parent names', () => {
    expect(caaParentNames('www.shop.example.com')).toEqual([
      'www.shop.example.com',
      'shop.example.com',
      'example.com',
      'com',
    ]);
  });

  it('reports a bounded parent walk instead of turning omitted evidence into absence', () => {
    const domain = [...Array.from({ length: 80 }, () => 'a'), 'b', 'c', 'test'].join('.');
    const walk = caaParentWalk(domain);

    expect(walk.names).toHaveLength(80);
    expect(walk).toMatchObject({
      firstOmitted: 'b.c.test',
      truncated: true,
    });
  });

  it('flags reserved bits and critical unknown properties', () => {
    const policy = parseCaaPolicy([
      { flags: 129, tag: 'custom', value: 'value' },
      { flags: 0, tag: 'issue', value: 'ca.example' },
    ]);
    expect(policy.diagnostics.map((item) => item.code)).toEqual(
      expect.arrayContaining(['flags-reserved', 'tag-unknown']),
    );
  });

  it('builds a generic critical issuewild record', () => {
    expect(buildCaaRecord('@', 'ca.example', { critical: true, tag: 'issuewild' })).toBe(
      '@ IN CAA 128 issuewild "ca.example"',
    );
  });

  it('parses standardised account and validation method parameters', () => {
    const policy = parseCaaPolicy([
      {
        flags: 0,
        tag: 'issue',
        value:
          'ca.example; accounturi=https://ca.example/account/123; validationmethods=dns-01,http-01',
      },
      { flags: 0, tag: 'issuemail', value: 'smime-ca.example' },
    ]);
    expect(policy.diagnostics.some((item) => item.severity === 'error')).toBe(false);
    expect(policy.properties[0]?.parameters).toEqual([
      { name: 'accounturi', value: 'https://ca.example/account/123' },
      { name: 'validationmethods', value: 'dns-01,http-01' },
    ]);
  });

  it('builds issuance constraints and an explicit prohibition', () => {
    expect(
      buildCaaRecord('@', 'ca.example', {
        accountUri: 'https://ca.example/account/123',
        critical: false,
        tag: 'issue',
        validationMethods: ['dns-01'],
      }),
    ).toBe(
      '@ IN CAA 0 issue "ca.example; accounturi=https://ca.example/account/123; validationmethods=dns-01"',
    );
    expect(buildCaaRecord('@', '', { critical: false, tag: 'issuemail' })).toBe(
      '@ IN CAA 0 issuemail ";"',
    );
  });

  it.each([
    ['not a domain', '', [], 'issuer-invalid'],
    ['ca.example', 'not a uri', [], 'accounturi-invalid'],
    ['ca.example', '', ['dns 01'], 'validationmethods-invalid'],
  ])('blocks malformed authored records (%s)', (issuer, accountUri, methods, code) => {
    const result = authorCaaRecord('@', issuer, {
      ...(accountUri === '' ? {} : { accountUri }),
      critical: false,
      tag: 'issue',
      validationMethods: methods,
    });

    expect(result.valid).toBe(false);
    expect(result.diagnostics).toContainEqual(
      expect.objectContaining({ code, severity: 'error' }),
    );
  });
});
