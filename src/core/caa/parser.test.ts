import { describe, expect, it } from 'vitest';

import { buildCaaRecord, caaParentNames, parseCaaPolicy } from './parser';

describe('CAA policy analysis', () => {
  it('walks from a host toward its parent names', () => {
    expect(caaParentNames('www.shop.example.com')).toEqual([
      'www.shop.example.com',
      'shop.example.com',
      'example.com',
      'com',
    ]);
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
});
