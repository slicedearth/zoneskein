import { describe, expect, it } from 'vitest';

import { authorRecord, chunkTxtValue } from './authoring';
import { verifyBindRecord } from './export-conformance';
import { parseZoneSnippet } from './parser';

describe('offline BIND export conformance', () => {
  it.each([0, 254, 255, 256, 510, 511, 1024])(
    'preserves %i TXT octets and every boundary',
    (length) => {
      const value = 'x'.repeat(length);
      const chunks = chunkTxtValue(value);
      expect(chunks.join('')).toBe(value);
      expect(chunks.every((chunk) => new TextEncoder().encode(chunk).length <= 255)).toBe(true);
      const output = authorRecord({ owner: '@', ttl: '300', type: 'TXT', fields: { value } });
      expect(output.valid).toBe(true);
      expect(
        verifyBindRecord(output.bind ?? '', {
          owner: '@',
          ttl: 300,
          type: 'TXT',
          txtValue: value,
          txtChunks: chunks,
        }),
      ).toBeNull();
    },
  );

  it.each([254, 255, 256, 510])('retains terminal SPF text across boundary %i', (boundary) => {
    const value = `v=spf1 ${' '.repeat(boundary - 7)}-all`;
    const chunks = chunkTxtValue(value);
    const bind = `example.test. IN TXT (${chunks.map((chunk) => JSON.stringify(chunk)).join(' ')})`;
    expect(chunks.join('')).toBe(value);
    expect(
      parseZoneSnippet(bind)
        .records[0]?.rdata.map((token) => token.value)
        .join(''),
    ).toBe(value);
    expect(
      verifyBindRecord(bind, { owner: 'example.test.', type: 'TXT', txtValue: value }),
    ).toBeNull();
  });

  it.each([
    '@ 300 IN TXT "unterminated',
    '@ 300 IN TXT "one"\n@ 300 IN TXT "two"',
    '@ 300 IN TXT "' + 'x'.repeat(256) + '"',
    '@ 300 IN A 999.1.1.1',
  ])('withholds malformed output: %s', (bind) => {
    expect(
      verifyBindRecord(bind, {
        owner: '@',
        ttl: 300,
        type: bind.includes(' IN A ') ? 'A' : 'TXT',
      }),
    ).not.toBeNull();
  });

  it('detects lost separators and changed TXT boundaries', () => {
    expect(
      verifyBindRecord('@ IN TXT "v=spf1" "-all"', {
        owner: '@',
        type: 'TXT',
        txtValue: 'v=spf1 -all',
      }),
    ).toMatch(/intended value/u);
    expect(
      verifyBindRecord('@ IN TXT "ab"', { owner: '@', type: 'TXT', txtChunks: ['a', 'b'] }),
    ).toMatch(/boundaries/u);
  });

  it('rejects a character that cannot survive UTF-8 roundtrip', () => {
    expect(
      authorRecord({ owner: '@', ttl: '300', type: 'TXT', fields: { value: '\ud800' } }).valid,
    ).toBe(false);
  });
});
