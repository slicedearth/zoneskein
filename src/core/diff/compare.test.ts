import { describe, expect, it } from 'vitest';

import { parseZoneSnippet } from '../zone/parser';
import {
  compareZoneDocuments,
  isDefinitiveDnsObservation,
  omitIncompleteRecordTypes,
} from './compare';

function compare(before: string, after: string) {
  return compareZoneDocuments(
    parseZoneSnippet(before, { origin: 'example.com' }),
    parseZoneSnippet(after, { origin: 'example.com' }),
  );
}

describe('semantic DNS change comparison', () => {
  it('treats ordinary RRset ordering as non-semantic', () => {
    const report = compare(
      'www 300 IN A 192.0.2.1\nwww 300 IN A 192.0.2.2',
      'www 300 IN A 192.0.2.2\nwww 300 IN A 192.0.2.1',
    );
    expect(report.changes).toEqual([]);
  });

  it('classifies added, removed, and TTL-only records', () => {
    const report = compare(
      'old 300 IN A 192.0.2.1\nkeep 300 IN A 192.0.2.2',
      'new 300 IN A 192.0.2.3\nkeep 60 IN A 192.0.2.2',
    );
    expect(report.changes.map((item) => item.category)).toEqual(
      expect.arrayContaining(['added', 'removed', 'ttl-only']),
    );
  });

  it('separates MX priority from value changes', () => {
    const report = compare(
      '@ 300 IN MX 10 mail.example.net.',
      '@ 300 IN MX 20 mail.example.net.',
    );
    expect(report.changes).toEqual([
      expect.objectContaining({ category: 'priority-changed', disruptive: true }),
    ]);
  });

  it('recognises TXT chunking and whitespace as formatting-only', () => {
    const report = compare('@ 300 IN TXT "v=spf1 " "-all"', '@    300 IN TXT "v=spf1 -all"');
    expect(report.changes).toEqual([
      expect.objectContaining({ category: 'formatting-only', disruptive: false }),
    ]);
  });

  it('omits changes whose current record type could not be observed', () => {
    const report = compare(
      '@ 300 IN A 192.0.2.1\n@ 300 IN MX 10 old.example.',
      '@ 300 IN A 192.0.2.2\n@ 300 IN MX 10 new.example.',
    );
    const complete = omitIncompleteRecordTypes(report, ['MX']);
    expect(complete.changes).toEqual([
      expect.objectContaining({ category: 'value-changed', type: 'A' }),
    ]);
    expect(complete.guidance.join(' ')).not.toMatch(/mail targets/iu);
  });

  it('treats only successful and authenticated-negative response codes as definitive', () => {
    expect(isDefinitiveDnsObservation('NOERROR')).toBe(true);
    expect(isDefinitiveDnsObservation('NXDOMAIN')).toBe(true);
    expect(isDefinitiveDnsObservation('SERVFAIL')).toBe(false);
    expect(isDefinitiveDnsObservation('REFUSED')).toBe(false);
    expect(isDefinitiveDnsObservation('EXTENDED_RCODE_19')).toBe(false);
  });

  it('reports multi-valued RRset changes as set additions and removals', () => {
    const report = compare(
      '@ 300 IN A 192.0.2.1\n@ 300 IN A 192.0.2.2',
      '@ 300 IN A 192.0.2.3\n@ 300 IN A 192.0.2.4',
    );

    expect(report.changes.map((item) => item.category)).toEqual([
      'removed',
      'removed',
      'added',
      'added',
    ]);
  });
});
