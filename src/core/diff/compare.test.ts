import { describe, expect, it } from 'vitest';

import { parseZoneSnippet, ZONE_ANALYSIS_LIMITS } from '../zone/parser';
import type { ZoneDocument, ZoneRecord } from '../zone/types';
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

  it('compares SOA unit timers as seconds without collapsing changes to NaN', () => {
    const changed = compare(
      '@ 300 IN SOA ns1.example. hostmaster.example. 20 1h 10m 1d 5m',
      '@ 300 IN SOA ns1.example. hostmaster.example. 20 2h 10m 1d 5m',
    );
    expect(changed.changes).toEqual([
      expect.objectContaining({ category: 'value-changed', type: 'SOA' }),
    ]);

    const equivalent = compare(
      '@ 300 IN SOA ns1.example. hostmaster.example. 20 1h 10m 1d 5m',
      '@ 300 IN SOA ns1.example. hostmaster.example. 20 3600 600 86400 300',
    );
    expect(equivalent.changes).toEqual([
      expect.objectContaining({ category: 'formatting-only', type: 'SOA' }),
    ]);
  });

  it('does not collapse ambiguous IPv4 text into a different canonical address', () => {
    const shorthand = compare('@ 300 IN A 127.1', '@ 300 IN A 127.0.0.1');
    const leadingZero = compare('@ 300 IN A 010.0.0.1', '@ 300 IN A 10.0.0.1');

    expect(shorthand.changes).toEqual([
      expect.objectContaining({ category: 'value-changed', type: 'A' }),
    ]);
    expect(leadingZero.changes).toEqual([
      expect.objectContaining({ category: 'value-changed', type: 'A' }),
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

  it('does not collapse escaped in-label dots into DNS label separators', () => {
    const report = compare(
      'a\\046b 300 IN CNAME target\\046name.example.',
      'a.b 300 IN CNAME target.name.example.',
    );

    expect(report.changes.map((item) => item.category)).toEqual(['removed', 'added']);
    expect(report.changes[0]?.owner).toBe('a\\046b.example.com.');
  });

  it('returns no partial change set when either parsed input is incomplete', () => {
    const oversized = Array.from(
      { length: ZONE_ANALYSIS_LIMITS.records + 1 },
      (_, index) => `record-${String(index)} IN A 192.0.2.1`,
    ).join('\n');
    const report = compareZoneDocuments(parseZoneSnippet(oversized), parseZoneSnippet(''));

    expect(report).toMatchObject({ changes: [], guidance: [], status: 'incomplete' });
    expect(report.incompleteReasons.join(' ')).toMatch(/record safety limit/iu);
  });

  it('returns no prefix when the complete change set would exceed its output limit', () => {
    const before = Array.from(
      { length: ZONE_ANALYSIS_LIMITS.records },
      (_, index) => `old-${String(index)} IN A 192.0.2.1`,
    ).join('\n');
    const after = Array.from(
      { length: ZONE_ANALYSIS_LIMITS.records },
      (_, index) => `new-${String(index)} IN A 192.0.2.2`,
    ).join('\n');
    const report = compare(before, after);

    expect(report).toMatchObject({ changes: [], guidance: [], status: 'incomplete' });
    expect(report.incompleteReasons.join(' ')).toMatch(/change safety limit/iu);
  });

  it('keeps dense unmatched RRset comparison near-linear', () => {
    let propertyReads = 0;
    const record = (value: string): ZoneRecord => ({
      className: 'IN',
      column: 1,
      get owner() {
        propertyReads += 1;
        return 'example.com.';
      },
      line: 1,
      original: `@ IN TXT "${value}"`,
      ownerToken: '@',
      rdata: [{ column: 10, line: 1, quoted: true, raw: `"${value}"`, value }],
      ttl: 300,
      get type() {
        propertyReads += 1;
        return 'TXT';
      },
    });
    const document = (prefix: string): ZoneDocument => ({
      diagnostics: [],
      records: Array.from({ length: 512 }, (_, index) => record(`${prefix}-${String(index)}`)),
      source: '',
    });

    const report = compareZoneDocuments(document('before'), document('after'));

    expect(report.status).toBe('complete');
    expect(report.changes).toHaveLength(1024);
    expect(propertyReads).toBeLessThan(50_000);
  });
});
