import { describe, expect, it } from 'vitest';

import { parseZoneSnippet } from '../zone/parser';
import { compareZoneDocuments } from './compare';

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

  it('recognizes TXT chunking and whitespace as formatting-only', () => {
    const report = compare('@ 300 IN TXT "v=spf1 " "-all"', '@    300 IN TXT "v=spf1 -all"');
    expect(report.changes).toEqual([
      expect.objectContaining({ category: 'formatting-only', disruptive: false }),
    ]);
  });
});
