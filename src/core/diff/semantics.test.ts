import { describe, expect, it } from 'vitest';

import { parseZoneSnippet } from '../zone/parser';
import { compareRecordConfidence } from '../zone/record-semantics';
import { compareZoneDocuments } from './compare';
import { planDnsChanges } from './plan';

function zone(origin: string, rdata: string) {
  return parseZoneSnippet(
    `$ORIGIN example.test.\n$ORIGIN ${origin}.example.test.\nwww.example.test. 300 IN ${rdata}`,
  );
}

describe('record-local origin and opaque semantics', () => {
  it.each([
    'CNAME target',
    'MX 10 target',
    'NS target',
    'SRV 1 2 443 target',
    'SOA target target 1 3600 600 86400 300',
  ])('recognises relative and absolute equivalence: %s', (rdata) => {
    const relative = zone('old', rdata);
    const absolute = zone('new', rdata.replaceAll('target', 'target.old.example.test.'));
    expect(compareZoneDocuments(relative, absolute).changes[0]?.category).toBe(
      'formatting-only',
    );
  });

  it('keeps escaped label dots distinct and uses label-aware membership', () => {
    const before = zone('old', String.raw`CNAME a\.b`);
    const equal = zone('old', String.raw`CNAME a\046b.old.example.test.`);
    const different = zone('old', 'CNAME a.b');
    expect(compareZoneDocuments(before, equal).changes[0]?.category).toBe('formatting-only');
    expect(compareZoneDocuments(before, different).changes[0]?.category).toBe('value-changed');
    const external = zone('old', String.raw`CNAME host\.example.test.`);
    expect(
      planDnsChanges(before, external, compareZoneDocuments(before, external)).findings.filter(
        (item) => item.code === 'internal-target-not-in-snapshot',
      ),
    ).toEqual([]);
  });

  it.each([
    ['A 192.0.2.1', 'A 192.0.2.1', 'canonical-wire-equal'],
    ['TXT "v=spf1 " "-all"', 'TXT "v=spf1 -all"', 'application-equivalent'],
    ['TXT "opaque" "data"', 'TXT "opaquedata"', 'unsupported'],
    [String.raw`TYPE65400 \# 2 AB01`, String.raw`TYPE65400 \# 2 ab01`, 'opaque-data-equal'],
    ['ALIAS target', 'ALIAS target', 'unsupported'],
  ])('separates confidence for %s', (left, right, state) => {
    const before = zone('old', left).records[0];
    const after = zone('old', right).records[0];
    if (before === undefined || after === undefined) throw new Error('Fixture did not parse');
    expect(compareRecordConfidence(before, after).state).toBe(state);
  });

  it('does not claim complete wire equality without a known TTL', () => {
    const record = parseZoneSnippet('example.test. IN A 192.0.2.1').records[0];
    if (record === undefined) throw new Error('Fixture did not parse');
    expect(compareRecordConfidence(record, record).state).toBe('unsupported');
  });
  it.each([
    'CNAME target',
    'MX 10 target',
    'NS target',
    'SRV 1 2 443 target',
    'SOA ns hostmaster 1 3600 600 86400 300',
  ])('detects a directive-only target change in %s', (rdata) => {
    expect(compareZoneDocuments(zone('old', rdata), zone('new', rdata)).changes).toEqual([
      expect.objectContaining({ category: 'value-changed' }),
    ]);
  });

  it('does not erase whitespace inside opaque NAPTR strings', () => {
    const before = zone('old', 'NAPTR 10 10 "u" "E2U+sip" "!^a  b$!sip:x@example.net!" .');
    const after = zone('old', 'NAPTR 10 10 "u" "E2U+sip" "!^a b$!sip:x@example.net!" .');
    expect(compareZoneDocuments(before, after).changes[0]?.category).toBe('value-changed');
  });

  it('resolves present and missing internal targets using their record origin', () => {
    const before = zone('old', 'CNAME target');
    const after = parseZoneSnippet(
      `${zone('new', 'CNAME target').source}\ntarget 300 IN A 192.0.2.1\nmissing.example.test. 300 IN MX 10 absent`,
    );
    const findings = planDnsChanges(
      before,
      after,
      compareZoneDocuments(before, after),
    ).findings.filter((item) => item.code === 'internal-target-not-in-snapshot');
    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain('absent.new.example.test.');
  });
});
