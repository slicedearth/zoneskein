import { describe, expect, it } from 'vitest';

import { parseZoneSnippet, ZONE_ANALYSIS_LIMITS } from '../zone/parser';
import { compareZoneDocuments } from './compare';
import { planDnsChanges } from './plan';

function plan(beforeSource: string, afterSource: string, plannedAt?: Date) {
  const before = parseZoneSnippet(beforeSource, { origin: 'example.com' });
  const after = parseZoneSnippet(afterSource, { origin: 'example.com' });
  return planDnsChanges(before, after, compareZoneDocuments(before, after), {
    now: new Date('2026-08-13T00:00:00.000Z'),
    ...(plannedAt === undefined ? {} : { plannedAt }),
  });
}

describe('DNS change planning', () => {
  it('classifies nameserver and DNSSEC transitions as critical', () => {
    const report = plan(
      '@ 86400 IN NS ns1.old.example.\n@ 3600 IN DS 123 13 2 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      '@ 300 IN NS ns1.new.example.\n@ 300 IN DS 456 13 2 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
    );
    expect(report.risk).toBe('critical');
    expect(report.impacts.map((item) => item.risk)).toContain('critical');
    expect(report.phases.find((phase) => phase.id === 'prepare')?.actions.join(' ')).toMatch(
      /rollover.*authoritative/iu,
    );
  });

  it('calculates TTL preparation and rollback horizons without calling them propagation', () => {
    const report = plan(
      '@ 3600 IN MX 10 old.example.',
      '@ 300 IN MX 10 new.example.',
      new Date('2026-08-13T00:30:00.000Z'),
    );
    expect(report.timing).toMatchObject({
      preparationDeadline: '2026-08-12T23:30:00.000Z',
      previousTtlSeconds: 3600,
      rollbackCacheHorizon: '2026-08-13T01:30:00.000Z',
      safeChangeAtIfLoweredNow: '2026-08-13T01:00:00.000Z',
    });
    expect(report.findings).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: 'change-window-too-soon' })]),
    );
  });

  it('preflights SOA serials, CNAME conflicts, and unresolved in-zone targets', () => {
    const report = plan(
      '@ 300 IN SOA ns1.example. hostmaster.example. 20 3600 600 86400 300',
      '@ 300 IN SOA ns1.example. hostmaster.example. 19 3600 600 86400 300\nwww 300 IN CNAME target.example.com.\nwww 300 IN A 192.0.2.1',
    );
    expect(report.findings.map((item) => item.code)).toEqual(
      expect.arrayContaining([
        'soa-serial-not-increased',
        'zone-cname-conflict',
        'internal-target-not-in-snapshot',
      ]),
    );
  });

  it('accepts an SOA serial that advances through the 32-bit wrap boundary', () => {
    const report = plan(
      '@ 300 IN SOA ns1.example. hostmaster.example. 4294967295 3600 600 86400 300',
      '@ 300 IN SOA ns1.example. hostmaster.example. 0 3600 600 86400 300',
    );
    expect(report.findings.map((item) => item.code)).not.toContain('soa-serial-not-increased');
  });

  it('rejects backwards and undefined half-range SOA serial transitions', () => {
    for (const after of ['9', '2147483658']) {
      const report = plan(
        '@ 300 IN SOA ns1.example. hostmaster.example. 10 3600 600 86400 300',
        `@ 300 IN SOA ns1.example. hostmaster.example. ${after} 3600 600 86400 300`,
      );
      expect(report.findings.map((item) => item.code)).toContain('soa-serial-not-increased');
    }
  });

  it('preserves an explicit incomplete-observation finding', () => {
    const before = parseZoneSnippet('@ 300 IN A 192.0.2.1', { origin: 'example.com' });
    const after = parseZoneSnippet('@ 300 IN A 192.0.2.2', { origin: 'example.com' });
    const report = compareZoneDocuments(before, after);
    const planned = planDnsChanges(before, after, report, { incompleteTypes: ['MX'] });
    expect(planned.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'current-observation-incomplete', risk: 'high' }),
      ]),
    );
  });

  it('keeps formatting-only changes informational', () => {
    const report = plan('@ 300 IN TXT "hello"', '@    300 IN TXT "hello"');
    expect(report.risk).toBe('information');
    expect(report.impacts).toEqual([expect.objectContaining({ risk: 'information' })]);
  });

  it('accepts the exact finding limit and fails closed beyond it', () => {
    const source = (count: number) =>
      Array.from(
        { length: count },
        (_, index) => `record-${String(index)} IN TYPE${String(index)} value`,
      ).join('\n');
    const exactSource = source(ZONE_ANALYSIS_LIMITS.findings);
    const exactBefore = parseZoneSnippet(exactSource, { origin: 'example.com' });
    const exactAfter = parseZoneSnippet(exactSource, { origin: 'example.com' });
    const exact = planDnsChanges(
      exactBefore,
      exactAfter,
      compareZoneDocuments(exactBefore, exactAfter),
    );

    expect(exact.status).toBe('complete');
    expect(exact.findings).toHaveLength(ZONE_ANALYSIS_LIMITS.findings);

    const overSource = source(ZONE_ANALYSIS_LIMITS.findings + 1);
    const overBefore = parseZoneSnippet(overSource, { origin: 'example.com' });
    const overAfter = parseZoneSnippet(overSource, { origin: 'example.com' });
    const over = planDnsChanges(
      overBefore,
      overAfter,
      compareZoneDocuments(overBefore, overAfter),
    );

    expect(over).toMatchObject({
      findings: [],
      impacts: [],
      phases: [],
      status: 'incomplete',
    });
    expect(over.incompleteReasons.join(' ')).toMatch(/finding safety limit/iu);
  });
});
