import { describe, expect, it } from 'vitest';

import { compareZoneDocuments } from '../core/diff/compare';
import { planDnsChanges } from '../core/diff/plan';
import type { DnsRecord } from '../core/dns/types';
import { dnskeyKeyTag } from '../core/dnssec/records';
import { verifyDnskeyRrset } from '../core/dnssec/verify';
import { DnssecWorkBudget } from '../core/dnssec/work-budget';
import { parseZoneSnippet, ZONE_ANALYSIS_LIMITS } from '../core/zone/parser';

const host = (
  globalThis as unknown as {
    process: { version: string; stdout: { write: (value: string) => void } };
  }
).process;

describe('bounded offline responsiveness samples', () => {
  it('profiles the maximum record count without changing the supported bound', () => {
    const source =
      '$ORIGIN example.test.\n' +
      Array.from(
        { length: ZONE_ANALYSIS_LIMITS.records },
        (_, i) => `host${String(i)} 300 IN A 192.0.2.1`,
      ).join('\n');
    const samples: { parseMs: number; compareMs: number; planMs: number }[] = [];
    for (let i = 0; i < 5; i += 1) {
      const start = performance.now();
      const before = parseZoneSnippet(source);
      const after = parseZoneSnippet(source.replaceAll('192.0.2.1', '192.0.2.2'));
      const parsed = performance.now();
      const report = compareZoneDocuments(before, after);
      const compared = performance.now();
      const plan = planDnsChanges(before, after, report);
      const planned = performance.now();
      expect(before.records).toHaveLength(ZONE_ANALYSIS_LIMITS.records);
      expect(report.status).toBe('complete');
      expect(plan.status).toBe('complete');
      samples.push({
        parseMs: parsed - start,
        compareMs: compared - parsed,
        planMs: planned - compared,
      });
    }
    host.stdout.write(
      `${JSON.stringify({ profile: 'zone-record-bound', node: host.version, records: ZONE_ANALYSIS_LIMITS.records, sourceCharacters: source.length, samples })}\n`,
    );
  });

  it('profiles 16 signatures against 32 candidate keys and preserves cancellation', async () => {
    const rawRdata = new Uint8Array([1, 1, 3, 15, ...new Uint8Array(32).fill(1)]);
    const key: DnsRecord = {
      class: 'IN',
      owner: 'example.test.',
      ttl: 300,
      type: 'DNSKEY',
      typeCode: 48,
      section: 'answer',
      rawRdata,
      data: {},
    };
    const signature: DnsRecord = {
      class: 'IN',
      owner: 'example.test.',
      ttl: 300,
      type: 'RRSIG',
      typeCode: 46,
      section: 'answer',
      rawRdata: new Uint8Array(),
      data: {
        algorithm: 15,
        expiration: 2_000_000_000,
        inception: 1_000_000_000,
        keyTag: dnskeyKeyTag(rawRdata),
        labels: 2,
        originalTTL: 300,
        signature: new Uint8Array(64),
        signersName: 'example.test.',
        typeCovered: 'DNSKEY',
      },
    };
    const records = [
      ...Array.from({ length: 32 }, () => key),
      ...Array.from({ length: 16 }, () => signature),
    ];
    const start = performance.now();
    const results = await verifyDnskeyRrset(records, 1_500_000_000);
    const elapsedMs = performance.now() - start;
    expect(results).toHaveLength(16);
    expect(results.every((result) => result.status === 'invalid')).toBe(true);
    const cancelled = await verifyDnskeyRrset(
      records,
      1_500_000_000,
      new DnssecWorkBudget({ signal: AbortSignal.abort() }),
    );
    expect(cancelled[0]?.status).toBe('resource-limit');
    host.stdout.write(
      `${JSON.stringify({ profile: 'signature-candidate-bound', signatures: 16, candidates: 32, elapsedMs })}\n`,
    );
  });
});
