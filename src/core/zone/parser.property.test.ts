import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { parseZoneSnippet, ZONE_ANALYSIS_LIMITS } from './parser';
import type { ZoneResource } from './types';

const ARBITRARY_ZONE_SEED = 0x20_5a_0e;
const ARBITRARY_ZONE_RUNS = 160;
const MAX_ARBITRARY_ZONE_CHARACTERS = 8_192;
const LIMIT_OVERAGE_RUNS = 3;
const LIMIT_PROPERTY_SEEDS: Readonly<Record<ZoneResource, number>> = {
  characters: 0x20_5a_0f,
  diagnostics: 0x20_5a_10,
  records: 0x20_5a_11,
  statements: 0x20_5a_12,
  tokens: 0x20_5a_13,
};

const arbitraryZoneText = fc.string({ maxLength: MAX_ARBITRARY_ZONE_CHARACTERS });

function sourceBeyond(resource: ZoneResource, overage: number): string {
  const count = ZONE_ANALYSIS_LIMITS[resource] + overage;
  if (resource === 'characters') return 'x'.repeat(count);
  if (resource === 'diagnostics') return '$UNSUPPORTED\n'.repeat(count);
  if (resource === 'records') {
    return Array.from(
      { length: count },
      (_, index) => `record-${String(index)} IN A 192.0.2.1`,
    ).join('\n');
  }
  if (resource === 'statements') return '$TTL 300\n'.repeat(count);
  return `@ IN TXT ${'x '.repeat(count)}`;
}

describe('zone parser properties', () => {
  it('parses arbitrary bounded text deterministically without exceeding output bounds', () => {
    fc.assert(
      fc.property(arbitraryZoneText, (source) => {
        const first = parseZoneSnippet(source, { origin: 'example.test' });
        const second = parseZoneSnippet(source, { origin: 'example.test' });

        expect(second).toEqual(first);
        expect(first.source).toBe(source);
        expect(first.records.length).toBeLessThanOrEqual(ZONE_ANALYSIS_LIMITS.records);
        expect(first.diagnostics.length).toBeLessThanOrEqual(ZONE_ANALYSIS_LIMITS.diagnostics);
        if (first.incomplete !== undefined) expect(first.records).toEqual([]);

        for (const diagnostic of first.diagnostics) {
          expect(Number.isSafeInteger(diagnostic.line)).toBe(true);
          expect(Number.isSafeInteger(diagnostic.column)).toBe(true);
          expect(diagnostic.line).toBeGreaterThanOrEqual(1);
          expect(diagnostic.column).toBeGreaterThanOrEqual(1);
        }
        for (const record of first.records) {
          expect(record.rdata.length).toBeLessThanOrEqual(ZONE_ANALYSIS_LIMITS.tokens);
          expect(record.line).toBeGreaterThanOrEqual(1);
          expect(record.column).toBeGreaterThanOrEqual(1);
        }
      }),
      {
        numRuns: ARBITRARY_ZONE_RUNS,
        seed: ARBITRARY_ZONE_SEED,
      },
    );
  }, 10_000);

  it.each<ZoneResource>(['characters', 'diagnostics', 'records', 'statements', 'tokens'])(
    'retains no prefix records after the %s limit is exhausted',
    (resource) => {
      fc.assert(
        fc.property(fc.integer({ max: 3, min: 1 }), (overage) => {
          const document = parseZoneSnippet(sourceBeyond(resource, overage), {
            origin: 'example.test',
          });

          expect(document.incomplete?.resource).toBe(resource);
          expect(document.records).toEqual([]);
          expect(document.diagnostics.at(-1)).toMatchObject({ severity: 'error' });
        }),
        {
          numRuns: LIMIT_OVERAGE_RUNS,
          seed: LIMIT_PROPERTY_SEEDS[resource],
        },
      );
    },
    10_000,
  );
});
