import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { parseZoneSnippet, ZONE_ANALYSIS_LIMITS } from '../zone/parser';
import type { ZoneDocument } from '../zone/types';
import { compareZoneDocuments } from './compare';

const IDENTITY_PROPERTY_SEED = 0x1d_e17_17;
const IDENTITY_PROPERTY_RUNS = 128;
const COMPARISON_PROPERTY_SEED = 0xc0_a4_e;
const COMPARISON_PROPERTY_RUNS = 128;
const MAX_GENERATED_RECORDS = 96;
const LABEL_CHARACTERS = Array.from('abcdefghijklmnopqrstuvwxyz0123456789');
const TEXT_CHARACTERS = Array.from('abcdefghijklmnopqrstuvwxyz0123456789-_ ');

interface GeneratedRecord {
  readonly line: string;
  readonly owner: string;
}

const labelArbitrary = fc
  .array(fc.constantFrom(...LABEL_CHARACTERS), {
    maxLength: 12,
    minLength: 1,
  })
  .map((characters) => `record-${characters.join('')}`);

const ttlArbitrary = fc.integer({ max: 86_400, min: 0 });
const ipv4Arbitrary = fc
  .tuple(
    fc.integer({ max: 255, min: 0 }),
    fc.integer({ max: 255, min: 0 }),
    fc.integer({ max: 255, min: 0 }),
    fc.integer({ max: 255, min: 0 }),
  )
  .map((octets) => octets.join('.'));
const textArbitrary = fc
  .array(fc.constantFrom(...TEXT_CHARACTERS), {
    maxLength: 24,
  })
  .map((characters) => characters.join('').trim());

const generatedRecordArbitrary: fc.Arbitrary<GeneratedRecord> = fc.oneof(
  fc
    .record({ address: ipv4Arbitrary, owner: labelArbitrary, ttl: ttlArbitrary })
    .map(({ address, owner, ttl }) => ({
      line: `${owner} ${String(ttl)} IN A ${address}`,
      owner,
    })),
  fc
    .record({ owner: labelArbitrary, target: labelArbitrary, ttl: ttlArbitrary })
    .map(({ owner, target, ttl }) => ({
      line: `${owner} ${String(ttl)} IN CNAME ${target}.example.net.`,
      owner,
    })),
  fc
    .record({
      owner: labelArbitrary,
      preference: fc.integer({ max: 65_535, min: 0 }),
      target: labelArbitrary,
      ttl: ttlArbitrary,
    })
    .map(({ owner, preference, target, ttl }) => ({
      line: `${owner} ${String(ttl)} IN MX ${String(preference)} ${target}.example.net.`,
      owner,
    })),
  fc
    .record({ owner: labelArbitrary, text: textArbitrary, ttl: ttlArbitrary })
    .map(({ owner, text, ttl }) => ({
      line: `${owner} ${String(ttl)} IN TXT "${text}"`,
      owner,
    })),
);

const validRecordSetArbitrary = fc.uniqueArray(generatedRecordArbitrary, {
  maxLength: MAX_GENERATED_RECORDS,
  selector: (record) => record.owner,
});

function parseRecordSet(records: readonly GeneratedRecord[]): ZoneDocument {
  return parseZoneSnippet(records.map((record) => record.line).join('\n'), {
    origin: 'example.test',
  });
}

describe('semantic comparison properties', () => {
  it('preserves identity when a generated valid record set is reordered', () => {
    fc.assert(
      fc.property(validRecordSetArbitrary, (records) => {
        const before = parseRecordSet(records);
        const after = parseRecordSet([...records].reverse());
        const report = compareZoneDocuments(before, after);

        expect(before.incomplete).toBeUndefined();
        expect(after.incomplete).toBeUndefined();
        expect(before.diagnostics).toEqual([]);
        expect(after.diagnostics).toEqual([]);
        expect(report).toMatchObject({ changes: [], guidance: [], status: 'complete' });
      }),
      {
        numRuns: IDENTITY_PROPERTY_RUNS,
        seed: IDENTITY_PROPERTY_SEED,
      },
    );
  });

  it('compares generated valid record sets deterministically within the change bound', () => {
    fc.assert(
      fc.property(
        validRecordSetArbitrary,
        validRecordSetArbitrary,
        (beforeRecords, afterRecords) => {
          const before = parseRecordSet(beforeRecords);
          const after = parseRecordSet(afterRecords);
          const beforeSnapshot = structuredClone(before);
          const afterSnapshot = structuredClone(after);
          const first = compareZoneDocuments(before, after);
          const second = compareZoneDocuments(before, after);

          expect(second).toEqual(first);
          expect(before).toEqual(beforeSnapshot);
          expect(after).toEqual(afterSnapshot);
          expect(first.status).toBe('complete');
          expect(first.changes.length).toBeLessThanOrEqual(
            beforeRecords.length + afterRecords.length,
          );
          expect(first.changes.length).toBeLessThanOrEqual(ZONE_ANALYSIS_LIMITS.changes);
        },
      ),
      {
        numRuns: COMPARISON_PROPERTY_RUNS,
        seed: COMPARISON_PROPERTY_SEED,
      },
    );
  });
});
