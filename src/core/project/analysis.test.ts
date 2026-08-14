import { describe, expect, it } from 'vitest';

import { analyseChangeWorkspace, mapChangeWorkspaceAnalysis } from './analysis';
import { createChangeLabWorkspace, editChangeWorkspace } from './create';

const ID = '00000000-0000-4000-8000-000000000001';
const CREATED_AT = '2026-08-14T00:00:00.000Z';

function create(currentSource: string, intendedSource: string) {
  return createChangeLabWorkspace(
    { currentSource, intendedSource, origin: 'example.test.' },
    { now: () => new Date(CREATED_AT), uuid: () => ID },
  );
}

describe('Change Workspace local analysis', () => {
  it('is deterministic for an injected clock and maps every plan field', () => {
    const created = create('@ 600 IN MX 10 old.example.', '@ 300 IN MX 20 new.example.');
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    const first = analyseChangeWorkspace(
      created.value,
      { plannedAt: new Date('2026-08-15T00:00:00.000Z') },
      { now: () => new Date('2026-08-14T02:00:00.000Z') },
    );
    const second = analyseChangeWorkspace(
      created.value,
      { plannedAt: new Date('2026-08-15T00:00:00.000Z') },
      { now: () => new Date('2026-08-14T02:00:00.000Z') },
    );
    expect(first).toEqual(second);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(first.value.analysis).toMatchObject({
      analysedAt: '2026-08-14T02:00:00.000Z',
      risk: 'high',
      status: 'complete',
      timing: {
        plannedAt: '2026-08-15T00:00:00.000Z',
        previousTtlSeconds: 600,
      },
    });
    expect(first.value.analysis.findings).toBeInstanceOf(Array);
    expect(first.value.analysis.guidance).toBeInstanceOf(Array);
    expect(first.value.analysis.phases.some((phase) => phase.id === 'prepare')).toBe(true);
    expect(first.value.analysis.changes[0]?.reasons).not.toHaveLength(0);
    expect(first.value.analysis.changes[0]?.rollback).toContain('Restore the prior MX value');
  });

  it('refuses to infer removals from a partial current input', () => {
    const created = create('@ 300 IN A 192.0.2.1', '@ 300 IN A 192.0.2.2');
    if (!created.ok) throw new Error(created.error.message);
    const edited = editChangeWorkspace(
      created.value,
      {
        current: {
          incompleteReasons: ['The current snapshot omitted MX.'],
          origin: 'example.test.',
          source: created.value.current.source,
          status: 'partial',
        },
      },
      { now: () => new Date('2026-08-14T01:00:00.000Z') },
    );
    if (!edited.ok) throw new Error(edited.error.message);
    const analysed = analyseChangeWorkspace(
      edited.value,
      {},
      {
        now: () => new Date('2026-08-14T02:00:00.000Z'),
      },
    );
    expect(analysed.ok).toBe(true);
    if (!analysed.ok) return;
    expect(analysed.value.analysis).toMatchObject({
      changes: [],
      findings: [],
      risk: null,
      status: 'partial',
    });
    expect(analysed.value.analysis.incompleteReasons.join(' ')).toMatch(
      /not run.*misclassified/iu,
    );
  });

  it('keeps analysis not-run when a zone state is unavailable', () => {
    const created = create('@ 300 IN A 192.0.2.1', '@ 300 IN A 192.0.2.2');
    if (!created.ok) throw new Error(created.error.message);
    const edited = editChangeWorkspace(
      created.value,
      {
        current: {
          incompleteReasons: ['The current snapshot is unavailable.'],
          origin: null,
          source: '',
          status: 'unavailable',
        },
      },
      { now: () => new Date('2026-08-14T01:00:00.000Z') },
    );
    if (!edited.ok) throw new Error(edited.error.message);
    const analysed = analyseChangeWorkspace(
      edited.value,
      {},
      { now: () => new Date('2026-08-14T02:00:00.000Z') },
    );
    expect(analysed.ok).toBe(true);
    if (!analysed.ok) return;
    expect(analysed.value.analysis).toEqual(edited.value.analysis);
    expect(analysed.value.analysis.status).toBe('not-run');
  });

  it('propagates parser resource incompleteness without retaining a partial change set', () => {
    const source = Array.from(
      { length: 4_097 },
      (_, index) => `r${String(index)} 300 IN A 192.0.2.1`,
    ).join('\n');
    const created = createChangeLabWorkspace(
      { currentSource: source, intendedSource: '', origin: 'example.test.' },
      { now: () => new Date(CREATED_AT), uuid: () => ID },
    );
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    expect(created.value.analysis).toMatchObject({ changes: [], status: 'partial' });
    expect(created.value.analysis.incompleteReasons.join(' ')).toMatch(/record safety limit/iu);
  });

  it('refuses to treat an unsupported include directive as an empty zone', () => {
    const created = create('$INCLUDE "external.zone"', '');
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    expect(created.value.analysis).toMatchObject({
      changes: [],
      risk: null,
      status: 'partial',
    });
    expect(created.value.analysis.incompleteReasons.join(' ')).toMatch(
      /omitted or unparseable input.*comparison was not run/iu,
    );
    expect(created.value.analysis.findings).toHaveLength(1);
    expect(created.value.analysis.findings[0]?.code).toBe('current-zone-input-incomplete');
    expect(created.value.analysis.findings[0]?.risk).toBe('high');
    expect(created.value.analysis.findings[0]?.message).toMatch(
      /directive-unsupported.*\$INCLUDE/iu,
    );
  });

  it('refuses to compare a malformed record that the parser could not retain', () => {
    const created = create('', 'www 300 IN');
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    expect(created.value.analysis).toMatchObject({
      changes: [],
      status: 'partial',
    });
    expect(created.value.analysis.findings).toHaveLength(1);
    expect(created.value.analysis.findings[0]?.code).toBe('intended-zone-input-incomplete');
    expect(created.value.analysis.findings[0]?.message).toMatch(
      /record-incomplete.*type is missing/iu,
    );
  });

  it('retains safely parsed records carrying a non-blocking unsupported-type warning', () => {
    const source = 'www 300 IN FROB value';
    const created = create(source, source);
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    expect(created.value.analysis.status).toBe('complete');
    expect(created.value.analysis.changes).toHaveLength(0);
    expect(created.value.analysis.findings.map((finding) => finding.code)).toContain(
      'zone-type-unsupported',
    );
  });

  it('bounds blocking parser findings without restoring misleading conclusions', () => {
    const malformed = Array.from(
      { length: 1_025 },
      (_, index) => `record-${String(index)} 300 IN`,
    ).join('\n');
    const created = create(malformed, '');
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    expect(created.value.analysis).toMatchObject({ changes: [], status: 'partial' });
    expect(created.value.analysis.findings).toHaveLength(1_024);
    expect(created.value.analysis.incompleteReasons.join(' ')).toMatch(
      /first 1024 of 1025 blocking parser diagnostics/iu,
    );
  });

  it('propagates change-planning bounds without retaining incomplete findings', () => {
    const source = Array.from(
      { length: 1_025 },
      (_, index) => `r${String(index)} 300 IN TYPE${String(index)} value`,
    ).join('\n');
    const created = create(source, source);
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    expect(created.value.analysis).toMatchObject({
      changes: [],
      findings: [],
      phases: [],
      status: 'partial',
    });
    expect(created.value.analysis.incompleteReasons.join(' ')).toMatch(
      /finding safety limit/iu,
    );
  });

  it('omits explicitly incomplete record types and marks the retained analysis partial', () => {
    const created = createChangeLabWorkspace(
      {
        currentSource: '@ 300 IN A 192.0.2.1\n@ 300 IN MX 10 unavailable.example.test.',
        incompleteTypes: ['MX', 'MX'],
        intendedSource: '@ 300 IN A 192.0.2.2',
        origin: 'example.test.',
      },
      { now: () => new Date(CREATED_AT), uuid: () => ID },
    );
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    expect(created.value.analysis.status).toBe('partial');
    expect(created.value.analysis.changes).toHaveLength(1);
    expect(created.value.analysis.changes[0]).toMatchObject({ type: 'A' });
    expect(created.value.analysis.findings.map((finding) => finding.code)).toContain(
      'current-observation-incomplete',
    );
    expect(created.value.analysis.risk).toBeNull();
    expect(created.value.analysis.changes[0]?.risk).toBe('moderate');
    expect(created.value.analysis.incompleteReasons.join(' ')).toMatch(
      /MX records were unavailable/iu,
    );
  });

  it('bounds and validates incomplete-type metadata and injected clocks', () => {
    const base = create('@ 300 IN A 192.0.2.1', '@ 300 IN A 192.0.2.2');
    if (!base.ok) throw new Error(base.error.message);
    expect(analyseChangeWorkspace(base.value, { incompleteTypes: ['mx'] }).ok).toBe(false);
    expect(
      analyseChangeWorkspace(base.value, {
        incompleteTypes: Array.from({ length: 1_025 }, () => 'MX'),
      }).ok,
    ).toBe(false);
    expect(
      analyseChangeWorkspace(
        base.value,
        {},
        {
          now: () => {
            throw new Error('clock failed');
          },
        },
      ).ok,
    ).toBe(false);
  });

  it('marks a captured report partial when impact assessments are missing', () => {
    const mapped = mapChangeWorkspaceAnalysis(
      {
        changes: [
          {
            before: {
              className: 'IN',
              column: 1,
              line: 1,
              original: '@ 300 IN A 192.0.2.1',
              owner: 'example.test.',
              ownerToken: '@',
              rdata: [],
              ttl: 300,
              type: 'A',
            },
            category: 'removed',
            disruptive: true,
            explanation: 'Removed.',
            owner: 'example.test.',
            type: 'A',
          },
        ],
        guidance: [],
        incompleteReasons: [],
        status: 'complete',
      },
      {
        findings: [],
        impacts: [],
        incompleteReasons: [],
        phases: [],
        risk: 'high',
        status: 'complete',
        timing: {},
      },
      CREATED_AT,
    );
    expect(mapped).toMatchObject({ changes: [], risk: null, status: 'partial' });
    expect(mapped.incompleteReasons.join(' ')).toMatch(/impact assessment/iu);
  });
});
