import { describe, expect, it } from 'vitest';

import { compareZoneDocuments } from '../diff/compare';
import { planDnsChanges } from '../diff/plan';
import { parseZoneSnippet } from '../zone/parser';
import {
  createBlankChangeWorkspace,
  createChangeLabWorkspace,
  createRecordStudioChangeWorkspace,
  editChangeWorkspace,
} from './create';
import { CHANGE_WORKSPACE_LIMITS } from './limits';
import type { ChangeWorkspaceDependencies, ChangeWorkspaceEvidence } from './index';

const CREATED_AT = '2026-08-14T01:02:03.000Z';
const ID = '00000000-0000-4000-8000-000000000001';

function dependencies(at = CREATED_AT, id = ID): ChangeWorkspaceDependencies {
  return { now: () => new Date(at), uuid: () => id };
}

function evidence(): ChangeWorkspaceEvidence {
  return {
    incompleteReasons: ['One resolver observation was unavailable.'],
    runs: [],
    status: 'partial',
  };
}

describe('Change Workspace constructors', () => {
  it('creates a deterministic blank workspace without treating absent zones as empty', () => {
    const created = createBlankChangeWorkspace({}, dependencies());
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    expect(created.value).toMatchObject({
      createdAt: CREATED_AT,
      id: ID,
      updatedAt: CREATED_AT,
    });
    expect(created.value.analysis).toMatchObject({ analysedAt: null, status: 'not-run' });
    expect(created.value.current).toMatchObject({ source: '', status: 'unavailable' });
    expect(created.value.intended).toMatchObject({ source: '', status: 'unavailable' });
    expect(created.value.current.incompleteReasons).not.toHaveLength(0);
  });

  it('constructs a Record Studio intended state with explicit current unavailability', () => {
    const created = createRecordStudioChangeWorkspace(
      {
        intendedSource: '@ 300 IN A 192.0.2.20',
        origin: 'example.test.',
        title: 'Web address change',
      },
      dependencies(),
    );
    expect(created).toMatchObject({
      ok: true,
      value: {
        analysis: { status: 'not-run' },
        current: { origin: null, source: '', status: 'unavailable' },
        intended: {
          incompleteReasons: [],
          origin: 'example.test.',
          source: '@ 300 IN A 192.0.2.20',
          status: 'complete',
        },
        title: 'Web address change',
      },
    });
  });

  it('analyses complete Change Lab inputs and retains typed impact and rollback details', () => {
    const created = createChangeLabWorkspace(
      {
        currentSource: '@ 3600 IN A 192.0.2.1',
        intendedSource: '@ 300 IN A 192.0.2.2',
        origin: 'example.test.',
        plannedAt: new Date('2026-08-14T03:00:00.000Z'),
      },
      dependencies(),
    );
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    expect(created.value.analysis).toMatchObject({
      analysedAt: CREATED_AT,
      status: 'complete',
      timing: {
        plannedAt: '2026-08-14T03:00:00.000Z',
        previousTtlSeconds: 3600,
      },
    });
    const change = created.value.analysis.changes[0];
    expect(change).toMatchObject({
      after: '@ 300 IN A 192.0.2.2',
      before: '@ 3600 IN A 192.0.2.1',
      category: 'value-changed',
      disruptive: false,
      owner: 'example.test.',
      risk: 'moderate',
      type: 'A',
    });
    expect(change?.reasons).not.toHaveLength(0);
    expect(change?.rollback).toMatch(/Restore the prior A value/iu);
  });

  it('preserves an already-rendered report, plan, timing instant, and evidence', () => {
    const currentSource = '@ 7200 IN MX 10 old.example.test.';
    const intendedSource = '@ 300 IN MX 10 new.example.test.';
    const current = parseZoneSnippet(currentSource, { origin: 'example.test.' });
    const intended = parseZoneSnippet(intendedSource, { origin: 'example.test.' });
    const report = compareZoneDocuments(current, intended);
    const plan = planDnsChanges(current, intended, report, {
      now: new Date('2026-08-14T00:00:00.000Z'),
      plannedAt: new Date('2026-08-15T00:00:00.000Z'),
    });
    const created = createChangeLabWorkspace(
      {
        analysis: {
          analysedAt: new Date('2026-08-14T00:00:00.000Z'),
          plan,
          report,
        },
        currentSource,
        evidence: evidence(),
        intendedSource,
        origin: 'example.test.',
      },
      dependencies(),
    );
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    expect(created.value.analysis.analysedAt).toBe('2026-08-14T00:00:00.000Z');
    expect(created.value.analysis.timing).toEqual({
      plannedAt: '2026-08-15T00:00:00.000Z',
      preparationDeadline: '2026-08-14T22:00:00.000Z',
      previousTtlSeconds: 7200,
      rollbackCacheHorizon: '2026-08-15T02:00:00.000Z',
      safeChangeAtIfLoweredNow: '2026-08-14T02:00:00.000Z',
    });
    expect(created.value.evidence).toEqual(evidence());
  });

  it('marks captured results partial when the current observation was incomplete', () => {
    const current = parseZoneSnippet('@ 300 IN A 192.0.2.1', { origin: 'example.test.' });
    const intended = parseZoneSnippet('@ 300 IN A 192.0.2.2', {
      origin: 'example.test.',
    });
    const report = compareZoneDocuments(current, intended);
    const plan = planDnsChanges(current, intended, report);
    const created = createChangeLabWorkspace(
      {
        analysis: { plan, report },
        currentIncompleteReasons: ['MX could not be observed.'],
        currentSource: current.source,
        currentStatus: 'partial',
        intendedSource: intended.source,
        origin: 'example.test.',
      },
      dependencies(),
    );
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    expect(created.value.analysis.status).toBe('partial');
    expect(created.value.analysis.changes).toHaveLength(1);
    expect(created.value.analysis.incompleteReasons.join(' ')).toMatch(/MX could not/iu);
  });

  it('drops captured conclusions when either zone state is unavailable', () => {
    const current = parseZoneSnippet('@ 300 IN A 192.0.2.1', { origin: 'example.test.' });
    const intended = parseZoneSnippet('@ 300 IN A 192.0.2.2', {
      origin: 'example.test.',
    });
    const report = compareZoneDocuments(current, intended);
    const plan = planDnsChanges(current, intended, report);
    const created = createChangeLabWorkspace(
      {
        analysis: { plan, report },
        currentIncompleteReasons: ['The current snapshot was not supplied.'],
        currentOrigin: null,
        currentSource: '',
        currentStatus: 'unavailable',
        intendedSource: intended.source,
        origin: 'example.test.',
      },
      dependencies(),
    );
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    expect(created.value.analysis).toEqual({
      analysedAt: null,
      changes: [],
      findings: [],
      guidance: [],
      incompleteReasons: [],
      phases: [],
      risk: null,
      status: 'not-run',
      timing: {
        plannedAt: null,
        preparationDeadline: null,
        previousTtlSeconds: null,
        rollbackCacheHorizon: null,
        safeChangeAtIfLoweredNow: null,
      },
    });
  });

  it('invalidates derived analysis after zone edits and clears evidence after current edits', () => {
    const created = createChangeLabWorkspace(
      {
        currentSource: '@ 300 IN A 192.0.2.1',
        evidence: evidence(),
        intendedSource: '@ 300 IN A 192.0.2.2',
        origin: 'example.test.',
      },
      dependencies(),
    );
    if (!created.ok) throw new Error(created.error.message);
    const renamed = editChangeWorkspace(
      created.value,
      { title: 'Renamed workspace' },
      { now: () => new Date('2026-08-14T01:03:00.000Z') },
    );
    expect(renamed.ok && renamed.value.analysis.status).toBe('complete');
    expect(renamed.ok && renamed.value.evidence).toEqual(evidence());

    const intendedEdited = editChangeWorkspace(
      created.value,
      {
        intended: {
          incompleteReasons: [],
          origin: 'example.test.',
          source: '@ 300 IN A 192.0.2.4',
          status: 'complete',
        },
      },
      { now: () => new Date('2026-08-14T01:03:30.000Z') },
    );
    expect(intendedEdited.ok && intendedEdited.value.analysis.status).toBe('not-run');
    expect(intendedEdited.ok && intendedEdited.value.evidence).toEqual(evidence());

    const edited = editChangeWorkspace(
      created.value,
      {
        current: {
          incompleteReasons: [],
          origin: 'example.test.',
          source: '@ 300 IN A 192.0.2.3',
          status: 'complete',
        },
      },
      { now: () => new Date('2026-08-14T01:04:00.000Z') },
    );
    expect(edited.ok).toBe(true);
    if (!edited.ok) return;
    expect(edited.value.analysis).toMatchObject({ analysedAt: null, status: 'not-run' });
    expect(edited.value.evidence).toEqual({
      incompleteReasons: [],
      runs: [],
      status: 'none',
    });

    const partialEdit = editChangeWorkspace(
      created.value,
      {
        intended: {
          incompleteReasons: ['The intended snapshot omitted MX records.'],
          origin: 'example.test.',
          source: '@ 300 IN A 192.0.2.4',
          status: 'partial',
        },
      },
      { now: () => new Date('2026-08-14T01:05:00.000Z') },
    );
    expect(partialEdit.ok).toBe(true);
    if (!partialEdit.ok) return;
    expect(partialEdit.value.analysis).toMatchObject({
      analysedAt: '2026-08-14T01:05:00.000Z',
      changes: [],
      findings: [],
      phases: [],
      risk: null,
      status: 'partial',
    });
    expect(partialEdit.value.analysis.incompleteReasons.join(' ')).toMatch(
      /intended snapshot omitted MX/iu,
    );

    const unavailableEdit = editChangeWorkspace(
      created.value,
      {
        intended: {
          incompleteReasons: ['The intended snapshot was not supplied.'],
          origin: null,
          source: '',
          status: 'unavailable',
        },
      },
      { now: () => new Date('2026-08-14T01:06:00.000Z') },
    );
    expect(unavailableEdit.ok).toBe(true);
    if (!unavailableEdit.ok) return;
    expect(unavailableEdit.value.analysis).toMatchObject({
      analysedAt: null,
      changes: [],
      findings: [],
      guidance: [],
      phases: [],
      risk: null,
      status: 'not-run',
    });
  });

  it('fails closed on invalid identity, timestamps, zone bounds, and partial-state metadata', () => {
    expect(createBlankChangeWorkspace({}, dependencies(CREATED_AT, 'not-a-uuid')).ok).toBe(
      false,
    );
    expect(createBlankChangeWorkspace({}, dependencies('invalid')).ok).toBe(false);
    expect(
      createRecordStudioChangeWorkspace(
        { intendedSource: 'x'.repeat(CHANGE_WORKSPACE_LIMITS.zoneCharacters + 1) },
        dependencies(),
      ).ok,
    ).toBe(false);
    expect(
      createRecordStudioChangeWorkspace(
        { intendedSource: '@ 300 IN A 192.0.2.1', intendedStatus: 'partial' },
        dependencies(),
      ).ok,
    ).toBe(false);

    const valid = createChangeLabWorkspace(
      { currentSource: '', intendedSource: '' },
      dependencies(),
    );
    if (!valid.ok) throw new Error(valid.error.message);
    expect(
      editChangeWorkspace(
        valid.value,
        {},
        {
          now: () => {
            throw new Error('clock failed');
          },
        },
      ).ok,
    ).toBe(false);
  });
});
