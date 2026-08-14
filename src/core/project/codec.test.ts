import { describe, expect, it, vi } from 'vitest';

import { decodeChangeWorkspace, encodeChangeWorkspace, parseChangeWorkspace } from './codec';
import { CHANGE_WORKSPACE_LIMITS } from './limits';
import {
  CHANGE_WORKSPACE_FORMAT,
  type ChangeWorkspace,
  type ChangeWorkspaceObservationRun,
  type ChangeWorkspaceQuestionObservation,
  type ChangeWorkspaceResolverObservation,
} from './types';

const textEncoder = new TextEncoder();

function uuid(index: number): string {
  return `00000000-0000-4000-8000-${index.toString(16).padStart(12, '0')}`;
}

function question(index = 4): ChangeWorkspaceQuestionObservation {
  return {
    authenticatedData: true,
    className: 'IN',
    error: null,
    id: uuid(index),
    name: 'www.example.test.',
    observedAt: '2026-08-14T00:02:00.000Z',
    records: ['www.example.test. 300 IN A 192.0.2.1'],
    responseCode: 0,
    status: 'answer',
    type: 'A',
  };
}

function resolver(index = 3): ChangeWorkspaceResolverObservation {
  return {
    endpoint: 'https://dns.example.test/dns-query',
    id: uuid(index),
    incompleteReasons: [],
    label: 'Example resolver',
    questions: [question()],
    resolverId: 'custom',
    status: 'complete',
  };
}

function run(index = 2): ChangeWorkspaceObservationRun {
  return {
    completedAt: '2026-08-14T00:03:00.000Z',
    id: uuid(index),
    incompleteReasons: [],
    resolvers: [resolver()],
    startedAt: '2026-08-14T00:01:00.000Z',
    status: 'complete',
  };
}

function workspace(): ChangeWorkspace {
  return {
    analysis: {
      analysedAt: '2026-08-14T00:00:30.000Z',
      changes: [
        {
          after: 'www 300 IN A 192.0.2.1',
          before: null,
          category: 'added',
          disruptive: false,
          explanation: 'The intended zone adds an address record.',
          owner: 'www.example.test.',
          reasons: ['The intended zone adds an address record.'],
          risk: 'low',
          rollback: 'Remove the added A value if verification fails.',
          type: 'A',
        },
      ],
      findings: [
        {
          code: 'new-address',
          message: 'Confirm the address serves the intended application.',
          risk: 'low',
        },
      ],
      guidance: ['Verify the record from more than one recursive resolver after publishing.'],
      incompleteReasons: [],
      phases: [
        {
          actions: ['Publish the intended RRset.'],
          id: 'publish',
          title: 'Publish the change',
        },
        {
          actions: ['Query each selected recursive resolver.'],
          id: 'verify',
          title: 'Verify observations',
        },
      ],
      risk: 'low',
      status: 'complete',
      timing: {
        plannedAt: '2026-08-15T00:00:00.000Z',
        preparationDeadline: '2026-08-14T23:55:00.000Z',
        previousTtlSeconds: 300,
        rollbackCacheHorizon: '2026-08-15T00:05:00.000Z',
        safeChangeAtIfLoweredNow: '2026-08-14T00:05:00.000Z',
      },
    },
    createdAt: '2026-08-14T00:00:00.000Z',
    current: {
      format: 'bind-zone-text',
      incompleteReasons: [],
      origin: 'example.test.',
      source: '$ORIGIN example.test.\n@ 300 IN SOA ns hostmaster 1 3600 600 86400 300\n',
      status: 'complete',
    },
    evidence: { incompleteReasons: [], runs: [run()], status: 'complete' },
    id: uuid(1),
    intended: {
      format: 'bind-zone-text',
      incompleteReasons: [],
      origin: 'example.test.',
      source:
        '$ORIGIN example.test.\n@ 300 IN SOA ns hostmaster 2 3600 600 86400 300\nwww 300 IN A 192.0.2.1\n',
      status: 'complete',
    },
    title: 'Example address rollout',
    updatedAt: '2026-08-14T00:04:00.000Z',
  };
}

function expectFailure(
  result: ReturnType<typeof parseChangeWorkspace>,
  code: string,
  path?: string,
): void {
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect(result.error.code).toBe(code);
    if (path !== undefined) expect(result.error.path).toBe(path);
  }
}

async function encodedObject(
  value: ChangeWorkspace = workspace(),
): Promise<Record<string, unknown>> {
  const encoded = await encodeChangeWorkspace(value);
  if (!encoded.ok) throw new Error(encoded.error.message);
  return JSON.parse(encoded.value) as Record<string, unknown>;
}

describe('portable Change Workspace codec', () => {
  it('round-trips a complete workspace as pretty JSON and reconstructs inert data', async () => {
    const original = workspace();
    const encoded = await encodeChangeWorkspace(original);
    expect(encoded.ok).toBe(true);
    if (!encoded.ok) return;
    expect(encoded.value.startsWith('{\n  "format": "zoneskein-project-v1",')).toBe(true);
    expect(encoded.value.endsWith('\n')).toBe(true);

    const decoded = await decodeChangeWorkspace(textEncoder.encode(encoded.value));
    expect(decoded.ok).toBe(true);
    if (decoded.ok) {
      expect(decoded.value.format).toBe(CHANGE_WORKSPACE_FORMAT);
      expect(decoded.value.integrity).toMatchObject({
        algorithm: 'SHA-256',
        authenticity: 'none',
        status: 'match',
      });
      expect(decoded.value.workspace).toEqual(original);
    }
    if (decoded.ok) {
      expect(decoded.value.workspace).not.toBe(original);
      expect(decoded.value.workspace.current).not.toBe(original.current);
      expect(decoded.value.workspace.evidence.runs[0]).not.toBe(original.evidence.runs[0]);
      expect(typeof decoded.value.workspace.evidence.runs[0]?.resolvers[0]?.endpoint).toBe(
        'string',
      );
    }
  });

  it('makes key order and insignificant whitespace irrelevant to integrity', async () => {
    const object = await encodedObject();
    const reordered = {
      workspace: object['workspace'],
      integrity: object['integrity'],
      format: object['format'],
    };
    const compact = JSON.stringify(reordered);
    const padded = ` \n\t${JSON.stringify(reordered, null, 4)}\r\n`;

    for (const serialised of [compact, padded]) {
      const decoded = await decodeChangeWorkspace(textEncoder.encode(serialised));
      expect(decoded.ok).toBe(true);
      if (decoded.ok) expect(decoded.value.integrity.status).toBe('match');
    }
  });

  it('reports tampering as a structured mismatch without claiming authenticity', async () => {
    const object = await encodedObject();
    const changed = object['workspace'] as Record<string, unknown>;
    changed['title'] = 'Tampered title';

    const decoded = await decodeChangeWorkspace(textEncoder.encode(JSON.stringify(object)));
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.value.integrity).toMatchObject({
      algorithm: 'SHA-256',
      authenticity: 'none',
      status: 'mismatch',
    });
    if (decoded.value.integrity.status === 'mismatch') {
      expect(decoded.value.integrity.claimedDigest).toMatch(/^[0-9a-f]{64}$/u);
      expect(decoded.value.integrity.calculatedDigest).toMatch(/^[0-9a-f]{64}$/u);
      expect(decoded.value.integrity.calculatedDigest).not.toBe(
        decoded.value.integrity.claimedDigest,
      );
    }
  });

  it('does not call a network API for imported resolver endpoints', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    try {
      const encoded = await encodeChangeWorkspace(workspace());
      if (!encoded.ok) throw new Error(encoded.error.message);
      const decoded = await decodeChangeWorkspace(textEncoder.encode(encoded.value));
      expect(decoded.ok).toBe(true);
      expect(fetch).not.toHaveBeenCalled();
      if (decoded.ok) {
        expect(decoded.value.workspace.evidence.runs[0]?.resolvers[0]?.endpoint).toBe(
          'https://dns.example.test/dns-query',
        );
      }
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('round-trips the fixed Quad9 relay endpoint as inert evidence', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    const original = workspace();
    const originalRun = original.evidence.runs[0];
    const originalResolver = originalRun?.resolvers[0];
    if (originalRun === undefined || originalResolver === undefined)
      throw new Error('Expected resolver evidence fixture.');
    const relayWorkspace: ChangeWorkspace = {
      ...original,
      evidence: {
        ...original.evidence,
        runs: [
          {
            ...originalRun,
            resolvers: [
              {
                ...originalResolver,
                endpoint: '/api/doh/quad9',
                label: 'Quad9 (compatibility mode)',
                resolverId: 'quad9-relay',
              },
            ],
          },
        ],
      },
    };

    try {
      const encoded = await encodeChangeWorkspace(relayWorkspace);
      expect(encoded.ok).toBe(true);
      if (!encoded.ok) return;
      const decoded = await decodeChangeWorkspace(textEncoder.encode(encoded.value));
      expect(decoded.ok).toBe(true);
      expect(fetch).not.toHaveBeenCalled();
      if (decoded.ok) {
        expect(decoded.value.workspace.evidence.runs[0]?.resolvers[0]).toMatchObject({
          endpoint: '/api/doh/quad9',
          label: 'Quad9 (compatibility mode)',
          resolverId: 'quad9-relay',
        });
      }
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('rejects getters during encoding without invoking them', async () => {
    let calls = 0;
    const value = workspace() as ChangeWorkspace & { trap?: string };
    Object.defineProperty(value, 'trap', {
      enumerable: true,
      get() {
        calls += 1;
        return 'do not read';
      },
    });

    const result = await encodeChangeWorkspace(value);
    expect(result).toMatchObject({ ok: false, error: { code: 'unsupported-value' } });
    expect(calls).toBe(0);
  });

  it('rejects direct-parser accessors without invoking them', () => {
    let calls = 0;
    const accessorWorkspace = Object.defineProperty(workspace(), 'analysis', {
      enumerable: true,
      get() {
        calls += 1;
        return workspace().analysis;
      },
    });
    const changes = Object.defineProperty([workspace().analysis.changes[0]], '0', {
      enumerable: true,
      get() {
        calls += 1;
        return workspace().analysis.changes[0];
      },
    });

    expectFailure(parseChangeWorkspace(accessorWorkspace), 'invalid-schema');
    expectFailure(
      parseChangeWorkspace({
        ...workspace(),
        analysis: { ...workspace().analysis, changes },
      }),
      'invalid-schema',
    );
    expect(calls).toBe(0);
  });

  it('fatally rejects oversized files, malformed UTF-8, JSON, duplicate keys, and outer schema', async () => {
    expect(
      await decodeChangeWorkspace(new Uint8Array(CHANGE_WORKSPACE_LIMITS.fileOctets + 1)),
    ).toMatchObject({ ok: false, error: { code: 'file-too-large' } });
    expect(await decodeChangeWorkspace(Uint8Array.from([0xff]))).toMatchObject({
      ok: false,
      error: { code: 'invalid-utf8' },
    });
    expect(await decodeChangeWorkspace(textEncoder.encode('{'))).toMatchObject({
      ok: false,
      error: { code: 'invalid-json' },
    });
    expect(
      await decodeChangeWorkspace(textEncoder.encode('{"format":1,"format":2}')),
    ).toMatchObject({ ok: false, error: { code: 'duplicate-key' } });

    const object = await encodedObject();
    object['extra'] = true;
    expect(
      await decodeChangeWorkspace(textEncoder.encode(JSON.stringify(object))),
    ).toMatchObject({
      ok: false,
      error: { code: 'invalid-schema', path: '$' },
    });
  });

  it.each([
    ['format', 'zoneskein-project-v2'],
    ['integrity.algorithm', 'SHA-1'],
    ['integrity.authenticity', 'signed'],
    ['integrity.digest', 'A'.repeat(64)],
  ])('rejects an invalid %s field', async (field, replacement) => {
    const object = await encodedObject();
    if (field === 'format') object['format'] = replacement;
    else {
      const integrity = object['integrity'] as Record<string, unknown>;
      integrity[field.split('.')[1] ?? ''] = replacement;
    }
    const result = await decodeChangeWorkspace(textEncoder.encode(JSON.stringify(object)));
    expect(result).toMatchObject({ ok: false, error: { code: 'invalid-schema' } });
  });

  it('rejects unknown nested keys, floating point, negative-zero, and unsafe numbers', async () => {
    const unknown = await encodedObject();
    (unknown['workspace'] as Record<string, unknown>)['extra'] = true;
    expect(
      await decodeChangeWorkspace(textEncoder.encode(JSON.stringify(unknown))),
    ).toMatchObject({
      ok: false,
      error: { code: 'invalid-schema', path: '$.workspace' },
    });

    for (const value of [1.5, -0, Number.MAX_SAFE_INTEGER + 1]) {
      const candidate = workspace() as unknown as Record<string, unknown>;
      candidate['updatedAt'] = value;
      const result = await encodeChangeWorkspace(candidate);
      expect(result).toMatchObject({ ok: false, error: { code: 'unsupported-value' } });
    }
  });

  it('rejects unpaired surrogates through both direct and byte decoders', async () => {
    expectFailure(
      parseChangeWorkspace({
        ...workspace(),
        current: { ...workspace().current, source: '\ud800' },
      }),
      'invalid-schema',
      '$.workspace.current.source',
    );
    const object = await encodedObject();
    const importedWorkspace = object['workspace'] as Record<string, unknown>;
    const current = importedWorkspace['current'] as Record<string, unknown>;
    current['source'] = '\udc00';
    const decoded = await decodeChangeWorkspace(textEncoder.encode(JSON.stringify(object)));
    expect(decoded).toMatchObject({ ok: false, error: { code: 'unsupported-value' } });
  });

  it.each([
    ['bad UUID', { id: '00000000-0000-1000-8000-000000000001' }],
    ['upper-case UUID', { id: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }],
    ['non-canonical timestamp', { createdAt: '2026-08-14T00:00:00Z' }],
    ['impossible timestamp', { createdAt: '2026-02-30T00:00:00.000Z' }],
    ['reversed timestamps', { updatedAt: '2026-08-13T23:59:59.999Z' }],
  ])('rejects %s', (_label, replacement) => {
    expectFailure(parseChangeWorkspace({ ...workspace(), ...replacement }), 'invalid-schema');
  });

  it('enforces title and zone source one-over limits', () => {
    expectFailure(
      parseChangeWorkspace({
        ...workspace(),
        title: 'x'.repeat(CHANGE_WORKSPACE_LIMITS.titleCharacters + 1),
      }),
      'resource-limit',
      '$.workspace.title',
    );
    expectFailure(
      parseChangeWorkspace({
        ...workspace(),
        current: {
          ...workspace().current,
          source: 'x'.repeat(CHANGE_WORKSPACE_LIMITS.zoneCharacters + 1),
        },
      }),
      'resource-limit',
      '$.workspace.current.source',
    );
    expectFailure(
      parseChangeWorkspace({
        ...workspace(),
        current: {
          ...workspace().current,
          source: '\u00e9'.repeat(Math.floor(CHANGE_WORKSPACE_LIMITS.zoneOctets / 2) + 1),
        },
      }),
      'resource-limit',
      '$.workspace.current.source',
    );
  });

  it('distinguishes unavailable, partial, complete, and deliberately empty zone states', () => {
    const unavailable = {
      format: 'bind-zone-text',
      incompleteReasons: ['Current zone records were not supplied.'],
      origin: null,
      source: '',
      status: 'unavailable',
    } as const;
    const deliberatelyEmpty = {
      format: 'bind-zone-text',
      incompleteReasons: [],
      origin: 'example.test.',
      source: '',
      status: 'complete',
    } as const;
    expect(
      parseChangeWorkspace({
        ...workspace(),
        analysis: {
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
        },
        current: unavailable,
      }).ok,
    ).toBe(true);
    expect(parseChangeWorkspace({ ...workspace(), current: deliberatelyEmpty }).ok).toBe(true);

    for (const current of [
      { ...unavailable, incompleteReasons: [] },
      { ...unavailable, source: '@ IN A 192.0.2.1' },
      { ...deliberatelyEmpty, incompleteReasons: ['Unexpected reason'] },
      { ...deliberatelyEmpty, incompleteReasons: [], status: 'partial' },
    ]) {
      expectFailure(parseChangeWorkspace({ ...workspace(), current }), 'invalid-schema');
    }
  });

  it('retains and validates structured timing and rollout phases', () => {
    const parsed = parseChangeWorkspace(workspace());
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value.analysis.phases.map((phase) => phase.id)).toEqual([
        'publish',
        'verify',
      ]);
      expect(parsed.value.analysis.timing.previousTtlSeconds).toBe(300);
      expect(parsed.value.analysis.timing.preparationDeadline).toBe('2026-08-14T23:55:00.000Z');
    }

    const base = workspace();
    const phase = base.analysis.phases[0];
    if (phase === undefined) throw new Error('Fixture is incomplete.');
    for (const analysis of [
      { ...base.analysis, phases: [{ ...phase, actions: [] }] },
      { ...base.analysis, phases: [phase, phase] },
      { ...base.analysis, phases: [{ ...phase, id: 'unknown' }] },
      { ...base.analysis, risk: null },
      {
        ...base.analysis,
        timing: {
          ...base.analysis.timing,
          preparationDeadline: '2026-08-16T00:00:00.000Z',
        },
      },
      {
        ...base.analysis,
        timing: { ...base.analysis.timing, previousTtlSeconds: -0 },
      },
      {
        ...base.analysis,
        timing: { ...base.analysis.timing, previousTtlSeconds: null },
      },
      {
        ...base.analysis,
        timing: {
          ...base.analysis.timing,
          preparationDeadline: '2026-08-14T23:54:59.999Z',
        },
      },
      {
        ...base.analysis,
        timing: {
          ...base.analysis.timing,
          rollbackCacheHorizon: '2026-08-14T23:59:59.999Z',
        },
      },
    ]) {
      expectFailure(parseChangeWorkspace({ ...base, analysis }), 'invalid-schema');
    }

    expectFailure(
      parseChangeWorkspace({
        ...base,
        analysis: {
          ...base.analysis,
          phases: Array.from(
            { length: CHANGE_WORKSPACE_LIMITS.analysisPhases + 1 },
            () => phase,
          ),
        },
      }),
      'resource-limit',
      '$.workspace.analysis.phases',
    );
    expectFailure(
      parseChangeWorkspace({
        ...base,
        analysis: {
          ...base.analysis,
          phases: [
            {
              ...phase,
              actions: Array.from(
                { length: CHANGE_WORKSPACE_LIMITS.actionsPerPhase + 1 },
                (_, index) => `Action ${String(index)}`,
              ),
            },
          ],
        },
      }),
      'resource-limit',
      '$.workspace.analysis.phases[0].actions',
    );
  });

  it('enforces coherence between zone-state completeness and stored analysis', async () => {
    const base = workspace();
    const partialCurrent = {
      ...base.current,
      incompleteReasons: ['The current snapshot omitted MX records.'],
      status: 'partial',
    } as const;
    const unavailableCurrent = {
      format: 'bind-zone-text',
      incompleteReasons: ['The current snapshot was not supplied.'],
      origin: null,
      source: '',
      status: 'unavailable',
    } as const;
    const notRun = {
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
    } as const;
    const partialAnalysis = {
      ...base.analysis,
      incompleteReasons: ['The current snapshot omitted MX records.'],
      risk: null,
      status: 'partial',
    } as const;
    const hostile = [
      { ...base, current: partialCurrent },
      { ...base, analysis: notRun, current: partialCurrent },
      { ...base, current: unavailableCurrent },
      { ...base, analysis: partialAnalysis, current: unavailableCurrent },
    ];
    for (const candidate of hostile) {
      expectFailure(parseChangeWorkspace(candidate), 'invalid-schema', '$.workspace.analysis');
      const encoded = await encodeChangeWorkspace(candidate);
      expect(encoded.ok).toBe(false);
      if (!encoded.ok) expect(encoded.error.path).toBe('$.workspace.analysis');
    }

    expect(
      parseChangeWorkspace({ ...base, analysis: partialAnalysis, current: partialCurrent }).ok,
    ).toBe(true);
    expect(
      parseChangeWorkspace({ ...base, analysis: notRun, current: unavailableCurrent }).ok,
    ).toBe(true);
  });

  it('retains typed impact reasons and rollback guidance for each analysed change', () => {
    const parsed = parseChangeWorkspace(workspace());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.analysis.changes[0]).toMatchObject({
      reasons: ['The intended zone adds an address record.'],
      rollback: 'Remove the added A value if verification fails.',
    });

    const base = workspace();
    const change = base.analysis.changes[0];
    if (change === undefined) throw new Error('Fixture is incomplete.');
    for (const candidate of [
      { ...change, reasons: [] },
      { ...change, rollback: '' },
    ]) {
      expectFailure(
        parseChangeWorkspace({
          ...base,
          analysis: { ...base.analysis, changes: [candidate] },
        }),
        'invalid-schema',
      );
    }
  });

  it('retains disruptive classification and permits repeated finding codes at distinct sites', () => {
    const base = workspace();
    const finding = base.analysis.findings[0];
    if (finding === undefined) throw new Error('Fixture is incomplete.');
    const parsed = parseChangeWorkspace({
      ...base,
      analysis: {
        ...base.analysis,
        findings: [finding, { ...finding, message: 'A second affected site.' }],
      },
    });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.analysis.changes[0]?.disruptive).toBe(false);
    expect(parsed.value.analysis.findings).toHaveLength(2);
  });

  it('enforces analysis change, finding, guidance, and incomplete-reason limits', () => {
    const base = workspace();
    const change = base.analysis.changes[0];
    const finding = base.analysis.findings[0];
    if (change === undefined || finding === undefined)
      throw new Error('Fixture is incomplete.');

    for (const [key, values] of [
      [
        'changes',
        Array.from({ length: CHANGE_WORKSPACE_LIMITS.analysisChanges + 1 }, () => change),
      ],
      [
        'findings',
        Array.from({ length: CHANGE_WORKSPACE_LIMITS.analysisFindings + 1 }, () => finding),
      ],
      [
        'guidance',
        Array.from(
          { length: CHANGE_WORKSPACE_LIMITS.guidanceItems + 1 },
          (_, index) => `Guidance ${String(index)}`,
        ),
      ],
      [
        'incompleteReasons',
        Array.from(
          { length: CHANGE_WORKSPACE_LIMITS.incompleteReasons + 1 },
          (_, index) => `Reason ${String(index)}`,
        ),
      ],
    ] as const) {
      expectFailure(
        parseChangeWorkspace({
          ...base,
          analysis: {
            ...base.analysis,
            [key]: values,
            status: key === 'incompleteReasons' ? 'partial' : 'complete',
          },
        }),
        'resource-limit',
      );
    }
  });

  it('enforces evidence run, resolver, question, and per-question record limits', () => {
    const base = workspace();
    expectFailure(
      parseChangeWorkspace({
        ...base,
        evidence: {
          ...base.evidence,
          runs: Array.from({ length: CHANGE_WORKSPACE_LIMITS.evidenceRuns + 1 }, () => run()),
        },
      }),
      'resource-limit',
      '$.workspace.evidence.runs',
    );
    expectFailure(
      parseChangeWorkspace({
        ...base,
        evidence: {
          ...base.evidence,
          runs: [
            {
              ...run(),
              resolvers: Array.from(
                { length: CHANGE_WORKSPACE_LIMITS.resolversPerRun + 1 },
                () => resolver(),
              ),
            },
          ],
        },
      }),
      'resource-limit',
      '$.workspace.evidence.runs[0].resolvers',
    );
    expectFailure(
      parseChangeWorkspace({
        ...base,
        evidence: {
          ...base.evidence,
          runs: [
            {
              ...run(),
              resolvers: [
                {
                  ...resolver(),
                  questions: Array.from(
                    { length: CHANGE_WORKSPACE_LIMITS.questionsPerResolver + 1 },
                    () => question(),
                  ),
                },
              ],
            },
          ],
        },
      }),
      'resource-limit',
      '$.workspace.evidence.runs[0].resolvers[0].questions',
    );
    expectFailure(
      parseChangeWorkspace({
        ...base,
        evidence: {
          ...base.evidence,
          runs: [
            {
              ...run(),
              resolvers: [
                {
                  ...resolver(),
                  questions: [
                    {
                      ...question(),
                      records: Array.from(
                        { length: CHANGE_WORKSPACE_LIMITS.recordsPerQuestion + 1 },
                        () => 'record',
                      ),
                    },
                  ],
                },
              ],
            },
          ],
        },
      }),
      'resource-limit',
      '$.workspace.evidence.runs[0].resolvers[0].questions[0].records',
    );
  });

  it('enforces aggregate evidence question and record limits', () => {
    const makeQuestion = (index: number, records: readonly string[] = ['r']) => ({
      ...question(10_000 + index),
      name: '.',
      records,
      type: `TYPE${String(index)}`,
    });
    const questionResolvers = Array.from({ length: 5 }, (_, resolverIndex) => ({
      ...resolver(20 + resolverIndex),
      endpoint: `https://resolver-${String(resolverIndex)}.example.test/dns-query`,
      questions: Array.from(
        {
          length: resolverIndex === 4 ? 1 : CHANGE_WORKSPACE_LIMITS.evidenceQuestions / 4,
        },
        (_, index) =>
          makeQuestion(resolverIndex * (CHANGE_WORKSPACE_LIMITS.evidenceQuestions / 4) + index),
      ),
    }));
    expectFailure(
      parseChangeWorkspace({
        ...workspace(),
        evidence: {
          incompleteReasons: [],
          runs: [{ ...run(), resolvers: questionResolvers }],
          status: 'complete',
        },
      }),
      'resource-limit',
    );

    const recordsPerQuestion = CHANGE_WORKSPACE_LIMITS.recordsPerQuestion;
    const recordQuestions = Array.from(
      { length: Math.floor(CHANGE_WORKSPACE_LIMITS.evidenceRecords / recordsPerQuestion) + 1 },
      (_, questionIndex) =>
        makeQuestion(
          30_000 + questionIndex,
          Array.from(
            { length: recordsPerQuestion },
            (_, recordIndex) => `${questionIndex.toString(36)}-${recordIndex.toString(36)}`,
          ),
        ),
    );
    expectFailure(
      parseChangeWorkspace({
        ...workspace(),
        evidence: {
          incompleteReasons: [],
          runs: [
            {
              ...run(),
              resolvers: [{ ...resolver(), questions: recordQuestions }],
            },
          ],
          status: 'complete',
        },
      }),
      'resource-limit',
    );
  });

  it('enforces the aggregate evidence-octet limit', () => {
    const reasons = Array.from(
      { length: 65 },
      (_, index) => `${String(index).padStart(3, '0')}${'x'.repeat(8_100)}`,
    );
    expectFailure(
      parseChangeWorkspace({
        ...workspace(),
        evidence: { incompleteReasons: reasons, runs: [], status: 'partial' },
      }),
      'resource-limit',
      '$.workspace.evidence.incompleteReasons[64]',
    );
  });

  it.each([
    [
      'not-run analysis with results',
      { ...workspace().analysis, analysedAt: null, status: 'not-run' },
    ],
    [
      'complete analysis with an incomplete reason',
      { ...workspace().analysis, incompleteReasons: ['missing input'] },
    ],
    [
      'partial analysis without an incomplete reason',
      { ...workspace().analysis, incompleteReasons: [], status: 'partial' },
    ],
    [
      'partial analysis claiming an overall risk',
      {
        ...workspace().analysis,
        incompleteReasons: ['The comparison scope was incomplete.'],
        risk: 'high',
        status: 'partial',
      },
    ],
  ])('rejects %s', (_label, analysis) => {
    expectFailure(parseChangeWorkspace({ ...workspace(), analysis }), 'invalid-schema');
  });

  it.each([
    ['none evidence with runs', { ...workspace().evidence, status: 'none' }],
    [
      'complete evidence with an incomplete reason',
      { ...workspace().evidence, incompleteReasons: ['missing response'] },
    ],
    [
      'partial evidence without an incomplete reason',
      { ...workspace().evidence, incompleteReasons: [], status: 'partial' },
    ],
    [
      'complete evidence with a partial run',
      {
        ...workspace().evidence,
        runs: [{ ...run(), incompleteReasons: ['cancelled'], status: 'partial' }],
      },
    ],
  ])('rejects %s', (_label, evidence) => {
    expectFailure(parseChangeWorkspace({ ...workspace(), evidence }), 'invalid-schema');
  });

  it('rejects inconsistent run and resolver completeness and reversed run timestamps', () => {
    const candidates = [
      {
        ...run(),
        resolvers: [{ ...resolver(), incompleteReasons: ['truncated'], status: 'partial' }],
      },
      { ...run(), incompleteReasons: [], status: 'partial' },
      { ...run(), completedAt: '2026-08-14T00:00:00.000Z' },
      { ...run(), resolvers: [] },
      { ...run(), resolvers: [{ ...resolver(), questions: [] }] },
      {
        ...run(),
        resolvers: [{ ...resolver(), incompleteReasons: [], status: 'partial' }],
        incompleteReasons: ['resolver partial'],
        status: 'partial',
      },
    ];
    for (const candidate of candidates) {
      expectFailure(
        parseChangeWorkspace({
          ...workspace(),
          evidence: { incompleteReasons: [], runs: [candidate], status: 'complete' },
        }),
        'invalid-schema',
      );
    }
  });

  it.each([
    ['timeout', null],
    ['network-error', null],
    ['cancelled', null],
    ['server-failure', 2],
    ['refused', 5],
  ] as const)(
    'rejects complete evidence containing a coherent %s question outcome',
    (status, responseCode) => {
      const failedQuestion: ChangeWorkspaceQuestionObservation =
        responseCode === null
          ? {
              ...question(),
              authenticatedData: null,
              error: `The question ended with ${status}.`,
              records: [],
              responseCode: null,
              status,
            }
          : {
              ...question(),
              authenticatedData: false,
              error: null,
              records: [],
              responseCode,
              status,
            };
      expectFailure(
        parseChangeWorkspace({
          ...workspace(),
          evidence: {
            incompleteReasons: [],
            runs: [
              {
                ...run(),
                resolvers: [{ ...resolver(), questions: [failedQuestion] }],
              },
            ],
            status: 'complete',
          },
        }),
        'invalid-schema',
      );
    },
  );

  it('accepts failed questions only through a consistently partial evidence hierarchy', () => {
    const timeout: ChangeWorkspaceQuestionObservation = {
      ...question(),
      authenticatedData: null,
      error: 'The resolver timed out.',
      records: [],
      responseCode: null,
      status: 'timeout',
    };
    const partial = parseChangeWorkspace({
      ...workspace(),
      evidence: {
        incompleteReasons: ['The observation run was incomplete.'],
        runs: [
          {
            ...run(),
            incompleteReasons: ['A resolver observation was incomplete.'],
            resolvers: [
              {
                ...resolver(),
                incompleteReasons: ['The A question timed out.'],
                questions: [timeout],
                status: 'partial',
              },
            ],
            status: 'partial',
          },
        ],
        status: 'partial',
      },
    });
    expect(partial.ok).toBe(true);
  });

  it.each(['2026-08-14T00:00:59.999Z', '2026-08-14T00:03:00.001Z'])(
    'rejects question evidence observed outside its run interval (%s)',
    (observedAt) => {
      expectFailure(
        parseChangeWorkspace({
          ...workspace(),
          evidence: {
            incompleteReasons: [],
            runs: [
              {
                ...run(),
                resolvers: [{ ...resolver(), questions: [{ ...question(), observedAt }] }],
              },
            ],
            status: 'complete',
          },
        }),
        'invalid-schema',
        '$.workspace.evidence.runs[0].resolvers[0].questions[0].observedAt',
      );
    },
  );

  it('rejects duplicate run, resolver, and question evidence', () => {
    const duplicateRun = { ...run(10), id: run().id };
    const duplicateResolver = { ...resolver(10), id: resolver().id };
    const duplicateEndpoint = { ...resolver(11), endpoint: resolver().endpoint };
    const duplicateQuestionId = { ...question(10), id: question().id, name: 'other.example.' };
    const duplicateQuestion = { ...question(11), id: uuid(11) };
    const candidates: readonly (readonly ChangeWorkspaceObservationRun[])[] = [
      [run(), duplicateRun],
      [{ ...run(), resolvers: [resolver(), duplicateResolver] }],
      [{ ...run(), resolvers: [resolver(), duplicateEndpoint] }],
      [
        {
          ...run(),
          resolvers: [{ ...resolver(), questions: [question(), duplicateQuestionId] }],
        },
      ],
      [
        {
          ...run(),
          resolvers: [{ ...resolver(), questions: [question(), duplicateQuestion] }],
        },
      ],
    ];
    for (const runs of candidates) {
      expectFailure(
        parseChangeWorkspace({
          ...workspace(),
          evidence: { incompleteReasons: [], runs, status: 'complete' },
        }),
        'invalid-schema',
      );
    }
  });

  it('rejects active or ambiguous endpoint strings and unknown enums', () => {
    for (const endpoint of [
      'javascript:alert(1)',
      'http://dns.example.test/dns-query',
      'https://user@dns.example.test/dns-query',
      'https://dns.example.test/dns-query#fragment',
    ]) {
      expectFailure(
        parseChangeWorkspace({
          ...workspace(),
          evidence: {
            incompleteReasons: [],
            runs: [{ ...run(), resolvers: [{ ...resolver(), endpoint }] }],
            status: 'complete',
          },
        }),
        'invalid-schema',
      );
    }
    for (const candidate of [
      { endpoint: 'https://dns.quad9.net/dns-query', resolverId: 'quad9-relay' },
      { endpoint: '/api/doh/quad9', resolverId: 'custom' },
      { endpoint: '/api/doh/quad9?dns=question', resolverId: 'quad9-relay' },
    ] as const) {
      expectFailure(
        parseChangeWorkspace({
          ...workspace(),
          evidence: {
            incompleteReasons: [],
            runs: [{ ...run(), resolvers: [{ ...resolver(), ...candidate }] }],
            status: 'complete',
          },
        }),
        'invalid-schema',
      );
    }
    expectFailure(
      parseChangeWorkspace({
        ...workspace(),
        analysis: { ...workspace().analysis, status: 'unknown' },
      }),
      'invalid-schema',
    );
  });

  it('rejects malformed questions and contradictory response metadata', () => {
    const candidates = [
      { ...question(), type: 'a' },
      { ...question(), type: 'TYPE65536' },
      { ...question(), className: 'CH' },
      { ...question(), responseCode: 1.5 },
      { ...question(), responseCode: -0 },
      { ...question(), responseCode: 16 },
      { ...question(), records: [], status: 'answer' },
      { ...question(), responseCode: 3, status: 'answer' },
      { ...question(), status: 'timeout' },
    ];
    for (const candidate of candidates) {
      expectFailure(
        parseChangeWorkspace({
          ...workspace(),
          evidence: {
            incompleteReasons: [],
            runs: [{ ...run(), resolvers: [{ ...resolver(), questions: [candidate] }] }],
            status: 'complete',
          },
        }),
        'invalid-schema',
      );
    }
  });

  it('accepts a coherent partial workspace without converting missing data into zero', () => {
    const partial: ChangeWorkspace = {
      ...workspace(),
      analysis: {
        analysedAt: '2026-08-14T00:00:30.000Z',
        changes: [],
        findings: [],
        guidance: [],
        incompleteReasons: ['Current zone parsing reached its record bound.'],
        phases: [],
        risk: null,
        status: 'partial',
        timing: workspace().analysis.timing,
      },
      evidence: {
        incompleteReasons: ['Resolver observation was cancelled.'],
        runs: [
          {
            ...run(),
            incompleteReasons: ['Resolver observation was cancelled.'],
            resolvers: [
              {
                ...resolver(),
                incompleteReasons: ['Question was cancelled.'],
                questions: [
                  {
                    ...question(),
                    authenticatedData: null,
                    error: 'The observation was cancelled.',
                    records: [],
                    responseCode: null,
                    status: 'cancelled',
                  },
                ],
                status: 'partial',
              },
            ],
            status: 'partial',
          },
        ],
        status: 'partial',
      },
    };

    const parsed = parseChangeWorkspace(partial);
    expect(parsed).toEqual({ ok: true, value: partial });
    if (parsed.ok) {
      expect(parsed.value.analysis.changes).toEqual([]);
      expect(parsed.value.analysis.status).toBe('partial');
      expect(
        parsed.value.evidence.runs[0]?.resolvers[0]?.questions[0]?.responseCode,
      ).toBeNull();
    }
  });

  it('accepts explicit not-run and no-evidence states and retains duplicate DNS records', () => {
    const unanalysed: ChangeWorkspace = {
      ...workspace(),
      analysis: {
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
      },
      evidence: { incompleteReasons: [], runs: [], status: 'none' },
    };
    expect(parseChangeWorkspace(unanalysed)).toEqual({ ok: true, value: unanalysed });

    const duplicateRecords = {
      ...workspace(),
      evidence: {
        incompleteReasons: [],
        runs: [
          {
            ...run(),
            resolvers: [
              {
                ...resolver(),
                questions: [
                  {
                    ...question(),
                    records: [question().records[0], question().records[0]],
                  },
                ],
              },
            ],
          },
        ],
        status: 'complete',
      },
    };
    expect(parseChangeWorkspace(duplicateRecords).ok).toBe(true);
  });
});
