import { failure, type Result } from '../result';
import type { DnsChangePlan, DiffReport } from '../diff/types';
import {
  analyseChangeWorkspace,
  emptyChangeWorkspaceAnalysis,
  mapChangeWorkspaceAnalysis,
  type ChangeWorkspaceDependencies,
} from './analysis';
import { parseChangeWorkspace } from './codec';
import type {
  ChangeWorkspace,
  ChangeWorkspaceAnalysis,
  ChangeWorkspaceCodecError,
  ChangeWorkspaceEvidence,
  ChangeWorkspaceZoneState,
} from './types';

export type ChangeWorkspaceZoneInput = Omit<ChangeWorkspaceZoneState, 'format'>;

export interface BlankChangeWorkspaceOptions {
  readonly title?: string;
}

export interface RecordStudioChangeWorkspaceOptions {
  readonly intendedIncompleteReasons?: readonly string[];
  readonly intendedSource: string;
  readonly intendedStatus?: ChangeWorkspaceZoneState['status'];
  readonly origin?: string | null;
  readonly title?: string;
}

export interface CapturedChangeWorkspaceAnalysis {
  readonly analysedAt?: Date;
  readonly plan: DnsChangePlan;
  readonly report: DiffReport;
}

export interface ChangeLabWorkspaceOptions {
  readonly analysis?: CapturedChangeWorkspaceAnalysis;
  readonly currentIncompleteReasons?: readonly string[];
  readonly currentOrigin?: string | null;
  readonly currentSource: string;
  readonly currentStatus?: ChangeWorkspaceZoneState['status'];
  readonly evidence?: ChangeWorkspaceEvidence;
  readonly incompleteTypes?: readonly string[];
  readonly intendedIncompleteReasons?: readonly string[];
  readonly intendedOrigin?: string | null;
  readonly intendedSource: string;
  readonly intendedStatus?: ChangeWorkspaceZoneState['status'];
  readonly origin?: string | null;
  readonly plannedAt?: Date;
  readonly title?: string;
}

export interface ChangeWorkspaceEditPatch {
  readonly current?: ChangeWorkspaceZoneInput;
  readonly evidence?: ChangeWorkspaceEvidence;
  readonly intended?: ChangeWorkspaceZoneInput;
  readonly title?: string;
}

const DEFAULT_DEPENDENCIES: ChangeWorkspaceDependencies = {
  now: () => new Date(),
  uuid: () => globalThis.crypto.randomUUID(),
};

function creationFailure(
  message: string,
  path: string,
): Result<never, ChangeWorkspaceCodecError> {
  return failure({ code: 'invalid-schema', message, path });
}

function timestamp(date: Date, path: string): Result<string, ChangeWorkspaceCodecError> {
  try {
    return { ok: true, value: date.toISOString() };
  } catch {
    return creationFailure('Expected a valid workspace timestamp.', path);
  }
}

function identity(
  dependencies: ChangeWorkspaceDependencies,
): Result<
  { readonly at: string; readonly date: Date; readonly id: string },
  ChangeWorkspaceCodecError
> {
  let date: Date;
  let id: string;
  try {
    date = dependencies.now();
    id = dependencies.uuid();
  } catch {
    return creationFailure(
      'The browser could not create a workspace identifier or timestamp.',
      '$.workspace',
    );
  }
  const at = timestamp(date, '$.workspace.createdAt');
  return at.ok ? { ok: true, value: { at: at.value, date, id } } : at;
}

function noneEvidence(): ChangeWorkspaceEvidence {
  return { incompleteReasons: [], runs: [], status: 'none' };
}

function unavailableZone(reason: string): ChangeWorkspaceZoneState {
  return {
    format: 'bind-zone-text',
    incompleteReasons: [reason],
    origin: null,
    source: '',
    status: 'unavailable',
  };
}

function zoneState(
  source: string,
  origin: string | null | undefined,
  status: ChangeWorkspaceZoneState['status'] | undefined,
  incompleteReasons: readonly string[] | undefined,
): ChangeWorkspaceZoneState {
  return {
    format: 'bind-zone-text',
    incompleteReasons: incompleteReasons ?? [],
    origin: origin ?? null,
    source,
    status: status ?? 'complete',
  };
}

function baseWorkspace(
  id: string,
  at: string,
  title: string,
  current: ChangeWorkspaceZoneState,
  intended: ChangeWorkspaceZoneState,
  evidence: ChangeWorkspaceEvidence = noneEvidence(),
): Result<ChangeWorkspace, ChangeWorkspaceCodecError> {
  return parseChangeWorkspace({
    analysis: initialAnalysis(current, intended, at),
    createdAt: at,
    current,
    evidence,
    id,
    intended,
    title,
    updatedAt: at,
  });
}

function inputReasons(
  current: ChangeWorkspaceZoneState,
  intended: ChangeWorkspaceZoneState,
): readonly string[] {
  const reasons: string[] = [];
  for (const [label, state] of [
    ['Current zone state', current],
    ['Intended zone state', intended],
  ] as const) {
    if (state.status === 'complete') continue;
    reasons.push(
      `${label} is ${state.status}; the captured analysis is bounded by that input.`,
      ...state.incompleteReasons.map((reason) => `${label}: ${reason}`),
    );
  }
  return [...new Set(reasons)];
}

function initialAnalysis(
  current: ChangeWorkspaceZoneState,
  intended: ChangeWorkspaceZoneState,
  analysedAt: string,
): ChangeWorkspaceAnalysis {
  if (current.status === 'unavailable' || intended.status === 'unavailable') {
    return emptyChangeWorkspaceAnalysis();
  }
  if (current.status === 'partial' || intended.status === 'partial') {
    return {
      analysedAt,
      changes: [],
      findings: [],
      guidance: [],
      incompleteReasons: inputReasons(current, intended),
      phases: [],
      risk: null,
      status: 'partial',
      timing: {
        plannedAt: null,
        preparationDeadline: null,
        previousTtlSeconds: null,
        rollbackCacheHorizon: null,
        safeChangeAtIfLoweredNow: null,
      },
    };
  }
  return emptyChangeWorkspaceAnalysis();
}

export function createBlankChangeWorkspace(
  options: BlankChangeWorkspaceOptions = {},
  dependencies: ChangeWorkspaceDependencies = DEFAULT_DEPENDENCIES,
): Result<ChangeWorkspace, ChangeWorkspaceCodecError> {
  const created = identity(dependencies);
  if (!created.ok) return created;
  return baseWorkspace(
    created.value.id,
    created.value.at,
    options.title ?? 'Untitled change workspace',
    unavailableZone('Current zone records have not been supplied.'),
    unavailableZone('Intended zone records have not been supplied.'),
  );
}

export function createRecordStudioChangeWorkspace(
  options: RecordStudioChangeWorkspaceOptions,
  dependencies: ChangeWorkspaceDependencies = DEFAULT_DEPENDENCIES,
): Result<ChangeWorkspace, ChangeWorkspaceCodecError> {
  const created = identity(dependencies);
  if (!created.ok) return created;
  return baseWorkspace(
    created.value.id,
    created.value.at,
    options.title ?? 'Record Studio intended state',
    unavailableZone('No current-zone snapshot accompanied this Record Studio hand-off.'),
    zoneState(
      options.intendedSource,
      options.origin,
      options.intendedStatus,
      options.intendedIncompleteReasons,
    ),
  );
}

export function createChangeLabWorkspace(
  options: ChangeLabWorkspaceOptions,
  dependencies: ChangeWorkspaceDependencies = DEFAULT_DEPENDENCIES,
): Result<ChangeWorkspace, ChangeWorkspaceCodecError> {
  const created = identity(dependencies);
  if (!created.ok) return created;
  const current = zoneState(
    options.currentSource,
    options.currentOrigin === undefined ? options.origin : options.currentOrigin,
    options.currentStatus,
    options.currentIncompleteReasons,
  );
  const intended = zoneState(
    options.intendedSource,
    options.intendedOrigin === undefined ? options.origin : options.intendedOrigin,
    options.intendedStatus,
    options.intendedIncompleteReasons,
  );
  const workspace = baseWorkspace(
    created.value.id,
    created.value.at,
    options.title ?? 'DNS Change Lab workspace',
    current,
    intended,
    options.evidence,
  );
  if (!workspace.ok) return workspace;

  if (current.status === 'unavailable' || intended.status === 'unavailable') {
    return workspace;
  }

  if (options.analysis === undefined) {
    return analyseChangeWorkspace(
      workspace.value,
      {
        ...(options.incompleteTypes === undefined
          ? {}
          : { incompleteTypes: options.incompleteTypes }),
        ...(options.plannedAt === undefined ? {} : { plannedAt: options.plannedAt }),
      },
      { now: () => created.value.date },
    );
  }

  const analysed = timestamp(
    options.analysis.analysedAt ?? created.value.date,
    '$.workspace.analysis.analysedAt',
  );
  if (!analysed.ok) return analysed;
  return parseChangeWorkspace({
    ...workspace.value,
    analysis: mapChangeWorkspaceAnalysis(
      options.analysis.report,
      options.analysis.plan,
      analysed.value,
      inputReasons(current, intended),
    ),
    updatedAt: analysed.value < created.value.at ? created.value.at : analysed.value,
  });
}

export function editChangeWorkspace(
  workspace: ChangeWorkspace,
  patch: ChangeWorkspaceEditPatch,
  dependencies: Pick<ChangeWorkspaceDependencies, 'now'> = DEFAULT_DEPENDENCIES,
): Result<ChangeWorkspace, ChangeWorkspaceCodecError> {
  const parsed = parseChangeWorkspace(workspace);
  if (!parsed.ok) return parsed;
  let now: Date;
  try {
    now = dependencies.now();
  } catch {
    return creationFailure(
      'The browser could not obtain an edit timestamp.',
      '$.workspace.updatedAt',
    );
  }
  const updatedAt = timestamp(now, '$.workspace.updatedAt');
  if (!updatedAt.ok) return updatedAt;
  const zoneChanged = patch.current !== undefined || patch.intended !== undefined;
  const current =
    patch.current === undefined
      ? parsed.value.current
      : { format: 'bind-zone-text' as const, ...patch.current };
  const intended =
    patch.intended === undefined
      ? parsed.value.intended
      : { format: 'bind-zone-text' as const, ...patch.intended };
  const evidence =
    patch.evidence ?? (patch.current === undefined ? parsed.value.evidence : noneEvidence());
  return parseChangeWorkspace({
    ...parsed.value,
    analysis: zoneChanged
      ? initialAnalysis(current, intended, updatedAt.value)
      : parsed.value.analysis,
    current,
    evidence,
    intended,
    title: patch.title ?? parsed.value.title,
    updatedAt: updatedAt.value,
  });
}
