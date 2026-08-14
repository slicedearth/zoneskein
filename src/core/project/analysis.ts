import { compareZoneDocuments, omitIncompleteRecordTypes } from '../diff/compare';
import { planDnsChanges } from '../diff/plan';
import type { DnsChangePlan, DiffReport } from '../diff/types';
import { failure, success, type Result } from '../result';
import { parseZoneSnippet } from '../zone/parser';
import type { ZoneDiagnostic, ZoneDocument } from '../zone/types';
import { parseChangeWorkspace } from './codec';
import { CHANGE_WORKSPACE_LIMITS } from './limits';
import type {
  ChangeWorkspace,
  ChangeWorkspaceAnalysis,
  ChangeWorkspaceAnalysedChange,
  ChangeWorkspaceCodecError,
  ChangeWorkspaceFinding,
  ChangeWorkspaceTiming,
} from './types';

export interface ChangeWorkspaceDependencies {
  readonly now: () => Date;
  readonly uuid: () => string;
}

export interface ChangeWorkspaceAnalysisOptions {
  readonly incompleteTypes?: readonly string[];
  readonly plannedAt?: Date;
}

export function emptyChangeWorkspaceAnalysis(): ChangeWorkspaceAnalysis {
  return {
    analysedAt: null,
    changes: [],
    findings: [],
    guidance: [],
    incompleteReasons: [],
    phases: [],
    risk: null,
    status: 'not-run',
    timing: emptyTiming(),
  };
}

function emptyTiming(): ChangeWorkspaceTiming {
  return {
    plannedAt: null,
    preparationDeadline: null,
    previousTtlSeconds: null,
    rollbackCacheHorizon: null,
    safeChangeAtIfLoweredNow: null,
  };
}

function codecFailure(message: string, path = '$.workspace.analysis') {
  return failure<ChangeWorkspaceCodecError>({ code: 'invalid-schema', message, path });
}

function resourceFailure(message: string, path: string) {
  return failure<ChangeWorkspaceCodecError>({ code: 'resource-limit', message, path });
}

function timestamp(date: Date, path: string): Result<string, ChangeWorkspaceCodecError> {
  try {
    const value = date.toISOString();
    return Number.isNaN(date.getTime())
      ? codecFailure('Expected a valid analysis timestamp.', path)
      : success(value);
  } catch {
    return codecFailure('Expected a valid analysis timestamp.', path);
  }
}

function unique(values: readonly string[]): readonly string[] {
  return [...new Set(values)];
}

function checkedIncompleteTypes(
  values: readonly string[] | undefined,
): Result<readonly string[], ChangeWorkspaceCodecError> {
  if (values === undefined) return success([]);
  if (values.length > CHANGE_WORKSPACE_LIMITS.incompleteReasons) {
    return resourceFailure(
      `Incomplete record types exceed the ${String(CHANGE_WORKSPACE_LIMITS.incompleteReasons)}-item safety limit.`,
      '$.workspace.analysis.incompleteTypes',
    );
  }
  const checked: string[] = [];
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (
      value === undefined ||
      value.length > 32 ||
      !/^(?:[A-Z][A-Z0-9-]{0,31}|TYPE(?:0|[1-9]\d{0,4}))$/u.test(value) ||
      (value.startsWith('TYPE') && Number(value.slice(4)) > 65_535)
    ) {
      return codecFailure(
        'Incomplete record types must use an upper-case mnemonic or TYPE number.',
        `$.workspace.analysis.incompleteTypes[${String(index)}]`,
      );
    }
    checked.push(value);
  }
  return success(unique(checked));
}

function partialAnalysis(
  analysedAt: string,
  reasons: readonly string[],
  findings: readonly ChangeWorkspaceFinding[] = [],
): ChangeWorkspaceAnalysis {
  return {
    analysedAt,
    changes: [],
    findings,
    guidance: [],
    incompleteReasons: unique(reasons),
    phases: [],
    risk: null,
    status: 'partial',
    timing: emptyTiming(),
  };
}

interface BlockingParserDiagnostic {
  readonly diagnostic: ZoneDiagnostic;
  readonly label: 'Current' | 'Intended';
  readonly scope: 'current' | 'intended';
}

function blocksComparison(diagnostic: ZoneDiagnostic): boolean {
  return diagnostic.severity === 'error' || diagnostic.rule === 'directive-unsupported';
}

function parserFailureAnalysis(
  current: ZoneDocument,
  intended: ZoneDocument,
  analysedAt: string,
): ChangeWorkspaceAnalysis | null {
  const reasons: string[] = [];
  const blocking: BlockingParserDiagnostic[] = [];
  for (const [label, scope, document] of [
    ['Current', 'current', current],
    ['Intended', 'intended', intended],
  ] as const) {
    if (document.incomplete !== undefined) {
      reasons.push(`${label} zone parsing is incomplete: ${document.incomplete.message}`);
    }
    const diagnostics = document.diagnostics.filter(blocksComparison);
    if (diagnostics.length > 0) {
      reasons.push(
        `${label} zone parsing reported ${String(diagnostics.length)} diagnostic${diagnostics.length === 1 ? '' : 's'} indicating omitted or unparseable input. Comparison was not run.`,
      );
      blocking.push(...diagnostics.map((diagnostic) => ({ diagnostic, label, scope })));
    }
  }
  if (reasons.length === 0) return null;

  const retained = blocking.slice(0, CHANGE_WORKSPACE_LIMITS.analysisFindings);
  if (blocking.length > retained.length) {
    reasons.push(
      `Only the first ${String(retained.length)} of ${String(blocking.length)} blocking parser diagnostics were retained within the workspace finding limit.`,
    );
  }
  return partialAnalysis(
    analysedAt,
    reasons,
    retained.map(({ diagnostic, label, scope }) => ({
      code: `${scope}-zone-input-incomplete`,
      message: `${label} line ${String(diagnostic.line)}:${String(diagnostic.column)} [${diagnostic.rule}] — ${diagnostic.message}`,
      risk: 'high',
    })),
  );
}

function mappedTiming(plan: DnsChangePlan): ChangeWorkspaceTiming {
  return {
    plannedAt: plan.timing.plannedAt ?? null,
    preparationDeadline: plan.timing.preparationDeadline ?? null,
    previousTtlSeconds: plan.timing.previousTtlSeconds ?? null,
    rollbackCacheHorizon: plan.timing.rollbackCacheHorizon ?? null,
    safeChangeAtIfLoweredNow: plan.timing.safeChangeAtIfLoweredNow ?? null,
  };
}

export function mapChangeWorkspaceAnalysis(
  report: DiffReport,
  plan: DnsChangePlan,
  analysedAt: string,
  incompleteInputReasons: readonly string[] = [],
): ChangeWorkspaceAnalysis {
  if (report.status === 'incomplete' || plan.status === 'incomplete') {
    return partialAnalysis(analysedAt, [
      ...incompleteInputReasons,
      ...report.incompleteReasons,
      ...plan.incompleteReasons,
    ]);
  }

  const impacts = new Map(plan.impacts.map((impact) => [impact.changeIndex, impact]));
  const impactShapeIsComplete =
    impacts.size === report.changes.length &&
    plan.impacts.every(
      (impact) =>
        impact.changeIndex >= 0 &&
        impact.changeIndex < report.changes.length &&
        Number.isSafeInteger(impact.changeIndex),
    );
  if (!impactShapeIsComplete) {
    return partialAnalysis(analysedAt, [
      ...incompleteInputReasons,
      'The captured change plan did not contain exactly one impact assessment for every classified change.',
    ]);
  }

  const changes: ChangeWorkspaceAnalysedChange[] = [];
  for (let index = 0; index < report.changes.length; index += 1) {
    const change = report.changes[index];
    const impact = impacts.get(index);
    if (change === undefined || impact === undefined) {
      return partialAnalysis(analysedAt, [
        ...incompleteInputReasons,
        'The captured change analysis could not be mapped without omitting an impact assessment.',
      ]);
    }
    changes.push({
      after: change.after?.original ?? null,
      before: change.before?.original ?? null,
      category: change.category,
      disruptive: change.disruptive,
      explanation: change.explanation,
      owner: change.owner,
      reasons: impact.reasons,
      risk: impact.risk,
      rollback: impact.rollback,
      type: change.type,
    });
  }

  const incompleteReasons = unique(incompleteInputReasons);
  return {
    analysedAt,
    changes,
    findings: plan.findings,
    guidance: report.guidance,
    incompleteReasons,
    phases: plan.phases,
    risk: incompleteReasons.length === 0 ? plan.risk : null,
    status: incompleteReasons.length === 0 ? 'complete' : 'partial',
    timing: mappedTiming(plan),
  };
}

function unavailableReasons(workspace: ChangeWorkspace): readonly string[] {
  const reasons: string[] = [];
  for (const [label, state] of [
    ['Current zone state', workspace.current],
    ['Intended zone state', workspace.intended],
  ] as const) {
    if (state.status === 'complete') continue;
    reasons.push(
      `${label} is ${state.status}; local comparison was not run because omitted records could otherwise be misclassified.`,
      ...state.incompleteReasons.map((reason) => `${label}: ${reason}`),
    );
  }
  return unique(reasons);
}

export function analyseChangeWorkspace(
  workspace: ChangeWorkspace,
  options: ChangeWorkspaceAnalysisOptions = {},
  dependencies: Pick<ChangeWorkspaceDependencies, 'now'> = { now: () => new Date() },
): Result<ChangeWorkspace, ChangeWorkspaceCodecError> {
  const parsed = parseChangeWorkspace(workspace);
  if (!parsed.ok) return parsed;
  let now: Date;
  try {
    now = dependencies.now();
  } catch {
    return codecFailure('The browser could not obtain an analysis timestamp.');
  }
  const analysedAt = timestamp(now, '$.workspace.analysis.analysedAt');
  if (!analysedAt.ok) return analysedAt;
  if (options.plannedAt !== undefined) {
    const plannedAt = timestamp(options.plannedAt, '$.workspace.analysis.timing.plannedAt');
    if (!plannedAt.ok) return plannedAt;
  }
  const incompleteTypes = checkedIncompleteTypes(options.incompleteTypes);
  if (!incompleteTypes.ok) return incompleteTypes;

  const inputReasons = unavailableReasons(parsed.value);
  if (
    parsed.value.current.status === 'unavailable' ||
    parsed.value.intended.status === 'unavailable'
  ) {
    return success(parsed.value);
  }
  let analysis: ChangeWorkspaceAnalysis;
  if (inputReasons.length > 0) {
    analysis = partialAnalysis(analysedAt.value, inputReasons);
  } else {
    const currentOptions =
      parsed.value.current.origin === null ? {} : { origin: parsed.value.current.origin };
    const intendedOptions =
      parsed.value.intended.origin === null ? {} : { origin: parsed.value.intended.origin };
    const current = parseZoneSnippet(parsed.value.current.source, currentOptions);
    const intended = parseZoneSnippet(parsed.value.intended.source, intendedOptions);
    const parserFailure = parserFailureAnalysis(current, intended, analysedAt.value);
    if (parserFailure !== null) {
      analysis = parserFailure;
    } else {
      const report = omitIncompleteRecordTypes(
        compareZoneDocuments(current, intended),
        incompleteTypes.value,
      );
      const plan = planDnsChanges(current, intended, report, {
        now,
        ...(incompleteTypes.value.length === 0
          ? {}
          : { incompleteTypes: incompleteTypes.value }),
        ...(options.plannedAt === undefined ? {} : { plannedAt: options.plannedAt }),
      });
      analysis = mapChangeWorkspaceAnalysis(
        report,
        plan,
        analysedAt.value,
        incompleteTypes.value.length === 0
          ? []
          : [
              `Current ${incompleteTypes.value.join(', ')} records were unavailable; changes for those types were omitted instead of inferred.`,
            ],
      );
    }
  }

  return parseChangeWorkspace({
    ...parsed.value,
    analysis,
    updatedAt: analysedAt.value,
  });
}
