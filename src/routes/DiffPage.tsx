import { useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { SnapshotButton } from '../components/SnapshotButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import {
  createChangeLabWorkspace,
  type ChangeWorkspace,
  type ChangeWorkspaceEvidence,
  type ChangeWorkspaceQuestionObservation,
  type ChangeWorkspaceQuestionStatus,
} from '../core/project';
import {
  compareZoneDocuments,
  isDefinitiveDnsObservation,
  omitIncompleteRecordTypes,
} from '../core/diff/compare';
import { planDnsChanges } from '../core/diff/plan';
import type { ChangeRisk, DiffReport, DnsChange, DnsChangePlan } from '../core/diff/types';
import { reachableAnswerRecords } from '../core/dns/answer-chain';
import { validateDnsName } from '../core/dns/names';
import { bindRecord } from '../core/dns/presentation';
import {
  DnsQueryError,
  type DnsRecord,
  type DnsRecordType,
  type DnsResponse,
  type ResolverId,
} from '../core/dns/types';
import { DnsQueryRun } from '../core/doh/query-run';
import { RESOLVERS } from '../core/doh/resolvers';
import { WireDnsResolver } from '../core/doh/wire-resolver';
import {
  escapeTechnicalText,
  markdownLiteral,
  markdownTableLiteral,
} from '../core/technical-text';
import { parseZoneSnippet, ZONE_ANALYSIS_LIMITS } from '../core/zone/parser';
import type { ZoneDocument, ZoneRecord } from '../core/zone/types';

type DiffMode = 'pasted' | 'current';
const CURRENT_TYPES = [
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'NS',
  'TXT',
  'CAA',
  'SRV',
] as const satisfies readonly DnsRecordType[];
const DEFAULT_CURRENT_TYPES = new Set<DnsRecordType>(['A', 'AAAA', 'MX', 'TXT', 'CAA']);
const RESOLVER_IDS = Object.keys(RESOLVERS) as ResolverId[];

interface DisplayReport {
  readonly after: ZoneDocument;
  readonly analysedAt: Date;
  readonly before: ZoneDocument;
  readonly currentIncompleteReasons?: readonly string[];
  readonly currentOrigin: string | null;
  readonly currentSnapshot?: string;
  readonly dependencySnapshot?: string;
  readonly evidence?: ChangeWorkspaceEvidence;
  readonly intendedOrigin: string | null;
  readonly partialErrors: readonly string[];
  readonly plan: DnsChangePlan;
  readonly report: DiffReport;
}

interface CurrentObservationOutcome {
  readonly bindingError?: string;
  readonly controlledRecords: readonly DnsRecord[];
  readonly dependencyRecords: readonly DnsRecord[];
  readonly error?: string;
  readonly errorCode?: DnsQueryError['code'];
  readonly observedAt: string;
  readonly records: readonly DnsRecord[];
  readonly response?: DnsResponse;
  readonly type: DnsRecordType;
}

export interface ChangeLabInput {
  readonly current: string;
  readonly currentIncompleteReasons?: readonly string[];
  readonly currentOrigin?: string | null;
  readonly currentStatus?: ChangeWorkspace['current']['status'];
  readonly intended: string;
  readonly intendedIncompleteReasons?: readonly string[];
  readonly intendedOrigin?: string | null;
  readonly intendedStatus?: ChangeWorkspace['intended']['status'];
  readonly origin?: string;
  readonly workspace?: ChangeWorkspace;
}

export interface DiffPageProps {
  readonly initialInput?: ChangeLabInput;
  readonly onCreateWorkspace?: (workspace: ChangeWorkspace) => void;
}

const RESPONSE_CODES = Object.freeze({
  NOERROR: 0,
  NXDOMAIN: 3,
  REFUSED: 5,
  SERVFAIL: 2,
} as const);

function failureStatus(code: DnsQueryError['code'] | undefined): ChangeWorkspaceQuestionStatus {
  if (code === 'timeout') return 'timeout';
  if (code === 'aborted') return 'cancelled';
  if (code === 'invalid-response') return 'malformed-response';
  return 'network-error';
}

function questionStatus(
  responseCode: keyof typeof RESPONSE_CODES,
  records: readonly string[],
): ChangeWorkspaceQuestionStatus {
  if (responseCode === 'NXDOMAIN') return 'name-error';
  if (responseCode === 'REFUSED') return 'refused';
  if (responseCode === 'SERVFAIL') return 'server-failure';
  return records.length === 0 ? 'no-data' : 'answer';
}

function currentEvidence(
  outcomes: readonly CurrentObservationOutcome[],
  resolverId: ResolverId,
  name: string,
  startedAt: string,
  completedAt: string,
  incompleteReasons: readonly string[],
): ChangeWorkspaceEvidence {
  const questions = outcomes.flatMap<ChangeWorkspaceQuestionObservation>((outcome) => {
    if (outcome.response === undefined || outcome.bindingError !== undefined) {
      return [
        {
          authenticatedData: null,
          className: 'IN',
          error: outcome.error ?? 'The DNS question did not produce a response.',
          id: crypto.randomUUID(),
          name,
          observedAt: outcome.observedAt,
          records: [],
          responseCode: null,
          status:
            outcome.bindingError === undefined
              ? failureStatus(outcome.errorCode)
              : 'malformed-response',
          type: outcome.type,
        },
      ];
    }
    const responseCode = outcome.response.message.responseCode;
    if (!(responseCode in RESPONSE_CODES)) return [];
    const code = responseCode as keyof typeof RESPONSE_CODES;
    const records = outcome.records.map(bindRecord);
    return [
      {
        authenticatedData: outcome.response.message.flags.authenticatedData,
        className: 'IN',
        error: null,
        id: crypto.randomUUID(),
        name,
        observedAt: outcome.response.receivedAt,
        records,
        responseCode: RESPONSE_CODES[code],
        status: questionStatus(code, records),
        type: outcome.type,
      },
    ];
  });
  const partial = incompleteReasons.length > 0 || questions.length !== outcomes.length;
  const reasons = [
    ...incompleteReasons,
    ...(questions.length === outcomes.length
      ? []
      : ['One or more resolver responses used an unsupported response code.']),
  ];
  const status = partial ? 'partial' : 'complete';
  const resolver = RESOLVERS[resolverId];
  const observedTimes = outcomes
    .map((outcome) => Date.parse(outcome.observedAt))
    .filter(Number.isFinite);
  const runStartedAt = new Date(
    Math.min(Date.parse(startedAt), ...observedTimes),
  ).toISOString();
  const runCompletedAt = new Date(
    Math.max(Date.parse(completedAt), ...observedTimes),
  ).toISOString();
  return {
    incompleteReasons: reasons,
    runs: [
      {
        completedAt: runCompletedAt,
        id: crypto.randomUUID(),
        incompleteReasons: reasons,
        resolvers: [
          {
            endpoint: resolver.endpoint,
            id: crypto.randomUUID(),
            incompleteReasons: reasons,
            label: resolver.label,
            questions,
            resolverId,
            status,
          },
        ],
        startedAt: runStartedAt,
        status,
      },
    ],
    status,
  };
}

function suppliedOrigin(
  specific: string | null | undefined,
  shared: string | undefined,
): string {
  return specific === null ? '' : (specific ?? shared ?? '');
}

function canonicalOwner(value: string): string {
  return value.toLowerCase().replace(/\.$/u, '');
}

function isWithinZone(name: string, zone: string): boolean {
  const owner = canonicalOwner(name);
  const origin = canonicalOwner(zone);
  return origin === '' || owner === origin || owner.endsWith(`.${origin}`);
}

function scopedDocument(document: ZoneDocument, records: readonly ZoneRecord[]): ZoneDocument {
  return {
    ...document,
    records,
    source: records.map((record) => recordText(record)).join('\n'),
  };
}

function blockingParserReasons(label: string, document: ZoneDocument): readonly string[] {
  const blocking = document.diagnostics.filter(
    (diagnostic) =>
      diagnostic.severity === 'error' || diagnostic.rule === 'directive-unsupported',
  );
  const retained = blocking.slice(0, 16);
  return [
    ...(document.incomplete === undefined
      ? []
      : [`${label} parsing is incomplete: ${document.incomplete.message}`]),
    ...(blocking.length === 0
      ? []
      : [
          `${label} parsing reported ${String(blocking.length)} diagnostic${blocking.length === 1 ? '' : 's'} indicating omitted or unparseable input.`,
          ...retained.map(
            (diagnostic) =>
              `${label} line ${String(diagnostic.line)}:${String(diagnostic.column)} [${diagnostic.rule}] — ${diagnostic.message}`,
          ),
          ...(retained.length === blocking.length
            ? []
            : [
                `${label} has ${String(blocking.length - retained.length)} additional blocking diagnostics.`,
              ]),
        ]),
  ];
}

function recordText(record: ZoneRecord | undefined): string {
  if (record === undefined) return '—';
  return `${record.owner} ${record.ttl === undefined ? '' : `${String(record.ttl)} `}${record.className} ${record.type} ${record.rdata.map((token) => token.raw).join(' ')}`;
}

function recordDisplayText(record: ZoneRecord | undefined): string {
  return escapeTechnicalText(recordText(record));
}

function categoryTone(change: DnsChange) {
  if (change.disruptive) return 'error';
  if (change.category === 'added') return 'pass';
  if (change.category === 'formatting-only') return 'information';
  return 'warning';
}

function riskTone(risk: ChangeRisk) {
  if (risk === 'critical' || risk === 'high') return 'error';
  if (risk === 'moderate') return 'warning';
  if (risk === 'low') return 'pass';
  return 'information';
}

function dateLabel(value: string | undefined): string {
  if (value === undefined) return 'Not established';
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value));
}

function markdown(report: DisplayReport): string {
  return [
    '# ZoneSkein DNS change comparison',
    '',
    `Overall risk: ${report.plan.risk}`,
    '',
    '| Category | Risk | Owner | Type | Before | After | Rollback |',
    '| --- | --- | --- | --- | --- | --- | --- |',
    ...report.report.changes.map((change, index) => {
      const impact = report.plan.impacts[index];
      return `| ${change.category} | ${impact?.risk ?? 'unknown'} | ${markdownTableLiteral(change.owner)} | ${markdownTableLiteral(change.type)} | ${markdownTableLiteral(recordText(change.before))} | ${markdownTableLiteral(recordText(change.after))} | ${markdownTableLiteral(impact?.rollback ?? '')} |`;
    }),
    '',
    '## Preflight findings',
    '',
    ...(report.plan.findings.length === 0
      ? ['- No warning or error findings in the supplied snapshots.']
      : report.plan.findings.map(
          (item) =>
            `- **${item.risk} / ${markdownLiteral(item.code)}:** ${markdownLiteral(item.message)}`,
        )),
    '',
    '## Timing evidence',
    '',
    `- Planned publication: ${dateLabel(report.plan.timing.plannedAt)}`,
    `- Largest observed prior TTL: ${report.plan.timing.previousTtlSeconds === undefined ? 'not established' : `${String(report.plan.timing.previousTtlSeconds)} seconds`}`,
    `- Preparatory publication deadline: ${dateLabel(report.plan.timing.preparationDeadline)}`,
    `- Earliest change if a lower TTL were published now: ${dateLabel(report.plan.timing.safeChangeAtIfLoweredNow)}`,
    `- Observed cache rollback horizon: ${dateLabel(report.plan.timing.rollbackCacheHorizon)}`,
    '',
    '## Staged rollout',
    '',
    ...report.plan.phases.flatMap((phase, index) => [
      `### ${String(index + 1)}. ${markdownLiteral(phase.title)}`,
      '',
      ...phase.actions.map((item) => `- ${markdownLiteral(item)}`),
      '',
    ]),
  ].join('\n');
}

export function DiffPage({ initialInput, onCreateWorkspace }: DiffPageProps = {}) {
  const [mode, setMode] = useState<DiffMode>('pasted');
  const [before, setBefore] = useState(initialInput?.current ?? '');
  const [after, setAfter] = useState(initialInput?.intended ?? '');
  const [domain, setDomain] = useState('');
  const [liveOrigin, setLiveOrigin] = useState('');
  const [currentOrigin, setCurrentOrigin] = useState(
    suppliedOrigin(initialInput?.currentOrigin, initialInput?.origin),
  );
  const [intendedOrigin, setIntendedOrigin] = useState(
    suppliedOrigin(initialInput?.intendedOrigin, initialInput?.origin),
  );
  const [plannedAt, setPlannedAt] = useState('');
  const [resolverId, setResolverId] = useState<ResolverId>('google');
  const [types, setTypes] = useState(DEFAULT_CURRENT_TYPES);
  const [state, setState] = useState<
    'idle' | 'loading' | 'complete' | 'cancelled' | 'incomplete'
  >('idle');
  const [error, setError] = useState('');
  const [display, setDisplay] = useState<DisplayReport | null>(null);
  const activeRun = useRef<DnsQueryRun | null>(null);

  function invalidateResult() {
    activeRun.current?.cancel();
    activeRun.current = null;
    setDisplay(null);
    setError('');
    setState('idle');
  }

  function toggleType(type: DnsRecordType) {
    invalidateResult();
    setTypes((current) => {
      const next = new Set(current);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }

  function suppliedInputReasons(): readonly string[] {
    if (mode !== 'pasted' || initialInput === undefined) return [];
    const reasons: string[] = [];
    for (const [label, status, incompleteReasons] of [
      [
        'Current zone state',
        initialInput.currentStatus ?? 'complete',
        initialInput.currentIncompleteReasons ?? [],
      ],
      [
        'Intended zone state',
        initialInput.intendedStatus ?? 'complete',
        initialInput.intendedIncompleteReasons ?? [],
      ],
    ] as const) {
      if (status === 'complete') continue;
      reasons.push(
        `${label} is ${status}; omitted records cannot be treated as absent.`,
        ...incompleteReasons.map((reason) => `${label}: ${reason}`),
      );
    }
    return [...new Set(reasons)];
  }

  function stopIncomplete(reasons: readonly string[]) {
    setDisplay(null);
    setError(
      `Comparison incomplete. ${reasons.join(' ')} No partial change set or plan was produced.`,
    );
    setState('incomplete');
  }

  async function compare(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    setError('');
    setDisplay(null);
    setState('idle');
    activeRun.current?.cancel();
    activeRun.current = null;
    const plannedDate = plannedAt === '' ? undefined : new Date(plannedAt);
    if (plannedDate !== undefined && Number.isNaN(plannedDate.getTime())) {
      setError('Enter a valid planned publication date and time.');
      return;
    }
    if (mode === 'pasted') {
      const incompleteInputReasons = suppliedInputReasons();
      if (incompleteInputReasons.length > 0) {
        stopIncomplete(incompleteInputReasons);
        return;
      }
      const prior = parseZoneSnippet(
        before,
        currentOrigin.trim() === '' ? {} : { origin: currentOrigin },
      );
      const next = parseZoneSnippet(
        after,
        intendedOrigin.trim() === '' ? {} : { origin: intendedOrigin },
      );
      const parserReasons = [
        ...blockingParserReasons('Current snapshot', prior),
        ...blockingParserReasons('Proposed snapshot', next),
      ];
      if (parserReasons.length > 0) {
        stopIncomplete(parserReasons);
        return;
      }
      const report = compareZoneDocuments(prior, next);
      if (report.status === 'incomplete') {
        stopIncomplete(report.incompleteReasons);
        return;
      }
      const plan = planDnsChanges(prior, next, report, {
        ...(plannedDate === undefined ? {} : { plannedAt: plannedDate }),
      });
      if (plan.status === 'incomplete') {
        stopIncomplete(plan.incompleteReasons);
        return;
      }
      setDisplay({
        after: next,
        analysedAt: new Date(),
        before: prior,
        currentOrigin: currentOrigin.trim() === '' ? null : currentOrigin.trim(),
        intendedOrigin: intendedOrigin.trim() === '' ? null : intendedOrigin.trim(),
        partialErrors: [],
        plan,
        report,
      });
      setState('complete');
      return;
    }

    const parsed = validateDnsName(domain);
    if (!parsed.ok) {
      setError(parsed.error.message);
      return;
    }
    const parsedOrigin = validateDnsName(liveOrigin);
    if (!parsedOrigin.ok) {
      setError(`Authoritative zone origin: ${parsedOrigin.error.message}`);
      return;
    }
    if (!isWithinZone(parsed.value.ascii, parsedOrigin.value.ascii)) {
      setError('The current DNS name must be the zone origin or a name beneath it.');
      return;
    }
    const selected = CURRENT_TYPES.filter((type) => types.has(type));
    if (selected.length === 0) {
      setError('Select at least one current record type.');
      return;
    }
    const run = new DnsQueryRun();
    activeRun.current = run;
    setState('loading');
    const resolver = new WireDnsResolver(RESOLVERS[resolverId]);
    const startedAt = new Date().toISOString();
    const outcomes = await Promise.all(
      selected.map(async (type) => {
        try {
          const response = await run.query(
            resolver,
            { name: parsed.value, type },
            { checkingDisabled: false, dnssecOk: true },
          );
          if (!isDefinitiveDnsObservation(response.message.responseCode)) {
            return {
              controlledRecords: [],
              dependencyRecords: [],
              error: `${type}: resolver returned ${response.message.responseCode}; this scope was not compared.`,
              observedAt: response.receivedAt,
              records: [],
              response,
              type,
            };
          }
          if (response.message.responseCode !== 'NOERROR')
            return {
              controlledRecords: [],
              dependencyRecords: [],
              observedAt: response.receivedAt,
              records: [],
              response,
              type,
            };
          const bound = reachableAnswerRecords(
            parsed.value.ascii,
            response.message.answers,
            type,
          );
          if (bound.error !== undefined) {
            return {
              bindingError: bound.error,
              controlledRecords: [],
              dependencyRecords: [],
              error: `${type}: ${bound.error}`,
              observedAt: response.receivedAt,
              records: [],
              response,
              type,
            };
          }
          const evidenceRecords = [...bound.aliases, ...bound.records];
          const controlledRecords = evidenceRecords.filter(
            (record) =>
              canonicalOwner(record.owner) === parsed.value.ascii &&
              isWithinZone(record.owner, parsedOrigin.value.ascii),
          );
          const controlled = new Set(controlledRecords);
          return {
            controlledRecords,
            dependencyRecords: evidenceRecords.filter((record) => !controlled.has(record)),
            observedAt: response.receivedAt,
            records: evidenceRecords,
            response,
            type,
          };
        } catch (cause) {
          const message =
            cause instanceof DnsQueryError
              ? cause.message
              : cause instanceof Error
                ? cause.message
                : 'DNS query failed.';
          return {
            controlledRecords: [],
            dependencyRecords: [],
            error: `${type}: ${message}`,
            ...(cause instanceof DnsQueryError ? { errorCode: cause.code } : {}),
            observedAt: new Date().toISOString(),
            records: [],
            type,
          };
        }
      }),
    );
    if (activeRun.current !== run) return;
    if (run.cancelled) {
      setState('cancelled');
      return;
    }
    const completedAt = new Date().toISOString();
    const currentSnapshot = [
      ...new Set(outcomes.flatMap((outcome) => outcome.controlledRecords).map(bindRecord)),
    ].join('\n');
    const dependencySnapshot = [
      ...new Set(outcomes.flatMap((outcome) => outcome.dependencyRecords).map(bindRecord)),
    ].join('\n');
    const partialErrors = outcomes.flatMap((outcome) =>
      outcome.error === undefined ? [] : [outcome.error],
    );
    const incompleteTypes = outcomes.flatMap((outcome) =>
      outcome.error === undefined ? [] : [outcome.type],
    );
    const prior = parseZoneSnippet(currentSnapshot, { origin: parsedOrigin.value.ascii });
    const next = parseZoneSnippet(after, { origin: parsedOrigin.value.ascii });
    const parserReasons = [
      ...blockingParserReasons('Observed current snapshot', prior),
      ...blockingParserReasons('Proposed snapshot', next),
    ];
    if (parserReasons.length > 0) {
      stopIncomplete(parserReasons);
      return;
    }
    const scopedRecords = next.records.filter(
      (record) => canonicalOwner(record.owner) === parsed.value.ascii,
    );
    const excludedProposedRecords = next.records.filter(
      (record) => canonicalOwner(record.owner) !== parsed.value.ascii,
    );
    const scopedNext = scopedDocument(next, scopedRecords);
    const observationScope = `Live comparison covers only ${parsed.value.absolute} for the selected ${selected.join(', ')} record types within the declared ${parsedOrigin.value.absolute} authoritative zone; other owners, unselected types and delegation boundaries remain unknown.`;
    const excludedScope =
      excludedProposedRecords.length === 0
        ? undefined
        : excludedProposedRecords.length === 1
          ? '1 proposed record at another owner was excluded because its current state was not observed.'
          : `${String(excludedProposedRecords.length)} proposed records at other owners were excluded because their current state was not observed.`;
    const currentIncompleteReasons = [
      observationScope,
      ...(excludedScope === undefined ? [] : [excludedScope]),
      ...partialErrors,
    ];
    const observedTypes = new Set<string>([...selected, 'CNAME']);
    const unobservedProposedTypes = [
      ...new Set(
        scopedNext.records
          .map((record) => record.type)
          .filter((type) => !observedTypes.has(type)),
      ),
    ];
    const report = omitIncompleteRecordTypes(compareZoneDocuments(prior, scopedNext), [
      ...incompleteTypes,
      ...unobservedProposedTypes,
    ]);
    if (report.status === 'incomplete') {
      stopIncomplete(report.incompleteReasons);
      return;
    }
    const plan = planDnsChanges(prior, scopedNext, report, {
      incompleteTypes: [...incompleteTypes, ...unobservedProposedTypes],
      observationLimitations: [
        observationScope,
        ...(excludedScope === undefined ? [] : [excludedScope]),
      ],
      ...(plannedDate === undefined ? {} : { plannedAt: plannedDate }),
    });
    if (plan.status === 'incomplete') {
      stopIncomplete(plan.incompleteReasons);
      return;
    }
    setDisplay({
      after: next,
      analysedAt: new Date(completedAt),
      before: prior,
      currentIncompleteReasons,
      currentOrigin: parsedOrigin.value.absolute,
      currentSnapshot,
      dependencySnapshot,
      evidence: currentEvidence(
        outcomes,
        resolverId,
        parsed.value.absolute,
        startedAt,
        completedAt,
        partialErrors,
      ),
      intendedOrigin: parsedOrigin.value.absolute,
      partialErrors,
      plan,
      report,
    });
    setState('complete');
  }

  function clear() {
    activeRun.current?.cancel();
    activeRun.current = null;
    setBefore('');
    setAfter('');
    setDomain('');
    setLiveOrigin('');
    setCurrentOrigin('');
    setIntendedOrigin('');
    setPlannedAt('');
    setError('');
    setDisplay(null);
    setState('idle');
  }

  function openWorkspace() {
    if (display === null || onCreateWorkspace === undefined) return;
    const observedCurrent = display.currentSnapshot !== undefined;
    const currentStatus = observedCurrent ? 'partial' : 'complete';
    const created = createChangeLabWorkspace({
      analysis: {
        analysedAt: display.analysedAt,
        plan: display.plan,
        report: display.report,
      },
      currentIncompleteReasons:
        currentStatus === 'partial'
          ? (display.currentIncompleteReasons ?? [
              'The current DNS source is a scoped observation rather than a complete zone.',
            ])
          : [],
      currentOrigin: display.currentOrigin,
      currentSource: display.before.source,
      currentStatus,
      ...(display.evidence === undefined ? {} : { evidence: display.evidence }),
      intendedOrigin: display.intendedOrigin,
      intendedSource: display.after.source,
      intendedStatus: 'complete',
      title: observedCurrent ? `${domain.trim()} DNS change` : 'Pasted DNS change',
    });
    if (!created.ok) {
      setError(`The Change Workspace could not be created. ${created.error.message}`);
      return;
    }
    onCreateWorkspace(created.value);
  }

  function initialInputIsUnchanged(): boolean {
    if (initialInput === undefined || mode !== 'pasted') return false;
    const expectedCurrentOrigin = suppliedOrigin(
      initialInput.currentOrigin,
      initialInput.origin,
    );
    const expectedIntendedOrigin = suppliedOrigin(
      initialInput.intendedOrigin,
      initialInput.origin,
    );
    return (
      before === initialInput.current &&
      after === initialInput.intended &&
      currentOrigin === expectedCurrentOrigin &&
      intendedOrigin === expectedIntendedOrigin
    );
  }

  function returnSuppliedWorkspace() {
    if (
      initialInput === undefined ||
      onCreateWorkspace === undefined ||
      !initialInputIsUnchanged()
    )
      return;
    if (initialInput.workspace !== undefined) {
      onCreateWorkspace(initialInput.workspace);
      return;
    }
    const created = createChangeLabWorkspace({
      currentIncompleteReasons: initialInput.currentIncompleteReasons ?? [],
      currentOrigin:
        initialInput.currentOrigin === undefined
          ? (initialInput.origin ?? null)
          : initialInput.currentOrigin,
      currentSource: initialInput.current,
      currentStatus: initialInput.currentStatus ?? 'complete',
      intendedIncompleteReasons: initialInput.intendedIncompleteReasons ?? [],
      intendedOrigin:
        initialInput.intendedOrigin === undefined
          ? (initialInput.origin ?? null)
          : initialInput.intendedOrigin,
      intendedSource: initialInput.intended,
      intendedStatus: initialInput.intendedStatus ?? 'complete',
      title: 'Change Workspace hand-off',
    });
    if (!created.ok) {
      setError(`The Change Workspace could not be restored. ${created.error.message}`);
      return;
    }
    onCreateWorkspace(created.value);
  }

  const parserDiagnostics =
    display === null ? [] : [...display.before.diagnostics, ...display.after.diagnostics];
  const incompleteSuppliedInput = suppliedInputReasons();
  const canReturnSuppliedWorkspace =
    onCreateWorkspace !== undefined &&
    incompleteSuppliedInput.length > 0 &&
    initialInputIsUnchanged();

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="DNS Change Lab" title="Compare records and plan a bounded rollout.">
        Compare unordered RRsets, TTLs, priorities, values, and presentation. Use pasted
        snapshots or observe selected current records, then review preflight risk, timing,
        rollback, and staged rollout guidance for a proposed snippet.
      </ToolIntro>
      <div className="mode-switch" aria-label="Change Lab source mode">
        <button
          aria-pressed={mode === 'pasted'}
          type="button"
          onClick={() => {
            invalidateResult();
            setMode('pasted');
          }}
        >
          Two pasted snapshots
        </button>
        <button
          aria-pressed={mode === 'current'}
          type="button"
          onClick={() => {
            invalidateResult();
            setMode('current');
          }}
        >
          Current DNS + proposed
        </button>
      </div>
      <form className="workbench-form diff-form" onSubmit={(event) => void compare(event)}>
        {mode === 'pasted' ? (
          <>
            <div className="field-group snapshot-field">
              <label htmlFor="before-snapshot">Current or earlier snapshot</label>
              <textarea
                id="before-snapshot"
                value={before}
                onChange={(event) => {
                  invalidateResult();
                  setBefore(event.currentTarget.value);
                }}
                rows={14}
                maxLength={ZONE_ANALYSIS_LIMITS.characters}
                spellCheck={false}
              />
            </div>
            <div className="field-group snapshot-field">
              <label htmlFor="after-snapshot">Proposed or later snapshot</label>
              <textarea
                id="after-snapshot"
                value={after}
                onChange={(event) => {
                  invalidateResult();
                  setAfter(event.currentTarget.value);
                }}
                rows={14}
                maxLength={ZONE_ANALYSIS_LIMITS.characters}
                spellCheck={false}
              />
            </div>
            <div className="field-group">
              <label htmlFor="diff-current-origin">Origin for relative names</label>
              <input
                id="diff-current-origin"
                value={currentOrigin}
                onChange={(event) => {
                  invalidateResult();
                  if (intendedOrigin === currentOrigin)
                    setIntendedOrigin(event.currentTarget.value);
                  setCurrentOrigin(event.currentTarget.value);
                }}
                placeholder="current.example"
                maxLength={253}
                spellCheck={false}
              />
            </div>
            <div className="field-group">
              <label htmlFor="diff-intended-origin">Proposed snapshot origin</label>
              <input
                id="diff-intended-origin"
                value={intendedOrigin}
                onChange={(event) => {
                  invalidateResult();
                  setIntendedOrigin(event.currentTarget.value);
                }}
                placeholder="example.com"
                maxLength={253}
                spellCheck={false}
              />
            </div>
          </>
        ) : (
          <>
            <div className="field-group">
              <label htmlFor="current-domain">Current DNS name</label>
              <input
                id="current-domain"
                value={domain}
                onChange={(event) => {
                  invalidateResult();
                  setDomain(event.currentTarget.value);
                }}
                placeholder="example.com"
                maxLength={2048}
                spellCheck={false}
              />
            </div>
            <div className="field-group">
              <label htmlFor="current-zone-origin">Authoritative zone origin</label>
              <input
                id="current-zone-origin"
                aria-describedby="current-zone-origin-note"
                value={liveOrigin}
                onChange={(event) => {
                  invalidateResult();
                  setLiveOrigin(event.currentTarget.value);
                }}
                placeholder="example.com"
                maxLength={2048}
                spellCheck={false}
              />
              <small id="current-zone-origin-note">
                Required to distinguish the queried owner from the zone apex and keep
                alias-target observations outside the controlled change state.
              </small>
            </div>
            <div className="field-group">
              <label htmlFor="diff-resolver">Resolver</label>
              <select
                id="diff-resolver"
                aria-describedby={
                  RESOLVERS[resolverId].selectionNote === undefined
                    ? undefined
                    : 'diff-resolver-note'
                }
                value={resolverId}
                onChange={(event) => {
                  invalidateResult();
                  setResolverId(event.currentTarget.value as ResolverId);
                }}
              >
                {RESOLVER_IDS.map((id) => (
                  <option value={id} key={id}>
                    {RESOLVERS[id].label}
                  </option>
                ))}
              </select>
              {RESOLVERS[resolverId].selectionNote === undefined ? null : (
                <small id="diff-resolver-note">{RESOLVERS[resolverId].selectionNote}</small>
              )}
            </div>
            <fieldset className="record-picker">
              <legend>Current record types</legend>
              <div>
                {CURRENT_TYPES.map((type) => (
                  <label className="check-control" key={type}>
                    <input
                      type="checkbox"
                      checked={types.has(type)}
                      onChange={() => toggleType(type)}
                    />
                    {type}
                  </label>
                ))}
              </div>
            </fieldset>
            <div className="field-group zone-source">
              <label htmlFor="proposed-snapshot">Proposed snapshot</label>
              <textarea
                id="proposed-snapshot"
                value={after}
                onChange={(event) => {
                  invalidateResult();
                  setAfter(event.currentTarget.value);
                }}
                rows={14}
                maxLength={ZONE_ANALYSIS_LIMITS.characters}
                spellCheck={false}
              />
            </div>
          </>
        )}
        <div className="field-group">
          <label htmlFor="planned-change-time">Planned publication time (optional)</label>
          <input
            id="planned-change-time"
            type="datetime-local"
            value={plannedAt}
            onChange={(event) => {
              invalidateResult();
              setPlannedAt(event.currentTarget.value);
            }}
          />
        </div>
        {error !== '' ? (
          <p className="form-error" role="alert">
            <bdi className="technical-value" dir="ltr">
              {escapeTechnicalText(error)}
            </bdi>
          </p>
        ) : null}
        <div className="form-actions">
          <button className="primary-button" type="submit" disabled={state === 'loading'}>
            {state === 'loading' ? 'Querying current DNS…' : 'Compare snapshots'}
          </button>
          {state === 'loading' ? (
            <button
              className="quiet-button"
              type="button"
              onClick={() => activeRun.current?.cancel()}
            >
              Cancel
            </button>
          ) : null}
          {canReturnSuppliedWorkspace ? (
            <button className="quiet-button" type="button" onClick={returnSuppliedWorkspace}>
              Return to Change Workspace
            </button>
          ) : null}
          <button className="quiet-button" type="button" onClick={clear}>
            Clear
          </button>
        </div>
      </form>
      <div className="run-status" aria-live="polite">
        {state === 'cancelled' ? 'The current-DNS query was cancelled.' : null}
        {state === 'incomplete'
          ? 'Comparison stopped because the required inputs are incomplete.'
          : null}
        {state === 'complete' && display !== null
          ? `Comparison found ${String(display.report.changes.length)} classified changes.`
          : null}
      </div>
      {display === null ? null : (
        <section className="results" aria-labelledby="diff-results-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Normalised comparison</p>
              <h2 id="diff-results-title">Change set</h2>
            </div>
            <div className="export-actions">
              <CopyButton label="Copy Markdown report" text={markdown(display)} />
              <SnapshotButton
                content={markdown(display)}
                title="DNS Change Lab report"
                tool="diff"
              />
              {onCreateWorkspace === undefined ? null : (
                <button className="quiet-button" type="button" onClick={openWorkspace}>
                  Open in Change Workspace
                </button>
              )}
            </div>
          </div>
          {display.currentIncompleteReasons !== undefined ? (
            <article className="conclusion-panel partial-panel">
              <StatusBadge tone="warning">Partial current view</StatusBadge>
              <p>
                <bdi className="technical-value" dir="ltr">
                  {escapeTechnicalText(display.currentIncompleteReasons.join(' '))}
                </bdi>
              </p>
            </article>
          ) : null}
          {parserDiagnostics.length > 0 ? (
            <article className="conclusion-panel">
              <StatusBadge tone="warning">Parser diagnostics</StatusBadge>
              <p>
                <bdi className="technical-value" dir="ltr">
                  {escapeTechnicalText(
                    parserDiagnostics
                      .map(
                        (item) => `${String(item.line)}:${String(item.column)} ${item.message}`,
                      )
                      .join(' '),
                  )}
                </bdi>
              </p>
            </article>
          ) : null}
          {display.currentSnapshot === undefined ? null : (
            <details className="method-note">
              <summary>Observed controlled-owner snapshot</summary>
              <pre className="spf-output technical-value" dir="ltr">
                {display.currentSnapshot === ''
                  ? 'No selected records were returned.'
                  : escapeTechnicalText(display.currentSnapshot)}
              </pre>
            </details>
          )}
          {display.dependencySnapshot === undefined ||
          display.dependencySnapshot === '' ? null : (
            <details className="method-note">
              <summary>Observed alias dependency evidence</summary>
              <pre className="spf-output technical-value" dir="ltr">
                {escapeTechnicalText(display.dependencySnapshot)}
              </pre>
              <p>
                These reachable alias-target records are retained as resolver evidence. They
                were not treated as current change-state values because this live comparison
                directly observed only the requested owner.
              </p>
            </details>
          )}
          <article className="result-panel change-plan-summary">
            <div className="result-heading">
              <div>
                <p className="eyebrow">Change Lab</p>
                <h3>Preflight and rollout plan</h3>
              </div>
              <StatusBadge tone={riskTone(display.plan.risk)}>
                {display.plan.risk} risk
              </StatusBadge>
            </div>
            <p className="empty-note">
              This plan is derived from the supplied snapshots. It does not publish records or
              claim that every recursive cache has converged.
            </p>
            <div className="change-timing-grid">
              <div>
                <span>Largest prior TTL</span>
                <strong>
                  {display.plan.timing.previousTtlSeconds === undefined
                    ? 'Unknown'
                    : `${String(display.plan.timing.previousTtlSeconds)} seconds`}
                </strong>
              </div>
              <div>
                <span>Preparation deadline</span>
                <strong>{dateLabel(display.plan.timing.preparationDeadline)}</strong>
              </div>
              <div>
                <span>Earliest if lowered now</span>
                <strong>{dateLabel(display.plan.timing.safeChangeAtIfLoweredNow)}</strong>
              </div>
              <div>
                <span>Rollback cache horizon</span>
                <strong>{dateLabel(display.plan.timing.rollbackCacheHorizon)}</strong>
              </div>
            </div>
            {display.plan.findings.length === 0 ? (
              <p className="empty-note">No warning or error findings in these snapshots.</p>
            ) : (
              <ul className="diagnostic-list">
                {display.plan.findings.map((finding) => (
                  <li key={`${finding.code}-${finding.message}`}>
                    <StatusBadge tone={riskTone(finding.risk)}>{finding.risk}</StatusBadge>
                    <bdi className="technical-value" dir="ltr">
                      <strong>{escapeTechnicalText(finding.code)}</strong> —{' '}
                      {escapeTechnicalText(finding.message)}
                    </bdi>
                  </li>
                ))}
              </ul>
            )}
          </article>
          <article className="result-panel">
            {display.report.changes.length === 0 ? (
              <p className="empty-note">No semantic, TTL, or formatting changes were found.</p>
            ) : (
              <div
                className="table-scroll"
                tabIndex={0}
                role="region"
                aria-label="Classified DNS changes"
              >
                <table>
                  <caption>Classified DNS changes</caption>
                  <thead>
                    <tr>
                      <th>Category</th>
                      <th>Owner / type</th>
                      <th>Before</th>
                      <th>After</th>
                      <th>Assessment</th>
                    </tr>
                  </thead>
                  <tbody>
                    {display.report.changes.map((change, index) => (
                      <tr
                        key={`${change.owner}-${change.type}-${change.category}-${String(index)}`}
                      >
                        <td>
                          <StatusBadge tone={categoryTone(change)}>
                            {change.category}
                          </StatusBadge>
                        </td>
                        <td>
                          <code className="technical-value" dir="ltr">
                            {escapeTechnicalText(change.owner)}
                          </code>
                          <br />
                          {change.type}
                        </td>
                        <td>
                          <code className="record-value technical-value" dir="ltr">
                            {recordDisplayText(change.before)}
                          </code>
                        </td>
                        <td>
                          <code className="record-value technical-value" dir="ltr">
                            {recordDisplayText(change.after)}
                          </code>
                        </td>
                        <td>
                          <StatusBadge
                            tone={riskTone(display.plan.impacts[index]?.risk ?? 'moderate')}
                          >
                            {display.plan.impacts[index]?.risk ?? 'moderate'} risk
                          </StatusBadge>{' '}
                          <bdi className="technical-value" dir="ltr">
                            {escapeTechnicalText(change.explanation)}
                          </bdi>
                          {change.disruptive ? ' Potentially disruptive.' : ''}
                          {display.plan.impacts[index] === undefined ? null : (
                            <details className="inline-details">
                              <summary>Impact and rollback</summary>
                              <ul>
                                {display.plan.impacts[index].reasons.map((reason) => (
                                  <li key={reason}>
                                    <bdi className="technical-value" dir="ltr">
                                      {escapeTechnicalText(reason)}
                                    </bdi>
                                  </li>
                                ))}
                              </ul>
                              <p>
                                <bdi className="technical-value" dir="ltr">
                                  {escapeTechnicalText(display.plan.impacts[index].rollback)}
                                </bdi>
                              </p>
                            </details>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </article>
          {display.report.guidance.length > 0 ? (
            <article className="result-panel">
              <h3>Rollout guidance</h3>
              <ul className="guidance-list">
                {display.report.guidance.map((item) => (
                  <li key={item}>
                    <bdi className="technical-value" dir="ltr">
                      {escapeTechnicalText(item)}
                    </bdi>
                  </li>
                ))}
              </ul>
            </article>
          ) : null}
          <article className="result-panel">
            <h3>Staged rollout</h3>
            <ol className="rollout-phases">
              {display.plan.phases.map((phase) => (
                <li key={phase.id}>
                  <h4>
                    <bdi className="technical-value" dir="ltr">
                      {escapeTechnicalText(phase.title)}
                    </bdi>
                  </h4>
                  <ul>
                    {phase.actions.map((action) => (
                      <li key={action}>
                        <bdi className="technical-value" dir="ltr">
                          {escapeTechnicalText(action)}
                        </bdi>
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ol>
          </article>
          <details className="method-note">
            <summary>How normalisation works</summary>
            <p>
              RRset order is ignored. Names and addresses are normalised where their record type
              defines case-insensitive name fields. TXT character-string boundaries are treated
              as presentation, while TTL, MX preference, and semantic RDATA remain distinct.
              “Propagation complete” is not assigned a universal time because prior TTLs and
              recursive caches vary.
            </p>
          </details>
        </section>
      )}
    </div>
  );
}
