import { useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { SnapshotButton } from '../components/SnapshotButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import {
  compareZoneDocuments,
  isDefinitiveDnsObservation,
  omitIncompleteRecordTypes,
} from '../core/diff/compare';
import { planDnsChanges } from '../core/diff/plan';
import type { ChangeRisk, DiffReport, DnsChange, DnsChangePlan } from '../core/diff/types';
import { validateDnsName } from '../core/dns/names';
import { bindRecord } from '../core/dns/presentation';
import { DnsQueryError, type DnsRecordType, type ResolverId } from '../core/dns/types';
import { DnsQueryRun } from '../core/doh/query-run';
import { RESOLVERS } from '../core/doh/resolvers';
import { WireDnsResolver } from '../core/doh/wire-resolver';
import { parseZoneSnippet } from '../core/zone/parser';
import type { ZoneDocument, ZoneRecord } from '../core/zone/types';

type DiffMode = 'pasted' | 'current';
const MAX_ZONE_CHARACTERS = 262_144;
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
  readonly before: ZoneDocument;
  readonly currentSnapshot?: string;
  readonly partialErrors: readonly string[];
  readonly plan: DnsChangePlan;
  readonly report: DiffReport;
}

function recordText(record: ZoneRecord | undefined): string {
  if (record === undefined) return '—';
  return `${record.owner} ${record.ttl === undefined ? '' : `${String(record.ttl)} `}${record.className} ${record.type} ${record.rdata.map((token) => token.raw).join(' ')}`;
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
      return `| ${change.category} | ${impact?.risk ?? 'unknown'} | ${change.owner} | ${change.type} | ${recordText(change.before).replaceAll('|', '\\|')} | ${recordText(change.after).replaceAll('|', '\\|')} | ${(impact?.rollback ?? '').replaceAll('|', '\\|')} |`;
    }),
    '',
    '## Preflight findings',
    '',
    ...(report.plan.findings.length === 0
      ? ['- No warning or error findings in the supplied snapshots.']
      : report.plan.findings.map(
          (item) => `- **${item.risk} / ${item.code}:** ${item.message}`,
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
      `### ${String(index + 1)}. ${phase.title}`,
      '',
      ...phase.actions.map((item) => `- ${item}`),
      '',
    ]),
  ].join('\n');
}

export function DiffPage() {
  const [mode, setMode] = useState<DiffMode>('pasted');
  const [before, setBefore] = useState('');
  const [after, setAfter] = useState('');
  const [domain, setDomain] = useState('');
  const [origin, setOrigin] = useState('');
  const [plannedAt, setPlannedAt] = useState('');
  const [resolverId, setResolverId] = useState<ResolverId>('google');
  const [types, setTypes] = useState(DEFAULT_CURRENT_TYPES);
  const [state, setState] = useState<'idle' | 'loading' | 'complete' | 'cancelled'>('idle');
  const [error, setError] = useState('');
  const [display, setDisplay] = useState<DisplayReport | null>(null);
  const activeRun = useRef<DnsQueryRun | null>(null);

  function toggleType(type: DnsRecordType) {
    setTypes((current) => {
      const next = new Set(current);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }

  async function compare(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    setError('');
    setDisplay(null);
    activeRun.current?.cancel();
    const plannedDate = plannedAt === '' ? undefined : new Date(plannedAt);
    if (plannedDate !== undefined && Number.isNaN(plannedDate.getTime())) {
      setError('Enter a valid planned publication date and time.');
      return;
    }
    const parseOptions = origin.trim() === '' ? {} : { origin };
    if (mode === 'pasted') {
      const prior = parseZoneSnippet(before, parseOptions);
      const next = parseZoneSnippet(after, parseOptions);
      const report = compareZoneDocuments(prior, next);
      setDisplay({
        after: next,
        before: prior,
        partialErrors: [],
        plan: planDnsChanges(prior, next, report, {
          ...(plannedDate === undefined ? {} : { plannedAt: plannedDate }),
        }),
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
    const selected = CURRENT_TYPES.filter((type) => types.has(type));
    if (selected.length === 0) {
      setError('Select at least one current record type.');
      return;
    }
    const run = new DnsQueryRun();
    activeRun.current = run;
    setState('loading');
    const resolver = new WireDnsResolver(RESOLVERS[resolverId]);
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
              error: `${type}: resolver returned ${response.message.responseCode}; this scope was not compared.`,
              records: [],
              type,
            };
          }
          return { records: response.message.answers, type };
        } catch (cause) {
          const message =
            cause instanceof DnsQueryError
              ? cause.message
              : cause instanceof Error
                ? cause.message
                : 'DNS query failed.';
          return { error: `${type}: ${message}`, records: [], type };
        }
      }),
    );
    if (activeRun.current !== run) return;
    if (outcomes.every((outcome) => outcome.error?.includes('cancelled') === true)) {
      setState('cancelled');
      return;
    }
    const currentSnapshot = [
      ...new Set(outcomes.flatMap((outcome) => outcome.records).map(bindRecord)),
    ].join('\n');
    const partialErrors = outcomes.flatMap((outcome) =>
      outcome.error === undefined ? [] : [outcome.error],
    );
    const incompleteTypes = outcomes.flatMap((outcome) =>
      outcome.error === undefined ? [] : [outcome.type],
    );
    const prior = parseZoneSnippet(currentSnapshot, { origin: parsed.value.ascii });
    const next = parseZoneSnippet(after, { origin: parsed.value.ascii });
    const report = omitIncompleteRecordTypes(
      compareZoneDocuments(prior, next),
      incompleteTypes,
    );
    setDisplay({
      after: next,
      before: prior,
      currentSnapshot,
      partialErrors,
      plan: planDnsChanges(prior, next, report, {
        incompleteTypes,
        ...(plannedDate === undefined ? {} : { plannedAt: plannedDate }),
      }),
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
    setOrigin('');
    setPlannedAt('');
    setError('');
    setDisplay(null);
    setState('idle');
  }

  const parserDiagnostics =
    display === null ? [] : [...display.before.diagnostics, ...display.after.diagnostics];

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="DNS change diff" title="Separate semantic changes from noise.">
        Compare unordered RRsets, TTLs, priorities, values, and presentation. Use pasted
        snapshots or observe selected current records before reviewing a proposed snippet.
      </ToolIntro>
      <div className="mode-switch" aria-label="Diff source mode">
        <button
          aria-pressed={mode === 'pasted'}
          type="button"
          onClick={() => setMode('pasted')}
        >
          Two pasted snapshots
        </button>
        <button
          aria-pressed={mode === 'current'}
          type="button"
          onClick={() => setMode('current')}
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
                onChange={(event) => setBefore(event.currentTarget.value)}
                rows={14}
                maxLength={MAX_ZONE_CHARACTERS}
                spellCheck={false}
              />
            </div>
            <div className="field-group snapshot-field">
              <label htmlFor="after-snapshot">Proposed or later snapshot</label>
              <textarea
                id="after-snapshot"
                value={after}
                onChange={(event) => setAfter(event.currentTarget.value)}
                rows={14}
                maxLength={MAX_ZONE_CHARACTERS}
                spellCheck={false}
              />
            </div>
            <div className="field-group">
              <label htmlFor="diff-origin">Origin for relative names</label>
              <input
                id="diff-origin"
                value={origin}
                onChange={(event) => setOrigin(event.currentTarget.value)}
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
                onChange={(event) => setDomain(event.currentTarget.value)}
                placeholder="example.com"
                maxLength={2048}
                spellCheck={false}
              />
            </div>
            <div className="field-group">
              <label htmlFor="diff-resolver">Resolver</label>
              <select
                id="diff-resolver"
                value={resolverId}
                onChange={(event) => setResolverId(event.currentTarget.value as ResolverId)}
              >
                {RESOLVER_IDS.map((id) => (
                  <option value={id} key={id}>
                    {RESOLVERS[id].label}
                  </option>
                ))}
              </select>
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
                onChange={(event) => setAfter(event.currentTarget.value)}
                rows={14}
                maxLength={MAX_ZONE_CHARACTERS}
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
            onChange={(event) => setPlannedAt(event.currentTarget.value)}
          />
        </div>
        {error !== '' ? (
          <p className="form-error" role="alert">
            {error}
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
          <button className="quiet-button" type="button" onClick={clear}>
            Clear
          </button>
        </div>
      </form>
      <div className="run-status" aria-live="polite">
        {state === 'cancelled' ? 'The current-DNS query was cancelled.' : null}
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
                title="DNS change comparison"
                tool="diff"
              />
            </div>
          </div>
          {display.partialErrors.length > 0 ? (
            <article className="conclusion-panel partial-panel">
              <StatusBadge tone="warning">Partial current view</StatusBadge>
              <p>{display.partialErrors.join(' ')}</p>
            </article>
          ) : null}
          {parserDiagnostics.length > 0 ? (
            <article className="conclusion-panel">
              <StatusBadge tone="warning">Parser diagnostics</StatusBadge>
              <p>
                {parserDiagnostics
                  .map((item) => `${String(item.line)}:${String(item.column)} ${item.message}`)
                  .join(' ')}
              </p>
            </article>
          ) : null}
          {display.currentSnapshot === undefined ? null : (
            <details className="method-note">
              <summary>Observed recursive-resolver snapshot</summary>
              <pre className="spf-output">
                {display.currentSnapshot === ''
                  ? 'No selected records were returned.'
                  : display.currentSnapshot}
              </pre>
            </details>
          )}
          <article className="result-panel change-plan-summary">
            <div className="result-heading">
              <div>
                <p className="eyebrow">Change lab</p>
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
                    <span>
                      <strong>{finding.code}</strong> — {finding.message}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </article>
          <article className="result-panel">
            {display.report.changes.length === 0 ? (
              <p className="empty-note">No semantic, TTL, or formatting changes were found.</p>
            ) : (
              <div className="table-scroll">
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
                          <code>{change.owner}</code>
                          <br />
                          {change.type}
                        </td>
                        <td>
                          <code className="record-value">{recordText(change.before)}</code>
                        </td>
                        <td>
                          <code className="record-value">{recordText(change.after)}</code>
                        </td>
                        <td>
                          <StatusBadge
                            tone={riskTone(display.plan.impacts[index]?.risk ?? 'moderate')}
                          >
                            {display.plan.impacts[index]?.risk ?? 'moderate'} risk
                          </StatusBadge>{' '}
                          {change.explanation}
                          {change.disruptive ? ' Potentially disruptive.' : ''}
                          {display.plan.impacts[index] === undefined ? null : (
                            <details className="inline-details">
                              <summary>Impact and rollback</summary>
                              <ul>
                                {display.plan.impacts[index].reasons.map((reason) => (
                                  <li key={reason}>{reason}</li>
                                ))}
                              </ul>
                              <p>{display.plan.impacts[index].rollback}</p>
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
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </article>
          ) : null}
          <article className="result-panel">
            <h3>Staged rollout</h3>
            <ol className="rollout-phases">
              {display.plan.phases.map((phase) => (
                <li key={phase.id}>
                  <h4>{phase.title}</h4>
                  <ul>
                    {phase.actions.map((action) => (
                      <li key={action}>{action}</li>
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
