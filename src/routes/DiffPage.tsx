import { useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { SnapshotButton } from '../components/SnapshotButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { compareZoneDocuments } from '../core/diff/compare';
import type { DiffReport, DnsChange } from '../core/diff/types';
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

function markdown(report: DisplayReport): string {
  return [
    '# ZoneSkein DNS change comparison',
    '',
    '| Category | Owner | Type | Before | After | Disruptive |',
    '| --- | --- | --- | --- | --- | --- |',
    ...report.report.changes.map(
      (change) =>
        `| ${change.category} | ${change.owner} | ${change.type} | ${recordText(change.before).replaceAll('|', '\\|')} | ${recordText(change.after).replaceAll('|', '\\|')} | ${change.disruptive ? 'yes' : 'no'} |`,
    ),
    '',
    '## Rollout guidance',
    '',
    ...report.report.guidance.map((item) => `- ${item}`),
  ].join('\n');
}

export function DiffPage() {
  const [mode, setMode] = useState<DiffMode>('pasted');
  const [before, setBefore] = useState('');
  const [after, setAfter] = useState('');
  const [domain, setDomain] = useState('');
  const [origin, setOrigin] = useState('');
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
    const parseOptions = origin.trim() === '' ? {} : { origin };
    if (mode === 'pasted') {
      const prior = parseZoneSnippet(before, parseOptions);
      const next = parseZoneSnippet(after, parseOptions);
      setDisplay({
        after: next,
        before: prior,
        partialErrors: [],
        report: compareZoneDocuments(prior, next),
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
    const prior = parseZoneSnippet(currentSnapshot, { origin: parsed.value.ascii });
    const next = parseZoneSnippet(after, { origin: parsed.value.ascii });
    setDisplay({
      after: next,
      before: prior,
      currentSnapshot,
      partialErrors,
      report: compareZoneDocuments(prior, next),
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
      <div className="mode-switch" role="tablist" aria-label="Diff source mode">
        <button
          role="tab"
          aria-selected={mode === 'pasted'}
          type="button"
          onClick={() => setMode('pasted')}
        >
          Two pasted snapshots
        </button>
        <button
          role="tab"
          aria-selected={mode === 'current'}
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
              <p className="eyebrow">Normalized comparison</p>
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
                          {change.explanation}
                          {change.disruptive ? ' Potentially disruptive.' : ''}
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
