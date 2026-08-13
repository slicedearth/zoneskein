import { useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { validateDnsName } from '../core/dns/names';
import type { ResolverId } from '../core/dns/types';
import { WireSpfDnsClient } from '../core/spf/dns-client';
import { analyseSpf } from '../core/spf/evaluator';
import { flattenSpf } from '../core/spf/flatten';
import type { SpfAnalysis, SpfSnapshot } from '../core/spf/types';
import { DnsQueryRun } from '../core/doh/query-run';
import { RESOLVERS } from '../core/doh/resolvers';
import { WireDnsResolver } from '../core/doh/wire-resolver';

type Mode = 'analysis' | 'flatten';
const RESOLVER_IDS = Object.keys(RESOLVERS) as ResolverId[];

interface SpfRunReport {
  readonly analysis: SpfAnalysis;
  readonly dnsQuestions: number;
  readonly snapshot?: SpfSnapshot;
}

function diagnosticTone(severity: string) {
  return severity === 'error' ? 'error' : severity === 'warning' ? 'warning' : 'information';
}

function SnapshotPanel({ snapshot }: { readonly snapshot: SpfSnapshot }) {
  if (!snapshot.safe) {
    return (
      <article className="result-panel unsafe-output">
        <div className="result-heading">
          <h3>No safe snapshot generated</h3>
          <StatusBadge tone="error">Blocked</StatusBadge>
        </div>
        <p>
          ZoneSkein withholds flattened output whenever preserving the effective pass set would
          require sender context, guessing, or incomplete DNS data.
        </p>
        <ul className="diagnostic-list">
          {snapshot.blockers.map((blocker) => (
            <li key={blocker}>{blocker}</li>
          ))}
        </ul>
      </article>
    );
  }
  const json = JSON.stringify(
    {
      earliestSourceExpiry: snapshot.earliestSourceExpiry,
      estimatedResponseBytes: snapshot.estimatedResponseBytes,
      generatedAt: snapshot.generatedAt,
      provenance: snapshot.provenance,
      recommendedRecheck: snapshot.recommendedRecheck,
      value: snapshot.value,
      warning: 'Point-in-time SPF snapshot — provider address ranges may change.',
    },
    null,
    2,
  );
  return (
    <article className="snapshot-panel">
      <div className="result-heading">
        <div>
          <p className="eyebrow">Snapshot flattener</p>
          <h3>Point-in-time SPF snapshot</h3>
        </div>
        <StatusBadge tone="warning">Provider ranges may change</StatusBadge>
      </div>
      <p className="snapshot-warning">
        Point-in-time SPF snapshot — provider address ranges may change. This is a publication
        preview, never an automatic DNS change.
      </p>
      <pre className="spf-output">{snapshot.value}</pre>
      <div className="export-actions">
        <CopyButton label="Copy SPF value" text={snapshot.value ?? ''} />
        <CopyButton label="Copy BIND TXT" text={snapshot.bindRecord ?? ''} />
        <CopyButton label="Copy provenance JSON" text={json} />
        <CopyButton label="Copy Markdown" text={snapshot.markdown ?? ''} />
      </div>
      <dl className="metadata-grid">
        <div>
          <dt>Generated</dt>
          <dd>{new Date(snapshot.generatedAt).toLocaleString()}</dd>
        </div>
        <div>
          <dt>Earliest source expiry</dt>
          <dd>
            {snapshot.earliestSourceExpiry === undefined
              ? 'Unknown'
              : new Date(snapshot.earliestSourceExpiry).toLocaleString()}
          </dd>
        </div>
        <div>
          <dt>Recommended recheck</dt>
          <dd>
            {snapshot.recommendedRecheck === undefined
              ? 'Unknown'
              : new Date(snapshot.recommendedRecheck).toLocaleString()}
          </dd>
        </div>
        <div>
          <dt>Estimated response</dt>
          <dd>{snapshot.estimatedResponseBytes} bytes</dd>
        </div>
      </dl>
      <details>
        <summary>TXT character-strings ({snapshot.chunks.length})</summary>
        <pre className="spf-output">
          {snapshot.chunks.map((chunk) => `"${chunk}"`).join(' ')}
        </pre>
      </details>
      {snapshot.warnings.length > 0 ? (
        <ul className="diagnostic-list warning-list">
          {snapshot.warnings.map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      ) : null}
      <div className="table-scroll">
        <table>
          <caption>Generated-network provenance</caption>
          <thead>
            <tr>
              <th>Network</th>
              <th>Original mechanism</th>
              <th>Complete path</th>
              <th>Source TTL</th>
            </tr>
          </thead>
          <tbody>
            {snapshot.provenance.map((item, index) => (
              <tr key={`${item.network}-${item.mechanism}-${String(index)}`}>
                <td>
                  <code>{item.network}</code>
                </td>
                <td>
                  <code>{item.mechanism}</code>
                </td>
                <td>{item.path.join(' → ')}</td>
                <td>{item.sourceTtl ?? 'Unknown'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <details className="method-note">
        <summary>Why flattening changes the trade-off</summary>
        <p>
          Replacing includes, a, and mx mechanisms with observed IP networks can reduce lookups
          during receiver evaluation. It also freezes provider-controlled ranges at one instant,
          so later provider changes can cause delivery failures or stale authorisation. Recheck
          before the earliest source expiry and after every provider notice.
        </p>
      </details>
    </article>
  );
}

function AnalysisPanel({ report }: { readonly report: SpfRunReport }) {
  const { analysis } = report;
  return (
    <section className="results" aria-labelledby="spf-results-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Ordered policy evaluation</p>
          <h2 id="spf-results-title">{analysis.rootDomain}</h2>
        </div>
      </div>
      <div className="metric-strip">
        <div>
          <strong>{analysis.maximumLookupTerms}</strong>
          <span>Worst-case SPF terms</span>
        </div>
        <div>
          <strong>{analysis.maximumVoidLookups}</strong>
          <span>Worst-case voids</span>
        </div>
        <div>
          <strong>{analysis.maximumDepth}</strong>
          <span>Dependency depth</span>
        </div>
        <div>
          <strong>{report.dnsQuestions}</strong>
          <span>DoH questions made</span>
        </div>
        <div>
          <strong>{analysis.totalResponseBytes}</strong>
          <span>Response bytes observed</span>
        </div>
      </div>
      <p className="detail-note">
        SPF’s ten-term limit applies to DNS-causing policy terms along evaluation paths. The DoH
        question count is separate and can be larger because a and mx expansion needs multiple
        record types.
      </p>
      {analysis.diagnostics.length > 0 ? (
        <article className="result-panel">
          <h3>Diagnostics</h3>
          <ul className="diagnostic-list">
            {analysis.diagnostics.map((item, index) => (
              <li key={`${item.code}-${item.sourceDomain ?? ''}-${String(index)}`}>
                <StatusBadge tone={diagnosticTone(item.severity)}>{item.severity}</StatusBadge>
                <span>
                  <strong>{item.code}</strong> · {item.sourceDomain ?? analysis.rootDomain} ·{' '}
                  {item.message}
                </span>
              </li>
            ))}
          </ul>
        </article>
      ) : (
        <article className="conclusion-panel">
          <StatusBadge tone="pass">No parser diagnostics</StatusBadge>
          <p>The observed policy graph did not trigger a current ZoneSkein rule.</p>
        </article>
      )}
      <article className="result-panel">
        <h3>Include and redirect graph</h3>
        {analysis.edges.length === 0 ? (
          <p className="empty-note">No include or redirect dependencies.</p>
        ) : (
          <div className="dependency-flow">
            {analysis.edges.map((edge, index) => (
              <div key={`${edge.from}-${edge.to}-${edge.kind}-${String(index)}`}>
                <code>{edge.from}</code>
                <span>{edge.kind} →</span>
                <code>{edge.to}</code>
              </div>
            ))}
          </div>
        )}
      </article>
      <div className="policy-list">
        {analysis.nodes.map((node) => (
          <article className="result-panel" key={node.domain}>
            <div className="result-heading">
              <h3>{node.domain}</h3>
              <StatusBadge tone={node.policy === undefined ? 'error' : 'information'}>
                {node.status}
              </StatusBadge>
            </div>
            {node.policy === undefined ? (
              <p className="empty-note">A single SPF policy was not available.</p>
            ) : (
              <>
                <pre className="spf-output">{node.policy.record}</pre>
                <div
                  className="term-sequence"
                  aria-label={`Ordered SPF terms for ${node.domain}`}
                >
                  {node.policy.terms.map((term, index) => (
                    <span
                      className={`term term-${term.kind}`}
                      key={`${term.original}-${String(index)}`}
                    >
                      <small>{String(index + 1).padStart(2, '0')}</small>
                      {term.original}
                    </span>
                  ))}
                </div>
                <dl className="metadata-grid">
                  <div>
                    <dt>Source TTL</dt>
                    <dd>{node.ttl ?? 'Unknown'}</dd>
                  </div>
                  <div>
                    <dt>TXT value</dt>
                    <dd>{node.txtOctets} octets</dd>
                  </div>
                  <div>
                    <dt>DNS message</dt>
                    <dd>{node.messageBytes} bytes</dd>
                  </div>
                  <div>
                    <dt>Resolved terms</dt>
                    <dd>{node.resolutions.length}</dd>
                  </div>
                </dl>
              </>
            )}
          </article>
        ))}
      </div>
      {report.snapshot === undefined ? null : <SnapshotPanel snapshot={report.snapshot} />}
    </section>
  );
}

export function SpfPage() {
  const [input, setInput] = useState('');
  const [resolverId, setResolverId] = useState<ResolverId>('google');
  const [mode, setMode] = useState<Mode>('analysis');
  const [state, setState] = useState<'idle' | 'loading' | 'complete' | 'cancelled'>('idle');
  const [error, setError] = useState('');
  const [report, setReport] = useState<SpfRunReport | null>(null);
  const activeRun = useRef<DnsQueryRun | null>(null);

  async function submit(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const parsed = validateDnsName(input);
    if (!parsed.ok) {
      setError(parsed.error.message);
      return;
    }
    activeRun.current?.cancel();
    const run = new DnsQueryRun();
    activeRun.current = run;
    setError('');
    setReport(null);
    setState('loading');
    const dns = new WireSpfDnsClient(new WireDnsResolver(RESOLVERS[resolverId]), run);
    try {
      if (mode === 'analysis') {
        const analysis = await analyseSpf(parsed.value.ascii, dns);
        if (activeRun.current !== run) return;
        setReport({ analysis, dnsQuestions: run.questionsUsed });
      } else {
        const result = await flattenSpf(parsed.value.ascii, dns);
        if (activeRun.current !== run) return;
        setReport({
          analysis: result.analysis,
          dnsQuestions: run.questionsUsed,
          snapshot: result.snapshot,
        });
      }
      setState('complete');
    } catch (cause) {
      if (run.cancelled) setState('cancelled');
      else {
        setError(cause instanceof Error ? cause.message : 'SPF analysis failed.');
        setState('idle');
      }
    }
  }

  function clear() {
    activeRun.current?.cancel();
    activeRun.current = null;
    setInput('');
    setError('');
    setReport(null);
    setState('idle');
  }

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="SPF policy workbench" title="Count policy paths before receivers do.">
        Parse ordered SPF terms, follow include and redirect dependencies, separate protocol
        limits from browser requests, and create a guarded point-in-time snapshot only when it
        is safe.
      </ToolIntro>
      <div className="mode-switch" role="tablist" aria-label="SPF mode">
        <button
          role="tab"
          aria-selected={mode === 'analysis'}
          type="button"
          onClick={() => setMode('analysis')}
        >
          Analysis
        </button>
        <button
          role="tab"
          aria-selected={mode === 'flatten'}
          type="button"
          onClick={() => setMode('flatten')}
        >
          Snapshot flattener
        </button>
      </div>
      <form className="workbench-form" onSubmit={(event) => void submit(event)}>
        <div className="field-group field-wide">
          <label htmlFor="spf-domain">Domain</label>
          <input
            id="spf-domain"
            value={input}
            onChange={(event) => setInput(event.currentTarget.value)}
            placeholder="example.com"
            maxLength={2048}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
        </div>
        <div className="field-group">
          <label htmlFor="spf-resolver">Resolver</label>
          <select
            id="spf-resolver"
            value={resolverId}
            onChange={(event) => setResolverId(event.currentTarget.value as ResolverId)}
          >
            {RESOLVER_IDS.map((id) => (
              <option key={id} value={id}>
                {RESOLVERS[id].label}
              </option>
            ))}
          </select>
        </div>
        {error !== '' ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : null}
        <div className="form-actions">
          <button className="primary-button" type="submit" disabled={state === 'loading'}>
            {state === 'loading'
              ? 'Resolving policy…'
              : mode === 'analysis'
                ? 'Analyse SPF'
                : 'Build guarded snapshot'}
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
        {state === 'loading'
          ? 'SPF dependencies are being evaluated within the DNS question budget.'
          : null}
        {state === 'cancelled' ? 'The SPF run was cancelled.' : null}
      </div>
      {report === null ? null : <AnalysisPanel report={report} />}
    </div>
  );
}
