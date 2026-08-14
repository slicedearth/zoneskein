import { useEffect, useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { SnapshotButton } from '../components/SnapshotButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { validateDnsName } from '../core/dns/names';
import type { ResolverId } from '../core/dns/types';
import { WireSpfDnsClient } from '../core/spf/dns-client';
import { analyseSpf } from '../core/spf/evaluator';
import { flattenSpf } from '../core/spf/flatten';
import {
  parseMailFromIdentity,
  parseSenderClientIp,
  parseSenderDomain,
} from '../core/spf/sender-input';
import { evaluateSpfSender, type SpfSenderEvaluation } from '../core/spf/sender-evaluator';
import type { SpfAnalysis, SpfSnapshot } from '../core/spf/types';
import { DnsQueryRun } from '../core/doh/query-run';
import { RESOLVERS } from '../core/doh/resolvers';
import { WireDnsResolver } from '../core/doh/wire-resolver';

type Mode = 'analysis' | 'flatten' | 'sender';
const RESOLVER_IDS = Object.keys(RESOLVERS) as ResolverId[];

interface SpfRunReport {
  readonly analysis: SpfAnalysis;
  readonly dnsQuestions: number;
  readonly resolverId: ResolverId;
  readonly snapshot?: SpfSnapshot;
}

interface SpfSenderReport {
  readonly evaluation: SpfSenderEvaluation;
  readonly resolverId: ResolverId;
}

function diagnosticTone(severity: string) {
  return severity === 'error' ? 'error' : severity === 'warning' ? 'warning' : 'information';
}

function senderTone(result: SpfSenderEvaluation['result']) {
  if (result === 'pass') return 'pass';
  if (result === 'fail' || result === 'permerror') return 'error';
  if (result === 'softfail' || result === 'temperror') return 'warning';
  return 'unknown';
}

function resolverEvidence(resolverId: ResolverId) {
  const resolver = RESOLVERS[resolverId];
  return {
    endpoint: resolver.endpoint,
    id: resolver.id,
    label: resolver.label,
    privacyUrl: resolver.privacyUrl,
    ...(resolver.relay === undefined ? {} : { relay: resolver.relay }),
  };
}

function resolverMarkdown(resolverId: ResolverId): readonly string[] {
  const resolver = RESOLVERS[resolverId];
  return [
    `- Resolver: ${resolver.label} (${resolver.id})`,
    `- Resolver endpoint: ${resolver.endpoint}`,
    ...(resolver.relay === undefined
      ? []
      : [
          `- Intermediary: ${resolver.relay.operator}`,
          `- Fixed upstream: ${resolver.relay.upstreamLabel} (${resolver.relay.upstreamEndpoint})`,
        ]),
  ];
}

function senderMarkdown(evaluation: SpfSenderEvaluation, resolverId: ResolverId): string {
  const escaped = (value: string) => value.replaceAll('|', '\\|').replaceAll('\n', ' ');
  return [
    '# ZoneSkein sender-context SPF evaluation',
    '',
    `- Result: ${evaluation.result}`,
    `- Identity: ${evaluation.identity}`,
    `- Client IP: ${evaluation.ip}`,
    `- Policy domain: ${evaluation.domain}`,
    ...resolverMarkdown(resolverId),
    ...(evaluation.capturedAt === undefined
      ? []
      : [`- Evaluated at: ${evaluation.capturedAt}`]),
    `- DNS terms: ${String(evaluation.dnsTerms)} of 10`,
    `- Void lookups: ${String(evaluation.voidLookups)} of 2`,
    `- DNS questions: ${String(evaluation.dnsQueries)}`,
    `- DNS response bytes: ${String(evaluation.responseBytes)}`,
    `- Reason: ${evaluation.reason}`,
    ...(evaluation.explanation === undefined
      ? []
      : [`- Publisher explanation: ${evaluation.explanation}`]),
    '',
    '## Trace',
    '',
    '| # | Depth | Stage | Domain | Term | Outcome | Evidence |',
    '| --- | --- | --- | --- | --- | --- | --- |',
    ...evaluation.trace
      .map((entry) =>
        [
          String(entry.sequence),
          String(entry.depth),
          entry.stage,
          entry.domain ?? '',
          entry.term ?? '',
          entry.outcome ?? '',
          entry.query === undefined
            ? entry.message
            : `${entry.message} ${entry.query.type} ${entry.query.name}: ${entry.query.status}, ${String(entry.query.valueCount)} values, ${String(entry.query.messageBytes)} bytes.`,
        ]
          .map(escaped)
          .join(' | '),
      )
      .map((row) => `| ${row} |`),
    '',
    'This is a point-in-time simulation for the supplied SMTP identity and client address. It is not a delivery guarantee.',
  ].join('\n');
}

function SnapshotPanel({
  resolverId,
  snapshot,
}: {
  readonly resolverId: ResolverId;
  readonly snapshot: SpfSnapshot;
}) {
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
      evidenceSchema: 'zoneskein-spf-snapshot-v1',
      estimatedResponseBytes: snapshot.estimatedResponseBytes,
      generatedAt: snapshot.generatedAt,
      provenance: snapshot.provenance,
      recommendedRecheck: snapshot.recommendedRecheck,
      resolver: resolverEvidence(resolverId),
      value: snapshot.value,
      warning: 'Point-in-time SPF snapshot — provider address ranges may change.',
    },
    null,
    2,
  );
  const markdown = [
    snapshot.markdown ?? '# ZoneSkein point-in-time SPF snapshot',
    '',
    '## Resolver provenance',
    '',
    ...resolverMarkdown(resolverId),
  ].join('\n');
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
        <CopyButton label="Copy Markdown" text={markdown} />
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
        <div>
          <dt>Resolver</dt>
          <dd>{RESOLVERS[resolverId].label}</dd>
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
      <div
        className="table-scroll"
        tabIndex={0}
        role="region"
        aria-label="SPF generated-network provenance"
      >
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
  const analysisJson = JSON.stringify(
    {
      ...analysis,
      dnsQuestions: report.dnsQuestions,
      evidenceSchema: 'zoneskein-spf-analysis-v1',
      resolver: resolverEvidence(report.resolverId),
    },
    null,
    2,
  );
  const snapshotContent =
    report.snapshot === undefined
      ? analysisJson
      : JSON.stringify(
          {
            evidenceSchema: 'zoneskein-spf-snapshot-v1',
            resolver: resolverEvidence(report.resolverId),
            snapshot: report.snapshot,
          },
          null,
          2,
        );
  return (
    <section className="results" aria-labelledby="spf-results-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Ordered policy evaluation</p>
          <h2 id="spf-results-title">{analysis.rootDomain}</h2>
        </div>
        <div className="export-actions">
          {report.snapshot === undefined ? (
            <CopyButton label="Copy analysis JSON" text={analysisJson} />
          ) : null}
          <SnapshotButton
            content={snapshotContent}
            title={`SPF ${report.snapshot === undefined ? 'analysis' : 'snapshot'} — ${analysis.rootDomain}`}
            tool="spf"
          />
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
      {report.snapshot === undefined ? null : (
        <SnapshotPanel resolverId={report.resolverId} snapshot={report.snapshot} />
      )}
    </section>
  );
}

function SenderPanel({ report }: { readonly report: SpfSenderReport }) {
  const { evaluation, resolverId } = report;
  const markdown = senderMarkdown(evaluation, resolverId);
  const json = JSON.stringify(
    {
      ...evaluation,
      evidenceSchema: 'zoneskein-spf-sender-v1',
      resolver: resolverEvidence(resolverId),
    },
    null,
    2,
  );
  return (
    <section className="results" aria-labelledby="spf-sender-results-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Sender-context evaluation</p>
          <h2 id="spf-sender-results-title">{evaluation.identity}</h2>
        </div>
        <StatusBadge tone={senderTone(evaluation.result)}>{evaluation.result}</StatusBadge>
      </div>
      <article className="conclusion-panel">
        <StatusBadge tone={senderTone(evaluation.result)}>{evaluation.result}</StatusBadge>
        <p>{evaluation.reason}</p>
        {evaluation.explanation === undefined ? null : (
          <p>Publisher explanation: {evaluation.explanation}</p>
        )}
      </article>
      <div className="metric-strip">
        <div>
          <strong>{evaluation.dnsTerms}/10</strong>
          <span>DNS terms entered</span>
        </div>
        <div>
          <strong>{evaluation.voidLookups}/2</strong>
          <span>Void lookups</span>
        </div>
        <div>
          <strong>{evaluation.dnsQueries}</strong>
          <span>DNS questions</span>
        </div>
        <div>
          <strong>{evaluation.responseBytes}</strong>
          <span>Response bytes</span>
        </div>
        <div>
          <strong>{evaluation.trace.length}</strong>
          <span>Trace entries</span>
        </div>
      </div>
      <article className="result-panel">
        <div className="result-heading">
          <h3>Evaluation identity</h3>
          <div className="export-actions">
            <CopyButton label="Copy evaluation JSON" text={json} />
            <CopyButton label="Copy evaluation Markdown" text={markdown} />
          </div>
        </div>
        <dl className="metadata-grid">
          <div>
            <dt>MAIL FROM identity</dt>
            <dd>{evaluation.identity}</dd>
          </div>
          <div>
            <dt>Client IP</dt>
            <dd>{evaluation.ip}</dd>
          </div>
          <div>
            <dt>Policy domain</dt>
            <dd>{evaluation.domain}</dd>
          </div>
          <div>
            <dt>Resolver</dt>
            <dd>{RESOLVERS[resolverId].label}</dd>
          </div>
          <div>
            <dt>Matched mechanism</dt>
            <dd>{evaluation.match?.term ?? 'None'}</dd>
          </div>
          <div>
            <dt>Evaluated at</dt>
            <dd>
              {evaluation.capturedAt === undefined
                ? 'Unknown'
                : new Date(evaluation.capturedAt).toLocaleString()}
            </dd>
          </div>
        </dl>
      </article>
      <article className="result-panel">
        <h3>Ordered evaluation trace</h3>
        <div
          className="table-scroll"
          tabIndex={0}
          role="region"
          aria-label="SPF ordered evaluation trace"
        >
          <table>
            <caption>SPF mechanisms, limits, macros, and DNS evidence</caption>
            <thead>
              <tr>
                <th>Step</th>
                <th>Stage</th>
                <th>Domain / term</th>
                <th>Outcome</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {evaluation.trace.map((entry) => (
                <tr key={entry.sequence}>
                  <td>{entry.sequence}</td>
                  <td>
                    {entry.stage}
                    <br />
                    <small>depth {entry.depth}</small>
                  </td>
                  <td>
                    {entry.domain ?? '—'}
                    <br />
                    <code>{entry.term ?? '—'}</code>
                  </td>
                  <td>{entry.outcome ?? '—'}</td>
                  <td>
                    {entry.message}
                    {entry.query === undefined ? null : (
                      <details className="inline-details">
                        <summary>
                          {entry.query.type} {entry.query.name} · {entry.query.status}
                        </summary>
                        <p>
                          {String(entry.query.valueCount)} values ·{' '}
                          {String(entry.query.messageBytes)} bytes
                          {entry.query.error === undefined ? '' : ` · ${entry.query.error}`}
                        </p>
                        {entry.query.values.length === 0 ? null : (
                          <pre className="spf-output">{entry.query.values.join('\n')}</pre>
                        )}
                      </details>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </article>
      <p className="detail-note">
        This is a local, point-in-time simulation for one supplied SMTP identity and client
        address. ZoneSkein does not transmit the mailbox or IP anywhere except in the DNS names
        that the SPF policy itself requires, and it does not save this evaluation automatically.
        Copying either export places the supplied mailbox, client IP, and derived evidence on
        your clipboard.
      </p>
    </section>
  );
}

export function SpfPage() {
  const [input, setInput] = useState('');
  const [clientIp, setClientIp] = useState('');
  const [mailFrom, setMailFrom] = useState('');
  const [heloDomain, setHeloDomain] = useState('');
  const [receiver, setReceiver] = useState('');
  const [resolverId, setResolverId] = useState<ResolverId>('google');
  const [mode, setMode] = useState<Mode>('analysis');
  const [state, setState] = useState<'idle' | 'loading' | 'complete' | 'cancelled'>('idle');
  const [error, setError] = useState('');
  const [report, setReport] = useState<SpfRunReport | null>(null);
  const [senderReport, setSenderReport] = useState<SpfSenderReport | null>(null);
  const activeRun = useRef<DnsQueryRun | null>(null);

  useEffect(
    () => () => {
      activeRun.current?.cancel();
      activeRun.current = null;
    },
    [],
  );

  function invalidateResult() {
    activeRun.current?.cancel();
    activeRun.current = null;
    setError('');
    setReport(null);
    setSenderReport(null);
    setState('idle');
  }

  async function submit(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    let policyDomain = '';
    let mailFromDomain = '';
    let localPart = '';
    let evaluationIp = clientIp;
    let evaluationHelo = heloDomain;
    let evaluationReceiver = receiver;
    if (mode === 'sender') {
      const identity = parseMailFromIdentity(mailFrom);
      if (!identity.ok) {
        setError(identity.error);
        return;
      }
      mailFromDomain = identity.value.domain;
      localPart = identity.value.localPart;
      const parsedIp = parseSenderClientIp(clientIp);
      if (!parsedIp.ok) {
        setError(parsedIp.error);
        return;
      }
      evaluationIp = parsedIp.value;
      if (identity.value.nullReversePath) {
        const parsedHelo = parseSenderDomain(heloDomain, 'HELO/EHLO');
        if (!parsedHelo.ok) {
          setError(parsedHelo.error);
          return;
        }
        evaluationHelo = parsedHelo.value;
      } else evaluationHelo = heloDomain.trim();
      if (receiver.trim() !== '') {
        const parsedReceiver = parseSenderDomain(receiver, 'receiver');
        if (!parsedReceiver.ok) {
          setError(parsedReceiver.error);
          return;
        }
        evaluationReceiver = parsedReceiver.value;
      } else evaluationReceiver = '';
    } else {
      const parsed = validateDnsName(input);
      if (!parsed.ok) {
        setError(parsed.error.message);
        return;
      }
      policyDomain = parsed.value.ascii;
    }
    activeRun.current?.cancel();
    const run = new DnsQueryRun();
    activeRun.current = run;
    setError('');
    setReport(null);
    setSenderReport(null);
    setState('loading');
    const selectedResolverId = resolverId;
    const dns = new WireSpfDnsClient(new WireDnsResolver(RESOLVERS[selectedResolverId]), run);
    try {
      if (mode === 'sender') {
        const evaluation = await evaluateSpfSender(
          {
            heloDomain: evaluationHelo,
            ip: evaluationIp,
            localPart,
            mailFromDomain,
            receiver: evaluationReceiver,
            signal: run.signal,
            timestamp: new Date(),
          },
          dns,
        );
        if (activeRun.current !== run) return;
        if (run.cancelled) {
          setState('cancelled');
          return;
        }
        setSenderReport({ evaluation, resolverId: selectedResolverId });
      } else if (mode === 'analysis') {
        const analysis = await analyseSpf(policyDomain, dns);
        if (activeRun.current !== run) return;
        if (run.cancelled) {
          setState('cancelled');
          return;
        }
        setReport({
          analysis,
          dnsQuestions: run.questionsUsed,
          resolverId: selectedResolverId,
        });
      } else {
        const result = await flattenSpf(policyDomain, dns);
        if (activeRun.current !== run) return;
        if (run.cancelled) {
          setState('cancelled');
          return;
        }
        setReport({
          analysis: result.analysis,
          dnsQuestions: run.questionsUsed,
          resolverId: selectedResolverId,
          snapshot: result.snapshot,
        });
      }
      setState('complete');
    } catch (cause) {
      if (activeRun.current !== run) return;
      if (run.cancelled) setState('cancelled');
      else {
        setError(cause instanceof Error ? cause.message : 'SPF analysis failed.');
        setState('idle');
      }
    }
  }

  function clear() {
    invalidateResult();
    setInput('');
    setClientIp('');
    setMailFrom('');
    setHeloDomain('');
    setReceiver('');
  }

  function selectMode(next: Mode) {
    invalidateResult();
    setMode(next);
  }

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="SPF policy workbench" title="Count policy paths before receivers do.">
        Parse ordered SPF terms, follow include and redirect dependencies, separate protocol
        limits from browser requests, simulate one sender context, and create a guarded
        point-in-time snapshot only when it is safe.
      </ToolIntro>
      <div className="mode-switch" aria-label="SPF mode">
        <button
          aria-pressed={mode === 'analysis'}
          type="button"
          disabled={state === 'loading'}
          onClick={() => selectMode('analysis')}
        >
          Analysis
        </button>
        <button
          aria-pressed={mode === 'flatten'}
          type="button"
          disabled={state === 'loading'}
          onClick={() => selectMode('flatten')}
        >
          Snapshot flattener
        </button>
        <button
          aria-pressed={mode === 'sender'}
          type="button"
          disabled={state === 'loading'}
          onClick={() => selectMode('sender')}
        >
          Sender evaluation
        </button>
      </div>
      <form className="workbench-form" onSubmit={(event) => void submit(event)}>
        {mode === 'sender' ? (
          <>
            <div className="field-group">
              <label htmlFor="spf-client-ip">SMTP client IP</label>
              <input
                id="spf-client-ip"
                value={clientIp}
                disabled={state === 'loading'}
                onChange={(event) => {
                  invalidateResult();
                  setClientIp(event.currentTarget.value);
                }}
                placeholder="192.0.2.10 or 2001:db8::10"
                maxLength={64}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                required
              />
            </div>
            <div className="field-group">
              <label htmlFor="spf-mail-from">MAIL FROM address</label>
              <input
                id="spf-mail-from"
                value={mailFrom}
                disabled={state === 'loading'}
                onChange={(event) => {
                  invalidateResult();
                  setMailFrom(event.currentTarget.value);
                }}
                placeholder="sender@example.com or <>"
                maxLength={512}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
              />
              <small>Leave empty or enter &lt;&gt; for the null reverse path.</small>
            </div>
            <div className="field-group">
              <label htmlFor="spf-helo-domain">HELO/EHLO domain</label>
              <input
                id="spf-helo-domain"
                value={heloDomain}
                disabled={state === 'loading'}
                onChange={(event) => {
                  invalidateResult();
                  setHeloDomain(event.currentTarget.value);
                }}
                placeholder="mail.sender.example"
                maxLength={253}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                required
              />
            </div>
            <div className="field-group">
              <label htmlFor="spf-receiver">Receiver hostname (optional)</label>
              <input
                id="spf-receiver"
                value={receiver}
                disabled={state === 'loading'}
                onChange={(event) => {
                  invalidateResult();
                  setReceiver(event.currentTarget.value);
                }}
                placeholder="mx.receiver.example"
                maxLength={253}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
              />
              <small>Used only when a policy expands the receiver macro.</small>
            </div>
          </>
        ) : (
          <div className="field-group field-wide">
            <label htmlFor="spf-domain">Domain</label>
            <input
              id="spf-domain"
              value={input}
              disabled={state === 'loading'}
              onChange={(event) => {
                invalidateResult();
                setInput(event.currentTarget.value);
              }}
              placeholder="example.com"
              maxLength={2048}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
          </div>
        )}
        <div className="field-group">
          <label htmlFor="spf-resolver">Resolver</label>
          <select
            id="spf-resolver"
            aria-describedby={
              RESOLVERS[resolverId].selectionNote === undefined
                ? undefined
                : 'spf-resolver-note'
            }
            value={resolverId}
            disabled={state === 'loading'}
            onChange={(event) => {
              invalidateResult();
              setResolverId(event.currentTarget.value as ResolverId);
            }}
          >
            {RESOLVER_IDS.map((id) => (
              <option key={id} value={id}>
                {RESOLVERS[id].label}
              </option>
            ))}
          </select>
          {RESOLVERS[resolverId].selectionNote === undefined ? null : (
            <small id="spf-resolver-note">{RESOLVERS[resolverId].selectionNote}</small>
          )}
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
                : mode === 'flatten'
                  ? 'Build guarded snapshot'
                  : 'Evaluate sender'}
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
      <div
        className="run-status"
        role="status"
        aria-label="SPF run status"
        aria-live="polite"
        aria-atomic="true"
      >
        {state === 'loading'
          ? mode === 'sender'
            ? 'The SPF sender context is being evaluated within the DNS question budget.'
            : 'SPF dependencies are being evaluated within the DNS question budget.'
          : null}
        {state === 'cancelled' ? 'The SPF run was cancelled.' : null}
        {state === 'complete' && senderReport !== null
          ? `SPF sender evaluation complete: ${senderReport.evaluation.result}.`
          : null}
        {state === 'complete' && report !== null
          ? report.snapshot === undefined
            ? 'SPF analysis complete.'
            : report.snapshot.safe
              ? 'The guarded SPF snapshot is ready.'
              : 'The guarded SPF snapshot was safely withheld.'
          : null}
      </div>
      {report === null ? null : <AnalysisPanel report={report} />}
      {senderReport === null ? null : <SenderPanel report={senderReport} />}
    </div>
  );
}
