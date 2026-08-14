import { useMemo, useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { discoverCaaPolicy, type CaaDiscoveryReport } from '../core/caa/discovery';
import { buildCaaRecord, caaParentNames, parseCaaPolicy } from '../core/caa/parser';
import { validateDnsName } from '../core/dns/names';
import { queryPolicyRecords } from '../core/dns/policy-query';
import type { ResolverId } from '../core/dns/types';
import { DnsQueryRun } from '../core/doh/query-run';
import { RESOLVERS } from '../core/doh/resolvers';
import { WireDnsResolver } from '../core/doh/wire-resolver';

const RESOLVER_IDS = Object.keys(RESOLVERS) as ResolverId[];
type CaaRunState = 'idle' | 'loading' | 'complete' | 'partial' | 'error' | 'cancelled';

function runStatusMessage(state: CaaRunState): string {
  switch (state) {
    case 'idle':
      return '';
    case 'loading':
      return 'CAA inspection in progress.';
    case 'complete':
      return 'CAA inspection complete.';
    case 'partial':
      return 'CAA inspection complete with partial DNS evidence.';
    case 'error':
      return 'CAA inspection could not be completed.';
    case 'cancelled':
      return 'The CAA walk was cancelled.';
  }
}

export function CaaPage() {
  const [domain, setDomain] = useState('');
  const [resolverId, setResolverId] = useState<ResolverId>('google');
  const [state, setState] = useState<CaaRunState>('idle');
  const [error, setError] = useState('');
  const [report, setReport] = useState<CaaDiscoveryReport | null>(null);
  const [issuer, setIssuer] = useState('letsencrypt.org');
  const [tag, setTag] = useState<'issue' | 'issuewild' | 'issuemail'>('issue');
  const [accountUri, setAccountUri] = useState('');
  const [validationMethods, setValidationMethods] = useState('');
  const [critical, setCritical] = useState(false);
  const activeRun = useRef<DnsQueryRun | null>(null);

  const builtRecord = useMemo(
    () =>
      buildCaaRecord('@', issuer, {
        ...(tag === 'issuemail' || accountUri.trim() === '' ? {} : { accountUri }),
        critical,
        tag,
        validationMethods:
          tag === 'issuemail'
            ? []
            : validationMethods
                .split(',')
                .map((method) => method.trim())
                .filter(Boolean),
      }),
    [accountUri, critical, issuer, tag, validationMethods],
  );

  async function inspect(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const parsed = validateDnsName(domain);
    if (!parsed.ok) {
      setError(parsed.error.message);
      setState('error');
      return;
    }
    activeRun.current?.cancel();
    const run = new DnsQueryRun();
    activeRun.current = run;
    setError('');
    setReport(null);
    setState('loading');
    const resolver = new WireDnsResolver(RESOLVERS[resolverId]);
    let discovered: CaaDiscoveryReport;
    try {
      discovered = await discoverCaaPolicy(
        caaParentNames(parsed.value.ascii),
        (name) => queryPolicyRecords(resolver, run, name, 'CAA'),
        () => run.cancelled,
      );
    } catch {
      if (activeRun.current !== run) return;
      if (run.cancelled) {
        activeRun.current = null;
        setState('cancelled');
        return;
      }
      activeRun.current = null;
      setError(
        'The CAA inspection could not be completed. Try again or choose another resolver.',
      );
      setState('error');
      return;
    }
    if (activeRun.current !== run) return;
    if (run.cancelled) {
      activeRun.current = null;
      setState('cancelled');
      return;
    }
    activeRun.current = null;
    setReport(discovered);
    setState(discovered.errors.length === 0 ? 'complete' : 'partial');
  }

  const policy = report === null ? null : parseCaaPolicy(report.records);
  function invalidateInspection() {
    activeRun.current?.cancel();
    activeRun.current = null;
    setError('');
    setReport(null);
    setState('idle');
  }

  function clear() {
    invalidateInspection();
    setDomain('');
  }

  return (
    <div className="tool-page">
      <ToolIntro
        eyebrow="CAA inspection and authoring"
        title="See where certificate policy is inherited."
      >
        Ask a recursive resolver to process aliases, then walk the original requested name
        towards its parents and stop at the first observed CAA RRset. Explain critical
        properties and author issue, issuewild, or issuemail records locally, including
        standardised CA account and validation-method constraints.
      </ToolIntro>
      <form className="workbench-form" onSubmit={(event) => void inspect(event)}>
        <div className="field-group field-wide">
          <label htmlFor="caa-domain">DNS name</label>
          <input
            id="caa-domain"
            value={domain}
            onChange={(event) => {
              invalidateInspection();
              setDomain(event.currentTarget.value);
            }}
            placeholder="www.example.com"
            maxLength={2048}
            spellCheck={false}
          />
        </div>
        <div className="field-group">
          <label htmlFor="caa-resolver">Resolver</label>
          <select
            id="caa-resolver"
            value={resolverId}
            onChange={(event) => {
              invalidateInspection();
              setResolverId(event.currentTarget.value as ResolverId);
            }}
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
            {state === 'loading' ? 'Walking parents…' : 'Inspect CAA'}
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
        aria-label="CAA run status"
        aria-live="polite"
        aria-atomic="true"
      >
        {runStatusMessage(state)}
      </div>
      {report === null || policy === null ? null : (
        <section className="results" aria-labelledby="caa-result-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Effective observed RRset</p>
              <h2 id="caa-result-title">
                {report.source ??
                  (report.errors.length > 0 ? 'CAA result incomplete' : 'No CAA record found')}
              </h2>
            </div>
            <StatusBadge
              tone={
                report.errors.length > 0
                  ? 'warning'
                  : report.records.length === 0
                    ? 'unknown'
                    : policy.diagnostics.some((item) => item.severity === 'error')
                      ? 'error'
                      : 'pass'
              }
            >
              {report.errors.length > 0
                ? 'Indeterminate'
                : report.records.length === 0
                  ? 'Unconstrained here'
                  : `${String(report.records.length)} records`}
            </StatusBadge>
          </div>
          {report.errors.length > 0 ? (
            <article className="conclusion-panel partial-panel">
              <StatusBadge tone="warning">Partial</StatusBadge>
              <p>{report.errors.join(' ')}</p>
            </article>
          ) : null}
          <article className="result-panel">
            <dl className="metadata-grid">
              <div>
                <dt>Requested</dt>
                <dd>{report.requested}</dd>
              </div>
              <div>
                <dt>Policy source</dt>
                <dd>{report.source ?? 'None observed'}</dd>
              </div>
              <div>
                <dt>Inheritance</dt>
                <dd>
                  {report.foundFor === undefined
                    ? 'None observed'
                    : report.foundFor === report.requested
                      ? report.source === report.requested
                        ? 'Direct'
                        : 'Direct question, alias-resolved'
                      : `Inherited from ${report.foundFor}`}
                </dd>
              </div>
              <div>
                <dt>TTL</dt>
                <dd>{report.ttl ?? 'Unknown'}</dd>
              </div>
            </dl>
            {report.records.length === 0 ? (
              <p className="empty-note">
                {report.errors.length > 0
                  ? 'No complete CAA conclusion can be reached because a required DNS question failed.'
                  : 'No CAA RRset was observed on the bounded parent walk. This permits CA processing to continue; it does not guarantee issuance.'}
              </p>
            ) : (
              <div
                className="table-scroll"
                tabIndex={0}
                role="region"
                aria-label="CAA policy records"
              >
                <table>
                  <thead>
                    <tr>
                      <th>Flags</th>
                      <th>Tag</th>
                      <th>Value</th>
                      <th>Parsed controls</th>
                      <th>Critical</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.records.map((record, index) => {
                      const property = policy.properties[index];
                      return (
                        <tr key={`${record.tag}-${record.value}-${String(index)}`}>
                          <td>{record.flags}</td>
                          <td>{record.tag}</td>
                          <td>
                            <code>{record.value}</code>
                          </td>
                          <td>
                            {property?.parameters.length
                              ? property.parameters
                                  .map((parameter) => `${parameter.name}=${parameter.value}`)
                                  .join('; ')
                              : 'None'}
                          </td>
                          <td>{(record.flags & 128) !== 0 ? 'Yes' : 'No'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </article>
          <article className="result-panel">
            <h3>Diagnostics</h3>
            <ul className="diagnostic-list">
              {policy.diagnostics.map((item, index) => (
                <li key={`${item.code}-${String(index)}`}>
                  <StatusBadge
                    tone={
                      item.severity === 'error'
                        ? 'error'
                        : item.severity === 'warning'
                          ? 'warning'
                          : 'information'
                    }
                  >
                    {item.severity}
                  </StatusBadge>
                  <span>{item.message}</span>
                </li>
              ))}
            </ul>
          </article>
          <details className="method-note">
            <summary>Names queried ({report.queried.length})</summary>
            <p>
              <code>{report.queried.join(' → ')}</code>
            </p>
            <p>
              This is recursive-resolver evidence. CAA narrows which certificate authorities may
              issue; it does not authenticate a certificate request or ensure issuance.
            </p>
            {report.aliases.length === 0 ? null : (
              <ul>
                {report.aliases.map((alias, index) => (
                  <li key={`${alias.type}-${alias.owner}-${alias.target}-${String(index)}`}>
                    {alias.type}: <code>{alias.owner}</code> → <code>{alias.target}</code>
                  </li>
                ))}
              </ul>
            )}
          </details>
        </section>
      )}
      <section className="authoring-panel" aria-labelledby="caa-author-title">
        <div>
          <p className="eyebrow">Local record authoring</p>
          <h2 id="caa-author-title">Build a CAA property</h2>
        </div>
        <div className="authoring-grid">
          <div className="field-group">
            <label htmlFor="caa-issuer">Issuer-domain-name</label>
            <input
              id="caa-issuer"
              value={issuer}
              onChange={(event) => setIssuer(event.currentTarget.value)}
            />
          </div>
          <div className="field-group">
            <label htmlFor="caa-tag">Property</label>
            <select
              id="caa-tag"
              value={tag}
              onChange={(event) =>
                setTag(event.currentTarget.value as 'issue' | 'issuewild' | 'issuemail')
              }
            >
              <option value="issue">issue</option>
              <option value="issuewild">issuewild</option>
              <option value="issuemail">issuemail (S/MIME)</option>
            </select>
          </div>
          {tag === 'issuemail' ? null : (
            <>
              <div className="field-group">
                <label htmlFor="caa-account-uri">CA account URI (optional)</label>
                <input
                  id="caa-account-uri"
                  value={accountUri}
                  onChange={(event) => setAccountUri(event.currentTarget.value)}
                  placeholder="https://ca.example/account/123"
                  spellCheck={false}
                />
              </div>
              <div className="field-group">
                <label htmlFor="caa-validation-methods">Validation methods (optional)</label>
                <input
                  id="caa-validation-methods"
                  value={validationMethods}
                  onChange={(event) => setValidationMethods(event.currentTarget.value)}
                  placeholder="dns-01,http-01"
                  spellCheck={false}
                />
              </div>
            </>
          )}
          <label className="check-control">
            <input
              type="checkbox"
              checked={critical}
              onChange={(event) => setCritical(event.currentTarget.checked)}
            />
            Critical flag
          </label>
        </div>
        <pre className="spf-output">{builtRecord}</pre>
        <CopyButton label="Copy CAA record" text={builtRecord} />
        <p className="detail-note">
          Confirm the exact issuer identifier in your certificate authority’s documentation
          before publishing.
        </p>
      </section>
    </div>
  );
}
