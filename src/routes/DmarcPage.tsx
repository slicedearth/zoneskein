import { useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { dmarcDiscoveryNames, parseDmarcRecord } from '../core/dmarc/parser';
import type { DmarcPolicy } from '../core/dmarc/types';
import { validateDnsName } from '../core/dns/names';
import { queryPolicyRecords } from '../core/dns/policy-query';
import type { ResolverId } from '../core/dns/types';
import { DnsQueryRun } from '../core/doh/query-run';
import { RESOLVERS } from '../core/doh/resolvers';
import { WireDnsResolver } from '../core/doh/wire-resolver';

const RESOLVER_IDS = Object.keys(RESOLVERS) as ResolverId[];

interface AuthorizationResult {
  readonly authorized: boolean;
  readonly error?: string;
  readonly name: string;
}

interface DmarcReport {
  readonly authorizations: readonly AuthorizationResult[];
  readonly inherited: boolean;
  readonly policy?: DmarcPolicy;
  readonly policyDomain?: string;
  readonly queryName?: string;
  readonly querySummary: readonly string[];
  readonly ttl?: number;
}

function runWasCancelled(run: DnsQueryRun): boolean {
  return run.cancelled;
}

export function DmarcPage() {
  const [domain, setDomain] = useState('');
  const [resolverId, setResolverId] = useState<ResolverId>('google');
  const [state, setState] = useState<'idle' | 'loading' | 'complete' | 'cancelled'>('idle');
  const [error, setError] = useState('');
  const [report, setReport] = useState<DmarcReport | null>(null);
  const activeRun = useRef<DnsQueryRun | null>(null);

  async function inspect(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const parsed = validateDnsName(domain);
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
    const resolver = new WireDnsResolver(RESOLVERS[resolverId]);
    const names = dmarcDiscoveryNames(parsed.value.ascii);
    const summaries: string[] = [];
    let selected:
      { name: string; policyDomain: string; record: string; ttl?: number } | undefined;
    for (const name of names) {
      const result = await queryPolicyRecords(resolver, run, name, 'TXT');
      if (run.cancelled) {
        setState('cancelled');
        return;
      }
      summaries.push(
        `${name}: ${result.error ?? `${result.responseCode}, ${String(result.values.length)} TXT values`}`,
      );
      const queryError =
        result.error ??
        (result.responseCode === 'NOERROR' || result.responseCode === 'NXDOMAIN'
          ? undefined
          : `resolver returned ${result.responseCode}`);
      if (queryError !== undefined) {
        setError(`${name}: ${queryError}. DMARC fallback cannot be evaluated safely.`);
        setState('idle');
        return;
      }
      const policies = result.values.filter((value) =>
        value.trimStart().toUpperCase().startsWith('V=DMARC1'),
      );
      if (policies.length > 1) {
        setError(`${name} publishes multiple DMARC policies.`);
        setState('idle');
        return;
      }
      const record = policies[0];
      if (record !== undefined) {
        selected = {
          name,
          policyDomain: name.slice('_dmarc.'.length),
          record,
          ...(result.ttl === undefined ? {} : { ttl: result.ttl }),
        };
        break;
      }
    }
    if (activeRun.current !== run) return;
    if (runWasCancelled(run)) {
      setState('cancelled');
      return;
    }
    if (selected === undefined) {
      setReport({ authorizations: [], inherited: false, querySummary: summaries });
      setState('complete');
      return;
    }
    const policy = parseDmarcRecord(selected.record, selected.policyDomain);
    const authorizationNames = [
      ...new Set(
        policy.destinations.flatMap((destination) =>
          destination.authorizationName === undefined ? [] : [destination.authorizationName],
        ),
      ),
    ].slice(0, 10);
    const authorizations = await Promise.all(
      authorizationNames.map(async (name): Promise<AuthorizationResult> => {
        const result = await queryPolicyRecords(resolver, run, name, 'TXT');
        const authorizationError =
          result.error ??
          (result.responseCode === 'NOERROR' || result.responseCode === 'NXDOMAIN'
            ? undefined
            : `resolver returned ${result.responseCode}`);
        return {
          authorized:
            authorizationError === undefined &&
            result.values.some((value) => value.trim().toUpperCase() === 'V=DMARC1'),
          ...(authorizationError === undefined ? {} : { error: authorizationError }),
          name,
        };
      }),
    );
    if (activeRun.current !== run) return;
    if (runWasCancelled(run)) {
      setState('cancelled');
      return;
    }
    setReport({
      authorizations,
      inherited: selected.policyDomain !== parsed.value.ascii,
      policy,
      policyDomain: selected.policyDomain,
      queryName: selected.name,
      querySummary: summaries,
      ...(selected.ttl === undefined ? {} : { ttl: selected.ttl }),
    });
    setState('complete');
  }

  function clear() {
    activeRun.current?.cancel();
    activeRun.current = null;
    setDomain('');
    setError('');
    setReport(null);
    setState('idle');
  }

  return (
    <div className="tool-page">
      <ToolIntro
        eyebrow="DMARC policy inspector"
        title="Follow discovery and reporting boundaries."
      >
        Discover direct or organizational-domain policy, parse every tag locally, and check the
        DNS authorization required for external aggregate and forensic report destinations.
      </ToolIntro>
      <form className="workbench-form" onSubmit={(event) => void inspect(event)}>
        <div className="field-group field-wide">
          <label htmlFor="dmarc-domain">Domain</label>
          <input
            id="dmarc-domain"
            value={domain}
            onChange={(event) => setDomain(event.currentTarget.value)}
            placeholder="mail.example.com"
            maxLength={2048}
            spellCheck={false}
          />
        </div>
        <div className="field-group">
          <label htmlFor="dmarc-resolver">Resolver</label>
          <select
            id="dmarc-resolver"
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
            {state === 'loading' ? 'Discovering…' : 'Inspect DMARC'}
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
        {state === 'cancelled' ? 'The DMARC run was cancelled.' : null}
      </div>
      {report === null ? null : (
        <section className="results" aria-labelledby="dmarc-result-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Discovery result</p>
              <h2 id="dmarc-result-title">DMARC policy</h2>
            </div>
            {report.policy === undefined ? (
              <StatusBadge tone="unknown">Not found</StatusBadge>
            ) : (
              <StatusBadge tone={report.policy.valid ? 'pass' : 'error'}>
                {report.policy.valid ? 'Syntax valid' : 'Errors found'}
              </StatusBadge>
            )}
          </div>
          {report.policy === undefined ? (
            <article className="conclusion-panel">
              <StatusBadge tone="unknown">No policy observed</StatusBadge>
              <p>
                Neither the exact domain nor its organizational-domain fallback returned one
                DMARC policy. This does not describe messages’ SPF or DKIM authentication
                results.
              </p>
            </article>
          ) : (
            <>
              <article className="result-panel">
                <div className="result-heading">
                  <h3>{report.queryName}</h3>
                  <CopyButton text={report.policy.record} />
                </div>
                <pre className="spf-output">{report.policy.record}</pre>
                <dl className="metadata-grid">
                  <div>
                    <dt>Policy domain</dt>
                    <dd>{report.policyDomain}</dd>
                  </div>
                  <div>
                    <dt>Discovery</dt>
                    <dd>
                      {report.inherited ? 'Inherited from organizational domain' : 'Direct'}
                    </dd>
                  </div>
                  <div>
                    <dt>TTL</dt>
                    <dd>{report.ttl ?? 'Unknown'}</dd>
                  </div>
                  <div>
                    <dt>Report destinations</dt>
                    <dd>{report.policy.destinations.length}</dd>
                  </div>
                </dl>
              </article>
              <div className="comparison-grid">
                <article className="result-panel">
                  <h3>Policy tags</h3>
                  <dl className="tag-list">
                    {report.policy.tags.map((tag) => (
                      <div key={tag.name}>
                        <dt>{tag.name}</dt>
                        <dd>{tag.value}</dd>
                      </div>
                    ))}
                  </dl>
                </article>
                <article className="result-panel">
                  <h3>Diagnostics</h3>
                  {report.policy.diagnostics.length === 0 ? (
                    <p className="empty-note">No syntax diagnostic.</p>
                  ) : (
                    <ul className="diagnostic-list">
                      {report.policy.diagnostics.map((item, index) => (
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
                          <span>
                            <strong>{item.code}</strong> · {item.message}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                </article>
              </div>
              <article className="result-panel">
                <h3>External reporting authorization</h3>
                {report.policy.destinations.length === 0 ? (
                  <p className="empty-note">No rua or ruf destinations.</p>
                ) : (
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Kind</th>
                          <th>URI</th>
                          <th>Boundary</th>
                          <th>Authorization</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.policy.destinations.map((destination, index) => {
                          const authorization = report.authorizations.find(
                            (item) => item.name === destination.authorizationName,
                          );
                          return (
                            <tr key={`${destination.uri}-${String(index)}`}>
                              <td>{destination.kind}</td>
                              <td>
                                <code>{destination.uri}</code>
                              </td>
                              <td>
                                {destination.external
                                  ? 'External'
                                  : 'Same organizational domain'}
                              </td>
                              <td>
                                {destination.external
                                  ? authorization?.authorized === true
                                    ? 'Authorized by DNS'
                                    : (authorization?.error ??
                                      'Authorization record not observed')
                                  : 'Not required'}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </article>
            </>
          )}
          <details className="method-note">
            <summary>Discovery questions</summary>
            <ul>
              {report.querySummary.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
            <p>
              Policy publication does not prove that senders align SPF or DKIM, that receivers
              enforce the requested disposition, or that report mailboxes accept data.
            </p>
          </details>
        </section>
      )}
    </div>
  );
}
