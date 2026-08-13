import { useMemo, useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import {
  buildCaaRecord,
  caaParentNames,
  parseCaaPolicy,
  type CaaInput,
} from '../core/caa/parser';
import { validateDnsName } from '../core/dns/names';
import { queryPolicyRecords } from '../core/dns/policy-query';
import type { DnsRecord, ResolverId } from '../core/dns/types';
import { DnsQueryRun } from '../core/doh/query-run';
import { RESOLVERS } from '../core/doh/resolvers';
import { WireDnsResolver } from '../core/doh/wire-resolver';

const RESOLVER_IDS = Object.keys(RESOLVERS) as ResolverId[];

function caaInput(record: DnsRecord): CaaInput | null {
  if (record.data === null || typeof record.data !== 'object') return null;
  const value = record.data as Record<string, unknown>;
  const tag = value['tag'];
  const content = value['value'];
  const flags = value['flags'];
  const critical = value['issuerCritical'];
  if (typeof tag !== 'string' || typeof content !== 'string') return null;
  return {
    flags: typeof flags === 'number' ? flags : critical === true ? 128 : 0,
    tag,
    value: content,
  };
}

interface CaaReport {
  readonly errors: readonly string[];
  readonly queried: readonly string[];
  readonly records: readonly CaaInput[];
  readonly source?: string;
  readonly ttl?: number;
}

function cnameTarget(records: readonly DnsRecord[]): string | null {
  const record = records.find((item) => item.type === 'CNAME');
  return record !== undefined && typeof record.data === 'string'
    ? record.data.toLowerCase().replace(/\.$/u, '')
    : null;
}

export function CaaPage() {
  const [domain, setDomain] = useState('');
  const [resolverId, setResolverId] = useState<ResolverId>('google');
  const [state, setState] = useState<'idle' | 'loading' | 'complete' | 'cancelled'>('idle');
  const [error, setError] = useState('');
  const [report, setReport] = useState<CaaReport | null>(null);
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
      return;
    }
    activeRun.current?.cancel();
    const run = new DnsQueryRun();
    activeRun.current = run;
    setError('');
    setReport(null);
    setState('loading');
    const resolver = new WireDnsResolver(RESOLVERS[resolverId]);
    const queried: string[] = [];
    const errors: string[] = [];
    let selected: CaaReport | undefined;
    parentWalk: for (const name of caaParentNames(parsed.value.ascii)) {
      let current = name;
      const aliases = new Set<string>();
      for (let aliasDepth = 0; aliasDepth <= 8; aliasDepth += 1) {
        queried.push(current);
        const result = await queryPolicyRecords(resolver, run, current, 'CAA');
        const queryError =
          result.error ??
          (result.responseCode === 'NOERROR' || result.responseCode === 'NXDOMAIN'
            ? undefined
            : `resolver returned ${result.responseCode}`);
        if (queryError !== undefined) {
          errors.push(`${current}: ${queryError}`);
          break parentWalk;
        }
        const records = result.records.flatMap((record) => {
          const value = caaInput(record);
          return value === null ? [] : [value];
        });
        if (records.length > 0) {
          const source = result.records[0]?.owner.replace(/\.$/u, '') ?? current;
          selected = {
            errors,
            queried,
            records,
            source,
            ...(result.ttl === undefined ? {} : { ttl: result.ttl }),
          };
          break parentWalk;
        }
        const target = cnameTarget(result.answers);
        if (target === null) break;
        if (aliases.has(target) || target === current) {
          errors.push(`${current}: CNAME cycle encountered during CAA discovery.`);
          break;
        }
        aliases.add(current);
        current = target;
        if (aliasDepth === 8) errors.push(`${name}: CNAME chain exceeded eight aliases.`);
      }
      if (run.cancelled) break;
    }
    if (activeRun.current !== run) return;
    if (run.cancelled) {
      setState('cancelled');
      return;
    }
    setReport(selected ?? { errors, queried, records: [] });
    setState('complete');
  }

  const policy = report === null ? null : parseCaaPolicy(report.records);
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
        eyebrow="CAA inspection and authoring"
        title="See where certificate policy is inherited."
      >
        Follow a bounded CNAME chain, walk from the requested name toward its parents, stop at
        the first observed CAA RRset, explain critical properties, and author a generic issue or
        issue, issuewild, or issuemail record locally, including standardized CA account and
        validation-method constraints.
      </ToolIntro>
      <form className="workbench-form" onSubmit={(event) => void inspect(event)}>
        <div className="field-group field-wide">
          <label htmlFor="caa-domain">DNS name</label>
          <input
            id="caa-domain"
            value={domain}
            onChange={(event) => setDomain(event.currentTarget.value)}
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
      <div className="run-status" aria-live="polite">
        {state === 'cancelled' ? 'The CAA walk was cancelled.' : null}
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
                <dd>{domain}</dd>
              </div>
              <div>
                <dt>Policy source</dt>
                <dd>{report.source ?? 'None observed'}</dd>
              </div>
              <div>
                <dt>Inheritance</dt>
                <dd>
                  {report.source !== undefined &&
                  report.source !== domain.toLowerCase().replace(/\.$/u, '')
                    ? 'Inherited'
                    : 'Direct or none'}
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
              <div className="table-scroll">
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
