import { useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { inspectDkimKey, parseDkimKeyRecord, validateDkimSelector } from '../core/dkim/parser';
import type { DkimKeyInspection, DkimKeyRecord } from '../core/dkim/types';
import { validateDnsName } from '../core/dns/names';
import { queryPolicyRecords } from '../core/dns/policy-query';
import type { ResolverId } from '../core/dns/types';
import { DnsQueryRun } from '../core/doh/query-run';
import { RESOLVERS } from '../core/doh/resolvers';
import { WireDnsResolver } from '../core/doh/wire-resolver';

const RESOLVER_IDS = Object.keys(RESOLVERS) as ResolverId[];

interface DkimReport {
  readonly inspection?: DkimKeyInspection;
  readonly key?: DkimKeyRecord;
  readonly name: string;
  readonly responseCode: string;
  readonly ttl?: number;
}

export function DkimPage() {
  const [domain, setDomain] = useState('');
  const [selector, setSelector] = useState('');
  const [resolverId, setResolverId] = useState<ResolverId>('google');
  const [state, setState] = useState<'idle' | 'loading' | 'complete' | 'cancelled'>('idle');
  const [error, setError] = useState('');
  const [report, setReport] = useState<DkimReport | null>(null);
  const activeRun = useRef<DnsQueryRun | null>(null);

  async function inspect(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const parsed = validateDnsName(domain);
    const selectorError = validateDkimSelector(selector);
    if (!parsed.ok || selectorError !== null) {
      setError(parsed.ok ? (selectorError ?? 'Invalid selector.') : parsed.error.message);
      return;
    }
    activeRun.current?.cancel();
    const run = new DnsQueryRun();
    activeRun.current = run;
    setError('');
    setReport(null);
    setState('loading');
    const name = `${selector.trim()}._domainkey.${parsed.value.ascii}`;
    const result = await queryPolicyRecords(
      new WireDnsResolver(RESOLVERS[resolverId]),
      run,
      name,
      'TXT',
    );
    if (activeRun.current !== run) return;
    if (run.cancelled) {
      setState('cancelled');
      return;
    }
    if (result.error !== undefined) {
      setError(result.error);
      setState('idle');
      return;
    }
    if (result.values.length > 1) {
      setError(`${name} returned multiple TXT values; the DKIM key record is ambiguous.`);
      setState('idle');
      return;
    }
    const record = result.values[0];
    if (record === undefined) {
      setReport({
        name,
        responseCode: result.responseCode,
        ...(result.ttl === undefined ? {} : { ttl: result.ttl }),
      });
    } else {
      const key = parseDkimKeyRecord(record);
      const inspection = await inspectDkimKey(key);
      setReport({
        inspection,
        key,
        name,
        responseCode: result.responseCode,
        ...(result.ttl === undefined ? {} : { ttl: result.ttl }),
      });
    }
    setState('complete');
  }

  function clear() {
    activeRun.current?.cancel();
    activeRun.current = null;
    setDomain('');
    setSelector('');
    setError('');
    setReport(null);
    setState('idle');
  }

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="DKIM key inspector" title="Inspect the selector you intend to use.">
        Construct the exact _domainkey name locally, parse the published key record, and ask Web
        Crypto to import RSA or Ed25519 material. Message-signature verification needs a message
        and is deliberately outside this DNS-only check.
      </ToolIntro>
      <form className="workbench-form" onSubmit={(event) => void inspect(event)}>
        <div className="field-group">
          <label htmlFor="dkim-domain">Signing domain</label>
          <input
            id="dkim-domain"
            value={domain}
            onChange={(event) => setDomain(event.currentTarget.value)}
            placeholder="example.com"
            maxLength={2048}
            spellCheck={false}
          />
        </div>
        <div className="field-group">
          <label htmlFor="dkim-selector">Selector</label>
          <input
            id="dkim-selector"
            value={selector}
            onChange={(event) => setSelector(event.currentTarget.value)}
            placeholder="selector-2026"
            maxLength={63}
            spellCheck={false}
          />
        </div>
        <div className="field-group">
          <label htmlFor="dkim-resolver">Resolver</label>
          <select
            id="dkim-resolver"
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
        {error !== '' ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : null}
        <div className="form-actions">
          <button className="primary-button" type="submit" disabled={state === 'loading'}>
            {state === 'loading' ? 'Inspecting…' : 'Inspect DKIM key'}
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
        {state === 'cancelled' ? 'The DKIM query was cancelled.' : null}
      </div>
      {report === null ? null : (
        <section className="results" aria-labelledby="dkim-result-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Selector result</p>
              <h2 id="dkim-result-title">{report.name}</h2>
            </div>
            {report.inspection === undefined ? (
              <StatusBadge tone="unknown">No key observed</StatusBadge>
            ) : (
              <StatusBadge
                tone={
                  report.inspection.status === 'valid'
                    ? 'pass'
                    : report.inspection.status === 'weak'
                      ? 'warning'
                      : report.inspection.status === 'revoked'
                        ? 'information'
                        : 'error'
                }
              >
                {report.inspection.status}
              </StatusBadge>
            )}
          </div>
          {report.key === undefined || report.inspection === undefined ? (
            <article className="conclusion-panel">
              <StatusBadge tone="unknown">{report.responseCode}</StatusBadge>
              <p>No single DKIM TXT key was returned for this exact selector name.</p>
            </article>
          ) : (
            <>
              <article className="result-panel">
                <div className="result-heading">
                  <h3>Published key record</h3>
                  <CopyButton text={report.key.record} />
                </div>
                <pre className="spf-output">{report.key.record}</pre>
                <p>{report.inspection.message}</p>
                <dl className="metadata-grid">
                  <div>
                    <dt>Key type</dt>
                    <dd>{report.key.keyType}</dd>
                  </div>
                  <div>
                    <dt>Key size</dt>
                    <dd>
                      {report.inspection.bits === undefined
                        ? 'Unknown'
                        : `${String(report.inspection.bits)} bits`}
                    </dd>
                  </div>
                  <div>
                    <dt>TTL</dt>
                    <dd>{report.ttl ?? 'Unknown'}</dd>
                  </div>
                  <div>
                    <dt>Mode</dt>
                    <dd>
                      {report.key.revoked
                        ? 'Revoked'
                        : report.key.testing
                          ? 'Testing'
                          : 'Normal'}
                    </dd>
                  </div>
                </dl>
              </article>
              <div className="comparison-grid">
                <article className="result-panel">
                  <h3>Tags</h3>
                  <dl className="tag-list">
                    {Object.entries(report.key.tags).map(([name, value]) => (
                      <div key={name}>
                        <dt>{name}</dt>
                        <dd>
                          {name === 'p'
                            ? `${value.slice(0, 30)}${value.length > 30 ? '…' : ''}`
                            : value}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </article>
                <article className="result-panel">
                  <h3>Diagnostics</h3>
                  {report.key.diagnostics.length === 0 ? (
                    <p className="empty-note">No syntax diagnostic.</p>
                  ) : (
                    <ul className="diagnostic-list">
                      {report.key.diagnostics.map((item, index) => (
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
                  )}
                </article>
              </div>
            </>
          )}
          <details className="method-note">
            <summary>What this does not prove</summary>
            <p>
              A well-formed DNS key does not prove that outgoing messages use this selector,
              that headers and body canonicalize correctly, or that a receiver accepts the
              signature. Inspect an actual message to verify those properties.
            </p>
          </details>
        </section>
      )}
    </div>
  );
}
