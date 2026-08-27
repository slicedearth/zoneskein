import ipaddr from 'ipaddr.js';
import { useEffect, useMemo, useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { EvidenceGraph } from '../components/EvidenceGraph';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { validateDnsName } from '../core/dns/names';
import { useDomainThread } from '../core/domain-thread';
import {
  analyseDnssecLifecycle,
  type DnssecLifecycleReport,
  type LifecycleFindingTone,
} from '../core/dnssec/lifecycle';
import { globalpingEvidenceBundle } from '../core/measurement/evidence';
import {
  reserveGlobalpingRun,
  runGlobalpingDns,
  type GlobalpingDnsMeasurement,
  type GlobalpingDnsProtocol,
  type GlobalpingDnsType,
} from '../core/measurement/globalping';
import { escapeTechnicalText, stringifyTechnicalEvidence } from '../core/technical-text';

const DNS_TYPES = [
  'NS',
  'SOA',
  'DS',
  'DNSKEY',
  'A',
  'AAAA',
  'CAA',
  'MX',
  'TXT',
  'HTTPS',
  'SVCB',
] as const satisfies readonly GlobalpingDnsType[];
const LOCATIONS = [
  ['world', 'Worldwide selection'],
  ['Australia', 'Australia'],
  ['Asia', 'Asia'],
  ['Europe', 'Europe'],
  ['North America', 'North America'],
  ['South America', 'South America'],
  ['Africa', 'Africa'],
] as const;

type Mode = 'trace' | 'authority' | 'lifecycle';

function tone(value: LifecycleFindingTone): 'pass' | 'information' | 'warning' | 'error' {
  return value;
}

function resolverInput(value: string): string | null {
  const trimmed = value.trim();
  if (ipaddr.isValid(trimmed)) return trimmed;
  const name = validateDnsName(trimmed);
  return name.ok ? name.value.ascii : null;
}

function MeasurementResults({
  measurement,
}: {
  readonly measurement: GlobalpingDnsMeasurement;
}) {
  const bundle = useMemo(() => globalpingEvidenceBundle(measurement), [measurement]);
  return (
    <section className="results" aria-labelledby="delegation-results-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">External vantage evidence</p>
          <h2 id="delegation-results-title">Delegation strands</h2>
        </div>
        <div className="export-actions">
          <StatusBadge tone={bundle.status === 'complete' ? 'pass' : 'warning'}>
            {bundle.status}
          </StatusBadge>
          <CopyButton
            label="Copy measurement evidence JSON"
            text={stringifyTechnicalEvidence({ bundle, measurement }, 2)}
          />
        </div>
      </div>
      <article className="conclusion-panel partial-panel">
        <StatusBadge tone="information">Point-in-time sample</StatusBadge>
        <p>
          Measurement {measurement.id} returned {measurement.results.length} vantage point
          {measurement.results.length === 1 ? '' : 's'}. This does not establish global
          propagation or prove that every authoritative address was reached.
        </p>
      </article>
      <EvidenceGraph bundle={bundle} />
      <div className="result-list">
        {measurement.results.map((result, resultIndex) => (
          <article
            className="result-panel"
            key={`${result.probe.country}-${result.probe.city}-${String(resultIndex)}`}
          >
            <div className="result-heading">
              <h3>
                {[result.probe.city, result.probe.country].filter(Boolean).join(', ') ||
                  result.probe.network}
              </h3>
              <StatusBadge tone={result.status === 'finished' ? 'pass' : 'warning'}>
                {result.status}
              </StatusBadge>
            </div>
            <p>
              {result.probe.network}
              {result.probe.asn === null ? '' : ` · AS${String(result.probe.asn)}`}
            </p>
            {result.hops.length === 0 ? (
              <p>No structured DNS hops were returned.</p>
            ) : (
              <div
                className="table-scroll"
                tabIndex={0}
                role="region"
                aria-label={`DNS hops from ${result.probe.city || result.probe.country}`}
              >
                <table>
                  <thead>
                    <tr>
                      <th>Hop</th>
                      <th>Responder</th>
                      <th>Time</th>
                      <th>Records</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.hops.map((hop, hopIndex) => (
                      <tr key={`${hop.resolver}-${String(hopIndex)}`}>
                        <td>{hopIndex + 1}</td>
                        <td>
                          <bdi className="technical-value" dir="ltr">
                            {escapeTechnicalText(hop.resolver)}
                          </bdi>
                        </td>
                        <td>
                          {hop.totalMs === null ? 'Unknown' : `${hop.totalMs.toFixed(1)} ms`}
                        </td>
                        <td>
                          {hop.answers.length === 0
                            ? 'No records'
                            : hop.answers
                                .map(
                                  (answer) =>
                                    `${answer.type} ${escapeTechnicalText(answer.value)}`,
                                )
                                .join(' · ')}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <details className="protocol-details">
              <summary>Raw measurement output</summary>
              <pre className="raw-output technical-value" dir="ltr">
                {escapeTechnicalText(result.rawOutput)}
              </pre>
            </details>
          </article>
        ))}
      </div>
    </section>
  );
}

function LifecycleResults({ report }: { readonly report: DnssecLifecycleReport }) {
  return (
    <section className="results" aria-labelledby="lifecycle-results-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Local rollover model</p>
          <h2 id="lifecycle-results-title">DNSSEC lifecycle</h2>
        </div>
        <div className="export-actions">
          <StatusBadge
            tone={
              report.status === 'complete'
                ? 'pass'
                : report.status === 'partial'
                  ? 'warning'
                  : 'unknown'
            }
          >
            {report.status}
          </StatusBadge>
          <CopyButton
            label="Copy lifecycle evidence JSON"
            text={stringifyTechnicalEvidence(report, 2)}
          />
        </div>
      </div>
      <ul className="diagnostic-list">
        {report.findings.map((finding, index) => (
          <li key={`${finding.code}-${String(index)}`}>
            <StatusBadge tone={tone(finding.tone)}>{finding.code}</StatusBadge>
            <span>{finding.message}</span>
          </li>
        ))}
      </ul>
      <div className="metadata-grid">
        <div>
          <dt>Parsed records</dt>
          <dd>{report.parsedRecords}</dd>
        </div>
        <div>
          <dt>Keys</dt>
          <dd>{report.keys.length}</dd>
        </div>
        <div>
          <dt>Supplied DS/CDS</dt>
          <dd>{report.dsRecords.length}</dd>
        </div>
        <div>
          <dt>Derived DS candidates</dt>
          <dd>{report.derivedDs.length}</dd>
        </div>
      </div>
      {report.keys.length === 0 ? null : (
        <div className="table-scroll" tabIndex={0} role="region" aria-label="DNSSEC key roles">
          <table>
            <thead>
              <tr>
                <th>Owner</th>
                <th>Type</th>
                <th>Key tag</th>
                <th>Algorithm</th>
                <th>Role</th>
              </tr>
            </thead>
            <tbody>
              {report.keys.map((key, index) => (
                <tr key={`${key.sourceType}-${String(key.keyTag)}-${String(index)}`}>
                  <td>{key.owner}</td>
                  <td>{key.sourceType}</td>
                  <td>{key.keyTag}</td>
                  <td>{key.algorithm}</td>
                  <td>{key.role}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {report.derivedDs.length === 0 ? null : (
        <details>
          <summary>Derived SHA-256 and SHA-384 DS candidates</summary>
          <div
            className="table-scroll"
            tabIndex={0}
            role="region"
            aria-label="Derived DS candidates"
          >
            <table>
              <thead>
                <tr>
                  <th>Owner</th>
                  <th>Key tag</th>
                  <th>Algorithm</th>
                  <th>Digest</th>
                </tr>
              </thead>
              <tbody>
                {report.derivedDs.map((record) => (
                  <tr key={`${String(record.keyTag)}-${String(record.digestType)}`}>
                    <td>{record.owner}</td>
                    <td>{record.keyTag}</td>
                    <td>{record.algorithm}</td>
                    <td>
                      <code>
                        {record.digestType} {record.digest}
                      </code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
      <ol className="rollout-timeline">
        {report.stages.map((stage) => (
          <li key={stage.id}>
            <span className="timeline-marker" aria-hidden="true" />
            <div>
              <p className="eyebrow">
                Earliest +{stage.earliestOffsetSeconds.toLocaleString()} seconds
              </p>
              <h3>{stage.title}</h3>
              <p>{stage.action}</p>
            </div>
          </li>
        ))}
      </ol>
      <p className="detail-note">
        This is ordering guidance, not an execution schedule. Actual registry automation, TTLs,
        signer behaviour and all authoritative server addresses must be checked before a parent
        change.
      </p>
    </section>
  );
}

export function DelegationPage() {
  const domainThread = useDomainThread();
  const [mode, setMode] = useState<Mode>('trace');
  const [target, setTarget] = useState(() => domainThread.domain?.display ?? '');
  const [resolver, setResolver] = useState('');
  const [type, setType] = useState<GlobalpingDnsType>('NS');
  const [protocol, setProtocol] = useState<GlobalpingDnsProtocol>('UDP');
  const [ipVersion, setIpVersion] = useState<4 | 6>(4);
  const [location, setLocation] = useState('world');
  const [probes, setProbes] = useState<1 | 2 | 3>(1);
  const [consent, setConsent] = useState(false);
  const [measurement, setMeasurement] = useState<GlobalpingDnsMeasurement | null>(null);
  const [source, setSource] = useState('');
  const [origin, setOrigin] = useState('');
  const [lifecycle, setLifecycle] = useState<DnssecLifecycleReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const controller = useRef<AbortController | null>(null);

  useEffect(() => () => controller.current?.abort(), []);

  function clearResult(): void {
    controller.current?.abort();
    controller.current = null;
    setMeasurement(null);
    setLifecycle(null);
    setBusy(false);
    setError('');
  }

  async function runMeasurement(event: React.SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const name = validateDnsName(target);
    if (!name.ok) {
      setError(name.error.message);
      return;
    }
    domainThread.setDomain(name.value);
    if (!consent) {
      setError('Confirm the external measurement disclosure before starting.');
      return;
    }
    const selectedResolver = mode === 'authority' ? resolverInput(resolver) : undefined;
    if (mode === 'authority' && selectedResolver === null) {
      setError('Enter one valid authoritative server hostname or IP address.');
      return;
    }
    const reservation = reserveGlobalpingRun(
      typeof localStorage === 'undefined' ? null : localStorage,
    );
    if (!reservation.ok) {
      setError(
        `This browser has reached ZoneSkein’s six-run hourly guardrail. Try again in ${Math.ceil(reservation.retryAfterMs / 60_000).toLocaleString()} minutes.`,
      );
      return;
    }
    controller.current?.abort();
    const nextController = new AbortController();
    controller.current = nextController;
    setMeasurement(null);
    setError('');
    setBusy(true);
    try {
      const result = await runGlobalpingDns(
        {
          ipVersion,
          location,
          probes,
          protocol,
          ...(selectedResolver === undefined || selectedResolver === null
            ? {}
            : { resolver: selectedResolver }),
          target: name.value.ascii,
          trace: mode === 'trace',
          type,
        },
        nextController.signal,
      );
      if (controller.current !== nextController) return;
      setMeasurement(result);
    } catch (cause) {
      if (nextController.signal.aborted) setError('The external measurement was cancelled.');
      else
        setError(cause instanceof Error ? cause.message : 'The external measurement failed.');
    } finally {
      if (controller.current === nextController) {
        controller.current = null;
        setBusy(false);
      }
    }
  }

  async function analyseLifecycle(event: React.SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError('');
    setLifecycle(null);
    try {
      setLifecycle(await analyseDnssecLifecycle(source, origin));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The lifecycle analysis failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="tool-page">
      <ToolIntro
        eyebrow="Delegation lab"
        title="Inspect the hand-offs, not just the destination."
      >
        Trace the public delegation path from bounded external vantage points, check one
        intended authority directly, or rehearse a DNSSEC rollover entirely in your browser.
      </ToolIntro>
      <div className="mode-tabs" role="group" aria-label="Delegation Lab mode">
        <button
          type="button"
          aria-pressed={mode === 'trace'}
          onClick={() => {
            clearResult();
            setMode('trace');
          }}
        >
          Delegation trace
        </button>
        <button
          type="button"
          aria-pressed={mode === 'authority'}
          onClick={() => {
            clearResult();
            setMode('authority');
          }}
        >
          Pre-delegation check
        </button>
        <button
          type="button"
          aria-pressed={mode === 'lifecycle'}
          onClick={() => {
            clearResult();
            setMode('lifecycle');
          }}
        >
          DNSSEC lifecycle
        </button>
      </div>
      {mode === 'lifecycle' ? (
        <form
          className="workbench-form zone-form"
          onSubmit={(event) => void analyseLifecycle(event)}
        >
          <div className="field-group field-wide">
            <label htmlFor="lifecycle-source">DNSSEC and delegation records</label>
            <textarea
              id="lifecycle-source"
              rows={15}
              maxLength={262_144}
              spellCheck={false}
              value={source}
              onChange={(event) => {
                clearResult();
                setSource(event.currentTarget.value);
              }}
              placeholder={
                '$ORIGIN example.com.\n@ 3600 IN DNSKEY 257 3 13 …\n@ 3600 IN DS 12345 13 2 …\n@ 3600 IN CDS 12345 13 2 …'
              }
            />
            <small>
              Paste current and intended DS, DNSKEY, CDS, CDNSKEY, CSYNC, DSYNC and RRSIG
              records. Cryptographic private keys are neither needed nor accepted.
            </small>
          </div>
          <div className="field-group">
            <label htmlFor="lifecycle-origin">Origin when $ORIGIN is absent</label>
            <input
              id="lifecycle-origin"
              value={origin}
              onChange={(event) => {
                clearResult();
                setOrigin(event.currentTarget.value);
              }}
              placeholder="example.com"
              spellCheck={false}
            />
          </div>
          {error === '' ? null : (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <div className="form-actions">
            <button className="primary-button" type="submit" disabled={busy}>
              {busy ? 'Checking…' : 'Model lifecycle'}
            </button>
          </div>
        </form>
      ) : (
        <form className="workbench-form" onSubmit={(event) => void runMeasurement(event)}>
          <div className="field-group">
            <label htmlFor="delegation-target">Public DNS name</label>
            <input
              id="delegation-target"
              value={target}
              onChange={(event) => {
                clearResult();
                setTarget(event.currentTarget.value);
              }}
              placeholder="example.com"
              spellCheck={false}
            />
          </div>
          {mode !== 'authority' ? null : (
            <div className="field-group">
              <label htmlFor="delegation-resolver">Intended authority</label>
              <input
                id="delegation-resolver"
                value={resolver}
                onChange={(event) => {
                  clearResult();
                  setResolver(event.currentTarget.value);
                }}
                placeholder="ns1.example.net or 192.0.2.53"
                spellCheck={false}
              />
              <small>
                One explicit server per run keeps the external work bounded. Repeat for every
                authoritative address before relying on the result.
              </small>
            </div>
          )}
          <div className="field-group">
            <label htmlFor="delegation-type">Record type</label>
            <select
              id="delegation-type"
              value={type}
              onChange={(event) => {
                clearResult();
                setType(event.currentTarget.value as GlobalpingDnsType);
              }}
            >
              {DNS_TYPES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>
          <div className="field-group">
            <label htmlFor="delegation-protocol">DNS transport</label>
            <select
              id="delegation-protocol"
              value={protocol}
              onChange={(event) => {
                clearResult();
                setProtocol(event.currentTarget.value as GlobalpingDnsProtocol);
              }}
            >
              <option value="UDP">UDP</option>
              <option value="TCP">TCP</option>
            </select>
          </div>
          <div className="field-group">
            <label htmlFor="delegation-ip-version">IP version</label>
            <select
              id="delegation-ip-version"
              value={ipVersion}
              onChange={(event) => {
                clearResult();
                setIpVersion(Number(event.currentTarget.value) as 4 | 6);
              }}
            >
              <option value={4}>IPv4</option>
              <option value={6}>IPv6</option>
            </select>
          </div>
          <div className="field-group">
            <label htmlFor="delegation-location">Probe region</label>
            <select
              id="delegation-location"
              value={location}
              onChange={(event) => {
                clearResult();
                setLocation(event.currentTarget.value);
              }}
            >
              {LOCATIONS.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </div>
          <div className="field-group">
            <label htmlFor="delegation-probes">Vantage points</label>
            <select
              id="delegation-probes"
              value={probes}
              onChange={(event) => {
                clearResult();
                setProbes(Number(event.currentTarget.value) as 1 | 2 | 3);
              }}
            >
              <option value={1}>1 probe</option>
              <option value={2}>2 probes</option>
              <option value={3}>3 probes</option>
            </select>
          </div>
          <label className="check-control field-wide">
            <input
              type="checkbox"
              checked={consent}
              onChange={(event) => {
                clearResult();
                setConsent(event.currentTarget.checked);
              }}
            />
            Send this public DNS target directly to Globalping
          </label>
          <p className="detail-note field-wide">
            Globalping receives the target and your ordinary connection metadata, selects public
            probes, and temporarily stores measurement results under its own terms. ZoneSkein
            sends no cookie, credentials or account token. The local interface permits at most
            three probes per run and six runs per browser hour.
          </p>
          {error === '' ? null : (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <div className="form-actions">
            <button className="primary-button" type="submit" disabled={busy}>
              {busy
                ? 'Measuring…'
                : mode === 'trace'
                  ? 'Trace delegation'
                  : 'Check intended authority'}
            </button>
            {busy ? (
              <button
                className="quiet-button"
                type="button"
                onClick={() => controller.current?.abort()}
              >
                Cancel
              </button>
            ) : null}
          </div>
        </form>
      )}
      <div className="run-status" aria-live="polite">
        {busy
          ? mode === 'lifecycle'
            ? 'Analysing supplied records locally.'
            : 'Waiting for the bounded external measurement.'
          : null}
      </div>
      {measurement === null ? null : <MeasurementResults measurement={measurement} />}
      {lifecycle === null ? null : <LifecycleResults report={lifecycle} />}
    </div>
  );
}
