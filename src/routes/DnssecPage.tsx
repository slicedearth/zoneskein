import { useMemo, useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { SnapshotButton } from '../components/SnapshotButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { validateDnsName } from '../core/dns/names';
import { parseRecordView } from '../core/dns/records';
import type { DnsQuestion, ResolverId, ValidatedDnsName } from '../core/dns/types';
import {
  DNSSEC_APPLICATION_TYPES,
  type DnssecApplicationResult,
  type DnssecApplicationType,
} from '../core/dnssec/application';
import {
  validateDnssecChain,
  type DnssecChainQuery,
  type DnssecChainReport,
  type DnssecChainState,
  type DnssecChainStep,
} from '../core/dnssec/chain';
import { hex } from '../core/dnssec/digest';
import { digestTypeName, dnssecAlgorithmName } from '../core/dnssec/records';
import type { SignatureVerification } from '../core/dnssec/types';
import { DnsQueryRun } from '../core/doh/query-run';
import { RESOLVERS } from '../core/doh/resolvers';
import { WireDnsResolver } from '../core/doh/wire-resolver';
import { MAX_SNAPSHOT_CONTENT_OCTETS } from '../core/snapshots/store';

const RESOLVER_IDS = Object.keys(RESOLVERS) as ResolverId[];

const ROOT_NAME: ValidatedDnsName = {
  absolute: '.',
  ascii: '',
  display: '.',
  hadRootDot: true,
  unicode: false,
};

function stateTone(
  state: DnssecChainState,
): 'pass' | 'information' | 'warning' | 'error' | 'unknown' {
  if (state === 'secure') return 'pass';
  if (state === 'bogus') return 'error';
  if (state === 'insecure' || state === 'not-delegated' || state === 'alias-boundary')
    return 'information';
  if (state === 'incomplete' || state === 'opt-out') return 'warning';
  return 'unknown';
}

function stateLabel(state: DnssecChainState): string {
  const labels: Readonly<Record<DnssecChainState, string>> = {
    'alias-boundary': 'DNAME boundary',
    bogus: 'Bogus',
    incomplete: 'Incomplete',
    insecure: 'Insecure delegation',
    'not-delegated': 'Not a delegation',
    'opt-out': 'Opt-Out: existence indeterminate',
    secure: 'Locally validated',
    unsupported: 'Unsupported',
  };
  return labels[state];
}

function reportJson(report: DnssecChainReport): string {
  return JSON.stringify(
    {
      application:
        report.application === undefined
          ? undefined
          : {
              explanation: report.application.explanation,
              owner: report.application.owner,
              records: report.application.records.map((record) => ({
                class: record.class,
                data: parseRecordView(record).text,
                owner: record.owner,
                rawRdataBase64: bytesBase64(record.rawRdata),
                section: record.section,
                ttl: record.ttl,
                type: record.type,
              })),
              state: report.application.state,
              type: report.application.type,
              verifications: report.application.verifications,
              wildcardExpanded: report.application.wildcardExpanded,
            },
      evidence: report.evidence,
      explanation: report.explanation,
      state: report.state,
      steps: report.steps.map((step) => ({
        denial:
          step.denial === undefined
            ? undefined
            : {
                explanation: step.denial.explanation,
                proofType: step.denial.proofType,
                state: step.denial.state,
              },
        dnskeys: step.dnskeys.map((key) => ({
          algorithm: key.algorithm,
          flags: key.flags,
          keyTag: key.keyTag,
          protocol: key.protocol,
          revoked: key.revoked,
          secureEntryPoint: key.secureEntryPoint,
          zoneKey: key.zoneKey,
        })),
        dnskeyVerifications: step.dnskeyVerifications,
        ds: step.ds.map((record) => ({
          algorithm: record.algorithm,
          digest: hex(record.digest),
          digestType: record.digestType,
          keyTag: record.keyTag,
        })),
        dsMatches: step.dsMatches.map((match) => ({
          digestType: match.digestType,
          keyTag: match.dnskey.keyTag,
          matches: match.matches,
        })),
        dsVerifications: step.dsVerifications,
        explanation: step.explanation,
        state: step.state,
        trustAnchors: step.trustAnchors?.map((match) => ({
          algorithm: match.anchor.algorithm,
          digest: match.anchor.digestHex,
          digestType: match.anchor.digestType,
          id: match.anchor.id,
          keyTag: match.anchor.keyTag,
          validFrom: match.anchor.validFrom,
          validUntil: match.anchor.validUntil,
        })),
        validatedAt: step.validatedAt,
        zone: step.zone,
      })),
      target: report.target,
      trustAnchorSource: report.trustAnchorSource,
      validatedAt: report.validatedAt,
      validatorVersion: report.validatorVersion,
    },
    null,
    2,
  );
}

function bytesBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function ApplicationDetails({ value }: { readonly value: DnssecApplicationResult }) {
  return (
    <article className="result-panel">
      <div className="result-heading">
        <h3>
          {value.owner} {value.type}
        </h3>
        <StatusBadge tone={stateTone(value.state)}>{stateLabel(value.state)}</StatusBadge>
      </div>
      <p>{value.explanation}</p>
      <dl className="metadata-grid">
        <div>
          <dt>Application RRset records</dt>
          <dd>{value.records.length}</dd>
        </div>
        <div>
          <dt>Wildcard expansion</dt>
          <dd>
            {value.wildcardExpanded
              ? value.state === 'secure'
                ? 'Authenticated'
                : 'Detected, proof incomplete'
              : 'No'}
          </dd>
        </div>
      </dl>
      {value.records.length === 0 ? null : (
        <div
          className="table-scroll"
          tabIndex={0}
          role="region"
          aria-label="DNSSEC positive application RRset"
        >
          <table>
            <caption>Positive application RRset</caption>
            <thead>
              <tr>
                <th>Owner</th>
                <th>TTL</th>
                <th>Type</th>
                <th>Data</th>
              </tr>
            </thead>
            <tbody>
              {value.records.map((record, index) => (
                <tr key={`${record.owner}-${record.type}-${String(index)}`}>
                  <td>{record.owner}</td>
                  <td>{record.ttl}</td>
                  <td>{record.type}</td>
                  <td>
                    <code className="record-value">{parseRecordView(record).text}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <VerificationList values={value.verifications} />
    </article>
  );
}

function VerificationList({ values }: { readonly values: readonly SignatureVerification[] }) {
  if (values.length === 0) return null;
  return (
    <ul className="diagnostic-list">
      {values.map((verification, index) => (
        <li
          key={`${String(verification.keyTag)}-${String(verification.algorithm)}-${String(index)}`}
        >
          <StatusBadge
            tone={
              verification.status === 'verified'
                ? 'pass'
                : verification.status === 'invalid'
                  ? 'error'
                  : 'unknown'
            }
          >
            {verification.status}
          </StatusBadge>
          <span>{verification.message}</span>
        </li>
      ))}
    </ul>
  );
}

function ChainPath({ steps }: { readonly steps: readonly DnssecChainStep[] }) {
  return (
    <div className="chain-scroll" aria-label="DNSSEC chain from the root to the requested name">
      {steps.map((step, index) => (
        <div className="chain-segment" key={step.zone}>
          {index === 0 ? null : (
            <span className="chain-join" aria-hidden="true">
              →
            </span>
          )}
          <article>
            <span className="chain-index">{index + 1}</span>
            <p className="step-label">
              {index === 0
                ? 'Trust anchor'
                : step.state === 'not-delegated'
                  ? 'Intermediate name'
                  : step.state === 'alias-boundary'
                    ? 'Alias boundary'
                    : step.state === 'opt-out'
                      ? 'Opt-Out interval'
                      : 'Delegation'}
            </p>
            <h3>{step.zone}</h3>
            <StatusBadge tone={stateTone(step.state)}>{stateLabel(step.state)}</StatusBadge>
          </article>
        </div>
      ))}
    </div>
  );
}

function StepDetails({ step }: { readonly step: DnssecChainStep }) {
  return (
    <article className="result-panel">
      <div className="result-heading">
        <h3>{step.zone}</h3>
        <StatusBadge tone={stateTone(step.state)}>{stateLabel(step.state)}</StatusBadge>
      </div>
      <p>{step.explanation}</p>
      <dl className="metadata-grid">
        <div>
          <dt>Validated at</dt>
          <dd>{new Date(step.validatedAt).toLocaleString()}</dd>
        </div>
        <div>
          <dt>Trust-anchor matches</dt>
          <dd>{step.trustAnchors?.length ?? 0}</dd>
        </div>
        <div>
          <dt>Parent DS records</dt>
          <dd>{step.ds.length}</dd>
        </div>
        <div>
          <dt>Child DNSKEY records</dt>
          <dd>{step.dnskeys.length}</dd>
        </div>
        <div>
          <dt>Authenticated denial</dt>
          <dd>{step.denial?.proofType ?? 'None'}</dd>
        </div>
      </dl>
      {step.trustAnchors === undefined || step.trustAnchors.length === 0 ? null : (
        <div
          className="table-scroll"
          tabIndex={0}
          role="region"
          aria-label="DNSSEC matched root trust anchors"
        >
          <table>
            <caption>Matched root trust anchors</caption>
            <thead>
              <tr>
                <th>Identifier</th>
                <th>Key tag</th>
                <th>Valid from</th>
                <th>Valid until</th>
                <th>Digest</th>
              </tr>
            </thead>
            <tbody>
              {step.trustAnchors.map((match) => (
                <tr key={match.anchor.id}>
                  <td>{match.anchor.id}</td>
                  <td>{match.anchor.keyTag}</td>
                  <td>{new Date(match.anchor.validFrom).toLocaleString()}</td>
                  <td>
                    {match.anchor.validUntil === undefined
                      ? 'No end date published'
                      : new Date(match.anchor.validUntil).toLocaleString()}
                  </td>
                  <td>
                    <code className="record-value">
                      {digestTypeName(match.anchor.digestType)} · {match.anchor.digestHex}
                    </code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {step.ds.length === 0 ? null : (
        <div
          className="table-scroll"
          tabIndex={0}
          role="region"
          aria-label="DNSSEC authenticated parent DS records"
        >
          <table>
            <caption>Authenticated parent DS records</caption>
            <thead>
              <tr>
                <th>Key tag</th>
                <th>Algorithm</th>
                <th>Digest</th>
                <th>Child match</th>
              </tr>
            </thead>
            <tbody>
              {step.ds.map((record) => (
                <tr
                  key={`${String(record.keyTag)}-${String(record.digestType)}-${hex(record.digest)}`}
                >
                  <td>{record.keyTag}</td>
                  <td>{dnssecAlgorithmName(record.algorithm)}</td>
                  <td>
                    <code className="record-value">
                      {digestTypeName(record.digestType)} · {hex(record.digest)}
                    </code>
                  </td>
                  <td>
                    {step.dsMatches.some((match) => match.ds === record && match.matches)
                      ? 'Matches DNSKEY'
                      : [1, 2, 4].includes(record.digestType)
                        ? 'No match'
                        : 'Unsupported digest'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {step.dnskeys.length === 0 ? null : (
        <div
          className="table-scroll"
          tabIndex={0}
          role="region"
          aria-label="DNSSEC DNSKEY records"
        >
          <table>
            <caption>DNSKEY records</caption>
            <thead>
              <tr>
                <th>Key tag</th>
                <th>Flags</th>
                <th>Protocol</th>
                <th>Algorithm</th>
                <th>Role</th>
              </tr>
            </thead>
            <tbody>
              {step.dnskeys.map((key) => (
                <tr
                  key={`${String(key.keyTag)}-${String(key.algorithm)}-${hex(key.key).slice(0, 16)}`}
                >
                  <td>{key.keyTag}</td>
                  <td>{key.flags}</td>
                  <td>{key.protocol}</td>
                  <td>{dnssecAlgorithmName(key.algorithm)}</td>
                  <td>
                    {key.revoked
                      ? 'Revoked'
                      : key.secureEntryPoint
                        ? 'SEP and zone key'
                        : key.zoneKey
                          ? 'Zone key'
                          : 'Other'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <VerificationList values={[...step.dsVerifications, ...step.dnskeyVerifications]} />
    </article>
  );
}

export function DnssecPage() {
  const [input, setInput] = useState('');
  const [resolverId, setResolverId] = useState<ResolverId>('google');
  const [rrsetType, setRrsetType] = useState<'chain' | DnssecApplicationType>('chain');
  const [state, setState] = useState<'idle' | 'loading' | 'complete' | 'cancelled'>('idle');
  const [error, setError] = useState('');
  const [report, setReport] = useState<DnssecChainReport | null>(null);
  const activeRun = useRef<DnsQueryRun | null>(null);
  const evidenceBundle = useMemo(() => (report === null ? '' : reportJson(report)), [report]);
  const evidenceOctets = useMemo(
    () => new TextEncoder().encode(evidenceBundle).length,
    [evidenceBundle],
  );

  function invalidateResult() {
    activeRun.current?.cancel();
    activeRun.current = null;
    setError('');
    setReport(null);
    setState('idle');
  }

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
    const selectedResolver = RESOLVERS[resolverId];
    const resolver = new WireDnsResolver(selectedResolver);
    const query: DnssecChainQuery = async (absoluteName, type) => {
      const validated =
        absoluteName === '.' ? ROOT_NAME : validateDnsName(absoluteName.replace(/\.$/u, ''));
      if ('ok' in validated && !validated.ok) throw new Error(validated.error.message);
      const question: DnsQuestion = {
        name: 'ok' in validated ? validated.value : validated,
        type,
      };
      return run.query(resolver, question, { checkingDisabled: true, dnssecOk: true });
    };
    try {
      const next = await validateDnssecChain(parsed.value.absolute, query, {
        ...(rrsetType === 'chain' ? {} : { rrsetType }),
        resolver: selectedResolver,
        signal: run.signal,
      });
      if (activeRun.current !== run) return;
      if (run.cancelled) {
        setState('cancelled');
        return;
      }
      setReport(next);
      setState('complete');
    } catch (cause) {
      if (activeRun.current !== run) return;
      setError(
        cause instanceof Error ? cause.message : 'DNSSEC validation could not complete.',
      );
      setState(run.cancelled ? 'cancelled' : 'idle');
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
      <ToolIntro
        eyebrow="Independent DNSSEC validator"
        title="Build trust from the root to an RRset locally."
      >
        Validate each DS and DNSKEY RRset from bundled IANA root trust anchors using DNS wire
        evidence and browser cryptography, then optionally authenticate a selected positive,
        negative, wildcard, or bounded alias-continuation result with the relevant zone keys.
        Resolver flags remain visible evidence, but they do not decide the local result.
      </ToolIntro>
      <form className="workbench-form" onSubmit={(event) => void submit(event)}>
        <div className="field-group field-wide">
          <label htmlFor="dnssec-zone">Zone or owner name</label>
          <input
            id="dnssec-zone"
            value={input}
            onChange={(event) => {
              setInput(event.currentTarget.value);
              invalidateResult();
            }}
            placeholder="example.com"
            maxLength={2048}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            disabled={state === 'loading'}
          />
        </div>
        <div className="field-group">
          <label htmlFor="dnssec-target">Validation target</label>
          <select
            id="dnssec-target"
            value={rrsetType}
            disabled={state === 'loading'}
            onChange={(event) => {
              setRrsetType(event.currentTarget.value as 'chain' | DnssecApplicationType);
              invalidateResult();
            }}
          >
            <option value="chain">Delegation chain only</option>
            {DNSSEC_APPLICATION_TYPES.map((type) => (
              <option key={type} value={type}>
                {type} RRset
              </option>
            ))}
          </select>
        </div>
        <div className="field-group">
          <label htmlFor="dnssec-resolver">Resolver transport</label>
          <select
            id="dnssec-resolver"
            aria-describedby={
              RESOLVERS[resolverId].selectionNote === undefined
                ? undefined
                : 'dnssec-resolver-note'
            }
            value={resolverId}
            disabled={state === 'loading'}
            onChange={(event) => {
              setResolverId(event.currentTarget.value as ResolverId);
              invalidateResult();
            }}
          >
            {RESOLVER_IDS.map((id) => (
              <option key={id} value={id}>
                {RESOLVERS[id].label}
              </option>
            ))}
          </select>
          {RESOLVERS[resolverId].selectionNote === undefined ? null : (
            <small id="dnssec-resolver-note">{RESOLVERS[resolverId].selectionNote}</small>
          )}
        </div>
        {error === '' ? null : (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <div className="form-actions">
          <button className="primary-button" type="submit" disabled={state === 'loading'}>
            {state === 'loading' ? 'Validating…' : 'Validate DNSSEC'}
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
          ? 'The bounded root-to-name validation chain is in progress.'
          : state === 'complete'
            ? 'The DNSSEC validation result is ready.'
            : state === 'cancelled'
              ? 'The DNSSEC run was cancelled.'
              : null}
      </div>

      {report === null ? null : (
        <section className="results" aria-labelledby="dnssec-result-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Independent validation result</p>
              <h2 id="dnssec-result-title">{report.target}</h2>
            </div>
            <div className="export-actions">
              <CopyButton label="Copy evidence bundle" text={evidenceBundle} />
              {evidenceOctets <= MAX_SNAPSHOT_CONTENT_OCTETS ? (
                <SnapshotButton
                  content={evidenceBundle}
                  title={`DNSSEC evidence — ${report.target}`}
                  tool="dnssec"
                />
              ) : (
                <button
                  className="quiet-button"
                  type="button"
                  disabled
                  title="Copy the evidence bundle instead; its raw DNS packets exceed the local snapshot limit."
                >
                  Snapshot too large
                </button>
              )}
            </div>
          </div>
          <p>
            The evidence bundle contains complete raw DNS packets, decoded questions, resolver
            names and endpoints, and capture times. Copying it, saving a local snapshot, or
            sharing that snapshot exposes those details to the destination or recipient.
          </p>
          <article className="conclusion-panel">
            <StatusBadge tone={stateTone(report.state)}>{stateLabel(report.state)}</StatusBadge>
            <p>{report.explanation}</p>
          </article>
          <ChainPath steps={report.steps} />
          {report.application === undefined ? null : (
            <ApplicationDetails value={report.application} />
          )}
          <article className="result-panel">
            <h3>Root trust-anchor provenance</h3>
            <dl className="metadata-grid">
              <div>
                <dt>IANA source update</dt>
                <dd>{report.trustAnchorSource.sourceUpdated}</dd>
              </div>
              <div>
                <dt>Last checked</dt>
                <dd>{report.trustAnchorSource.retrievedAt}</dd>
              </div>
              <div>
                <dt>Maintenance check</dt>
                <dd>
                  <code>npm run check:dnssec-anchors</code>
                </dd>
              </div>
              <div>
                <dt>Evidence bundle</dt>
                <dd>{Math.ceil(evidenceOctets / 1024).toLocaleString()} KiB</dd>
              </div>
            </dl>
            <p className="detail-note">
              The maintenance command downloads the current IANA XML and detached signature,
              verifies the named signer through the reviewed ICANN root certificate committed
              with ZoneSkein, and fails if the current anchor set differs from the committed
              copy. Runtime validation makes no extra web request for anchor data.
            </p>
          </article>
          {report.steps.map((step) => (
            <StepDetails key={step.zone} step={step} />
          ))}
          <article className="result-panel">
            <h3>Captured DNS evidence</h3>
            <div
              className="table-scroll"
              tabIndex={0}
              role="region"
              aria-label="DNSSEC captured DNS evidence"
            >
              <table>
                <thead>
                  <tr>
                    <th>Question</th>
                    <th>Decoded question</th>
                    <th>Type</th>
                    <th>Resolver</th>
                    <th>Response</th>
                    <th>AD</th>
                    <th>Extended errors</th>
                  </tr>
                </thead>
                <tbody>
                  {report.evidence.map((item, index) => (
                    <tr key={`${item.name}-${item.type}-${String(index)}`}>
                      <td>{item.name}</td>
                      <td>
                        {item.decodedQuestion === undefined
                          ? 'No response'
                          : `${item.decodedQuestion.name} ${item.decodedQuestion.class} ${item.decodedQuestion.type}`}
                      </td>
                      <td>{item.type}</td>
                      <td>{item.resolver ?? 'No response'}</td>
                      <td>{item.error ?? item.responseCode ?? 'Unknown'}</td>
                      <td>
                        {item.authenticatedData === undefined
                          ? 'Unknown'
                          : item.authenticatedData
                            ? 'Set'
                            : 'Clear'}
                      </td>
                      <td>
                        {item.extendedErrors?.length
                          ? item.extendedErrors
                              .map((value) => `EDE ${String(value.code)} ${value.name}`)
                              .join('; ')
                          : 'None'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </article>
          <details className="method-note">
            <summary>Validation method and boundaries</summary>
            <p>
              ZoneSkein retrieves DNSSEC material with checking disabled, matches the root
              DNSKEY against the bundled IANA anchors, verifies that DNSKEY RRset locally, then
              validates each parent DS signature, DS digest, and child DNSKEY signature in turn.
              SHA-1, SHA-256, and SHA-384 DS digests are supported. Exact NSEC and bounded NSEC3
              proofs distinguish exact authenticated insecure delegations from missing evidence.
              NSEC3 Opt-Out is reported separately because it cannot authenticate whether the
              covered delegation exists. When an application type is selected, the exact
              positive RRset is canonicalised and verified with the authenticated
              containing-zone keys. Authenticated NSEC or NSEC3 proof sets can establish
              application NODATA, NXDOMAIN, wildcard synthesis, or wildcard NODATA. For other
              requested types, signed CNAME, DNAME, and SVCB or HTTPS AliasMode transitions are
              followed within the shared run bounds until the final answer authenticates.
            </p>
            <p>
              Secure means that this exact root-to-name chain validated at the captured time. It
              does not prove service safety or establish that every recursive resolver sees the
              same data. A result remains incomplete unless every required denial or alias link
              authenticates at the same common validation instant. Locally validated,
              Incomplete, Insecure delegation, Opt-Out, DNAME boundary, Not a delegation, Bogus,
              and Unsupported outcomes remain distinct.
            </p>
          </details>
        </section>
      )}
    </div>
  );
}
