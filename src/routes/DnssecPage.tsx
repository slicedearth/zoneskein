import { useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { SnapshotButton } from '../components/SnapshotButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { validateDnsName } from '../core/dns/names';
import {
  DnsQueryError,
  type DnsRecordType,
  type DnsResponse,
  type ResolverId,
} from '../core/dns/types';
import { classifyDnssecEvidence, type DnssecConclusion } from '../core/dnssec/classify';
import { compareDsToDnskeys, hex } from '../core/dnssec/digest';
import {
  digestTypeName,
  dnssecAlgorithmName,
  parseDnskey,
  parseDs,
  parseRrsig,
} from '../core/dnssec/records';
import type {
  DnskeyInfo,
  DsInfo,
  DsMatch,
  RrsigInfo,
  SignatureVerification,
} from '../core/dnssec/types';
import { verifyDnskeyRrset } from '../core/dnssec/verify';
import { DnsQueryRun } from '../core/doh/query-run';
import { RESOLVERS } from '../core/doh/resolvers';
import { WireDnsResolver } from '../core/doh/wire-resolver';

const RESOLVER_IDS = Object.keys(RESOLVERS) as ResolverId[];

interface QueryOutcome {
  readonly error?: DnsQueryError;
  readonly response?: DnsResponse;
}

interface DnssecReport {
  readonly checkingDnskey: QueryOutcome;
  readonly checkingDs: QueryOutcome;
  readonly conclusion: DnssecConclusion;
  readonly dnskeys: readonly DnskeyInfo[];
  readonly ds: readonly DsInfo[];
  readonly matches: readonly DsMatch[];
  readonly signatures: readonly RrsigInfo[];
  readonly verifications: readonly SignatureVerification[];
  readonly validatingDnskey: QueryOutcome;
  readonly validatingDs: QueryOutcome;
  readonly zone: string;
}

function asError(cause: unknown): DnsQueryError {
  return cause instanceof DnsQueryError
    ? cause
    : new DnsQueryError(
        'transport-error',
        cause instanceof Error ? cause.message : 'The DNSSEC query failed.',
      );
}

function responseSummary(outcome: QueryOutcome): string {
  if (outcome.error !== undefined) return `${outcome.error.code}: ${outcome.error.message}`;
  if (outcome.response === undefined) return 'No response';
  const message = outcome.response.message;
  return `${message.responseCode}; AD=${message.flags.authenticatedData ? 'set' : 'clear'}; ${String(message.messageBytes)} bytes`;
}

function reportJson(report: DnssecReport): string {
  return JSON.stringify(
    {
      checkingDisabled: {
        dnskey: responseSummary(report.checkingDnskey),
        ds: responseSummary(report.checkingDs),
      },
      conclusion: report.conclusion,
      dnskeys: report.dnskeys.map((key) => ({
        algorithm: key.algorithm,
        flags: key.flags,
        keyTag: key.keyTag,
        protocol: key.protocol,
      })),
      ds: report.ds.map((record) => ({
        algorithm: record.algorithm,
        digest: hex(record.digest),
        digestType: record.digestType,
        keyTag: record.keyTag,
      })),
      matches: report.matches.map((match) => ({
        digestType: match.digestType,
        keyTag: match.dnskey.keyTag,
        matches: match.matches,
      })),
      signatures: report.signatures.map((signature) => ({
        algorithm: signature.algorithm,
        expiration: new Date(signature.expiration * 1000).toISOString(),
        inception: new Date(signature.inception * 1000).toISOString(),
        keyTag: signature.keyTag,
        timeState: signature.timeState,
        typeCovered: signature.typeCovered,
      })),
      validating: {
        dnskey: responseSummary(report.validatingDnskey),
        ds: responseSummary(report.validatingDs),
      },
      verifications: report.verifications,
      zone: report.zone,
    },
    null,
    2,
  );
}

function QueryComparison({ report }: { readonly report: DnssecReport }) {
  return (
    <div className="comparison-grid">
      <article>
        <p className="step-label">Checking enabled</p>
        <h3>Resolver validation path</h3>
        <dl className="compact-list">
          <div>
            <dt>DNSKEY</dt>
            <dd>{responseSummary(report.validatingDnskey)}</dd>
          </div>
          <div>
            <dt>DS</dt>
            <dd>{responseSummary(report.validatingDs)}</dd>
          </div>
        </dl>
      </article>
      <article>
        <p className="step-label">Checking disabled</p>
        <h3>Diagnostic retrieval path</h3>
        <dl className="compact-list">
          <div>
            <dt>DNSKEY</dt>
            <dd>{responseSummary(report.checkingDnskey)}</dd>
          </div>
          <div>
            <dt>DS</dt>
            <dd>{responseSummary(report.checkingDs)}</dd>
          </div>
        </dl>
      </article>
    </div>
  );
}

function EvidenceChain({ report }: { readonly report: DnssecReport }) {
  const anyMatch = report.matches.some((match) => match.matches);
  const localSignature = report.verifications.some(
    (verification) => verification.status === 'verified',
  );
  return (
    <div className="evidence-chain" aria-label="DNSSEC evidence chain">
      <article>
        <span className="chain-index">1</span>
        <p className="step-label">Parent evidence</p>
        <h3>
          {report.ds.length} DS record{report.ds.length === 1 ? '' : 's'}
        </h3>
        <StatusBadge tone={report.ds.length > 0 ? 'information' : 'unknown'}>
          {report.ds.length > 0 ? 'Published' : 'Not returned'}
        </StatusBadge>
      </article>
      <span className="chain-join" aria-hidden="true">
        →
      </span>
      <article>
        <span className="chain-index">2</span>
        <p className="step-label">Digest calculation</p>
        <h3>
          {report.dnskeys.length} child DNSKEY{report.dnskeys.length === 1 ? '' : 's'}
        </h3>
        <StatusBadge tone={anyMatch ? 'pass' : 'unknown'}>
          {anyMatch ? 'DS match' : 'No supported match'}
        </StatusBadge>
      </article>
      <span className="chain-join" aria-hidden="true">
        →
      </span>
      <article>
        <span className="chain-index">3</span>
        <p className="step-label">Local cryptography</p>
        <h3>DNSKEY RRset signature</h3>
        <StatusBadge tone={localSignature ? 'pass' : 'unknown'}>
          {localSignature ? 'Verified locally' : 'Not locally verified'}
        </StatusBadge>
      </article>
    </div>
  );
}

export function DnssecPage() {
  const [input, setInput] = useState('');
  const [resolverId, setResolverId] = useState<ResolverId>('google');
  const [state, setState] = useState<'idle' | 'loading' | 'complete' | 'error' | 'cancelled'>(
    'idle',
  );
  const [error, setError] = useState('');
  const [report, setReport] = useState<DnssecReport | null>(null);
  const activeRun = useRef<DnsQueryRun | null>(null);

  async function submit(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const parsed = validateDnsName(input);
    if (!parsed.ok) {
      setError(parsed.error.message);
      return;
    }
    setError('');
    setReport(null);
    activeRun.current?.cancel();
    const run = new DnsQueryRun();
    activeRun.current = run;
    setState('loading');
    const resolver = new WireDnsResolver(RESOLVERS[resolverId]);
    const query = async (
      type: DnsRecordType,
      checkingDisabled: boolean,
    ): Promise<QueryOutcome> => {
      try {
        return {
          response: await run.query(
            resolver,
            { name: parsed.value, type },
            { checkingDisabled, dnssecOk: true },
          ),
        };
      } catch (cause) {
        return { error: asError(cause) };
      }
    };
    const [validatingDnskey, checkingDnskey, validatingDs, checkingDs] = await Promise.all([
      query('DNSKEY', false),
      query('DNSKEY', true),
      query('DS', false),
      query('DS', true),
    ]);
    if (activeRun.current !== run) return;
    const cancelled = [validatingDnskey, checkingDnskey, validatingDs, checkingDs].every(
      (outcome) => outcome.error?.code === 'aborted',
    );
    if (cancelled) {
      setState('cancelled');
      return;
    }

    const keyResponse = checkingDnskey.response ?? validatingDnskey.response;
    const dsResponse = checkingDs.response ?? validatingDs.response;
    const keyRecords = keyResponse?.message.answers ?? [];
    const dnskeys = keyRecords.flatMap((record) => {
      const key = parseDnskey(record);
      return key === null ? [] : [key];
    });
    const ds = (dsResponse?.message.answers ?? []).flatMap((record) => {
      const value = parseDs(record);
      return value === null ? [] : [value];
    });
    const signatures = keyRecords.flatMap((record) => {
      const signature = parseRrsig(record);
      return signature === null ? [] : [signature];
    });
    const matches = await compareDsToDnskeys(parsed.value.absolute, ds, dnskeys);
    const verifications = await verifyDnskeyRrset(keyRecords);
    const conclusion = classifyDnssecEvidence({
      ...(checkingDnskey.response === undefined
        ? {}
        : { checkingDnskey: checkingDnskey.response }),
      dsMatches: matches,
      publishedDsCount: ds.length,
      signatures: verifications,
      ...(validatingDnskey.response === undefined
        ? {}
        : { validatingDnskey: validatingDnskey.response }),
      ...(validatingDs.response === undefined ? {} : { validatingDs: validatingDs.response }),
    });
    setReport({
      checkingDnskey,
      checkingDs,
      conclusion,
      dnskeys,
      ds,
      matches,
      signatures,
      validatingDnskey,
      validatingDs,
      verifications,
      zone: parsed.value.absolute,
    });
    setState('complete');
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
        eyebrow="DNSSEC chain inspector"
        title="Follow the evidence, not a green light."
      >
        Compare validating and checking-disabled answers, calculate DS candidates locally, and
        verify returned DNSKEY RRset signatures when the browser supports their algorithm.
      </ToolIntro>
      <form className="workbench-form" onSubmit={(event) => void submit(event)}>
        <div className="field-group field-wide">
          <label htmlFor="dnssec-zone">Zone name</label>
          <input
            id="dnssec-zone"
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
          <label htmlFor="dnssec-resolver">Resolver</label>
          <select
            id="dnssec-resolver"
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
            {state === 'loading' ? 'Inspecting…' : 'Inspect DNSSEC'}
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
        {state === 'loading' ? 'Four bounded DNSSEC evidence questions are in progress.' : null}
        {state === 'cancelled' ? 'The DNSSEC run was cancelled.' : null}
        {state === 'error' ? 'DNSSEC inspection could not complete.' : null}
      </div>

      {report !== null ? (
        <section className="results" aria-labelledby="dnssec-result-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Conservative conclusion</p>
              <h2 id="dnssec-result-title">{report.zone}</h2>
            </div>
            <div className="export-actions">
              <CopyButton label="Copy evidence JSON" text={reportJson(report)} />
              <SnapshotButton
                content={reportJson(report)}
                title={`DNSSEC evidence — ${report.zone}`}
                tool="dnssec"
              />
            </div>
          </div>
          <article className="conclusion-panel">
            <StatusBadge tone={report.conclusion.tone}>{report.conclusion.label}</StatusBadge>
            <p>{report.conclusion.explanation}</p>
          </article>
          <EvidenceChain report={report} />
          <QueryComparison report={report} />

          <div className="comparison-grid">
            <article className="result-panel">
              <h3>Child DNSKEY records</h3>
              {report.dnskeys.length === 0 ? (
                <p className="empty-note">No DNSKEY data returned.</p>
              ) : (
                <div className="table-scroll">
                  <table>
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
                      {report.dnskeys.map((key) => (
                        <tr key={`${String(key.keyTag)}-${String(key.algorithm)}`}>
                          <td>{key.keyTag}</td>
                          <td>{key.flags}</td>
                          <td>{key.protocol}</td>
                          <td>
                            {dnssecAlgorithmName(key.algorithm)} ({key.algorithm})
                          </td>
                          <td>
                            {key.revoked
                              ? 'Revoked'
                              : key.secureEntryPoint
                                ? 'SEP / zone key'
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
            </article>
            <article className="result-panel">
              <h3>Published parent DS records</h3>
              {report.ds.length === 0 ? (
                <p className="empty-note">No DS data returned.</p>
              ) : (
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Key tag</th>
                        <th>Algorithm</th>
                        <th>Digest</th>
                        <th>Local comparison</th>
                      </tr>
                    </thead>
                    <tbody>
                      {report.ds.map((ds) => {
                        const match = report.matches.find(
                          (item) => item.ds === ds && item.matches,
                        );
                        return (
                          <tr
                            key={`${String(ds.keyTag)}-${String(ds.digestType)}-${hex(ds.digest)}`}
                          >
                            <td>{ds.keyTag}</td>
                            <td>{dnssecAlgorithmName(ds.algorithm)}</td>
                            <td>
                              <code className="record-value">
                                {digestTypeName(ds.digestType)} · {hex(ds.digest)}
                              </code>
                            </td>
                            <td>
                              {ds.digestType === 2 || ds.digestType === 4
                                ? match === undefined
                                  ? 'No match'
                                  : 'Matches DNSKEY'
                                : 'Unsupported digest'}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </article>
          </div>

          <article className="result-panel">
            <h3>DNSKEY signature checks</h3>
            {report.signatures.length === 0 ? (
              <p className="empty-note">No DNSKEY-covering RRSIG was returned.</p>
            ) : (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Covered</th>
                      <th>Key tag</th>
                      <th>Algorithm</th>
                      <th>Inception</th>
                      <th>Expiration</th>
                      <th>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.signatures.map((signature, index) => (
                      <tr key={`${String(signature.keyTag)}-${String(index)}`}>
                        <td>{signature.typeCovered}</td>
                        <td>{signature.keyTag}</td>
                        <td>{dnssecAlgorithmName(signature.algorithm)}</td>
                        <td>{new Date(signature.inception * 1000).toLocaleString()}</td>
                        <td>{new Date(signature.expiration * 1000).toLocaleString()}</td>
                        <td>{signature.timeState}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {report.verifications.map((verification, index) => (
              <p key={`${String(verification.keyTag)}-${String(index)}`}>
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
                </StatusBadge>{' '}
                {verification.message}
              </p>
            ))}
          </article>

          <details className="method-note">
            <summary>How this conclusion was reached</summary>
            <p>
              ZoneSkein sent wire-format DNSKEY and DS questions with DNSSEC requested, once
              with resolver checking enabled and once with checking disabled. SHA-256 and
              SHA-384 DS digests were calculated locally. DNSKEY RRset signatures use Web Crypto
              for RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256, ECDSA P-384, and Ed25519
              where available.
            </p>
            <p>
              The parent DS answer is not independently chained to a bundled root trust anchor.
              A local DS match and DNSKEY signature therefore strengthen the evidence but do not
              replace a complete validating resolver or prove every RRset in the zone.
            </p>
          </details>
        </section>
      ) : null}
    </div>
  );
}
