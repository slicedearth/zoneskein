import { useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import {
  MAX_DKIM_MESSAGE_BYTES,
  parseDkimMessage,
  verifyParsedDkimMessage,
} from '../core/dkim/message-verifier';
import { bindDkimKeyAnswer } from '../core/dkim/key-answer';
import { inspectDkimKey, parseDkimKeyRecord, validateDkimSelector } from '../core/dkim/parser';
import type {
  DkimKeyInspection,
  DkimKeyRecord,
  DkimMessage,
  DkimSignatureVerification,
} from '../core/dkim/types';
import { validateDnsName } from '../core/dns/names';
import { queryPolicyRecords } from '../core/dns/policy-query';
import type { ResolverId } from '../core/dns/types';
import { DnsQueryRun } from '../core/doh/query-run';
import { RESOLVERS } from '../core/doh/resolvers';
import { WireDnsResolver } from '../core/doh/wire-resolver';
import {
  encodeMailAuthenticationEvidence,
  evidenceFromDkim,
  type MailAuthenticationEvidence,
} from '../core/mail/evidence';

const RESOLVER_IDS = Object.keys(RESOLVERS) as ResolverId[];
type DkimMode = 'key' | 'message';

interface DkimReport {
  readonly inspection?: DkimKeyInspection;
  readonly key?: DkimKeyRecord;
  readonly name: string;
  readonly responseCode: string;
  readonly ttl?: number;
}

interface DkimMessageReport {
  readonly capturedAt: string;
  readonly dnsQuestions: number;
  readonly inputLabel: string;
  readonly inputKind: 'pasted-text' | 'uploaded-eml';
  readonly lineEndingsNormalised: boolean;
  readonly resolverId: ResolverId;
  readonly results: readonly DkimSignatureVerification[];
  readonly sourceOctets: number;
}

function verificationTone(result: DkimSignatureVerification) {
  if (result.status === 'pass') return result.keyTesting === true ? 'warning' : 'pass';
  const { status } = result;
  if (status === 'temperror' || status === 'unsupported') return 'warning';
  return 'error';
}

function overallMessageStatus(
  results: readonly DkimSignatureVerification[],
  lineEndingsNormalised: boolean,
): {
  readonly label: string;
  readonly tone: 'pass' | 'warning' | 'error' | 'unknown';
} {
  if (results.some((result) => result.status === 'pass' && result.keyTesting !== true))
    return lineEndingsNormalised
      ? { label: 'Pass after CRLF reconstruction', tone: 'warning' }
      : { label: 'At least one signature passes', tone: 'pass' };
  if (results.some((result) => result.status === 'pass' && result.keyTesting === true))
    return { label: 'Testing-key result only', tone: 'unknown' };
  if (results.length === 0) return { label: 'No DKIM signature', tone: 'unknown' };
  if (
    results.some((result) => result.status === 'temperror' || result.status === 'unsupported')
  )
    return { label: 'Verification incomplete', tone: 'warning' };
  return { label: 'No passing signature', tone: 'error' };
}

function resultLabel(result: DkimSignatureVerification): string {
  if (result.status === 'pass' && result.keyTesting === true) return 'pass · testing key';
  return result.status;
}

function timestamp(value: number | undefined): string {
  return value === undefined ? 'Not supplied' : new Date(value * 1000).toLocaleString();
}

function evidenceResult(result: DkimSignatureVerification): Record<string, unknown> {
  const { identity, ...safe } = result;
  if (identity === undefined) return safe;
  const separator = identity.lastIndexOf('@');
  return {
    ...safe,
    identity: separator < 0 ? 'redacted' : `redacted@${identity.slice(separator + 1)}`,
  };
}

function MessageVerificationResults({
  onUseForDmarc,
  report,
}: {
  readonly onUseForDmarc?: (evidence: MailAuthenticationEvidence) => void;
  readonly report: DkimMessageReport;
}) {
  const overall = overallMessageStatus(report.results, report.lineEndingsNormalised);
  const dmarcEvidence = evidenceFromDkim(
    report.results,
    report.capturedAt,
    report.resolverId,
    report.lineEndingsNormalised,
  );
  const evidence = JSON.stringify(
    {
      capturedAt: report.capturedAt,
      dnsQuestions: report.dnsQuestions,
      evidenceSchema: 'zoneskein-dkim-message-v1',
      inputKind: report.inputKind,
      lineEndingsNormalised: report.lineEndingsNormalised,
      resolver: {
        id: report.resolverId,
        label: RESOLVERS[report.resolverId].label,
      },
      results: report.results.map(evidenceResult),
      sourceOctets: report.sourceOctets,
    },
    null,
    2,
  );
  return (
    <section className="results" aria-labelledby="dkim-message-result-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Message verification</p>
          <h2 id="dkim-message-result-title">{overall.label}</h2>
        </div>
        <div className="export-actions">
          <StatusBadge tone={overall.tone}>{overall.label}</StatusBadge>
          <CopyButton label="Copy verification JSON" text={evidence} />
          {dmarcEvidence === null ? null : (
            <>
              <CopyButton
                label="Copy DMARC hand-off JSON"
                text={encodeMailAuthenticationEvidence(dmarcEvidence)}
              />
              {onUseForDmarc === undefined ? null : (
                <button
                  className="quiet-button"
                  type="button"
                  onClick={() => onUseForDmarc(dmarcEvidence)}
                >
                  Use passing domains in DMARC
                </button>
              )}
            </>
          )}
        </div>
      </div>
      <article className="result-panel">
        <dl className="metadata-grid">
          <div>
            <dt>Input</dt>
            <dd>{report.inputLabel}</dd>
          </div>
          <div>
            <dt>Original size</dt>
            <dd>{report.sourceOctets.toLocaleString()} octets</dd>
          </div>
          <div>
            <dt>DNS questions</dt>
            <dd>{report.dnsQuestions}</dd>
          </div>
          <div>
            <dt>Resolver</dt>
            <dd>{RESOLVERS[report.resolverId].label}</dd>
          </div>
          <div>
            <dt>Validated at</dt>
            <dd>{new Date(report.capturedAt).toLocaleString()}</dd>
          </div>
        </dl>
        {report.lineEndingsNormalised ? (
          <p className="snapshot-warning">
            The input did not use network CRLF line endings throughout. ZoneSkein reconstructed
            CRLF before canonicalisation, so treat the result as reconstructed-text evidence
            rather than an exact wire-octet verification.
          </p>
        ) : null}
      </article>
      {report.results.length === 0 ? (
        <article className="conclusion-panel">
          <StatusBadge tone="unknown">Unsigned</StatusBadge>
          <p>No DKIM-Signature header field was present in the bounded message.</p>
        </article>
      ) : (
        <div className="policy-list">
          {report.results.map((result, index) => (
            <article className="result-panel" key={`${result.keyName}-${String(index)}`}>
              <div className="result-heading">
                <div>
                  <p className="eyebrow">Signature {String(index + 1)}</p>
                  <h3>{result.domain}</h3>
                </div>
                <StatusBadge tone={verificationTone(result)}>{resultLabel(result)}</StatusBadge>
              </div>
              <p>{result.reason}</p>
              {result.length === undefined ? null : (
                <p className="snapshot-warning">
                  This signature uses l={result.length}, so content after the signed body prefix
                  is not authenticated by this signature.
                </p>
              )}
              <dl className="metadata-grid">
                <div>
                  <dt>Selector</dt>
                  <dd>{result.selector}</dd>
                </div>
                <div>
                  <dt>Algorithm</dt>
                  <dd>{result.algorithm}</dd>
                </div>
                <div>
                  <dt>Canonicalisation</dt>
                  <dd>
                    {result.headerCanonicalisation}/{result.bodyCanonicalisation}
                  </dd>
                </div>
                <div>
                  <dt>Body hash</dt>
                  <dd>{result.bodyHashMatches ? 'Matches' : 'Does not match'}</dd>
                </div>
                <div>
                  <dt>Canonical body</dt>
                  <dd>{result.canonicalBodyOctets.toLocaleString()} octets</dd>
                </div>
                <div>
                  <dt>Key</dt>
                  <dd>
                    {result.keyBits === undefined
                      ? 'Size unknown'
                      : `${String(result.keyBits)} bits`}
                    {result.keyTesting === true ? ' · testing mode' : ''}
                  </dd>
                </div>
                <div>
                  <dt>Signed at</dt>
                  <dd>{timestamp(result.signedAt)}</dd>
                </div>
                <div>
                  <dt>Expires</dt>
                  <dd>{timestamp(result.expiresAt)}</dd>
                </div>
              </dl>
              <details className="method-note">
                <summary>Signed header sequence ({result.signedHeaders.length})</summary>
                <p>
                  <code>{result.signedHeaders.join(' → ')}</code>
                </p>
                <p>
                  Key question: <code>{result.keyName}</code>
                </p>
              </details>
            </article>
          ))}
        </div>
      )}
      <p className="detail-note">
        A passing signature authenticates the signed content for its signing domain. It does not
        by itself establish DMARC alignment, sender reputation, or delivery acceptance.
        {report.results.some((result) => result.keyTesting === true)
          ? ' A testing-mode key is reported as diagnostic evidence only and is not equivalent to deployed authentication.'
          : ''}
        {dmarcEvidence === null
          ? ''
          : ' The DMARC hand-off contains only unique passing production signing domains, capture time, reconstruction status, and resolver identifier; it excludes the raw message, file name, selectors, identities, and content.'}
      </p>
    </section>
  );
}

export interface DkimPageProps {
  readonly onUseForDmarc?: (evidence: MailAuthenticationEvidence) => void;
}

export function DkimPage({ onUseForDmarc }: DkimPageProps = {}) {
  const [mode, setMode] = useState<DkimMode>('key');
  const [domain, setDomain] = useState('');
  const [selector, setSelector] = useState('');
  const [rawMessage, setRawMessage] = useState('');
  const [messageBytes, setMessageBytes] = useState<Uint8Array | null>(null);
  const [messageFileName, setMessageFileName] = useState('');
  const [resolverId, setResolverId] = useState<ResolverId>('google');
  const [state, setState] = useState<'idle' | 'loading' | 'complete' | 'cancelled'>('idle');
  const [error, setError] = useState('');
  const [report, setReport] = useState<DkimReport | null>(null);
  const [messageReport, setMessageReport] = useState<DkimMessageReport | null>(null);
  const activeRun = useRef<DnsQueryRun | null>(null);
  const messageFileInput = useRef<HTMLInputElement | null>(null);
  const messageFileRead = useRef(0);

  function invalidateRun() {
    activeRun.current?.cancel();
    activeRun.current = null;
    setError('');
    setReport(null);
    setMessageReport(null);
    setState('idle');
  }

  function cancelRun() {
    activeRun.current?.cancel();
    activeRun.current = null;
    setState('cancelled');
  }

  async function inspect(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    if (mode === 'message') {
      const source = messageBytes ?? rawMessage;
      const inputKind = messageBytes === null ? 'pasted-text' : 'uploaded-eml';
      const inputLabel = messageBytes === null ? 'Pasted UTF-8 text' : messageFileName;
      if (source.length === 0) {
        setError('Paste a complete message or choose a bounded .eml file.');
        return;
      }
      let message: DkimMessage;
      try {
        message = parseDkimMessage(source);
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : 'The message could not be parsed.');
        return;
      }
      activeRun.current?.cancel();
      const run = new DnsQueryRun();
      activeRun.current = run;
      setError('');
      setReport(null);
      setMessageReport(null);
      setState('loading');
      const selectedResolverId = resolverId;
      const resolver = new WireDnsResolver(RESOLVERS[selectedResolverId]);
      const capturedAt = new Date();
      try {
        const results = await verifyParsedDkimMessage(
          message,
          async (name) => {
            const result = await queryPolicyRecords(resolver, run, name, 'TXT');
            const responseFailure =
              result.responseCode === 'NOERROR' || result.responseCode === 'NXDOMAIN'
                ? undefined
                : `Resolver returned ${result.responseCode}.`;
            const bound =
              result.responseCode === 'NOERROR'
                ? bindDkimKeyAnswer(result.answers, name)
                : { values: [] };
            const queryError = result.error ?? responseFailure ?? bound.error;
            return {
              ...(queryError === undefined ? {} : { error: queryError }),
              records: queryError === undefined ? bound.values : [],
              temporary: result.error !== undefined || responseFailure !== undefined,
            };
          },
          capturedAt,
          run.signal,
        );
        if (activeRun.current !== run) return;
        if (run.cancelled) {
          setState('cancelled');
          return;
        }
        setMessageReport({
          capturedAt: capturedAt.toISOString(),
          dnsQuestions: run.questionsUsed,
          inputLabel,
          inputKind,
          lineEndingsNormalised: message.lineEndingsNormalised,
          resolverId: selectedResolverId,
          results,
          sourceOctets: message.sourceOctets,
        });
        setState('complete');
      } catch (cause) {
        if (activeRun.current !== run) return;
        if (run.cancelled) setState('cancelled');
        else {
          setError(cause instanceof Error ? cause.message : 'DKIM verification failed.');
          setState('idle');
        }
      }
      return;
    }
    const parsed = validateDnsName(domain);
    const selectorError = validateDkimSelector(selector);
    if (!parsed.ok || selectorError !== null) {
      setError(parsed.ok ? (selectorError ?? 'Invalid selector.') : parsed.error.message);
      return;
    }
    const name = `${selector.trim()}._domainkey.${parsed.value.ascii}`;
    const parsedName = validateDnsName(name);
    if (!parsedName.ok) {
      setError(`The complete DKIM selector name is invalid: ${parsedName.error.message}`);
      return;
    }
    activeRun.current?.cancel();
    const run = new DnsQueryRun();
    activeRun.current = run;
    setError('');
    setReport(null);
    setMessageReport(null);
    setState('loading');
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
    const responseFailure =
      result.responseCode === 'NOERROR' || result.responseCode === 'NXDOMAIN'
        ? undefined
        : `Resolver returned ${result.responseCode}.`;
    const bound =
      result.responseCode === 'NOERROR'
        ? bindDkimKeyAnswer(result.answers, name)
        : { values: [] };
    const queryError = result.error ?? responseFailure ?? bound.error;
    if (queryError !== undefined) {
      setError(queryError);
      setState('idle');
      return;
    }
    if (bound.values.length > 1) {
      setError(`${name} returned multiple TXT values; the DKIM key record is ambiguous.`);
      setState('idle');
      return;
    }
    const record = bound.values[0];
    if (record === undefined) {
      setReport({
        name,
        responseCode: result.responseCode,
        ...(bound.ttl === undefined ? {} : { ttl: bound.ttl }),
      });
    } else {
      const key = parseDkimKeyRecord(record);
      const inspection = await inspectDkimKey(key);
      if (activeRun.current !== run) return;
      setReport({
        inspection,
        key,
        name,
        responseCode: result.responseCode,
        ...(bound.ttl === undefined ? {} : { ttl: bound.ttl }),
      });
    }
    setState('complete');
  }

  async function loadMessageFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0];
    if (file === undefined) return;
    const read = ++messageFileRead.current;
    invalidateRun();
    setRawMessage('');
    setMessageBytes(null);
    setMessageFileName('');
    if (file.size > MAX_DKIM_MESSAGE_BYTES) {
      setError(
        `Message file exceeds the ${MAX_DKIM_MESSAGE_BYTES.toLocaleString()}-byte safety limit.`,
      );
      event.currentTarget.value = '';
      return;
    }
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (messageFileRead.current !== read) return;
      setMessageBytes(bytes);
      setMessageFileName(file.name);
      setRawMessage(new TextDecoder().decode(bytes));
      setError('');
      setMessageReport(null);
    } catch {
      if (messageFileRead.current !== read) return;
      setError('The selected message file could not be read.');
    }
  }

  function clear() {
    messageFileRead.current += 1;
    invalidateRun();
    setDomain('');
    setSelector('');
    setRawMessage('');
    setMessageBytes(null);
    setMessageFileName('');
    if (messageFileInput.current !== null) messageFileInput.current.value = '';
  }

  function selectMode(next: DkimMode) {
    messageFileRead.current += 1;
    invalidateRun();
    setMode(next);
  }

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="DKIM key inspector" title="Inspect the selector you intend to use.">
        Inspect a published selector or verify every bounded DKIM signature in a pasted message
        or byte-preserving .eml file. Canonicalisation and signature checks run locally through
        Web Crypto; only selector DNS questions leave the browser.
      </ToolIntro>
      <div className="mode-switch" aria-label="DKIM mode">
        <button aria-pressed={mode === 'key'} type="button" onClick={() => selectMode('key')}>
          Key inspector
        </button>
        <button
          aria-pressed={mode === 'message'}
          type="button"
          onClick={() => selectMode('message')}
        >
          Message verifier
        </button>
      </div>
      {mode === 'message' ? (
        <p className="detail-note" id="dkim-message-privacy-note">
          Use a real message only when you are authorised to process its contents. Raw message
          bytes stay in this tab, but derived selector and signing-domain DNS questions are sent
          to the selected resolver.
        </p>
      ) : null}
      <form
        className="workbench-form"
        aria-label="DKIM inputs"
        aria-describedby={mode === 'message' ? 'dkim-message-privacy-note' : undefined}
        onSubmit={(event) => void inspect(event)}
      >
        {mode === 'key' ? (
          <>
            <div className="field-group">
              <label htmlFor="dkim-domain">Signing domain</label>
              <input
                key="dkim-key-domain"
                id="dkim-domain"
                value={domain}
                onChange={(event) => {
                  invalidateRun();
                  setDomain(event.currentTarget.value);
                }}
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
                onChange={(event) => {
                  invalidateRun();
                  setSelector(event.currentTarget.value);
                }}
                placeholder="selector-2026"
                maxLength={253}
                spellCheck={false}
              />
            </div>
          </>
        ) : (
          <>
            <div className="field-group field-wide">
              <label htmlFor="dkim-message-file">Raw message file (optional)</label>
              <input
                key="dkim-message-file"
                id="dkim-message-file"
                ref={messageFileInput}
                type="file"
                accept=".eml,message/rfc822,text/plain"
                onChange={(event) => void loadMessageFile(event)}
              />
              <small>
                Files are read locally and retain their original octets. Maximum{' '}
                {MAX_DKIM_MESSAGE_BYTES.toLocaleString()} bytes.
              </small>
            </div>
            <div className="field-group field-wide">
              <label htmlFor="dkim-raw-message">Raw RFC 5322 message</label>
              <textarea
                id="dkim-raw-message"
                value={rawMessage}
                onChange={(event) => {
                  messageFileRead.current += 1;
                  invalidateRun();
                  setRawMessage(event.currentTarget.value);
                  setMessageBytes(null);
                  setMessageFileName('');
                  if (messageFileInput.current !== null) messageFileInput.current.value = '';
                }}
                placeholder={'DKIM-Signature: …\nFrom: sender@example.com\n\nMessage body'}
                rows={18}
                maxLength={MAX_DKIM_MESSAGE_BYTES}
                spellCheck={false}
              />
              <small>
                Editing an uploaded preview switches verification to its UTF-8 text. Raw message
                content is held in memory only and is never saved or placed in a share link.
              </small>
            </div>
          </>
        )}
        <div className="field-group">
          <label htmlFor="dkim-resolver">Resolver</label>
          <select
            id="dkim-resolver"
            aria-describedby={
              RESOLVERS[resolverId].selectionNote === undefined
                ? undefined
                : 'dkim-resolver-note'
            }
            value={resolverId}
            onChange={(event) => {
              invalidateRun();
              setResolverId(event.currentTarget.value as ResolverId);
            }}
          >
            {RESOLVER_IDS.map((id) => (
              <option value={id} key={id}>
                {RESOLVERS[id].label}
              </option>
            ))}
          </select>
          {RESOLVERS[resolverId].selectionNote === undefined ? null : (
            <small id="dkim-resolver-note">{RESOLVERS[resolverId].selectionNote}</small>
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
              ? mode === 'key'
                ? 'Inspecting…'
                : 'Verifying…'
              : mode === 'key'
                ? 'Inspect DKIM key'
                : 'Verify message signatures'}
          </button>
          {state === 'loading' ? (
            <button className="quiet-button" type="button" onClick={cancelRun}>
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
        aria-label="DKIM run status"
        aria-live="polite"
        aria-atomic="true"
      >
        {state === 'loading'
          ? mode === 'message'
            ? 'DKIM signatures are being checked locally while required selector keys are resolved.'
            : 'The DKIM selector key is being resolved and inspected.'
          : null}
        {state === 'cancelled' ? 'The DKIM verification run was cancelled.' : null}
        {state === 'complete' && messageReport !== null
          ? `DKIM message verification complete: ${overallMessageStatus(messageReport.results, messageReport.lineEndingsNormalised).label}.`
          : null}
        {state === 'complete' && report !== null
          ? `DKIM key inspection complete: ${report.inspection?.status ?? 'no key observed'}.`
          : null}
      </div>
      {messageReport === null ? null : (
        <MessageVerificationResults
          {...(onUseForDmarc === undefined ? {} : { onUseForDmarc })}
          report={messageReport}
        />
      )}
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
              that headers and body canonicalise correctly, or that a receiver accepts the
              signature. Inspect an actual message to verify those properties.
            </p>
          </details>
        </section>
      )}
    </div>
  );
}
