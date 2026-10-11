import { useEffect, useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { inspectArcChain, type ArcChainReport } from '../core/mail/arc';
import {
  inspectBimiSvg,
  parseBimiRecord,
  type BimiRecord,
  type BimiSvgReport,
} from '../core/mail/bimi';
import {
  inspectCertificate,
  verifyTlsaAssociation,
  type CertificateInspection,
} from '../core/mail/certificate';
import {
  parseDmarcAggregateXml,
  type DmarcAggregateReport,
} from '../core/mail/dmarc-aggregate';
import {
  authorMtaStsPolicy,
  mtaStsMxCoverage,
  parseMtaStsPolicy,
  type MtaStsPolicy,
} from '../core/mail/mta-sts';
import { MAIL_REPORT_ARCHIVE_LIMITS } from '../core/mail/report-archive';
import { extractMailReportPayloadsAsync } from '../core/mail/report-archive-client';
import { RequestLifetime } from '../core/request-lifetime';
import {
  parseTlsAggregateJson,
  parseTlsRptRecord,
  type TlsAggregateReport,
  type TlsRptRecord,
} from '../core/mail/tlsrpt';
import { stringifyTechnicalEvidence } from '../core/technical-text';

type Mode = 'reports' | 'transport' | 'certificate' | 'bimi' | 'arc';
type ParsedReport =
  | { readonly kind: 'dmarc'; readonly name: string; readonly report: DmarcAggregateReport }
  | { readonly kind: 'tls'; readonly name: string; readonly report: TlsAggregateReport };

interface CertificateResult {
  readonly inspection: CertificateInspection;
  readonly tlsa: { readonly matches: boolean; readonly reason: string } | null;
}

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (cause) {
    throw new Error('The report is not valid UTF-8 text.', { cause });
  }
}

function ReportsResults({ reports }: { readonly reports: readonly ParsedReport[] }) {
  const totals = reports.reduce(
    (sum, item) =>
      item.kind === 'dmarc'
        ? {
            dmarcMessages: sum.dmarcMessages + item.report.summary.total,
            tlsFailed: sum.tlsFailed,
            tlsSuccessful: sum.tlsSuccessful,
          }
        : {
            dmarcMessages: sum.dmarcMessages,
            tlsFailed: sum.tlsFailed + item.report.summary.failed,
            tlsSuccessful: sum.tlsSuccessful + item.report.summary.successful,
          },
    { dmarcMessages: 0, tlsFailed: 0, tlsSuccessful: 0 },
  );
  return (
    <section className="results" aria-labelledby="mail-report-results-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Local report bundle</p>
          <h2 id="mail-report-results-title">Delivery evidence</h2>
        </div>
        <div className="export-actions">
          <StatusBadge tone="pass">Parsed locally</StatusBadge>
          <CopyButton
            label="Copy report evidence JSON"
            text={stringifyTechnicalEvidence({ reports, totals }, 2)}
          />
        </div>
      </div>
      <dl className="metadata-grid">
        <div>
          <dt>Reports</dt>
          <dd>{reports.length}</dd>
        </div>
        <div>
          <dt>DMARC messages</dt>
          <dd>{totals.dmarcMessages.toLocaleString()}</dd>
        </div>
        <div>
          <dt>TLS sessions passed</dt>
          <dd>{totals.tlsSuccessful.toLocaleString()}</dd>
        </div>
        <div>
          <dt>TLS sessions failed</dt>
          <dd>{totals.tlsFailed.toLocaleString()}</dd>
        </div>
      </dl>
      <div className="result-list">
        {reports.map((item, index) =>
          item.kind === 'dmarc' ? (
            <article className="result-panel" key={`${item.name}-${String(index)}`}>
              <div className="result-heading">
                <h3>{item.name}</h3>
                <StatusBadge tone={item.report.errors.length === 0 ? 'pass' : 'warning'}>
                  DMARC aggregate
                </StatusBadge>
              </div>
              <dl className="metadata-grid">
                <div>
                  <dt>Reporter</dt>
                  <dd>{item.report.organisation || 'Unavailable'}</dd>
                </div>
                <div>
                  <dt>Report ID</dt>
                  <dd>{item.report.reportId || 'Unavailable'}</dd>
                </div>
                <div>
                  <dt>Policy domain</dt>
                  <dd>{item.report.domain || 'Unavailable'}</dd>
                </div>
                <div>
                  <dt>Messages</dt>
                  <dd>{item.report.summary.total.toLocaleString()}</dd>
                </div>
                <div>
                  <dt>DKIM or SPF aligned</dt>
                  <dd>{item.report.summary.aligned.toLocaleString()}</dd>
                </div>
                <div>
                  <dt>Rejected</dt>
                  <dd>{item.report.summary.rejected.toLocaleString()}</dd>
                </div>
              </dl>
              {item.report.errors.length === 0 ? null : (
                <ul className="diagnostic-list">
                  {item.report.errors.map((error) => (
                    <li key={error}>
                      <StatusBadge tone="warning">partial</StatusBadge>
                      <span>{error}</span>
                    </li>
                  ))}
                </ul>
              )}
              <details>
                <summary>Source groups ({item.report.records.length})</summary>
                <div
                  className="table-scroll"
                  tabIndex={0}
                  role="region"
                  aria-label={`DMARC source groups in ${item.name}`}
                >
                  <table>
                    <thead>
                      <tr>
                        <th>Source IP</th>
                        <th>Messages</th>
                        <th>From</th>
                        <th>DKIM</th>
                        <th>SPF</th>
                        <th>Disposition</th>
                      </tr>
                    </thead>
                    <tbody>
                      {item.report.records.slice(0, 1_000).map((row, rowIndex) => (
                        <tr key={`${row.sourceIp}-${String(rowIndex)}`}>
                          <td>
                            <bdi dir="ltr">{row.sourceIp}</bdi>
                          </td>
                          <td>{row.count}</td>
                          <td>{row.headerFrom}</td>
                          <td>{row.dkim}</td>
                          <td>{row.spf}</td>
                          <td>{row.disposition}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {item.report.records.length > 1_000 ? (
                  <p className="detail-note">
                    The interface shows the first 1,000 groups; the bounded export retains all{' '}
                    {item.report.records.length.toLocaleString()} parsed groups.
                  </p>
                ) : null}
              </details>
            </article>
          ) : (
            <article className="result-panel" key={`${item.name}-${String(index)}`}>
              <div className="result-heading">
                <h3>{item.name}</h3>
                <StatusBadge tone={item.report.summary.failed === 0 ? 'pass' : 'warning'}>
                  TLS aggregate
                </StatusBadge>
              </div>
              <dl className="metadata-grid">
                <div>
                  <dt>Reporter</dt>
                  <dd>{item.report.organisation || 'Unavailable'}</dd>
                </div>
                <div>
                  <dt>Report ID</dt>
                  <dd>{item.report.reportId || 'Unavailable'}</dd>
                </div>
                <div>
                  <dt>Successful sessions</dt>
                  <dd>{item.report.summary.successful.toLocaleString()}</dd>
                </div>
                <div>
                  <dt>Failed sessions</dt>
                  <dd>{item.report.summary.failed.toLocaleString()}</dd>
                </div>
              </dl>
              <div
                className="table-scroll"
                tabIndex={0}
                role="region"
                aria-label={`TLS policies in ${item.name}`}
              >
                <table>
                  <thead>
                    <tr>
                      <th>Policy domain</th>
                      <th>Type</th>
                      <th>Passed</th>
                      <th>Failed</th>
                      <th>Top failures</th>
                    </tr>
                  </thead>
                  <tbody>
                    {item.report.policies.slice(0, 1_000).map((policy, policyIndex) => (
                      <tr key={`${policy.domain}-${String(policyIndex)}`}>
                        <td>{policy.domain}</td>
                        <td>{policy.policyType}</td>
                        <td>{policy.successful}</td>
                        <td>{policy.failed}</td>
                        <td>
                          {policy.failures
                            .slice(0, 3)
                            .map(
                              (failure) => `${failure.resultType} (${String(failure.count)})`,
                            )
                            .join(', ') || 'None supplied'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </article>
          ),
        )}
      </div>
      <p className="detail-note">
        Report source IPs and domains can be sensitive operational data. ZoneSkein does not
        upload or persist this bundle, but copied or downloaded evidence remains your
        responsibility.
      </p>
    </section>
  );
}

export function MailLabPage() {
  const lifetime = useRef(new RequestLifetime());
  const reportController = useRef<AbortController | null>(null);
  useEffect(() => {
    const current = lifetime.current;
    current.enter();
    return () => {
      current.leave();
      reportController.current?.abort();
    };
  }, []);
  const [mode, setMode] = useState<Mode>('reports');
  const [reports, setReports] = useState<readonly ParsedReport[]>([]);
  const [mtaPolicy, setMtaPolicy] = useState('');
  const [mxHosts, setMxHosts] = useState('');
  const [tlsRpt, setTlsRpt] = useState('v=TLSRPTv1; rua=mailto:tlsrpt@example.com');
  const [transportResult, setTransportResult] = useState<{
    readonly coverage: readonly { readonly covered: boolean; readonly host: string }[];
    readonly policy: MtaStsPolicy;
    readonly tls: TlsRptRecord;
  } | null>(null);
  const [certificate, setCertificate] = useState('');
  const [tlsa, setTlsa] = useState('');
  const [certificateResult, setCertificateResult] = useState<CertificateResult | null>(null);
  const [bimiRecord, setBimiRecord] = useState('v=BIMI1; l=; a=');
  const [bimiSvg, setBimiSvg] = useState('');
  const [bimiResult, setBimiResult] = useState<{
    readonly record: BimiRecord;
    readonly svg: BimiSvgReport | null;
  } | null>(null);
  const [arcMessage, setArcMessage] = useState('');
  const [arcResult, setArcResult] = useState<ArcChainReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  function invalidate(): number {
    const generation = lifetime.current.invalidate();
    reportController.current?.abort();
    reportController.current = null;
    setBusy(false);
    setError('');
    return generation;
  }

  function changeMode(value: Mode): void {
    invalidate();
    setMode(value);
    setError('');
    setReports([]);
    setTransportResult(null);
    setCertificateResult(null);
    setBimiResult(null);
    setArcResult(null);
  }

  async function importReports(event: React.ChangeEvent<HTMLInputElement>): Promise<void> {
    const input = event.currentTarget;
    const files = [...(input.files ?? [])];
    input.value = '';
    if (files.length === 0) return;
    const generation = invalidate();
    setReports([]);
    if (files.length > 10) {
      setError('Import no more than ten report files at once.');
      return;
    }
    setBusy(true);
    setError('');
    setReports([]);
    const controller = new AbortController();
    reportController.current = controller;
    try {
      const parsed: ParsedReport[] = [];
      let expandedOctets = 0;
      for (const file of files) {
        if (file.size > MAIL_REPORT_ARCHIVE_LIMITS.archiveOctets)
          throw new Error(`${file.name} exceeds the compressed-input safety limit.`);
        const bytes = new Uint8Array(await file.arrayBuffer());
        if (!lifetime.current.isCurrent(generation)) return;
        const payloads = await extractMailReportPayloadsAsync(file.name, bytes, {
          signal: controller.signal,
          expandedOctets: MAIL_REPORT_ARCHIVE_LIMITS.expandedOctets - expandedOctets,
        });
        if (!lifetime.current.isCurrent(generation)) return;
        for (const payload of payloads) {
          expandedOctets += payload.bytes.length;
          if (expandedOctets > MAIL_REPORT_ARCHIVE_LIMITS.expandedOctets)
            throw new Error('The report bundle exceeds the 10 MiB expanded-output limit.');
          const text = decodeUtf8(payload.bytes);
          if (payload.name.toLowerCase().endsWith('.json') || text.trimStart().startsWith('{'))
            parsed.push({
              kind: 'tls',
              name: payload.name,
              report: parseTlsAggregateJson(text),
            });
          else
            parsed.push({
              kind: 'dmarc',
              name: payload.name,
              report: parseDmarcAggregateXml(text),
            });
          if (parsed.length > 20)
            throw new Error('The imported report bundle exceeds the 20-report limit.');
        }
      }
      if (lifetime.current.isCurrent(generation)) setReports(parsed);
    } catch (cause) {
      if (lifetime.current.isCurrent(generation))
        setError(
          cause instanceof Error ? cause.message : 'The report bundle could not be parsed.',
        );
    } finally {
      if (lifetime.current.isCurrent(generation)) {
        reportController.current = null;
        setBusy(false);
      }
    }
  }

  function analyseTransport(event: React.SyntheticEvent<HTMLFormElement>): void {
    event.preventDefault();
    const policy = parseMtaStsPolicy(mtaPolicy);
    const tls = parseTlsRptRecord(tlsRpt);
    const hosts = mxHosts
      .split(/\r?\n/u)
      .map((host) => host.trim())
      .filter(Boolean);
    if (hosts.length > 100) {
      setError('Enter no more than 100 MX hostnames.');
      return;
    }
    setError('');
    setTransportResult({ coverage: mtaStsMxCoverage(policy, hosts), policy, tls });
  }

  async function analyseCertificate(
    event: React.SyntheticEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const generation = invalidate();
    setBusy(true);
    setError('');
    setCertificateResult(null);
    try {
      const value = await inspectCertificate(certificate);
      if (!lifetime.current.isCurrent(generation)) return;
      const result = {
        inspection: value.inspection,
        tlsa:
          tlsa.trim() === ''
            ? null
            : await verifyTlsaAssociation(tlsa, value.der, value.inspection.spki),
      };
      if (lifetime.current.isCurrent(generation)) setCertificateResult(result);
    } catch (cause) {
      if (lifetime.current.isCurrent(generation))
        setError(
          cause instanceof Error ? cause.message : 'The certificate could not be inspected.',
        );
    } finally {
      if (lifetime.current.isCurrent(generation)) setBusy(false);
    }
  }

  function analyseBimi(event: React.SyntheticEvent<HTMLFormElement>): void {
    event.preventDefault();
    setError('');
    setBimiResult({
      record: parseBimiRecord(bimiRecord),
      svg: bimiSvg.trim() === '' ? null : inspectBimiSvg(bimiSvg),
    });
  }
  function analyseArc(event: React.SyntheticEvent<HTMLFormElement>): void {
    event.preventDefault();
    try {
      setError('');
      setArcResult(inspectArcChain(arcMessage));
    } catch (cause) {
      setArcResult(null);
      setError(
        cause instanceof Error ? cause.message : 'The ARC chain could not be inspected.',
      );
    }
  }

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="Mail lab" title="Follow policy into delivery evidence.">
        Open aggregate reports, check MTA-STS and TLS-RPT, match certificates to TLSA, inspect
        BIMI assets, and review ARC chain structure without uploading message or report
        contents.
      </ToolIntro>
      <div className="mode-tabs" role="group" aria-label="Mail Lab mode">
        {(
          [
            ['reports', 'Reports'],
            ['transport', 'Transport policy'],
            ['certificate', 'Certificate & TLSA'],
            ['bimi', 'BIMI'],
            ['arc', 'ARC chain'],
          ] as const
        ).map(([value, label]) => (
          <button
            key={value}
            type="button"
            aria-pressed={mode === value}
            onClick={() => changeMode(value)}
          >
            {label}
          </button>
        ))}
      </div>
      {mode === 'reports' ? (
        <section className="workbench-form" aria-labelledby="report-import-title">
          <div className="field-group field-wide">
            <h2 id="report-import-title">Open local reports</h2>
            <label className="file-button" htmlFor="mail-report-files">
              Choose XML, JSON, gzip, or ZIP reports
            </label>
            <input
              className="visually-hidden"
              id="mail-report-files"
              type="file"
              accept=".xml,.json,.gz,.zip,application/xml,application/json,application/gzip,application/zip"
              multiple
              onChange={(event) => void importReports(event)}
            />
            <small>
              Up to ten files, twenty expanded reports, 5 MiB per compressed input and 10 MiB
              expanded in total. ZIP paths, entry counts and streaming output are bounded before
              retention.
            </small>
          </div>
        </section>
      ) : mode === 'transport' ? (
        <form className="workbench-form zone-form" onSubmit={analyseTransport}>
          <div className="field-group field-wide">
            <label htmlFor="mta-sts-policy">MTA-STS policy</label>
            <textarea
              id="mta-sts-policy"
              rows={10}
              value={mtaPolicy}
              onChange={(event) => {
                setTransportResult(null);
                setMtaPolicy(event.currentTarget.value);
              }}
              placeholder={
                'version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800'
              }
              maxLength={65_536}
              spellCheck={false}
            />
          </div>
          <div className="field-group">
            <label htmlFor="mta-sts-mx">Published MX hosts</label>
            <textarea
              id="mta-sts-mx"
              rows={6}
              value={mxHosts}
              onChange={(event) => {
                setTransportResult(null);
                setMxHosts(event.currentTarget.value);
              }}
              placeholder="mail.example.com"
              maxLength={32_768}
              spellCheck={false}
            />
            <small>One hostname per line for local policy-coverage checking.</small>
          </div>
          <div className="field-group">
            <label htmlFor="tls-rpt-record">TLS-RPT TXT value</label>
            <textarea
              id="tls-rpt-record"
              rows={6}
              value={tlsRpt}
              onChange={(event) => {
                setTransportResult(null);
                setTlsRpt(event.currentTarget.value);
              }}
              maxLength={65_536}
              spellCheck={false}
            />
          </div>
          <div className="form-actions">
            <button className="primary-button" type="submit">
              Check transport policy
            </button>
            <button
              className="quiet-button"
              type="button"
              onClick={() => {
                setTransportResult(null);
                setMtaPolicy(
                  authorMtaStsPolicy(
                    'enforce',
                    604800,
                    mxHosts
                      .split(/\r?\n/u)
                      .map((value) => value.trim())
                      .filter(Boolean),
                  ),
                );
              }}
            >
              Build enforce policy
            </button>
          </div>
        </form>
      ) : mode === 'certificate' ? (
        <form
          className="workbench-form zone-form"
          onSubmit={(event) => void analyseCertificate(event)}
        >
          <div className="field-group field-wide">
            <label htmlFor="certificate-pem">X.509 certificate</label>
            <textarea
              id="certificate-pem"
              rows={15}
              value={certificate}
              onChange={(event) => {
                invalidate();
                setCertificateResult(null);
                setCertificate(event.currentTarget.value);
              }}
              placeholder="-----BEGIN CERTIFICATE-----"
              maxLength={131_072}
              spellCheck={false}
            />
            <small>
              Paste one public PEM or Base64 DER certificate. Private keys are not accepted.
            </small>
          </div>
          <div className="field-group field-wide">
            <label htmlFor="tlsa-association">Optional TLSA RDATA</label>
            <input
              id="tlsa-association"
              value={tlsa}
              onChange={(event) => {
                invalidate();
                setCertificateResult(null);
                setTlsa(event.currentTarget.value);
              }}
              placeholder="3 1 1 012345…"
              maxLength={140_000}
              spellCheck={false}
            />
          </div>
          <div className="form-actions">
            <button className="primary-button" type="submit" disabled={busy}>
              {busy ? 'Inspecting…' : 'Inspect certificate'}
            </button>
          </div>
        </form>
      ) : mode === 'bimi' ? (
        <form className="workbench-form zone-form" onSubmit={analyseBimi}>
          <div className="field-group field-wide">
            <label htmlFor="bimi-record">BIMI TXT value</label>
            <input
              id="bimi-record"
              value={bimiRecord}
              onChange={(event) => {
                setBimiResult(null);
                setBimiRecord(event.currentTarget.value);
              }}
              maxLength={65_536}
              spellCheck={false}
            />
          </div>
          <div className="field-group field-wide">
            <label htmlFor="bimi-svg">Optional local SVG logo</label>
            <textarea
              id="bimi-svg"
              rows={14}
              value={bimiSvg}
              onChange={(event) => {
                setBimiResult(null);
                setBimiSvg(event.currentTarget.value);
              }}
              placeholder={
                '<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 100 100">…</svg>'
              }
              maxLength={2 * 1024 * 1024}
              spellCheck={false}
            />
            <small>
              The inspector rejects active content and external references and checks a
              conservative static Tiny P/S profile. It does not predict whether a mailbox
              provider will display the logo.
            </small>
          </div>
          <div className="form-actions">
            <button className="primary-button" type="submit">
              Inspect BIMI inputs
            </button>
          </div>
        </form>
      ) : (
        <form className="workbench-form zone-form" onSubmit={analyseArc}>
          <div className="field-group field-wide">
            <label htmlFor="arc-message">Raw email message</label>
            <textarea
              id="arc-message"
              rows={18}
              value={arcMessage}
              onChange={(event) => {
                setArcResult(null);
                setArcMessage(event.currentTarget.value);
              }}
              placeholder={
                'From: sender@example.com\nARC-Seal: i=1; a=rsa-sha256; …\n\nMessage body'
              }
              spellCheck={false}
              maxLength={1_048_576}
            />
            <small>
              This pass checks bounded ARC instance ordering, completeness and required tags. It
              does not establish seal cryptography or whether a receiver should trust an
              intermediary.
            </small>
          </div>
          <div className="form-actions">
            <button className="primary-button" type="submit">
              Inspect ARC structure
            </button>
          </div>
        </form>
      )}
      {error === '' ? null : (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      <div className="run-status" aria-live="polite">
        {busy ? 'Parsing bounded local input.' : null}
      </div>
      {busy ? (
        <button
          type="button"
          className="quiet-button"
          onClick={() => {
            invalidate();
            setError('Local operation cancelled.');
          }}
        >
          Cancel local operation
        </button>
      ) : null}
      {reports.length === 0 ? null : <ReportsResults reports={reports} />}
      {transportResult === null ? null : (
        <section className="results" aria-labelledby="transport-results-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Local policy review</p>
              <h2 id="transport-results-title">Mail transport policy</h2>
            </div>
            <StatusBadge
              tone={
                transportResult.policy.valid &&
                transportResult.tls.valid &&
                transportResult.coverage.every((item) => item.covered)
                  ? 'pass'
                  : 'warning'
              }
            >
              reviewed
            </StatusBadge>
          </div>
          <article className="result-panel">
            <h3>MTA-STS</h3>
            <dl className="metadata-grid">
              <div>
                <dt>Mode</dt>
                <dd>{transportResult.policy.mode ?? 'Invalid'}</dd>
              </div>
              <div>
                <dt>Maximum age</dt>
                <dd>{transportResult.policy.maxAge ?? 'Invalid'}</dd>
              </div>
              <div>
                <dt>MX patterns</dt>
                <dd>{transportResult.policy.mx.length}</dd>
              </div>
            </dl>
            <ul className="diagnostic-list">
              {transportResult.policy.diagnostics.map((diagnostic) => (
                <li key={diagnostic}>
                  <StatusBadge tone="error">policy</StatusBadge>
                  <span>{diagnostic}</span>
                </li>
              ))}
              {transportResult.coverage.map((item) => (
                <li key={item.host}>
                  <StatusBadge tone={item.covered ? 'pass' : 'error'}>
                    {item.covered ? 'covered' : 'uncovered'}
                  </StatusBadge>
                  <span>{item.host}</span>
                </li>
              ))}
            </ul>
          </article>
          <article className="result-panel">
            <h3>TLS-RPT</h3>
            <StatusBadge tone={transportResult.tls.valid ? 'pass' : 'error'}>
              {transportResult.tls.valid ? 'syntax valid' : 'needs work'}
            </StatusBadge>
            <ul>
              {transportResult.tls.diagnostics.map((diagnostic) => (
                <li key={diagnostic}>{diagnostic}</li>
              ))}
            </ul>
          </article>
        </section>
      )}
      {certificateResult === null ? null : (
        <section className="results" aria-labelledby="certificate-results-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Local X.509 decode</p>
              <h2 id="certificate-results-title">Certificate evidence</h2>
            </div>
            <StatusBadge
              tone={
                certificateResult.tlsa === null || certificateResult.tlsa.matches
                  ? 'pass'
                  : 'error'
              }
            >
              {certificateResult.tlsa === null
                ? 'parsed'
                : certificateResult.tlsa.matches
                  ? 'TLSA match'
                  : 'TLSA mismatch'}
            </StatusBadge>
          </div>
          <article className="result-panel">
            <dl className="metadata-grid">
              <div>
                <dt>Subject</dt>
                <dd>{certificateResult.inspection.subject}</dd>
              </div>
              <div>
                <dt>Issuer</dt>
                <dd>{certificateResult.inspection.issuer}</dd>
              </div>
              <div>
                <dt>Valid from</dt>
                <dd>{certificateResult.inspection.notBefore}</dd>
              </div>
              <div>
                <dt>Valid until</dt>
                <dd>{certificateResult.inspection.notAfter}</dd>
              </div>
              <div>
                <dt>Public-key algorithm</dt>
                <dd>{certificateResult.inspection.publicKeyAlgorithm}</dd>
              </div>
              <div>
                <dt>SHA-256 fingerprint</dt>
                <dd>
                  <code>{certificateResult.inspection.fingerprintSha256}</code>
                </dd>
              </div>
            </dl>
            {certificateResult.tlsa === null ? null : <p>{certificateResult.tlsa.reason}</p>}
          </article>
        </section>
      )}
      {bimiResult === null ? null : (
        <section className="results" aria-labelledby="bimi-results-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Local BIMI inspection</p>
              <h2 id="bimi-results-title">Policy and logo</h2>
            </div>
            <StatusBadge
              tone={
                bimiResult.record.valid && (bimiResult.svg?.valid ?? true) ? 'pass' : 'warning'
              }
            >
              compliance check
            </StatusBadge>
          </div>
          <article className="result-panel">
            <h3>BIMI record</h3>
            <p>
              Logo: {bimiResult.record.logoUrl ?? 'No location supplied'} · authority:{' '}
              {bimiResult.record.authorityUrl ?? 'No certificate location supplied'}
            </p>
            <ul>
              {bimiResult.record.diagnostics.map((diagnostic) => (
                <li key={diagnostic}>{diagnostic}</li>
              ))}
            </ul>
          </article>
          {bimiResult.svg === null ? null : (
            <article className="result-panel">
              <h3>SVG Tiny P/S profile</h3>
              <dl className="metadata-grid">
                <div>
                  <dt>Elements</dt>
                  <dd>{bimiResult.svg.elements}</dd>
                </div>
                <div>
                  <dt>Title</dt>
                  <dd>{bimiResult.svg.title ?? 'Missing'}</dd>
                </div>
                <div>
                  <dt>View box</dt>
                  <dd>{bimiResult.svg.viewBox ?? 'Missing'}</dd>
                </div>
              </dl>
              <ul>
                {bimiResult.svg.diagnostics.map((diagnostic) => (
                  <li key={diagnostic}>{diagnostic}</li>
                ))}
              </ul>
            </article>
          )}
        </section>
      )}
      {arcResult === null ? null : (
        <section className="results" aria-labelledby="arc-results-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Local message structure</p>
              <h2 id="arc-results-title">ARC chain</h2>
            </div>
            <StatusBadge
              tone={
                arcResult.state === 'structurally-valid'
                  ? 'pass'
                  : arcResult.state === 'none'
                    ? 'unknown'
                    : 'error'
              }
            >
              {arcResult.state}
            </StatusBadge>
          </div>
          <article className="conclusion-panel partial-panel">
            <StatusBadge tone="information">Structure only</StatusBadge>
            <p>
              A structurally valid chain is not a cryptographic pass and does not make an
              intermediary trustworthy. Use the DKIM message verifier for ordinary DKIM
              signatures; ARC seal verification remains a separate evidence family.
            </p>
          </article>
          <ul className="diagnostic-list">
            {arcResult.diagnostics.map((diagnostic) => (
              <li key={diagnostic}>
                <StatusBadge tone="error">invalid</StatusBadge>
                <span>{diagnostic}</span>
              </li>
            ))}
          </ul>
          <div className="table-scroll" tabIndex={0} role="region" aria-label="ARC instances">
            <table>
              <thead>
                <tr>
                  <th>Instance</th>
                  <th>AAR</th>
                  <th>AMS</th>
                  <th>Seal</th>
                  <th>cv</th>
                  <th>Domain</th>
                  <th>Selector</th>
                </tr>
              </thead>
              <tbody>
                {arcResult.instances.map((instance) => (
                  <tr key={instance.instance}>
                    <td>{instance.instance}</td>
                    <td>{instance.authenticationResults ? 'Present' : 'Missing'}</td>
                    <td>{instance.messageSignature ? 'Present' : 'Missing'}</td>
                    <td>{instance.seal ? 'Present' : 'Missing'}</td>
                    <td>{instance.cv ?? 'Missing'}</td>
                    <td>{instance.domain ?? 'Missing'}</td>
                    <td>{instance.selector ?? 'Missing'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
