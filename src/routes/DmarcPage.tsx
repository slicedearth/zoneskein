import { useEffect, useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { StatusBadge, type StatusTone } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import {
  discoverAndEvaluateDmarcAlignment,
  type DmarcAlignmentDiscoveryResult,
} from '../core/dmarc/alignment-discovery';
import type { DmarcAuthenticationProvenance } from '../core/dmarc/alignment';
import {
  DmarcDiscoverySession,
  type DmarcDiscoveryResult,
  type DmarcTxtLookup,
  type DmarcTxtLookupResult,
} from '../core/dmarc/discovery';
import {
  discoverDmarcReportingAuthorization,
  type DmarcReportingCheck,
} from '../core/dmarc/reporting-discovery';
import type { DmarcDestination, DmarcPolicy } from '../core/dmarc/types';
import { validateDnsName } from '../core/dns/names';
import { queryPolicyRecords } from '../core/dns/policy-query';
import type { DnsResolver, ResolverId } from '../core/dns/types';
import { DnsQueryRun } from '../core/doh/query-run';
import {
  createDnsResolver,
  RESOLVERS,
  resolverOptionLabel,
  resolverSelectionNote,
  SELECTABLE_RESOLVER_IDS,
  type SelectableResolverId,
} from '../core/doh/resolvers';
import {
  decodeMailAuthenticationEvidence,
  encodeMailAuthenticationEvidence,
  MAIL_AUTHENTICATION_EVIDENCE_LIMITS,
  type MailAuthenticationEvidence,
} from '../core/mail/evidence';
import {
  escapeTechnicalText,
  hasUnsafeTechnicalText,
  stringifyTechnicalEvidence,
  utf8Base64Evidence,
} from '../core/technical-text';

const SPF_RESULTS = [
  'none',
  'neutral',
  'pass',
  'fail',
  'softfail',
  'temperror',
  'permerror',
] as const;
const MAX_DKIM_DOMAINS = 20;
const MAX_DKIM_INPUT_CHARACTERS = 5_120;
const MAX_EVIDENCE_JSON_CHARACTERS = 65_535;

type Mode = 'policy' | 'alignment';
type SpfResult = (typeof SPF_RESULTS)[number];

interface ReportingResult {
  readonly check: DmarcReportingCheck;
  readonly destination: DmarcDestination;
}

interface PolicyReport {
  readonly capturedAt: string;
  readonly discovery: DmarcDiscoveryResult;
  readonly policy?: DmarcPolicy;
  readonly reporting: readonly ReportingResult[];
  readonly resolverId: ResolverId;
}

interface DmarcAlignmentReport extends DmarcAlignmentDiscoveryResult {
  readonly capturedAt: string;
  readonly evidenceAcknowledged: boolean;
  readonly priorEvidence?: MailAuthenticationEvidence;
  readonly resolverId: ResolverId;
}

function reportingTag(kind: DmarcDestination['kind']): 'rua' | 'ruf' {
  return kind === 'aggregate' ? 'rua' : 'ruf';
}

function boundedEvidenceJson(
  evidence: unknown,
  fallback: Readonly<Record<string, unknown>>,
): string {
  const serialised = stringifyTechnicalEvidence(evidence, 2);
  if (serialised.length <= MAX_EVIDENCE_JSON_CHARACTERS) return serialised;
  return stringifyTechnicalEvidence(
    {
      ...fallback,
      evidenceTruncated: true,
      reason: `Evidence exceeded the ${String(MAX_EVIDENCE_JSON_CHARACTERS)}-character export limit.`,
    },
    2,
  );
}

function policyEvidence(report: PolicyReport): string {
  return boundedEvidenceJson(
    {
      capturedAt: report.capturedAt,
      discovery: {
        authorDomainExistence: report.discovery.authorDomainExistence,
        domain: report.discovery.domain,
        organizationalDomain: report.discovery.organizationalDomain,
        questions: report.discovery.questions,
        reason: report.discovery.reason,
        rejected:
          report.discovery.rejected === undefined
            ? undefined
            : {
                domain: report.discovery.rejected.domain,
                queryName: report.discovery.rejected.queryName,
                record: report.discovery.rejected.record,
                recordRaw: utf8Base64Evidence(report.discovery.rejected.record),
                ttl: report.discovery.rejected.ttl,
              },
        selected:
          report.discovery.selected === undefined
            ? undefined
            : {
                domain: report.discovery.selected.domain,
                queryName: report.discovery.selected.queryName,
                record: report.discovery.selected.record,
                recordRaw: utf8Base64Evidence(report.discovery.selected.record),
                ttl: report.discovery.selected.ttl,
                assessment: report.discovery.selected.assessment,
              },
        source: report.discovery.selection.source,
        status: report.discovery.status,
      },
      evidenceSchema: 'zoneskein-dmarc-policy-v1',
      policy:
        report.policy === undefined
          ? undefined
          : {
              applicable: report.policy.applicable,
              assessmentPolicyInvalid: report.policy.assessmentPolicyInvalid,
              destinations: report.policy.destinations,
              diagnostics: report.policy.diagnostics,
              effectiveDisposition: report.policy.effectiveDisposition,
              fallbackToNone: report.policy.fallbackToNone,
              psd: report.policy.psd,
              tags: report.policy.tags,
              valid: report.policy.valid,
            },
      reporting: report.reporting.map(({ check, destination }) => ({
        authorisationName: check.authorizationName,
        destination,
        destinationBoundary: check.discovery?.organizationalDomain,
        reason: check.reason,
        selectedUris: check.selectedUris,
        status: check.status,
      })),
      resolver: { id: report.resolverId, label: RESOLVERS[report.resolverId].label },
      textProjection: 'visible-escapes-v1',
    },
    {
      capturedAt: report.capturedAt,
      domain: report.discovery.domain,
      evidenceSchema: 'zoneskein-dmarc-policy-v1',
      resolver: { id: report.resolverId, label: RESOLVERS[report.resolverId].label },
      status: report.discovery.status,
      textProjection: 'visible-escapes-v1',
    },
  );
}

function alignmentEvidence(report: DmarcAlignmentReport): string {
  return boundedEvidenceJson(
    {
      capturedAt: report.capturedAt,
      evidence: report.evaluation?.evidence,
      evidenceAcknowledged: report.evidenceAcknowledged,
      evidenceSchema: 'zoneskein-dmarc-alignment-v2',
      fromDomain: report.evaluation?.fromDomain,
      identifierBoundaries: report.identifierDiscoveries.map(({ discovery, domain }) => ({
        domain,
        organizationalDomain: discovery.organizationalDomain,
        questions: discovery.questions,
        reason: discovery.reason,
        status: discovery.status,
      })),
      modes:
        report.evaluation === undefined
          ? undefined
          : { adkim: report.evaluation.adkim, aspf: report.evaluation.aspf },
      policyAssessment: report.policyDiscovery.selected?.assessment,
      policyBoundary: report.policyDiscovery.organizationalDomain,
      policyDomain: report.policyDomain,
      priorAuthentication: report.priorEvidence,
      questionsUsed: report.questionsUsed,
      reason: report.reason,
      resolver: { id: report.resolverId, label: RESOLVERS[report.resolverId].label },
      result: report.result,
      textProjection: 'visible-escapes-v1',
    },
    {
      capturedAt: report.capturedAt,
      evidenceAcknowledged: report.evidenceAcknowledged,
      evidenceSchema: 'zoneskein-dmarc-alignment-v2',
      policyDomain: report.policyDomain,
      resolver: { id: report.resolverId, label: RESOLVERS[report.resolverId].label },
      result: report.result,
      textProjection: 'visible-escapes-v1',
    },
  );
}

function isLookupSuccess(responseCode: string): boolean {
  return responseCode === 'NOERROR' || responseCode === 'NXDOMAIN';
}

function createLookup(resolver: DnsResolver, run: DnsQueryRun): DmarcTxtLookup {
  return async (name): Promise<DmarcTxtLookupResult> => {
    const result = await queryPolicyRecords(resolver, run, name, 'TXT');
    if (run.cancelled)
      return { error: 'The DMARC run was cancelled.', status: 'temperror', values: [] };
    if (result.error !== undefined)
      return { error: result.error, status: 'temperror', values: [] };
    if (!isLookupSuccess(result.responseCode))
      return {
        error: `The resolver returned ${result.responseCode}.`,
        status: result.responseCode === 'SERVFAIL' ? 'temperror' : 'permerror',
        values: [],
      };
    return {
      status:
        result.responseCode === 'NXDOMAIN'
          ? 'nxdomain'
          : result.values.length === 0
            ? 'nodata'
            : 'answer',
      ...(result.ttl === undefined ? {} : { ttl: result.ttl }),
      values: result.values,
    };
  };
}

function questionSummary(discovery: DmarcDiscoveryResult): readonly string[] {
  return discovery.questions.map(
    (question) => `${question.name}: ${question.status}; ${question.detail}`,
  );
}

function resultTone(result: DmarcAlignmentDiscoveryResult['result']): StatusTone {
  if (result === 'pass') return 'pass';
  if (result === 'fail' || result === 'permerror') return 'error';
  if (result === 'temperror') return 'warning';
  return 'unknown';
}

function evidenceTone(status: string): StatusTone {
  if (status === 'aligned' || status === 'authorized' || status === 'internal') return 'pass';
  if (status === 'temperror') return 'warning';
  if (status === 'indeterminate' || status === 'not-authenticated') return 'unknown';
  return 'error';
}

function evidenceStatusLabel(status: string): string {
  if (status === 'authorized') return 'authorised';
  if (status === 'unauthorized') return 'unauthorised';
  return status;
}

function parseDkimDomains(
  value: string,
): { readonly domains: readonly string[] } | { readonly error: string } {
  if (value.length > MAX_DKIM_INPUT_CHARACTERS)
    return {
      error: `DKIM domain input is limited to ${String(MAX_DKIM_INPUT_CHARACTERS)} characters.`,
    };
  const domains = value
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
  if (domains.length > MAX_DKIM_DOMAINS)
    return { error: `Enter no more than ${String(MAX_DKIM_DOMAINS)} passing DKIM domains.` };
  return { domains };
}

function DmarcPolicyResults({ report }: { readonly report: PolicyReport }) {
  const { discovery, policy } = report;
  const assessment = discovery.selected?.assessment;
  return (
    <section className="results" aria-labelledby="dmarc-result-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Discovery result</p>
          <h2 id="dmarc-result-title">DMARC policy</h2>
        </div>
        <div className="export-actions">
          {policy === undefined ? (
            <StatusBadge tone={discovery.status === 'complete' ? 'unknown' : 'error'}>
              {discovery.status === 'complete' ? 'Not found' : discovery.status}
            </StatusBadge>
          ) : (
            <StatusBadge tone={policy.valid ? 'pass' : 'error'}>
              {policy.valid ? 'Syntax valid' : 'Errors found'}
            </StatusBadge>
          )}
          <CopyButton label="Copy DMARC evidence JSON" text={policyEvidence(report)} />
        </div>
      </div>
      {policy === undefined || discovery.selected === undefined ? (
        <article className="conclusion-panel">
          <StatusBadge tone={discovery.status === 'complete' ? 'unknown' : 'error'}>
            {discovery.status}
          </StatusBadge>
          <p>{discovery.reason}</p>
        </article>
      ) : (
        <>
          <article className="result-panel">
            <div className="result-heading">
              <h3>{discovery.selected.queryName}</h3>
              <div className="export-actions">
                <CopyButton
                  label="Copy safe DMARC record"
                  text={escapeTechnicalText(policy.record)}
                />
                {hasUnsafeTechnicalText(policy.record) ? (
                  <CopyButton
                    label="Copy exact DMARC record as Base64"
                    text={utf8Base64Evidence(policy.record).value}
                  />
                ) : null}
              </div>
            </div>
            <pre className="spf-output technical-value" dir="ltr">
              {escapeTechnicalText(policy.record)}
            </pre>
            <dl className="metadata-grid">
              <div>
                <dt>Policy domain</dt>
                <dd>{discovery.selected.domain}</dd>
              </div>
              <div>
                <dt>Discovery</dt>
                <dd>
                  {discovery.selection.source === 'public-suffix'
                    ? 'Inherited from a public suffix'
                    : discovery.selection.source === 'organizational'
                      ? 'Inherited from organisational domain'
                      : 'Direct'}
                </dd>
              </div>
              <div>
                <dt>Organisational domain</dt>
                <dd>{discovery.organizationalDomain}</dd>
              </div>
              <div>
                <dt>TTL</dt>
                <dd>{discovery.selected.ttl ?? 'Unknown'}</dd>
              </div>
              <div>
                <dt>Report destinations</dt>
                <dd>{policy.destinations.length}</dd>
              </div>
              <div>
                <dt>Selected assessment tag</dt>
                <dd>{assessment?.selectedTag ?? 'Not applicable'}</dd>
              </div>
              <div>
                <dt>Declared disposition</dt>
                <dd>{assessment?.declaredDisposition ?? 'Not validly declared'}</dd>
              </div>
              <div>
                <dt>Applied disposition</dt>
                <dd>{assessment?.appliedDisposition ?? 'Not applicable'}</dd>
              </div>
            </dl>
            {assessment === undefined ? null : <p>{assessment.reason}</p>}
          </article>
          <div className="comparison-grid">
            <article className="result-panel">
              <h3>Policy tags</h3>
              <dl className="tag-list">
                {policy.tags.map((tag, index) => (
                  <div key={`${tag.name}-${String(index)}`}>
                    <dt>{escapeTechnicalText(tag.name)}</dt>
                    <dd>{escapeTechnicalText(tag.value)}</dd>
                  </div>
                ))}
              </dl>
            </article>
            <article className="result-panel">
              <h3>Diagnostics</h3>
              {policy.diagnostics.length === 0 ? (
                <p className="empty-note">No syntax diagnostic.</p>
              ) : (
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
                      <span>
                        <strong>{escapeTechnicalText(item.code)}</strong> ·{' '}
                        {escapeTechnicalText(item.message)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </article>
          </div>
          <article className="result-panel">
            <h3>Reporting boundaries and authorisation</h3>
            {policy.destinations.length === 0 ? (
              <p className="empty-note">No rua or ruf destinations.</p>
            ) : (
              <div
                className="table-scroll"
                tabIndex={0}
                role="region"
                aria-label="DMARC reporting boundaries and authorisation"
              >
                <table>
                  <thead>
                    <tr>
                      <th>Kind</th>
                      <th>URI</th>
                      <th>Boundary result</th>
                      <th>Selected destination</th>
                    </tr>
                  </thead>
                  <tbody>
                    {policy.destinations.map((destination, index) => {
                      const result = report.reporting[index];
                      return (
                        <tr key={`${destination.uri}-${String(index)}`}>
                          <td>{destination.kind}</td>
                          <td>
                            <code>{escapeTechnicalText(destination.uri)}</code>
                          </td>
                          <td>
                            {result === undefined ? (
                              'Not checked'
                            ) : (
                              <>
                                <StatusBadge tone={evidenceTone(result.check.status)}>
                                  {evidenceStatusLabel(result.check.status)}
                                </StatusBadge>{' '}
                                {escapeTechnicalText(result.check.reason)}
                              </>
                            )}
                          </td>
                          <td>
                            {result === undefined
                              ? 'Not checked'
                              : result.check.selectedUris.length === 0
                                ? 'No authorised destination'
                                : result.check.selectedUris.map(escapeTechnicalText).join(', ')}
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
          {questionSummary(discovery).map((item, index) => (
            <li key={`${String(index)}-${item}`}>{item}</li>
          ))}
        </ul>
        <p>
          Policy publication does not prove that senders align SPF or DKIM, that receivers
          enforce the requested disposition, or that report mailboxes accept data.
        </p>
      </details>
    </section>
  );
}

function DmarcAlignmentResults({ report }: { readonly report: DmarcAlignmentReport }) {
  const assessment = report.policyDiscovery.selected?.assessment;
  const qualifiedEvidence = report.evaluation?.evidence.filter(
    (item) => item.qualification !== undefined,
  );
  return (
    <section className="results" aria-labelledby="dmarc-alignment-result-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Alignment result</p>
          <h2 id="dmarc-alignment-result-title">DMARC {report.result}</h2>
        </div>
        <div className="export-actions">
          <StatusBadge tone={resultTone(report.result)}>{report.result}</StatusBadge>
          <CopyButton label="Copy alignment evidence JSON" text={alignmentEvidence(report)} />
        </div>
      </div>
      <article className="conclusion-panel">
        <StatusBadge tone={resultTone(report.result)}>{report.result}</StatusBadge>
        <p>{report.reason}</p>
      </article>
      {qualifiedEvidence === undefined || qualifiedEvidence.length === 0 ? null : (
        <p className="snapshot-warning">
          This result uses qualified prior authentication evidence.{' '}
          {report.evidenceAcknowledged
            ? 'The relationship was explicitly acknowledged, so any pass is conditional.'
            : 'The relationship was not acknowledged, so aligned prior evidence cannot assert a pass.'}
        </p>
      )}
      {assessment === undefined ? null : (
        <article className="result-panel">
          <h3>Assessment policy</h3>
          <dl className="metadata-grid">
            <div>
              <dt>Selected tag</dt>
              <dd>{assessment.selectedTag}</dd>
            </div>
            <div>
              <dt>Declared disposition</dt>
              <dd>{assessment.declaredDisposition ?? 'Not validly declared'}</dd>
            </div>
            <div>
              <dt>Applied disposition</dt>
              <dd>{assessment.appliedDisposition}</dd>
            </div>
          </dl>
          <p>{assessment.reason}</p>
        </article>
      )}
      {report.evaluation === undefined ? null : (
        <article className="result-panel">
          <h3>Per-method evidence</h3>
          <div
            className="table-scroll"
            tabIndex={0}
            role="region"
            aria-label="DMARC per-method evidence"
          >
            <table>
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Authenticated domain</th>
                  <th>Mode</th>
                  <th>Outcome</th>
                  <th>Evidence</th>
                </tr>
              </thead>
              <tbody>
                {report.evaluation.evidence.map((item, index) => (
                  <tr key={`${item.method}-${item.domain ?? 'none'}-${String(index)}`}>
                    <td>{item.method.toUpperCase()}</td>
                    <td>{item.domain ?? 'None'}</td>
                    <td>{item.mode}</td>
                    <td>
                      <StatusBadge tone={evidenceTone(item.status)}>{item.status}</StatusBadge>
                    </td>
                    <td>
                      <p>{item.reason}</p>
                      {item.qualification === undefined ? null : (
                        <small>
                          {item.qualification}{' '}
                          {item.acknowledged
                            ? 'The user acknowledged this qualification for the current run.'
                            : 'This qualification was not acknowledged for the current run.'}
                        </small>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>
      )}
      <details className="method-note">
        <summary>DNS boundary evidence</summary>
        <p>{report.policyDiscovery.reason}</p>
        {report.identifierDiscoveries.map((item) => (
          <p key={item.domain}>
            {item.domain}: {item.discovery.reason}
          </p>
        ))}
        <p>
          This check accepts only domains and prior authentication results. It never accepts a
          raw message or persists the identifiers entered here. Required DNS names are sent only
          to the resolver selected for this run.
        </p>
      </details>
    </section>
  );
}

export interface DmarcPageProps {
  readonly initialEvidence?: MailAuthenticationEvidence;
  readonly onEvidenceChange?: (evidence: MailAuthenticationEvidence | null) => void;
}

export function DmarcPage({ initialEvidence, onEvidenceChange }: DmarcPageProps = {}) {
  const [mode, setMode] = useState<Mode>(
    initialEvidence === undefined ? 'policy' : 'alignment',
  );
  const [domain, setDomain] = useState('');
  const [dkimDomains, setDkimDomains] = useState(
    initialEvidence?.dkim.map((entry) => entry.domain).join('\n') ?? '',
  );
  const [spfResult, setSpfResult] = useState<SpfResult>(initialEvidence?.spf?.result ?? 'none');
  const [spfDomain, setSpfDomain] = useState(initialEvidence?.spf?.domain ?? '');
  const [transferredEvidence, setTransferredEvidence] = useState(initialEvidence ?? null);
  const [evidenceAcknowledged, setEvidenceAcknowledged] = useState(false);
  const [evidenceInput, setEvidenceInput] = useState('');
  const [evidenceError, setEvidenceError] = useState('');
  const [resolverId, setResolverId] = useState<SelectableResolverId>('google');
  const [state, setState] = useState<'idle' | 'loading' | 'complete' | 'cancelled'>('idle');
  const [error, setError] = useState('');
  const [policyReport, setPolicyReport] = useState<PolicyReport | null>(null);
  const [alignmentReport, setAlignmentReport] = useState<DmarcAlignmentReport | null>(null);
  const activeRun = useRef<DnsQueryRun | null>(null);

  useEffect(
    () => () => {
      activeRun.current?.cancel();
    },
    [],
  );

  async function inspectPolicy(
    lookup: DmarcTxtLookup,
    run: DnsQueryRun,
    capturedAt: string,
    resolver: DnsResolver,
  ): Promise<void> {
    const stopped = () => activeRun.current !== run || run.cancelled;
    const session = new DmarcDiscoverySession(lookup, 80, () => run.cancelled);
    const discovery = await session.discover(domain);
    if (stopped()) return;
    const selected = discovery.selected;
    const organizationalDomain = discovery.organizationalDomain;
    const policy = selected?.policy ?? discovery.rejected?.policy;
    const reporting: ReportingResult[] = [];
    if (
      policy?.applicable === true &&
      selected !== undefined &&
      organizationalDomain !== undefined
    ) {
      for (const destination of policy.destinations.slice(0, 10)) {
        if (stopped()) return;
        const check = await discoverDmarcReportingAuthorization(
          selected.domain,
          organizationalDomain,
          destination.uri,
          session,
          reportingTag(destination.kind),
        );
        if (stopped()) return;
        reporting.push({ check, destination });
      }
    }
    if (stopped()) return;
    setPolicyReport({
      capturedAt,
      discovery,
      ...(policy === undefined ? {} : { policy }),
      reporting,
      resolverId: resolver.definition.id,
    });
  }

  async function inspect(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const parsed = validateDnsName(domain);
    if (!parsed.ok || parsed.value.ascii === '') {
      setError(
        parsed.ok
          ? mode === 'alignment'
            ? 'Enter the domain from the message’s visible From address.'
            : 'Enter a domain.'
          : parsed.error.message,
      );
      return;
    }
    const dkim =
      mode === 'alignment' ? parseDkimDomains(dkimDomains) : ({ domains: [] } as const);
    if ('error' in dkim) {
      setError(dkim.error);
      return;
    }
    if (mode === 'alignment' && spfResult === 'pass' && spfDomain.trim() === '') {
      setError('Enter the domain authenticated by the passing SPF result.');
      return;
    }

    activeRun.current?.cancel();
    const run = new DnsQueryRun();
    activeRun.current = run;
    setError('');
    setPolicyReport(null);
    setAlignmentReport(null);
    setState('loading');
    const capturedAt = new Date().toISOString();
    const resolver = createDnsResolver(resolverId);
    const lookup = createLookup(resolver, run);
    try {
      if (mode === 'policy') await inspectPolicy(lookup, run, capturedAt, resolver);
      else {
        const dkimEvidence = dkim.domains.map((dkimDomain) => {
          const transferred = transferredEvidence?.dkim.find(
            (entry) => entry.domain === dkimDomain,
          );
          const provenance: DmarcAuthenticationProvenance =
            transferred === undefined
              ? { correlation: 'unbound', source: 'manual' }
              : {
                  capturedAt: transferred.capturedAt,
                  correlation: 'unbound',
                  reconstructed: transferred.reconstructed,
                  resolverId: transferred.resolverId,
                  source: transferred.source,
                };
          return { domain: dkimDomain, provenance };
        });
        const transferredSpf = transferredEvidence?.spf;
        const spfProvenance: DmarcAuthenticationProvenance =
          transferredSpf === undefined
            ? { correlation: 'unbound', source: 'manual' }
            : {
                capturedAt: transferredSpf.capturedAt,
                correlation: 'unbound',
                ...(transferredSpf.identitySource === undefined
                  ? {}
                  : { identitySource: transferredSpf.identitySource }),
                resolverId: transferredSpf.resolverId,
                source: transferredSpf.source,
              };
        const result = await discoverAndEvaluateDmarcAlignment(
          {
            dkimEvidence,
            dkimDomains: dkim.domains,
            evidenceAcknowledged,
            fromDomain: parsed.value.ascii,
            spf: {
              ...(spfDomain.trim() === '' ? {} : { domain: spfDomain }),
              provenance: spfProvenance,
              result: spfResult,
            },
          },
          lookup,
          80,
          () => run.cancelled,
        );
        if (activeRun.current === run && !run.cancelled)
          setAlignmentReport({
            ...result,
            capturedAt,
            evidenceAcknowledged,
            ...(transferredEvidence === null ? {} : { priorEvidence: transferredEvidence }),
            resolverId: resolver.definition.id,
          });
      }
      if (activeRun.current === run) setState(run.cancelled ? 'cancelled' : 'complete');
    } catch (cause) {
      if (activeRun.current !== run) return;
      setError(cause instanceof Error ? cause.message : 'The DMARC run failed safely.');
      setState(run.cancelled ? 'cancelled' : 'idle');
    }
  }

  function resetResults() {
    activeRun.current?.cancel();
    activeRun.current = null;
    setError('');
    setPolicyReport(null);
    setAlignmentReport(null);
    setState('idle');
  }

  function detachTransferredEvidence() {
    resetResults();
    setEvidenceAcknowledged(false);
    if (transferredEvidence === null) return;
    setTransferredEvidence(null);
    onEvidenceChange?.(null);
  }

  function applyTransferredEvidence(evidence: MailAuthenticationEvidence) {
    resetResults();
    setMode('alignment');
    setDkimDomains(evidence.dkim.map((entry) => entry.domain).join('\n'));
    setSpfResult(evidence.spf?.result ?? 'none');
    setSpfDomain(evidence.spf?.domain ?? '');
    setEvidenceAcknowledged(false);
    setTransferredEvidence(evidence);
    setEvidenceInput('');
    setEvidenceError('');
    onEvidenceChange?.(evidence);
  }

  function importTransferredEvidence() {
    const decoded = decodeMailAuthenticationEvidence(evidenceInput);
    if (!decoded.ok) {
      setEvidenceError(decoded.error);
      return;
    }
    applyTransferredEvidence(decoded.value);
  }

  function clearTransferredEvidence() {
    resetResults();
    setDkimDomains('');
    setSpfResult('none');
    setSpfDomain('');
    setEvidenceAcknowledged(false);
    setTransferredEvidence(null);
    setEvidenceInput('');
    setEvidenceError('');
    onEvidenceChange?.(null);
  }

  function clear() {
    resetResults();
    setDomain('');
    setDkimDomains('');
    setSpfResult('none');
    setSpfDomain('');
    setEvidenceAcknowledged(false);
    setTransferredEvidence(null);
    setEvidenceInput('');
    setEvidenceError('');
    onEvidenceChange?.(null);
  }

  function selectMode(next: Mode) {
    resetResults();
    setMode(next);
  }

  return (
    <div className="tool-page">
      <ToolIntro
        eyebrow="DMARC policy workbench"
        title="Follow policy, reporting, and alignment."
      >
        Follow the bounded DMARC DNS Tree Walk, inspect policy and reporting boundaries, or
        check whether earlier passing DKIM or SPF results align, without uploading a message.
      </ToolIntro>
      <div className="mode-switch" aria-label="DMARC mode">
        <button
          aria-pressed={mode === 'policy'}
          type="button"
          disabled={state === 'loading'}
          onClick={() => selectMode('policy')}
        >
          Policy discovery
        </button>
        <button
          aria-pressed={mode === 'alignment'}
          type="button"
          disabled={state === 'loading'}
          onClick={() => selectMode('alignment')}
        >
          Alignment check
        </button>
      </div>
      {mode === 'alignment' ? (
        <section className="result-panel" aria-labelledby="dmarc-prior-evidence-title">
          <div className="result-heading">
            <div>
              <p className="eyebrow">Prior authentication</p>
              <h2 id="dmarc-prior-evidence-title">Transfer bounded SPF and DKIM evidence</h2>
            </div>
            {transferredEvidence === null ? null : (
              <div className="export-actions">
                <CopyButton
                  label="Copy prior authentication JSON"
                  text={encodeMailAuthenticationEvidence(transferredEvidence)}
                />
                <button
                  className="quiet-button"
                  type="button"
                  onClick={clearTransferredEvidence}
                >
                  Clear prior evidence
                </button>
              </div>
            )}
          </div>
          {transferredEvidence === null ? (
            <p>
              Use an in-memory hand-off from the SPF or DKIM tool, or paste its bounded hand-off
              JSON below. The transfer contains domain-level results only.
            </p>
          ) : (
            <>
              <p>
                Loaded {transferredEvidence.dkim.length}{' '}
                {transferredEvidence.dkim.length === 1
                  ? 'passing DKIM domain'
                  : 'passing DKIM domains'}
                {transferredEvidence.spf === undefined
                  ? ' and no SPF result.'
                  : transferredEvidence.spf.domain === undefined
                    ? ` and an SPF ${transferredEvidence.spf.result} result with no unauthenticated domain retained.`
                    : ` and an SPF ${transferredEvidence.spf.result} result for its authenticated ${transferredEvidence.spf.identitySource === 'helo' ? 'HELO-derived' : 'MAIL FROM'} domain ${transferredEvidence.spf.domain}.`}
              </p>
              <p className="detail-note">
                Created {new Date(transferredEvidence.createdAt).toLocaleString()}. The transfer
                does not contain raw messages, mailbox local parts, client IP addresses,
                selectors, policy text, or DNS traces. Resolver identifiers are inert provenance
                and do not change the resolver selected below.
              </p>
              <ul>
                {transferredEvidence.dkim.map((entry) => (
                  <li key={`dkim-${entry.domain}`}>
                    DKIM {entry.domain}: captured {new Date(entry.capturedAt).toLocaleString()}
                    {' · '}resolver {entry.resolverId}
                    {entry.reconstructed ? ' · reconstructed line endings' : ''}
                  </li>
                ))}
                {transferredEvidence.spf === undefined ? null : (
                  <li>
                    SPF {transferredEvidence.spf.result}: captured{' '}
                    {new Date(transferredEvidence.spf.capturedAt).toLocaleString()}
                    {' · '}resolver {transferredEvidence.spf.resolverId}
                    {transferredEvidence.spf.identitySource === undefined
                      ? ''
                      : ` · ${transferredEvidence.spf.identitySource === 'helo' ? 'HELO-derived' : 'MAIL FROM'} identity`}
                  </li>
                )}
              </ul>
              <p className="snapshot-warning">
                This hand-off is not cryptographically bound to the visible From domain or a
                common message context. Confirm that relationship below before a conditional
                pass can be asserted.
              </p>
              {transferredEvidence.dkim.some((entry) => entry.reconstructed) ? (
                <p className="snapshot-warning">
                  At least one DKIM result passed only after pasted line endings were
                  reconstructed. Treat that signing domain as reconstructed-text evidence.
                </p>
              ) : null}
            </>
          )}
          <details className="method-note">
            <summary>Import prior authentication JSON</summary>
            <div className="field-group field-wide">
              <label htmlFor="dmarc-evidence-json">Prior authentication hand-off JSON</label>
              <textarea
                id="dmarc-evidence-json"
                value={evidenceInput}
                onChange={(event) => {
                  setEvidenceInput(event.currentTarget.value);
                  setEvidenceError('');
                }}
                rows={8}
                maxLength={MAIL_AUTHENTICATION_EVIDENCE_LIMITS.jsonOctets}
                spellCheck={false}
              />
              <small>
                Maximum {MAIL_AUTHENTICATION_EVIDENCE_LIMITS.jsonOctets.toLocaleString()} UTF-8
                octets. Unknown fields, duplicate keys, duplicate domains, malformed values, and
                excessive nesting are rejected.
              </small>
            </div>
            {evidenceError === '' ? null : (
              <p className="form-error" role="alert">
                {evidenceError}
              </p>
            )}
            <button
              className="quiet-button"
              type="button"
              disabled={evidenceInput.trim() === ''}
              onClick={importTransferredEvidence}
            >
              Import prior evidence
            </button>
          </details>
        </section>
      ) : null}
      <form className="workbench-form" onSubmit={(event) => void inspect(event)}>
        <div className="field-group field-wide">
          <label htmlFor="dmarc-domain">
            {mode === 'alignment' ? 'Visible From address domain' : 'Domain'}
          </label>
          <input
            id="dmarc-domain"
            value={domain}
            disabled={state === 'loading'}
            onChange={(event) => {
              resetResults();
              if (mode === 'alignment') setEvidenceAcknowledged(false);
              setDomain(event.currentTarget.value);
            }}
            placeholder="mail.example.com"
            maxLength={2048}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            required
          />
          {mode === 'alignment' ? (
            <small>Enter the part after @ in the message’s visible From address.</small>
          ) : null}
        </div>
        {mode === 'alignment' ? (
          <>
            <div className="field-group field-wide">
              <label htmlFor="dmarc-dkim-domains">Domains from passing DKIM signatures</label>
              <textarea
                id="dmarc-dkim-domains"
                value={dkimDomains}
                disabled={state === 'loading'}
                onChange={(event) => {
                  detachTransferredEvidence();
                  setDkimDomains(event.currentTarget.value);
                }}
                placeholder={'signer.example.com\nsecond.example.com'}
                rows={6}
                maxLength={MAX_DKIM_INPUT_CHARACTERS}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
              />
              <small>
                In ZoneSkein’s DKIM Message verifier, use the signing domain shown for each
                signature that passed. Enter one domain per line; maximum 20.
              </small>
              <small>
                This alignment check does not verify the signatures again or rerun SPF. Manual
                values remain unbound prior evidence and require the explicit confirmation below
                before they can support a conditional pass.
              </small>
            </div>
            <div className="field-group">
              <label htmlFor="dmarc-spf-result">Previous SPF result</label>
              <select
                id="dmarc-spf-result"
                value={spfResult}
                disabled={state === 'loading'}
                onChange={(event) => {
                  detachTransferredEvidence();
                  setSpfResult(event.currentTarget.value as SpfResult);
                }}
              >
                {SPF_RESULTS.map((result) => (
                  <option key={result} value={result}>
                    {result}
                  </option>
                ))}
              </select>
            </div>
            <div className="field-group">
              <label htmlFor="dmarc-spf-domain">Domain authenticated by SPF</label>
              <input
                id="dmarc-spf-domain"
                value={spfDomain}
                disabled={state === 'loading'}
                onChange={(event) => {
                  detachTransferredEvidence();
                  setSpfDomain(event.currentTarget.value);
                }}
                placeholder="bounce.example.com"
                maxLength={253}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
              />
              <small>
                Use the policy domain shown by ZoneSkein’s SPF Sender evaluation when it passes.
                For a null reverse path, use the HELO domain that SPF evaluated as the
                postmaster identity.
              </small>
            </div>
            <label className="check-control field-wide">
              <input
                type="checkbox"
                checked={evidenceAcknowledged}
                disabled={state === 'loading'}
                onChange={(event) => {
                  resetResults();
                  setEvidenceAcknowledged(event.currentTarget.checked);
                }}
              />
              I confirm these prior SPF and DKIM results belong to this message and visible From
              context
            </label>
            <p className="detail-note field-wide">
              Without this confirmation, an otherwise aligned prior identifier remains
              indeterminate. Confirmation permits only a conditional pass; capture and
              reconstruction qualifications remain visible and exported.
            </p>
          </>
        ) : null}
        <div className="field-group">
          <label htmlFor="dmarc-resolver">Resolver</label>
          <select
            id="dmarc-resolver"
            aria-describedby={
              resolverSelectionNote(resolverId) === undefined
                ? undefined
                : 'dmarc-resolver-note'
            }
            value={resolverId}
            disabled={state === 'loading'}
            onChange={(event) => {
              resetResults();
              setResolverId(event.currentTarget.value as SelectableResolverId);
            }}
          >
            {SELECTABLE_RESOLVER_IDS.map((id) => (
              <option key={id} value={id}>
                {resolverOptionLabel(id)}
              </option>
            ))}
          </select>
          {resolverSelectionNote(resolverId) === undefined ? null : (
            <small id="dmarc-resolver-note">{resolverSelectionNote(resolverId)}</small>
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
              ? mode === 'policy'
                ? 'Discovering…'
                : 'Checking alignment…'
              : mode === 'policy'
                ? 'Inspect DMARC'
                : 'Check alignment'}
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
        aria-label="DMARC run status"
        aria-live="polite"
        aria-atomic="true"
      >
        {state === 'loading'
          ? 'DMARC boundaries are being discovered within one bounded DNS run.'
          : null}
        {state === 'cancelled' ? 'The DMARC run was cancelled.' : null}
        {state === 'complete' && policyReport !== null
          ? policyReport.policy === undefined
            ? 'DMARC policy discovery complete: no applicable policy was found.'
            : `DMARC policy discovery complete: ${policyReport.policy.valid ? 'syntax valid' : 'errors found'}.`
          : null}
        {state === 'complete' && alignmentReport !== null
          ? `DMARC alignment check complete: ${alignmentReport.result}.`
          : null}
      </div>
      {policyReport === null ? null : <DmarcPolicyResults report={policyReport} />}
      {alignmentReport === null ? null : <DmarcAlignmentResults report={alignmentReport} />}
    </div>
  );
}
