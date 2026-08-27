import { useEffect, useMemo, useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { EvidenceGraph } from '../components/EvidenceGraph';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { validateDnsName } from '../core/dns/names';
import { DnsQueryError, type DnsQuestion, type DnsRecordType } from '../core/dns/types';
import { useDomainThread } from '../core/domain-thread';
import { DnsQueryRun } from '../core/doh/query-run';
import {
  createDnsResolver,
  resolverOptionLabel,
  resolverSelectionNote,
  SELECTABLE_RESOLVER_IDS,
  type SelectableResolverId,
} from '../core/doh/resolvers';
import { buildDnsEvidenceBundle, type DnsGraphObservation } from '../core/evidence/dns-graph';
import {
  compareDnsGraphObservations,
  type ResolverQuestionComparison,
} from '../core/evidence/resolver-comparison';
import type { EvidenceBundle } from '../core/evidence/types';
import { stringifyTechnicalEvidence } from '../core/technical-text';

const MAP_TYPES = [
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'NS',
  'TXT',
  'CAA',
  'HTTPS',
  'SVCB',
  'DS',
] as const satisfies readonly DnsRecordType[];

type RunState = 'idle' | 'loading' | 'complete' | 'partial' | 'cancelled';

export function EvidenceMapPage() {
  const domainThread = useDomainThread();
  const [domain, setDomain] = useState(() => domainThread.domain?.display ?? '');
  const [resolverId, setResolverId] = useState<SelectableResolverId>('google');
  const [compare, setCompare] = useState(false);
  const [bundle, setBundle] = useState<EvidenceBundle | null>(null);
  const [comparisons, setComparisons] = useState<readonly ResolverQuestionComparison[]>([]);
  const [error, setError] = useState('');
  const [state, setState] = useState<RunState>('idle');
  const activeRun = useRef<DnsQueryRun | null>(null);
  const evidenceJson = useMemo(
    () => (bundle === null ? '' : stringifyTechnicalEvidence(bundle, 2)),
    [bundle],
  );

  useEffect(() => () => activeRun.current?.cancel(), []);

  function invalidate(): void {
    activeRun.current?.cancel();
    activeRun.current = null;
    setBundle(null);
    setComparisons([]);
    setError('');
    setState('idle');
  }

  async function mapDomain(event: React.SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const parsed = validateDnsName(domain);
    if (!parsed.ok) {
      setError(parsed.error.message);
      return;
    }
    domainThread.setDomain(parsed.value);
    activeRun.current?.cancel();
    const run = new DnsQueryRun();
    activeRun.current = run;
    setBundle(null);
    setError('');
    setState('loading');
    const resolverIds: readonly SelectableResolverId[] = compare
      ? SELECTABLE_RESOLVER_IDS
      : [resolverId];
    const resolvers = new Map(resolverIds.map((id) => [id, createDnsResolver(id)]));
    const questions: readonly DnsQuestion[] = MAP_TYPES.map((type) => ({
      name: parsed.value,
      type,
    }));
    const observations = await Promise.all(
      questions.flatMap((question) =>
        resolverIds.map(async (targetResolver): Promise<DnsGraphObservation> => {
          const resolver = resolvers.get(targetResolver);
          if (resolver === undefined)
            return {
              error: 'The resolver client was not created.',
              questionName: question.name.absolute,
              questionType: question.type,
              resolverLabel: resolverOptionLabel(targetResolver),
            };
          try {
            const response = await run.query(resolver, question, {
              checkingDisabled: false,
              dnssecOk: true,
            });
            return {
              questionName: question.name.absolute,
              questionType: question.type,
              resolverLabel: resolverOptionLabel(targetResolver),
              response,
            };
          } catch (cause) {
            return {
              error:
                cause instanceof DnsQueryError || cause instanceof Error
                  ? cause.message
                  : 'The DNS question failed.',
              questionName: question.name.absolute,
              questionType: question.type,
              resolverLabel: resolverOptionLabel(targetResolver),
            };
          }
        }),
      ),
    );
    if (activeRun.current !== run || run.cancelled) {
      setState('cancelled');
      return;
    }
    const next = buildDnsEvidenceBundle(parsed.value.absolute, observations);
    setBundle(next);
    setComparisons(compare ? compareDnsGraphObservations(observations) : []);
    setState(next.status === 'complete' ? 'complete' : 'partial');
    activeRun.current = null;
  }

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="Evidence map" title="See how the strands connect.">
        Turn a bounded set of live DNS observations into an explorable map. Every line retains
        its source, time, TTL and uncertainty; the graph never promotes resolver agreement into
        proof.
      </ToolIntro>
      <form className="workbench-form" onSubmit={(event) => void mapDomain(event)}>
        <div className="field-group">
          <label htmlFor="evidence-domain">DNS name</label>
          <input
            id="evidence-domain"
            value={domain}
            onChange={(event) => {
              invalidate();
              setDomain(event.currentTarget.value);
            }}
            placeholder="example.com"
            spellCheck={false}
          />
        </div>
        <div className="field-group">
          <label htmlFor="evidence-resolver">Resolver transport</label>
          <select
            id="evidence-resolver"
            value={resolverId}
            aria-describedby={
              resolverSelectionNote(resolverId) === undefined
                ? undefined
                : 'evidence-resolver-note'
            }
            onChange={(event) => {
              invalidate();
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
            <small id="evidence-resolver-note">{resolverSelectionNote(resolverId)}</small>
          )}
        </div>
        <label className="check-control compare-control">
          <input
            type="checkbox"
            checked={compare}
            onChange={(event) => {
              invalidate();
              setCompare(event.currentTarget.checked);
            }}
          />
          Compare all resolvers
        </label>
        <p className="detail-note field-wide">
          This run asks {compare ? 'thirty' : 'ten'} bounded questions for address, alias, mail,
          authority, policy, service-binding and delegation evidence. Named dependencies are
          shown but are not recursively queried.
        </p>
        {error === '' ? null : (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <div className="form-actions">
          <button className="primary-button" type="submit" disabled={state === 'loading'}>
            {state === 'loading' ? 'Following strands…' : 'Build evidence map'}
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
        </div>
      </form>
      <div className="run-status" aria-live="polite">
        {state === 'loading'
          ? 'Gathering bounded resolver observations.'
          : state === 'cancelled'
            ? 'The evidence run was cancelled.'
            : bundle === null
              ? null
              : `${String(bundle.nodes.length)} nodes and ${String(bundle.links.length)} relationships mapped.`}
      </div>
      {bundle === null ? null : (
        <section className="results" aria-labelledby="evidence-map-results-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Bounded evidence bundle</p>
              <h2 id="evidence-map-results-title">{bundle.subject}</h2>
            </div>
            <div className="export-actions">
              <StatusBadge tone={bundle.status === 'complete' ? 'pass' : 'warning'}>
                {bundle.status}
              </StatusBadge>
              <CopyButton label="Copy evidence JSON" text={evidenceJson} />
            </div>
          </div>
          {bundle.incompleteReasons.length === 0 ? null : (
            <article className="conclusion-panel partial-panel">
              <StatusBadge tone="warning">Loose ends retained</StatusBadge>
              <ul>
                {bundle.incompleteReasons.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            </article>
          )}
          {comparisons.length === 0 ? null : (
            <article className="result-panel">
              <div className="result-heading">
                <h3>Resolver agreement and loose ends</h3>
                <StatusBadge
                  tone={
                    comparisons.some((item) => item.state === 'disagreement')
                      ? 'warning'
                      : comparisons.some(
                            (item) =>
                              item.state === 'incomplete' || item.state === 'unavailable',
                          )
                        ? 'unknown'
                        : 'pass'
                  }
                >
                  {comparisons.filter((item) => item.state === 'disagreement').length}{' '}
                  differences
                </StatusBadge>
              </div>
              <p className="detail-note">
                Agreement means these recursive resolvers returned equivalent bounded evidence
                at this moment. It does not establish authoritative truth, global propagation,
                ownership, or safety.
              </p>
              <div className="comparison-list">
                {comparisons.map((comparison) => (
                  <details
                    key={`${comparison.questionName}-${comparison.questionType}`}
                    open={comparison.state !== 'agreement'}
                  >
                    <summary>
                      <span>{comparison.questionType}</span>
                      <StatusBadge
                        tone={
                          comparison.state === 'agreement'
                            ? 'pass'
                            : comparison.state === 'disagreement'
                              ? 'warning'
                              : 'unknown'
                        }
                      >
                        {comparison.state}
                      </StatusBadge>
                    </summary>
                    {comparison.differences.length === 0 ? null : (
                      <ul className="diagnostic-list">
                        {comparison.differences.map((difference) => (
                          <li key={difference.kind}>
                            <strong>{difference.label}</strong>
                            <span>{difference.explanation}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                    <div
                      className="table-scroll"
                      tabIndex={0}
                      role="region"
                      aria-label={`${comparison.questionType} resolver observations`}
                    >
                      <table>
                        <thead>
                          <tr>
                            <th>Resolver</th>
                            <th>Response</th>
                            <th>Answers</th>
                            <th>AD</th>
                            <th>Extended error / failure</th>
                          </tr>
                        </thead>
                        <tbody>
                          {comparison.observations.map((observation) => (
                            <tr key={observation.resolver}>
                              <td>{observation.resolver}</td>
                              <td>{observation.responseCode ?? 'Unavailable'}</td>
                              <td>{observation.answerCount ?? '—'}</td>
                              <td>
                                {observation.authenticatedData === null
                                  ? '—'
                                  : observation.authenticatedData
                                    ? 'Set'
                                    : 'Clear'}
                              </td>
                              <td>
                                {observation.error ??
                                  (observation.extendedErrors.length === 0
                                    ? 'None supplied'
                                    : observation.extendedErrors.join('; '))}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </details>
                ))}
              </div>
            </article>
          )}
          <EvidenceGraph bundle={bundle} />
        </section>
      )}
    </div>
  );
}
