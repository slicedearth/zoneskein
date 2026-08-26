import { useEffect, useMemo, useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { RecordTable } from '../components/RecordTable';
import { SnapshotButton } from '../components/SnapshotButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { validateDnsName } from '../core/dns/names';
import { bindRecord, recordDataText } from '../core/dns/presentation';
import { recordJson } from '../core/dns/records';
import { reverseNameFromAddress } from '../core/dns/reverse';
import {
  DNS_RECORD_TYPES,
  DnsQueryError,
  type DnsEdns,
  type DnsQuestion,
  type DnsRecord,
  type DnsRecordType,
  type DnsResponse,
  type ResolverDefinition,
  type ResolverId,
} from '../core/dns/types';
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
  escapeTechnicalText,
  markdownLiteral,
  markdownTableLiteral,
  projectedTechnicalText,
  stringifyTechnicalEvidence,
} from '../core/technical-text';

const DEFAULT_RECORD_TYPES = [
  'A',
  'AAAA',
  'MX',
  'TXT',
] as const satisfies readonly DnsRecordType[];
const FORWARD_RECORD_TYPES = DNS_RECORD_TYPES.filter((type) => type !== 'PTR');
const DIRECT_COMPARISON_RESOLVERS = [
  'cloudflare',
  'google',
] as const satisfies readonly ResolverId[];

interface QueryResultBase {
  readonly question: DnsQuestion;
  readonly resolverId: ResolverId;
}

interface QueryFailure extends QueryResultBase {
  readonly error: DnsQueryError;
  readonly outcome: 'error';
}

interface QuerySuccess extends QueryResultBase {
  readonly outcome: 'response';
  readonly response: DnsResponse;
}

type QueryResult = QueryFailure | QuerySuccess;

interface LookupRunDescriptor {
  readonly comparison: boolean;
  readonly recordTypes: readonly DnsRecordType[];
  readonly resolverIds: readonly ResolverId[];
  readonly startedAt: string;
  readonly submittedInput: string;
}

interface CompletedLookupRun {
  readonly completedAt: string;
  readonly descriptor: LookupRunDescriptor;
  readonly results: readonly QueryResult[];
}

type RunState = 'idle' | 'loading' | 'success' | 'partial' | 'error' | 'cancelled';

function queryName(input: string, type: DnsRecordType) {
  if (type !== 'PTR') return validateDnsName(input);
  const reverse = reverseNameFromAddress(input);
  return reverse.ok ? validateDnsName(reverse.value.name) : reverse;
}

function asError(cause: unknown): DnsQueryError {
  return cause instanceof DnsQueryError
    ? cause
    : new DnsQueryError(
        'transport-error',
        cause instanceof Error ? cause.message : 'The DNS query failed.',
      );
}

function rawHex(response: DnsResponse): string {
  return [...response.message.raw]
    .map((value) => value.toString(16).padStart(2, '0'))
    .join(' ');
}

function resolverProvenance(resolver: ResolverDefinition) {
  return {
    endpoint: resolver.endpoint,
    httpMethod: resolver.httpMethod,
    id: resolver.id,
    label: resolver.label,
    transport:
      resolver.relay === undefined
        ? { kind: 'direct' as const }
        : {
            intermediary: {
              label: resolver.relay.operator,
              privacyUrl: resolver.privacyUrl,
            },
            kind: 'relay' as const,
            upstream: {
              endpoint: resolver.relay.upstreamEndpoint,
              label: resolver.relay.upstreamLabel,
              privacyUrl: resolver.relay.upstreamPrivacyUrl,
            },
          },
  };
}

function markdownResolverProvenance(resolver: ResolverDefinition): string | null {
  if (resolver.relay === undefined) return null;
  return `- ${resolver.label}: ${resolver.relay.operator} compatibility relay → ${resolver.relay.upstreamLabel} (${resolver.relay.upstreamEndpoint})`;
}

function answerRecords(results: readonly QueryResult[]) {
  return results.flatMap((result) =>
    result.outcome === 'response' ? result.response.message.answers : [],
  );
}

function recordEvidence(record: DnsRecord): Record<string, unknown> {
  const evidence = recordJson(record);
  const data = evidence['data'];
  const owner = evidence['owner'];
  const rawFields = evidence['fields'];
  if (
    typeof data !== 'string' ||
    typeof owner !== 'string' ||
    rawFields === null ||
    typeof rawFields !== 'object' ||
    Array.isArray(rawFields)
  ) {
    throw new Error('DNS record evidence has an invalid internal shape.');
  }
  const fields = Object.fromEntries(
    Object.entries(rawFields).map(([label, value]) => {
      if (typeof value !== 'string') {
        throw new Error('DNS record evidence contains a non-text display field.');
      }
      return [label, projectedTechnicalText(value)];
    }),
  );
  return {
    ...evidence,
    data: projectedTechnicalText(data),
    fields,
    owner: projectedTechnicalText(owner),
  };
}

function ednsEvidence(edns: DnsEdns | undefined): Record<string, unknown> | undefined {
  if (edns === undefined) return undefined;
  return {
    ...edns,
    extendedErrors: edns.extendedErrors.map((error) => ({
      ...error,
      ...(error.text === undefined ? {} : { text: projectedTechnicalText(error.text) }),
    })),
  };
}

function jsonExport(run: CompletedLookupRun): string {
  return stringifyTechnicalEvidence(
    {
      observations: run.results.map((result) => {
        const resolver = RESOLVERS[result.resolverId];
        const context = {
          question: {
            name: result.question.name.absolute,
            type: result.question.type,
          },
          resolver: resolverProvenance(resolver),
        };
        if (result.outcome === 'error') {
          return {
            ...context,
            error: {
              code: result.error.code,
              message: result.error.message,
              ...(result.error.retryAfterMs === undefined
                ? {}
                : { retryAfterMs: result.error.retryAfterMs }),
            },
            outcome: result.outcome,
          };
        }
        const { message, cache, queryTimeMs, receivedAt } = result.response;
        return {
          ...context,
          outcome: result.outcome,
          response: {
            additionalRecords: message.additionals.map(recordEvidence),
            answerRecords: message.answers.map(recordEvidence),
            authorityRecords: message.authorities.map(recordEvidence),
            cache,
            edns: ednsEvidence(message.edns),
            flags: message.flags,
            messageBytes: message.messageBytes,
            negativeCacheTtl: message.negativeCacheTtl,
            queryTimeMs,
            receivedAt,
            responseCode: message.responseCode,
          },
        };
      }),
      run: {
        comparison: run.descriptor.comparison,
        completedAt: run.completedAt,
        recordTypes: run.descriptor.recordTypes,
        resolvers: run.descriptor.resolverIds.map((id) => resolverProvenance(RESOLVERS[id])),
        startedAt: run.descriptor.startedAt,
        submittedInput: run.descriptor.submittedInput,
      },
      schemaVersion: 1,
      textProjection: 'visible-escapes-v1',
      tool: 'lookup',
    },
    2,
  );
}

function markdownExport(run: CompletedLookupRun): string {
  const relayProvenance = run.descriptor.resolverIds
    .map((id) => markdownResolverProvenance(RESOLVERS[id]))
    .filter((line): line is string => line !== null);
  const lines = [
    `# ZoneSkein DNS lookup — ${markdownLiteral(run.descriptor.submittedInput)}`,
    '',
    `- Started: ${run.descriptor.startedAt}`,
    `- Completed: ${run.completedAt}`,
    `- Record types: ${run.descriptor.recordTypes.join(', ')}`,
    `- Resolvers: ${run.descriptor.resolverIds.map((id) => RESOLVERS[id].label).join(', ')}`,
    ...relayProvenance,
    '',
  ];
  for (const type of run.descriptor.recordTypes) {
    lines.push(`## ${type}`, '');
    for (const result of run.results.filter((candidate) => candidate.question.type === type)) {
      const resolver = RESOLVERS[result.resolverId];
      if (result.outcome === 'error') {
        lines.push(
          `### ${resolver.label} — ${result.error.code}`,
          '',
          `> ${markdownLiteral(result.error.message)}`,
          '',
        );
        continue;
      }
      const { message } = result.response;
      const count = message.answers.length;
      lines.push(
        `### ${resolver.label} — ${message.responseCode}`,
        '',
        `${String(count)} ${count === 1 ? 'answer' : 'answers'} · ${result.response.queryTimeMs.toFixed(1)} ms · cache ${result.response.cache} · AD ${message.flags.authenticatedData ? 'set' : 'clear'}`,
        '',
      );
      if (count === 0) {
        lines.push('_No answer records returned._', '');
        continue;
      }
      lines.push('| Owner | TTL | Type | Data |', '| --- | ---: | --- | --- |');
      for (const record of message.answers) {
        lines.push(
          `| ${markdownTableLiteral(record.owner)} | ${String(record.ttl)} | ${markdownTableLiteral(record.type)} | ${markdownTableLiteral(recordDataText(record))} |`,
        );
      }
      lines.push('');
    }
  }
  lines.push('> Recursive-resolver observations captured at one point in time.');
  return lines.join('\n');
}

function exportText(
  run: CompletedLookupRun,
  format: 'plain' | 'bind' | 'json' | 'markdown',
): string {
  const records = answerRecords(run.results);
  if (format === 'plain') return records.map(recordDataText).join('\n');
  if (format === 'bind') return records.map(bindRecord).join('\n');
  if (format === 'json') return jsonExport(run);
  return markdownExport(run);
}

function resultSummary(response: DnsResponse): string {
  const count = response.message.answers.length;
  return `${response.resolver.label}, ${response.message.responseCode}, ${String(count)} ${count === 1 ? 'answer' : 'answers'}, ${response.queryTimeMs.toFixed(1)} milliseconds, cache ${response.cache}, authenticated data ${response.message.flags.authenticatedData ? 'set' : 'clear'}`;
}

function ResultPanel({
  collapsedByDefault,
  result,
}: {
  readonly collapsedByDefault: boolean;
  readonly result: QueryResult;
}) {
  const resolver = RESOLVERS[result.resolverId];
  const [expanded, setExpanded] = useState(
    () =>
      result.outcome === 'response' &&
      (!collapsedByDefault ||
        result.response.message.responseCode !== 'NOERROR' ||
        (result.response.message.edns?.extendedErrors.length ?? 0) > 0),
  );
  if (result.outcome === 'error') {
    return (
      <article className="result-panel lookup-result">
        <div className="result-heading">
          <h4>{resolver.label}</h4>
          <StatusBadge tone="error">{result.error.code}</StatusBadge>
        </div>
        <p>
          <bdi className="technical-value" dir="ltr">
            {escapeTechnicalText(result.error.message)}
          </bdi>
        </p>
      </article>
    );
  }
  const { response } = result;
  const { message } = response;
  const answerCount = message.answers.length;
  return (
    <details
      className="result-panel lookup-result"
      open={expanded}
      onToggle={(event) => setExpanded(event.currentTarget.open)}
    >
      <summary className="result-summary" aria-label={resultSummary(response)}>
        <strong>{response.resolver.label}</strong>
        <StatusBadge tone={message.responseCode === 'NOERROR' ? 'pass' : 'warning'}>
          {message.responseCode}
        </StatusBadge>
        <span>
          {answerCount} {answerCount === 1 ? 'answer' : 'answers'}
        </span>
        <span>{response.queryTimeMs.toFixed(1)} ms</span>
        <span>cache {response.cache}</span>
        <span>AD {message.flags.authenticatedData ? 'set' : 'clear'}</span>
      </summary>
      {expanded ? (
        <>
          {message.edns !== undefined && message.edns.extendedErrors.length > 0 ? (
            <section
              className="conclusion-panel partial-panel"
              aria-label="Extended DNS errors"
            >
              <StatusBadge tone="warning">Resolver explanation</StatusBadge>
              <ul className="diagnostic-list">
                {message.edns.extendedErrors.map((error, index) => (
                  <li key={`${String(error.code)}-${String(index)}`}>
                    <span>
                      <strong>
                        EDE {error.code}: {error.name}
                      </strong>
                      {error.text === undefined ? null : (
                        <>
                          {' · '}
                          <bdi className="technical-value" dir="ltr">
                            {error.text}
                          </bdi>
                        </>
                      )}
                      {error.rawText === undefined ? null : (
                        <details className="raw-evidence-details">
                          <summary>
                            Raw EDE text · {error.rawText.octets} octets ·{' '}
                            {error.textEncoding ?? 'binary'}
                          </summary>
                          <code className="record-value technical-value" dir="ltr">
                            Base64: {error.rawText.value}
                          </code>
                        </details>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
          <RecordTable
            compact
            label={`${response.resolver.label} ${result.question.type} answer records`}
            records={message.answers}
          />
          <details className="protocol-details">
            <summary>Protocol details</summary>
            <dl className="metadata-grid">
              <div>
                <dt>Observed</dt>
                <dd>{new Date(response.receivedAt).toLocaleString()}</dd>
              </div>
              <div>
                <dt>Query time</dt>
                <dd>{response.queryTimeMs.toFixed(1)} ms</dd>
              </div>
              <div>
                <dt>Message size</dt>
                <dd>{message.messageBytes} bytes</dd>
              </div>
              <div>
                <dt>Cache</dt>
                <dd>{response.cache}</dd>
              </div>
              <div>
                <dt>DoH transport</dt>
                <dd>RFC 8484 {response.resolver.httpMethod}</dd>
              </div>
              {response.resolver.relay === undefined ? null : (
                <div>
                  <dt>Resolver path</dt>
                  <dd>
                    {response.resolver.relay.operator} relay →{' '}
                    {response.resolver.relay.upstreamLabel}
                  </dd>
                </div>
              )}
              {message.negativeCacheTtl === undefined ? null : (
                <div>
                  <dt>Negative cache TTL</dt>
                  <dd>{message.negativeCacheTtl} seconds</dd>
                </div>
              )}
              {message.edns === undefined ? null : (
                <div>
                  <dt>EDNS</dt>
                  <dd>
                    v{message.edns.version}, {message.edns.udpPayloadSize} byte UDP size
                  </dd>
                </div>
              )}
            </dl>
            <div className="flag-list" aria-label="DNS response flags">
              {Object.entries({
                AD: message.flags.authenticatedData,
                CD: message.flags.checkingDisabled,
                TC: message.flags.truncated,
                RD: message.flags.recursionDesired,
                RA: message.flags.recursionAvailable,
              }).map(([flag, enabled]) => (
                <span className={enabled ? 'flag-on' : 'flag-off'} key={flag}>
                  {flag} {enabled ? 'set' : 'clear'}
                </span>
              ))}
            </div>
          </details>
          {message.authorities.length > 0 ? (
            <details>
              <summary>Authority section ({message.authorities.length})</summary>
              <RecordTable
                compact
                label={`${response.resolver.label} ${result.question.type} authority records`}
                records={message.authorities}
              />
            </details>
          ) : null}
          {message.additionals.length > 0 ? (
            <details>
              <summary>Additional section ({message.additionals.length})</summary>
              <RecordTable
                compact
                label={`${response.resolver.label} ${result.question.type} additional records`}
                records={message.additionals}
              />
            </details>
          ) : null}
          <details>
            <summary>Raw DNS wire message</summary>
            <p className="detail-note">
              Exact response bytes in hexadecimal. This is a recursive-resolver response, not an
              authoritative observation.
            </p>
            <pre className="raw-output">{rawHex(response)}</pre>
          </details>
        </>
      ) : null}
    </details>
  );
}

export function LookupPage() {
  const [input, setInput] = useState('');
  const [selectedTypes, setSelectedTypes] = useState<Set<DnsRecordType>>(
    () => new Set(DEFAULT_RECORD_TYPES),
  );
  const [resolverId, setResolverId] = useState<SelectableResolverId>('google');
  const [compare, setCompare] = useState(false);
  const [state, setState] = useState<RunState>('idle');
  const [completedRun, setCompletedRun] = useState<CompletedLookupRun | null>(null);
  const [localError, setLocalError] = useState('');
  const activeRun = useRef<DnsQueryRun | null>(null);

  const selected = useMemo(
    () => DNS_RECORD_TYPES.filter((type) => selectedTypes.has(type)),
    [selectedTypes],
  );
  const exports = useMemo(
    () =>
      completedRun === null
        ? null
        : {
            bind: exportText(completedRun, 'bind'),
            json: exportText(completedRun, 'json'),
            markdown: exportText(completedRun, 'markdown'),
            plain: exportText(completedRun, 'plain'),
          },
    [completedRun],
  );
  const resolverNote = compare
    ? resolverSelectionNote('quad9')
    : resolverSelectionNote(resolverId);

  useEffect(
    () => () => {
      activeRun.current?.cancel();
      activeRun.current = null;
    },
    [],
  );

  function invalidateRun() {
    activeRun.current?.cancel();
    activeRun.current = null;
    setCompletedRun(null);
    setLocalError('');
    setState('idle');
  }

  function toggleType(type: DnsRecordType) {
    invalidateRun();
    setSelectedTypes((current) => {
      if (type === 'PTR') return current.has('PTR') ? new Set() : new Set(['PTR']);
      const next = current.has('PTR') ? new Set<DnsRecordType>() : new Set(current);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }

  function selectAllForwardTypes() {
    invalidateRun();
    setSelectedTypes(new Set(FORWARD_RECORD_TYPES));
  }

  function resetRecordTypes() {
    invalidateRun();
    setSelectedTypes(new Set(DEFAULT_RECORD_TYPES));
  }

  async function submit(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    setLocalError('');
    if (selected.length === 0) {
      setLocalError('Select at least one record type.');
      return;
    }
    const questions: DnsQuestion[] = [];
    for (const type of selected) {
      const parsed = queryName(input, type);
      if (!parsed.ok) {
        const message = typeof parsed.error === 'string' ? parsed.error : parsed.error.message;
        setLocalError(message);
        return;
      }
      questions.push({ name: parsed.value, type });
    }

    activeRun.current?.cancel();
    const run = new DnsQueryRun();
    activeRun.current = run;
    setCompletedRun(null);
    setState('loading');
    const targetResolvers: readonly SelectableResolverId[] = compare
      ? [...DIRECT_COMPARISON_RESOLVERS, 'quad9']
      : [resolverId];
    const descriptor: LookupRunDescriptor = {
      comparison: compare,
      recordTypes: questions.map((question) => question.type),
      resolverIds: [...targetResolvers],
      startedAt: new Date().toISOString(),
      submittedInput: input.trim(),
    };
    const clients = new Map(
      targetResolvers.map((targetResolver) => [
        targetResolver,
        createDnsResolver(targetResolver),
      ]),
    );
    const settled = await Promise.all(
      questions.flatMap((question) =>
        targetResolvers.map(async (targetResolver): Promise<QueryResult> => {
          try {
            const client = clients.get(targetResolver);
            if (client === undefined) throw new Error('Resolver client was not created.');
            const response = await run.query(client, question, {
              checkingDisabled: false,
              dnssecOk: true,
            });
            return {
              outcome: 'response',
              question,
              resolverId: response.resolver.id,
              response,
            };
          } catch (cause) {
            const client = clients.get(targetResolver);
            return {
              error: asError(cause),
              outcome: 'error',
              question,
              resolverId: client?.definition.id ?? targetResolver,
            };
          }
        }),
      ),
    );
    if (activeRun.current !== run) return;
    activeRun.current = null;
    setCompletedRun({
      completedAt: new Date().toISOString(),
      descriptor: {
        ...descriptor,
        resolverIds: [...new Set(settled.map((result) => result.resolverId))],
      },
      results: settled,
    });
    const successes = settled.filter((result) => result.outcome === 'response').length;
    const cancelled = settled.every(
      (result) => result.outcome === 'error' && result.error.code === 'aborted',
    );
    setState(
      cancelled
        ? 'cancelled'
        : successes === settled.length
          ? 'success'
          : successes === 0
            ? 'error'
            : 'partial',
    );
  }

  function cancel() {
    activeRun.current?.cancel();
  }

  function clearQueryAndResults() {
    invalidateRun();
    setInput('');
  }

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="DNS record explorer" title="Follow a name to its answers.">
        Choose the record types and resolver. ZoneSkein reads the wire answer, keeps its
        provenance attached, and shows the loose ends. Results remain point-in-time
        observations, not proof of global propagation.
      </ToolIntro>

      <form className="workbench-form" onSubmit={(event) => void submit(event)}>
        <div className="field-group field-wide">
          <label htmlFor="lookup-name">
            DNS name{selectedTypes.has('PTR') ? ' or IP address' : ''}
          </label>
          <input
            id="lookup-name"
            name="name"
            value={input}
            onChange={(event) => {
              invalidateRun();
              setInput(event.currentTarget.value);
            }}
            placeholder={selectedTypes.has('PTR') ? '2001:db8::1' : 'example.com'}
            maxLength={2048}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
        </div>
        <div className="field-group">
          <label htmlFor="resolver">Resolver</label>
          <select
            id="resolver"
            value={resolverId}
            aria-describedby={
              compare || resolverNote === undefined ? undefined : 'lookup-resolver-note'
            }
            onChange={(event) => {
              invalidateRun();
              setResolverId(event.currentTarget.value as SelectableResolverId);
            }}
            disabled={compare}
          >
            {SELECTABLE_RESOLVER_IDS.map((id) => (
              <option value={id} key={id}>
                {resolverOptionLabel(id)}
              </option>
            ))}
          </select>
          {compare || resolverNote === undefined ? null : (
            <small id="lookup-resolver-note">{resolverNote}</small>
          )}
        </div>
        <label className="check-control compare-control">
          <input
            type="checkbox"
            checked={compare}
            onChange={(event) => {
              invalidateRun();
              setCompare(event.currentTarget.checked);
            }}
          />
          Compare Cloudflare, Google and Quad9
        </label>
        {compare && resolverNote !== undefined ? (
          <small id="lookup-resolver-note" className="field-wide">
            {resolverNote}
          </small>
        ) : null}
        <fieldset className="record-picker">
          <legend>Record types</legend>
          <div className="record-picker-actions">
            <button className="quiet-button" type="button" onClick={selectAllForwardTypes}>
              Select all
            </button>
            <button className="quiet-button" type="button" onClick={resetRecordTypes}>
              Reset to defaults
            </button>
          </div>
          <p className="detail-note record-picker-note">
            Select all includes all {FORWARD_RECORD_TYPES.length} forward record types. PTR
            remains a separate reverse-address mode.
          </p>
          <div>
            {DNS_RECORD_TYPES.map((type) => (
              <label className="check-control" key={type}>
                <input
                  type="checkbox"
                  checked={selectedTypes.has(type)}
                  onChange={() => toggleType(type)}
                />
                {type}
              </label>
            ))}
          </div>
        </fieldset>
        {localError !== '' ? (
          <p className="form-error" role="alert">
            {localError}
          </p>
        ) : null}
        <div className="form-actions">
          <button className="primary-button" type="submit" disabled={state === 'loading'}>
            {state === 'loading' ? 'Querying…' : 'Inspect records'}
          </button>
          {state === 'loading' ? (
            <button className="quiet-button" type="button" onClick={cancel}>
              Cancel
            </button>
          ) : null}
          <button className="quiet-button" type="button" onClick={clearQueryAndResults}>
            Clear query and results
          </button>
        </div>
      </form>

      <div
        className="run-status"
        role="status"
        aria-label="DNS lookup status"
        aria-live="polite"
        aria-atomic="true"
      >
        {state === 'loading' ? 'DNS questions are in progress.' : null}
        {state === 'success' && completedRun !== null
          ? `Completed ${String(completedRun.results.length)} DNS questions.`
          : null}
        {state === 'partial' ? 'The run completed with partial results.' : null}
        {state === 'error' ? 'No DNS question completed successfully.' : null}
        {state === 'cancelled' ? 'The run was cancelled.' : null}
      </div>

      {completedRun === null || exports === null ? null : (
        <section className="results lookup-results" aria-labelledby="lookup-results-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Observed evidence</p>
              <h2 id="lookup-results-title">
                Lookup results for {completedRun.descriptor.submittedInput}
              </h2>
            </div>
            <div className="export-actions" aria-label="Copy results">
              {completedRun.descriptor.resolverIds.length > 1 ? (
                <>
                  <button
                    className="quiet-button"
                    type="button"
                    disabled
                    title="Use JSON or Markdown to preserve resolver provenance and failures."
                  >
                    Plain answers unavailable
                  </button>
                  <button
                    className="quiet-button"
                    type="button"
                    disabled
                    title="Use JSON or Markdown to preserve resolver provenance and failures."
                  >
                    BIND answers unavailable
                  </button>
                </>
              ) : (
                <>
                  <CopyButton label="Copy plain answers" text={exports.plain} />
                  <CopyButton label="Copy BIND answers" text={exports.bind} />
                </>
              )}
              <CopyButton label="Copy JSON evidence" text={exports.json} />
              <CopyButton label="Copy Markdown evidence" text={exports.markdown} />
              <SnapshotButton
                content={exports.json}
                title={`DNS lookup — ${completedRun.descriptor.submittedInput}`}
                tool="lookup"
              />
            </div>
          </div>
          {completedRun.descriptor.recordTypes.map((type) => (
            <section
              className="lookup-result-group"
              aria-labelledby={`lookup-result-group-${type.toLowerCase()}`}
              key={type}
            >
              <h3 id={`lookup-result-group-${type.toLowerCase()}`}>{type} records</h3>
              {completedRun.results
                .filter((result) => result.question.type === type)
                .map((result) => (
                  <ResultPanel
                    collapsedByDefault={completedRun.descriptor.comparison}
                    result={result}
                    key={`${result.question.type}-${result.resolverId}`}
                  />
                ))}
            </section>
          ))}
        </section>
      )}
    </div>
  );
}
