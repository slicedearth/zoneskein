import { useMemo, useRef, useState } from 'react';

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
  type DnsQuestion,
  type DnsRecordType,
  type DnsResponse,
  type ResolverId,
} from '../core/dns/types';
import { DnsQueryRun } from '../core/doh/query-run';
import { RESOLVERS } from '../core/doh/resolvers';
import { WireDnsResolver } from '../core/doh/wire-resolver';

const DEFAULT_TYPES = new Set<DnsRecordType>(['A', 'AAAA', 'MX', 'TXT']);
const RESOLVER_IDS = Object.keys(RESOLVERS) as ResolverId[];

interface QueryResult {
  readonly error?: DnsQueryError;
  readonly response?: DnsResponse;
  readonly resolverId: ResolverId;
  readonly type: DnsRecordType;
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

function exportText(
  results: readonly QueryResult[],
  format: 'plain' | 'bind' | 'json' | 'markdown',
) {
  const responses = results.flatMap((result) =>
    result.response === undefined ? [] : [result.response],
  );
  const records = responses.flatMap((response) => response.message.answers);
  if (format === 'plain') return records.map(recordDataText).join('\n');
  if (format === 'bind') return records.map(bindRecord).join('\n');
  if (format === 'json') {
    return JSON.stringify(
      responses.map((response) => ({
        edns: response.message.edns,
        flags: response.message.flags,
        messageBytes: response.message.messageBytes,
        negativeCacheTtl: response.message.negativeCacheTtl,
        question: response.question,
        records: response.message.answers.map(recordJson),
        resolver: response.resolver.label,
        responseCode: response.message.responseCode,
      })),
      null,
      2,
    );
  }
  const rows = records.map(
    (record) =>
      `| ${record.owner} | ${String(record.ttl)} | ${record.type} | ${recordDataText(record).replaceAll('|', '\\|')} |`,
  );
  return [
    '# ZoneSkein DNS lookup',
    '',
    '| Owner | TTL | Type | Data |',
    '| --- | ---: | --- | --- |',
    ...rows,
    '',
    '> Recursive-resolver observations captured at one point in time.',
  ].join('\n');
}

function ResultPanel({ result }: { readonly result: QueryResult }) {
  if (result.error !== undefined) {
    return (
      <article className="result-panel">
        <div className="result-heading">
          <h3>
            {RESOLVERS[result.resolverId].label} · {result.type}
          </h3>
          <StatusBadge tone="error">{result.error.code}</StatusBadge>
        </div>
        <p>{result.error.message}</p>
      </article>
    );
  }
  const response = result.response;
  if (response === undefined) return null;
  const { message } = response;
  return (
    <article className="result-panel">
      <div className="result-heading">
        <h3>
          {response.resolver.label} · {result.type}
        </h3>
        <StatusBadge tone={message.responseCode === 'NOERROR' ? 'pass' : 'warning'}>
          {message.responseCode}
        </StatusBadge>
      </div>
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
      {message.edns !== undefined && message.edns.extendedErrors.length > 0 ? (
        <section className="conclusion-panel partial-panel" aria-label="Extended DNS errors">
          <StatusBadge tone="warning">Resolver explanation</StatusBadge>
          <ul className="diagnostic-list">
            {message.edns.extendedErrors.map((error, index) => (
              <li key={`${String(error.code)}-${String(index)}`}>
                <span>
                  <strong>
                    EDE {error.code}: {error.name}
                  </strong>
                  {error.text === undefined ? '' : ` · ${error.text}`}
                </span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      <RecordTable records={message.answers} />
      {message.authorities.length > 0 ? (
        <details>
          <summary>Authority section ({message.authorities.length})</summary>
          <RecordTable records={message.authorities} />
        </details>
      ) : null}
      {message.additionals.length > 0 ? (
        <details>
          <summary>Additional section ({message.additionals.length})</summary>
          <RecordTable records={message.additionals} />
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
    </article>
  );
}

export function LookupPage() {
  const [input, setInput] = useState('');
  const [selectedTypes, setSelectedTypes] = useState(DEFAULT_TYPES);
  const [resolverId, setResolverId] = useState<ResolverId>('google');
  const [compare, setCompare] = useState(false);
  const [state, setState] = useState<RunState>('idle');
  const [results, setResults] = useState<readonly QueryResult[]>([]);
  const [localError, setLocalError] = useState('');
  const activeRun = useRef<DnsQueryRun | null>(null);

  const selected = useMemo(
    () => DNS_RECORD_TYPES.filter((type) => selectedTypes.has(type)),
    [selectedTypes],
  );

  function toggleType(type: DnsRecordType) {
    setSelectedTypes((current) => {
      if (type === 'PTR') return current.has('PTR') ? new Set() : new Set(['PTR']);
      const next = current.has('PTR') ? new Set<DnsRecordType>() : new Set(current);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
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
    setResults([]);
    setState('loading');
    const targetResolvers = compare ? RESOLVER_IDS : [resolverId];
    const clients = Object.fromEntries(
      targetResolvers.map((targetResolver) => [
        targetResolver,
        new WireDnsResolver(RESOLVERS[targetResolver]),
      ]),
    ) as Partial<Record<ResolverId, WireDnsResolver>>;
    const settled = await Promise.all(
      targetResolvers.flatMap((targetResolver) =>
        questions.map(async (question): Promise<QueryResult> => {
          try {
            const client = clients[targetResolver];
            if (client === undefined) throw new Error('Resolver client was not created.');
            const response = await run.query(client, question, {
              checkingDisabled: false,
              dnssecOk: true,
            });
            return { resolverId: targetResolver, response, type: question.type };
          } catch (cause) {
            return { error: asError(cause), resolverId: targetResolver, type: question.type };
          }
        }),
      ),
    );
    if (activeRun.current !== run) return;
    setResults(settled);
    const successes = settled.filter((result) => result.response !== undefined).length;
    const cancelled = settled.every((result) => result.error?.code === 'aborted');
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

  function clear() {
    activeRun.current?.cancel();
    activeRun.current = null;
    setInput('');
    setResults([]);
    setLocalError('');
    setState('idle');
  }

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="DNS record explorer" title="Inspect a recursive answer.">
        Query explicitly selected record types using DNS-over-HTTPS wire messages. Results are
        point-in-time observations from the resolver you choose, not proof of global
        propagation.
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
            onChange={(event) => setInput(event.currentTarget.value)}
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
            onChange={(event) => setResolverId(event.currentTarget.value as ResolverId)}
            disabled={compare}
          >
            {RESOLVER_IDS.map((id) => (
              <option value={id} key={id}>
                {RESOLVERS[id].label}
              </option>
            ))}
          </select>
        </div>
        <label className="check-control compare-control">
          <input
            type="checkbox"
            checked={compare}
            onChange={(event) => setCompare(event.currentTarget.checked)}
          />
          Compare all allowlisted resolvers
        </label>
        <fieldset className="record-picker">
          <legend>Record types</legend>
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
          <button className="quiet-button" type="button" onClick={clear}>
            Clear
          </button>
        </div>
      </form>

      <div className="run-status" aria-live="polite">
        {state === 'loading' ? 'DNS questions are in progress.' : null}
        {state === 'success' ? `Completed ${String(results.length)} DNS questions.` : null}
        {state === 'partial' ? 'The run completed with partial results.' : null}
        {state === 'error' ? 'No DNS question completed successfully.' : null}
        {state === 'cancelled' ? 'The run was cancelled.' : null}
      </div>

      {results.length > 0 ? (
        <section className="results" aria-labelledby="lookup-results-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Observed evidence</p>
              <h2 id="lookup-results-title">Lookup results</h2>
            </div>
            <div className="export-actions" aria-label="Copy results">
              <CopyButton label="Copy plain" text={exportText(results, 'plain')} />
              <CopyButton label="Copy BIND" text={exportText(results, 'bind')} />
              <CopyButton label="Copy JSON" text={exportText(results, 'json')} />
              <CopyButton label="Copy Markdown" text={exportText(results, 'markdown')} />
              <SnapshotButton
                content={exportText(results, 'json')}
                title={`DNS lookup — ${input.trim()}`}
                tool="lookup"
              />
            </div>
          </div>
          {results.map((result, index) => (
            <ResultPanel
              result={result}
              key={`${result.resolverId}-${result.type}-${String(index)}`}
            />
          ))}
        </section>
      ) : null}
    </div>
  );
}
