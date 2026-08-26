import { useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { SnapshotButton } from '../components/SnapshotButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { MAX_SNAPSHOT_CONTENT_OCTETS } from '../core/snapshots/store';
import { lintZoneSnippet } from '../core/zone/lint';
import type { ZoneDocument, ZoneSeverity } from '../core/zone/types';
import {
  analyseZoneDigest,
  type ZoneDigestReport,
  type ZoneDigestState,
} from '../core/zone/zonemd';

const MAX_ZONE_CHARACTERS = 262_144;

function tone(severity: ZoneSeverity) {
  return severity === 'error' ? 'error' : severity === 'warning' ? 'warning' : 'information';
}

function severityOrder(severity: ZoneSeverity): number {
  return severity === 'error' ? 0 : severity === 'warning' ? 1 : 2;
}

function digestTone(
  state: ZoneDigestState,
): 'pass' | 'information' | 'warning' | 'error' | 'unknown' {
  if (state === 'verified') return 'pass';
  if (state === 'generated') return 'information';
  if (state === 'mismatch') return 'error';
  if (state === 'unsupported') return 'warning';
  return 'unknown';
}

function digestLabel(state: ZoneDigestState): string {
  const labels: Readonly<Record<ZoneDigestState, string>> = {
    generated: 'Digests generated',
    mismatch: 'Digest mismatch',
    unavailable: 'Not calculated',
    unsupported: 'Unsupported publication',
    verified: 'Digest verified',
  };
  return labels[state];
}

export function ZoneLintPage() {
  const [source, setSource] = useState('');
  const [origin, setOrigin] = useState('');
  const [minimumTtl, setMinimumTtl] = useState('300');
  const [maximumTtl, setMaximumTtl] = useState('86400');
  const [completeZone, setCompleteZone] = useState(false);
  const [error, setError] = useState('');
  const [document, setDocument] = useState<ZoneDocument | null>(null);
  const [digestReport, setDigestReport] = useState<ZoneDigestReport | null>(null);
  const [analysing, setAnalysing] = useState(false);
  const runId = useRef(0);

  function invalidateResult() {
    runId.current += 1;
    setError('');
    setDocument(null);
    setDigestReport(null);
    setAnalysing(false);
  }

  async function lint(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const minimum = Number(minimumTtl);
    const maximum = Number(maximumTtl);
    if (
      !Number.isInteger(minimum) ||
      !Number.isInteger(maximum) ||
      minimum < 0 ||
      maximum < minimum
    ) {
      setError(
        'Recommended TTLs must be whole seconds, and maximum must not be below minimum.',
      );
      setDocument(null);
      setDigestReport(null);
      return;
    }
    const currentRun = runId.current + 1;
    runId.current = currentRun;
    setError('');
    setDocument(null);
    setDigestReport(null);
    setAnalysing(true);
    const next = lintZoneSnippet(source, {
      maximumTtl: maximum,
      minimumTtl: minimum,
      ...(origin.trim() === '' ? {} : { origin }),
    });
    const nextDigest = await analyseZoneDigest(next, completeZone);
    if (runId.current !== currentRun) return;
    setDocument(next);
    setDigestReport(nextDigest);
    setAnalysing(false);
  }

  function clear() {
    runId.current += 1;
    setSource('');
    setOrigin('');
    setCompleteZone(false);
    setError('');
    setDocument(null);
    setDigestReport(null);
    setAnalysing(false);
  }

  const diagnostics = [...(document?.diagnostics ?? [])].sort(
    (left, right) =>
      severityOrder(left.severity) - severityOrder(right.severity) ||
      left.line - right.line ||
      left.column - right.column,
  );
  const snapshotContent =
    document === null
      ? ''
      : JSON.stringify(
          {
            diagnostics,
            zoneDigest: digestReport,
            records: document.records,
            source: document.source,
          },
          null,
          2,
        );
  const snapshotOctets = new TextEncoder().encode(snapshotContent).length;

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="Zone-snippet linter" title="Catch record mistakes before publishing.">
        Parse a practical, recoverable subset of zone-file syntax locally. Your original text
        stays untouched; ZoneSkein offers individual corrections only when they are unambiguous.
      </ToolIntro>
      <form className="workbench-form zone-form" onSubmit={(event) => void lint(event)}>
        <div className="field-group field-wide zone-source">
          <label htmlFor="zone-source">Zone snippet</label>
          <textarea
            id="zone-source"
            value={source}
            onChange={(event) => {
              invalidateResult();
              setSource(event.currentTarget.value);
            }}
            placeholder={
              '$ORIGIN example.com.\n@ 3600 IN MX 10 mail.example.com.\nwww 300 IN A 192.0.2.10'
            }
            maxLength={MAX_ZONE_CHARACTERS}
            rows={16}
            spellCheck={false}
          />
          <span className="field-help">
            {source.length.toLocaleString()} / {MAX_ZONE_CHARACTERS.toLocaleString()} characters
          </span>
        </div>
        <div className="field-group">
          <label htmlFor="zone-origin">Origin when $ORIGIN is absent</label>
          <input
            id="zone-origin"
            value={origin}
            onChange={(event) => {
              invalidateResult();
              setOrigin(event.currentTarget.value);
            }}
            placeholder="example.com"
            maxLength={253}
            spellCheck={false}
          />
        </div>
        <div className="field-group ttl-range">
          <label htmlFor="minimum-ttl">Recommended TTL range</label>
          <div>
            <input
              id="minimum-ttl"
              type="number"
              min="0"
              value={minimumTtl}
              onChange={(event) => {
                invalidateResult();
                setMinimumTtl(event.currentTarget.value);
              }}
              aria-label="Minimum recommended TTL"
            />
            <span>to</span>
            <input
              type="number"
              min="0"
              value={maximumTtl}
              onChange={(event) => {
                invalidateResult();
                setMaximumTtl(event.currentTarget.value);
              }}
              aria-label="Maximum recommended TTL"
            />
          </div>
        </div>
        <label className="check-control field-wide">
          <input
            type="checkbox"
            aria-describedby="complete-zone-note"
            checked={completeZone}
            onChange={(event) => {
              invalidateResult();
              setCompleteZone(event.currentTarget.checked);
            }}
          />
          Treat this input as a complete standalone zone for ZONEMD calculation
        </label>
        <p className="detail-note field-wide" id="complete-zone-note">
          Leave this off for snippets. A zone-wide digest is meaningful only when every
          authoritative record, delegation, glue record, and DNSSEC record is present.
        </p>
        {error !== '' ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : null}
        <div className="form-actions">
          <button className="primary-button" type="submit" disabled={analysing}>
            {analysing ? 'Analysing…' : 'Lint zone input'}
          </button>
          <button className="quiet-button" type="button" onClick={clear}>
            Clear
          </button>
        </div>
      </form>
      <div className="run-status" aria-live="polite">
        {analysing
          ? 'The local zone analysis is in progress.'
          : document === null
            ? null
            : `Parsed ${String(document.records.length)} records and produced ${String(document.diagnostics.length)} diagnostics.`}
      </div>

      {document === null ? null : (
        <section className="results" aria-labelledby="lint-results-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Local analysis</p>
              <h2 id="lint-results-title">Lint results</h2>
            </div>
            <div className="export-actions">
              <StatusBadge
                tone={
                  diagnostics.some((item) => item.severity === 'error')
                    ? 'error'
                    : diagnostics.some((item) => item.severity === 'warning')
                      ? 'warning'
                      : 'pass'
                }
              >
                {diagnostics.length === 0
                  ? 'No diagnostics'
                  : `${String(diagnostics.length)} diagnostics`}
              </StatusBadge>
              {snapshotOctets <= MAX_SNAPSHOT_CONTENT_OCTETS ? (
                <SnapshotButton
                  content={snapshotContent}
                  title="Zone lint report"
                  tool="zone-lint"
                />
              ) : (
                <button
                  className="quiet-button"
                  type="button"
                  disabled
                  title={`This report exceeds the ${MAX_SNAPSHOT_CONTENT_OCTETS.toLocaleString()}-octet snapshot limit.`}
                >
                  Snapshot too large
                </button>
              )}
            </div>
          </div>
          {digestReport === null ? null : (
            <article className="result-panel">
              <div className="result-heading">
                <h3>Complete-zone integrity digest</h3>
                <StatusBadge tone={digestTone(digestReport.state)}>
                  {digestLabel(digestReport.state)}
                </StatusBadge>
              </div>
              <p>{digestReport.explanation}</p>
              <dl className="metadata-grid">
                <div>
                  <dt>Zone origin</dt>
                  <dd>{digestReport.origin ?? 'Unavailable'}</dd>
                </div>
                <div>
                  <dt>SOA serial</dt>
                  <dd>{digestReport.serial ?? 'Unavailable'}</dd>
                </div>
                <div>
                  <dt>Records digested</dt>
                  <dd>{digestReport.includedRecords}</dd>
                </div>
                <div>
                  <dt>Duplicates omitted</dt>
                  <dd>{digestReport.duplicatesOmitted}</dd>
                </div>
                <div>
                  <dt>Out-of-zone omitted</dt>
                  <dd>{digestReport.excludedOutOfZoneRecords}</dd>
                </div>
                <div>
                  <dt>Apex digest records omitted</dt>
                  <dd>{digestReport.excludedApexRecords}</dd>
                </div>
              </dl>
              {digestReport.digests.length === 0 ? null : (
                <div
                  className="table-scroll"
                  tabIndex={0}
                  role="region"
                  aria-label="Calculated and published zone digests"
                >
                  <table>
                    <caption>Canonical SIMPLE zone digests</caption>
                    <thead>
                      <tr>
                        <th>Algorithm</th>
                        <th>Calculated digest</th>
                        <th>Published checks</th>
                      </tr>
                    </thead>
                    <tbody>
                      {digestReport.digests.map((digest) => (
                        <tr key={digest.hashAlgorithm}>
                          <td>{digest.hashName}</td>
                          <td>
                            <code className="record-value">{digest.calculated}</code>
                          </td>
                          <td>
                            {digest.publications.length === 0 ? (
                              'Not published'
                            ) : (
                              <ul className="diagnostic-list">
                                {digest.publications.map((publication, index) => (
                                  <li key={`${String(publication.scheme)}-${String(index)}`}>
                                    <StatusBadge
                                      tone={
                                        publication.matches === true
                                          ? 'pass'
                                          : publication.matches === false
                                            ? 'error'
                                            : 'unknown'
                                      }
                                    >
                                      {publication.matches === true
                                        ? 'Matches'
                                        : publication.matches === false
                                          ? 'Mismatch'
                                          : 'Not verified'}
                                    </StatusBadge>
                                    <span>{publication.reason ?? 'Supported publication'}</span>
                                  </li>
                                ))}
                              </ul>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {digestReport.suggestedRecords.length === 0 ? null : (
                <div>
                  <h4>Generated publication records</h4>
                  <ul className="diagnostic-list">
                    {digestReport.suggestedRecords.map((record) => (
                      <li key={record.hashAlgorithm}>
                        <code className="record-value">{record.text}</code>
                        <CopyButton
                          label={`Copy ${record.hashName} ZONEMD record`}
                          text={record.text}
                        />
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <p className="detail-note">
                {digestReport.authentication === 'covering-signature-present-but-unvalidated'
                  ? 'A covering RRSIG is present in the supplied text, but this local file workflow has not validated that signature or its chain of trust. The digest result therefore establishes internal consistency only.'
                  : 'Without separately validated DNSSEC protection, a ZONEMD match is a checksum against accidental change, not proof of origin or resistance to deliberate replacement.'}
              </p>
              {digestReport.issues.length === 0 ? null : (
                <ul className="diagnostic-list">
                  {digestReport.issues.map((issue) => (
                    <li key={issue}>{issue}</li>
                  ))}
                </ul>
              )}
            </article>
          )}
          <article className="result-panel">
            <h3>Diagnostics</h3>
            {diagnostics.length === 0 ? (
              <p className="empty-note">No rule fired for this supported syntax subset.</p>
            ) : (
              <div
                className="table-scroll"
                tabIndex={0}
                role="region"
                aria-label="Zone lint diagnostics"
              >
                <table>
                  <caption>Zone lint diagnostics</caption>
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Location</th>
                      <th>Rule</th>
                      <th>Explanation</th>
                      <th>Suggested correction</th>
                    </tr>
                  </thead>
                  <tbody>
                    {diagnostics.map((item, index) => (
                      <tr
                        key={`${item.rule}-${String(item.line)}-${String(item.column)}-${String(index)}`}
                      >
                        <td>
                          <StatusBadge tone={tone(item.severity)}>{item.severity}</StatusBadge>
                        </td>
                        <td>
                          {item.line}:{item.column}
                        </td>
                        <td>
                          <code>{item.rule}</code>
                        </td>
                        <td>{item.message}</td>
                        <td>
                          {item.suggestion === undefined ? (
                            '—'
                          ) : (
                            <div className="suggestion">
                              <code>{item.suggestion}</code>
                              <CopyButton text={item.suggestion} />
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </article>
          <article className="result-panel">
            <h3>Parsed records</h3>
            {document.records.length === 0 ? (
              <p className="empty-note">No records could be parsed.</p>
            ) : (
              <div
                className="table-scroll"
                tabIndex={0}
                role="region"
                aria-label="Parsed zone records"
              >
                <table>
                  <caption>Parsed zone records</caption>
                  <thead>
                    <tr>
                      <th>Line</th>
                      <th>Owner</th>
                      <th>TTL</th>
                      <th>Type</th>
                      <th>Data</th>
                    </tr>
                  </thead>
                  <tbody>
                    {document.records.map((record, index) => (
                      <tr key={`${record.owner}-${record.type}-${String(index)}`}>
                        <td>{record.line}</td>
                        <td>
                          <code>{record.owner}</code>
                        </td>
                        <td>{record.ttl ?? 'Inherited / unspecified'}</td>
                        <td>{record.type}</td>
                        <td>
                          <code className="record-value">
                            {record.rdata.map((token) => token.raw).join(' ')}
                          </code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </article>
          <details className="method-note">
            <summary>Supported syntax and conclusion limits</summary>
            <p>
              This is a zone-snippet linter, not a complete BIND parser or a provider-specific
              validator. It understands comments, quoted TXT chunks, parenthesised records,
              $ORIGIN, $TTL, inherited owners, relative names, IN class, and common record
              types. Provider extensions such as ALIAS and ANAME require the provider’s own
              validation. Complete-zone digest mode implements canonical RFC 8976 SIMPLE SHA-384
              and SHA-512 calculation, duplicate omission, apex ZONEMD and covering RRSIG
              exclusion, numeric type ordering, and RFC 3597 generic RDATA. It stops when any
              included record cannot be encoded without guessing.
            </p>
          </details>
        </section>
      )}
    </div>
  );
}
