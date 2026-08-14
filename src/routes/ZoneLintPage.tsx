import { useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { SnapshotButton } from '../components/SnapshotButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { lintZoneSnippet } from '../core/zone/lint';
import type { ZoneDocument, ZoneSeverity } from '../core/zone/types';

const MAX_ZONE_CHARACTERS = 262_144;

function tone(severity: ZoneSeverity) {
  return severity === 'error' ? 'error' : severity === 'warning' ? 'warning' : 'information';
}

function severityOrder(severity: ZoneSeverity): number {
  return severity === 'error' ? 0 : severity === 'warning' ? 1 : 2;
}

export function ZoneLintPage() {
  const [source, setSource] = useState('');
  const [origin, setOrigin] = useState('');
  const [minimumTtl, setMinimumTtl] = useState('300');
  const [maximumTtl, setMaximumTtl] = useState('86400');
  const [error, setError] = useState('');
  const [document, setDocument] = useState<ZoneDocument | null>(null);

  function lint(event: React.SyntheticEvent<HTMLFormElement>) {
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
      return;
    }
    setError('');
    setDocument(
      lintZoneSnippet(source, {
        maximumTtl: maximum,
        minimumTtl: minimum,
        ...(origin.trim() === '' ? {} : { origin }),
      }),
    );
  }

  function clear() {
    setSource('');
    setOrigin('');
    setError('');
    setDocument(null);
  }

  const diagnostics = [...(document?.diagnostics ?? [])].sort(
    (left, right) =>
      severityOrder(left.severity) - severityOrder(right.severity) ||
      left.line - right.line ||
      left.column - right.column,
  );

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="Zone-snippet linter" title="Catch record mistakes before publishing.">
        Parse a practical, recoverable subset of zone-file syntax locally. Your original text
        stays untouched; ZoneSkein offers individual corrections only when they are unambiguous.
      </ToolIntro>
      <form className="workbench-form zone-form" onSubmit={lint}>
        <div className="field-group field-wide zone-source">
          <label htmlFor="zone-source">Zone snippet</label>
          <textarea
            id="zone-source"
            value={source}
            onChange={(event) => setSource(event.currentTarget.value)}
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
            onChange={(event) => setOrigin(event.currentTarget.value)}
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
              onChange={(event) => setMinimumTtl(event.currentTarget.value)}
              aria-label="Minimum recommended TTL"
            />
            <span>to</span>
            <input
              type="number"
              min="0"
              value={maximumTtl}
              onChange={(event) => setMaximumTtl(event.currentTarget.value)}
              aria-label="Maximum recommended TTL"
            />
          </div>
        </div>
        {error !== '' ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : null}
        <div className="form-actions">
          <button className="primary-button" type="submit">
            Lint snippet
          </button>
          <button className="quiet-button" type="button" onClick={clear}>
            Clear
          </button>
        </div>
      </form>
      <div className="run-status" aria-live="polite">
        {document === null
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
              <SnapshotButton
                content={JSON.stringify(
                  { diagnostics, records: document.records, source: document.source },
                  null,
                  2,
                )}
                title="Zone lint report"
                tool="zone-lint"
              />
            </div>
          </div>
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
              validation.
            </p>
          </details>
        </section>
      )}
    </div>
  );
}
