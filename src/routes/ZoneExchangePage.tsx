import { useEffect, useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import {
  expandZoneBundle,
  ZONE_BUNDLE_LIMITS,
  type ExpandedZoneBundle,
  type ZoneBundleFile,
} from '../core/zone/bundle';
import {
  previewDomainConnectTemplate,
  type DomainConnectPreview,
} from '../core/zone/domain-connect';
import { exportZoneInfrastructure, type ZoneInfrastructureExports } from '../core/zone/iac';
import { lintZoneSnippet } from '../core/zone/lint';
import { escapeTechnicalText } from '../core/technical-text';
import { RequestLifetime } from '../core/request-lifetime';

type Mode = 'bundle' | 'template' | 'export';

const SAMPLE_TEMPLATE = JSON.stringify(
  {
    providerId: 'service.example',
    providerName: 'Example Service',
    records: [
      { host: '@', pointsTo: '%address%', ttl: 300, type: 'A' },
      { host: 'www', pointsTo: '@', ttl: 300, type: 'CNAME' },
    ],
    serviceId: 'website',
    serviceName: 'Website',
    version: 1,
  },
  null,
  2,
);

function commonRoot(files: readonly File[]): string | null {
  const roots = files.map((file) => file.webkitRelativePath.split('/')[0]).filter(Boolean);
  return roots.length === files.length && new Set(roots).size === 1 ? (roots[0] ?? null) : null;
}

async function localFiles(value: FileList): Promise<readonly ZoneBundleFile[]> {
  const files = [...value];
  if (files.length > ZONE_BUNDLE_LIMITS.files)
    throw new Error(`Choose no more than ${String(ZONE_BUNDLE_LIMITS.files)} files.`);
  const total = files.reduce((sum, file) => sum + file.size, 0);
  if (total > ZONE_BUNDLE_LIMITS.sourceCharacters)
    throw new Error(
      `Combined files exceed the ${ZONE_BUNDLE_LIMITS.sourceCharacters.toLocaleString()}-octet input limit.`,
    );
  const root = commonRoot(files);
  const decoder = new TextDecoder('utf-8', { fatal: true });
  return Promise.all(
    files.map(async (file) => {
      const path = file.webkitRelativePath || file.name;
      return {
        name: root === null ? path : path.slice(root.length + 1),
        source: decoder.decode(await file.arrayBuffer()),
      };
    }),
  );
}

function tone(status: 'complete' | 'invalid' | 'ready' | 'partial') {
  return status === 'complete' || status === 'ready'
    ? 'pass'
    : status === 'partial'
      ? 'warning'
      : 'error';
}

export function ZoneExchangePage() {
  const [mode, setMode] = useState<Mode>('bundle');
  const [files, setFiles] = useState<readonly ZoneBundleFile[]>([]);
  const [entry, setEntry] = useState('');
  const [bundleOrigin, setBundleOrigin] = useState('');
  const [bundleResult, setBundleResult] = useState<ExpandedZoneBundle | null>(null);
  const [template, setTemplate] = useState('');
  const [templateDomain, setTemplateDomain] = useState('');
  const [variables, setVariables] = useState('{}');
  const [templateResult, setTemplateResult] = useState<DomainConnectPreview | null>(null);
  const [exportSource, setExportSource] = useState('');
  const [exportOrigin, setExportOrigin] = useState('');
  const [exports, setExports] = useState<ZoneInfrastructureExports | null>(null);
  const [error, setError] = useState('');
  const [reading, setReading] = useState(false);
  const lifetime = useRef(new RequestLifetime());

  useEffect(() => {
    const current = lifetime.current;
    current.enter();
    return () => current.leave();
  }, []);

  function resetResults(): void {
    lifetime.current.invalidate();
    setReading(false);
    setError('');
    setBundleResult(null);
    setTemplateResult(null);
    setExports(null);
  }

  async function selectFiles(list: FileList | null): Promise<void> {
    resetResults();
    setFiles([]);
    setEntry('');
    if (list === null || list.length === 0) return;
    const generation = lifetime.current.capture();
    setReading(true);
    try {
      const selected = await localFiles(list);
      if (!lifetime.current.isCurrent(generation)) return;
      setFiles(selected);
      setEntry(selected[0]?.name ?? '');
    } catch (cause) {
      if (!lifetime.current.isCurrent(generation)) return;
      setFiles([]);
      setEntry('');
      setError(cause instanceof Error ? cause.message : 'The local files could not be read.');
    } finally {
      if (lifetime.current.isCurrent(generation)) setReading(false);
    }
  }

  function expand(event: React.SyntheticEvent<HTMLFormElement>): void {
    event.preventDefault();
    setError('');
    const result = expandZoneBundle(files, entry, bundleOrigin);
    setBundleResult(result);
  }

  function previewTemplate(event: React.SyntheticEvent<HTMLFormElement>): void {
    event.preventDefault();
    setError('');
    try {
      const parsedVariables: unknown = JSON.parse(variables);
      setTemplateResult(
        previewDomainConnectTemplate(template, templateDomain, parsedVariables),
      );
    } catch (cause) {
      setTemplateResult(null);
      setError(cause instanceof Error ? cause.message : 'The template could not be previewed.');
    }
  }

  function generateExports(event: React.SyntheticEvent<HTMLFormElement>): void {
    event.preventDefault();
    setError('');
    const document = lintZoneSnippet(exportSource, {
      ...(exportOrigin.trim() === '' ? {} : { origin: exportOrigin }),
    });
    if (document.incomplete !== undefined) {
      setExports(null);
      setError(document.incomplete.message);
      return;
    }
    setExports(exportZoneInfrastructure(document));
  }

  return (
    <div className="tool-page">
      <ToolIntro
        eyebrow="Zone interoperability"
        title="Move the zone without dropping a thread."
      >
        Expand a local master-file bundle, rehearse a service template, or translate a reviewed
        common record set into portable configuration. Nothing here signs in to or changes a DNS
        provider.
      </ToolIntro>
      <div className="mode-tabs" role="group" aria-label="Zone Exchange mode">
        {(
          [
            ['bundle', 'Zone bundle'],
            ['template', 'Service template'],
            ['export', 'Portable export'],
          ] as const
        ).map(([value, label]) => (
          <button
            key={value}
            type="button"
            aria-pressed={mode === value}
            onClick={() => {
              resetResults();
              setMode(value);
              setError('');
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {mode === 'bundle' ? (
        <form className="workbench-form zone-form" onSubmit={expand}>
          <div className="field-group field-wide">
            <span className="field-label">Local master files</span>
            <div className="form-actions">
              <label className="file-button" htmlFor="zone-bundle-files">
                Choose files
              </label>
              <input
                id="zone-bundle-files"
                className="visually-hidden"
                type="file"
                multiple
                onChange={(event) => void selectFiles(event.currentTarget.files)}
              />
              <label className="file-button" htmlFor="zone-bundle-directory">
                Choose folder
              </label>
              <input
                id="zone-bundle-directory"
                className="visually-hidden"
                type="file"
                multiple
                {...({ webkitdirectory: '' } as React.InputHTMLAttributes<HTMLInputElement>)}
                onChange={(event) => void selectFiles(event.currentTarget.files)}
              />
              <span className="field-help" role="status">
                {reading
                  ? 'Reading local files…'
                  : files.length === 0
                    ? 'No files selected'
                    : `${String(files.length)} local file${files.length === 1 ? '' : 's'}`}
              </span>
            </div>
          </div>
          <div className="field-group">
            <label htmlFor="zone-bundle-entry">Entry file</label>
            <select
              id="zone-bundle-entry"
              value={entry}
              onChange={(event) => {
                setEntry(event.currentTarget.value);
                setBundleResult(null);
              }}
              disabled={files.length === 0}
            >
              {files.map((file) => (
                <option key={file.name} value={file.name}>
                  {file.name}
                </option>
              ))}
            </select>
          </div>
          <div className="field-group">
            <label htmlFor="zone-bundle-origin">Initial origin, if absent</label>
            <input
              id="zone-bundle-origin"
              value={bundleOrigin}
              onChange={(event) => {
                resetResults();
                setBundleOrigin(event.currentTarget.value);
                setBundleResult(null);
              }}
              placeholder="example.com"
              maxLength={253}
              spellCheck={false}
            />
          </div>
          <p className="detail-note field-wide">
            Supports local $INCLUDE, bounded $GENERATE substitutions, nested origin restoration,
            RFC 3597 generic records, cycle checks, and line provenance. Included paths cannot
            leave the selected bundle.
          </p>
          <div className="form-actions">
            <button className="primary-button" type="submit" disabled={files.length === 0}>
              Expand bundle
            </button>
            <button
              className="quiet-button"
              type="button"
              onClick={() => {
                resetResults();
                setFiles([]);
                setEntry('');
                setBundleResult(null);
                setError('');
              }}
            >
              Clear
            </button>
          </div>
        </form>
      ) : mode === 'template' ? (
        <form className="workbench-form zone-form" onSubmit={previewTemplate}>
          <div className="field-group field-wide">
            <label htmlFor="domain-connect-template">Domain Connect template JSON</label>
            <textarea
              id="domain-connect-template"
              value={template}
              onChange={(event) => {
                setTemplate(event.currentTarget.value);
                setTemplateResult(null);
              }}
              maxLength={262_144}
              rows={14}
              spellCheck={false}
              placeholder={SAMPLE_TEMPLATE}
            />
          </div>
          <div className="field-group">
            <label htmlFor="template-domain">Domain</label>
            <input
              id="template-domain"
              value={templateDomain}
              onChange={(event) => {
                setTemplateDomain(event.currentTarget.value);
                setTemplateResult(null);
              }}
              placeholder="example.com"
              maxLength={253}
              spellCheck={false}
            />
          </div>
          <div className="field-group">
            <label htmlFor="template-variables">Variables JSON</label>
            <textarea
              id="template-variables"
              value={variables}
              onChange={(event) => {
                setVariables(event.currentTarget.value);
                setTemplateResult(null);
              }}
              rows={6}
              maxLength={65_536}
              spellCheck={false}
              placeholder={'{"address":"192.0.2.10"}'}
            />
          </div>
          <p className="detail-note field-wide">
            The preview validates and substitutes common A, AAAA, CNAME, NS, TXT, MX, SPFM, SRV,
            and generic record entries. Redirect and apex-alias actions remain explicit because
            they are provider behaviour, not portable DNS records.
          </p>
          <div className="form-actions">
            <button className="primary-button" type="submit">
              Preview records
            </button>
            <button
              className="quiet-button"
              type="button"
              onClick={() => {
                setTemplate(SAMPLE_TEMPLATE);
                setVariables('{\n  "address": "192.0.2.10"\n}');
                setTemplateDomain('example.com');
                setTemplateResult(null);
                setError('');
              }}
            >
              Load safe example
            </button>
          </div>
        </form>
      ) : (
        <form className="workbench-form zone-form" onSubmit={generateExports}>
          <div className="field-group field-wide">
            <label htmlFor="exchange-zone-source">Reviewed BIND-style zone text</label>
            <textarea
              id="exchange-zone-source"
              value={exportSource}
              onChange={(event) => {
                setExportSource(event.currentTarget.value);
                setExports(null);
              }}
              maxLength={262_144}
              rows={16}
              spellCheck={false}
              placeholder="$ORIGIN example.com.\n@ 300 IN A 192.0.2.10"
            />
          </div>
          <div className="field-group">
            <label htmlFor="exchange-zone-origin">Origin when $ORIGIN is absent</label>
            <input
              id="exchange-zone-origin"
              value={exportOrigin}
              onChange={(event) => {
                setExportOrigin(event.currentTarget.value);
                setExports(null);
              }}
              placeholder="example.com"
              maxLength={253}
              spellCheck={false}
            />
          </div>
          <p className="detail-note field-wide">
            Exports only the common record subset represented consistently by both target
            formats. Unsupported, malformed, DNSSEC-managed, and out-of-zone records are
            reported and omitted instead of guessed.
          </p>
          <div className="form-actions">
            <button className="primary-button" type="submit">
              Generate portable drafts
            </button>
            {bundleResult?.status === 'complete' ? (
              <button
                className="quiet-button"
                type="button"
                onClick={() => {
                  setExportSource(bundleResult.source);
                  setExportOrigin(bundleOrigin);
                  setExports(null);
                }}
              >
                Use expanded bundle
              </button>
            ) : null}
          </div>
        </form>
      )}

      {error === '' ? null : (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}

      {mode === 'bundle' && bundleResult !== null ? (
        <section className="results" aria-labelledby="bundle-result-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Local expansion</p>
              <h2 id="bundle-result-title">Expanded zone bundle</h2>
            </div>
            <StatusBadge tone={tone(bundleResult.status)}>{bundleResult.status}</StatusBadge>
          </div>
          {bundleResult.diagnostics.length === 0 ? null : (
            <ul className="diagnostic-list">
              {bundleResult.diagnostics.map((item, index) => (
                <li key={`${item.file}-${String(item.line)}-${String(index)}`}>
                  <StatusBadge tone={item.severity === 'error' ? 'error' : 'warning'}>
                    {item.severity}
                  </StatusBadge>{' '}
                  <code>{escapeTechnicalText(`${item.file}:${String(item.line)}`)}</code>{' '}
                  {item.message}
                </li>
              ))}
            </ul>
          )}
          {bundleResult.source === '' ? null : (
            <article className="result-panel">
              <div className="result-heading">
                <h3>Reviewable master file</h3>
                <div className="export-actions">
                  <CopyButton text={bundleResult.source} label="Copy expanded zone" />
                  <button
                    type="button"
                    className="quiet-button"
                    onClick={() => {
                      setExportSource(bundleResult.source);
                      setExportOrigin(bundleOrigin);
                      setMode('export');
                      setExports(null);
                    }}
                  >
                    Open in export
                  </button>
                </div>
              </div>
              <pre className="record-value technical-value" dir="ltr">
                {escapeTechnicalText(bundleResult.source)}
              </pre>
              <details className="method-note">
                <summary>
                  Line provenance ({bundleResult.provenance.length.toLocaleString()})
                </summary>
                <div
                  className="table-scroll"
                  tabIndex={0}
                  role="region"
                  aria-label="Expanded line provenance"
                >
                  <table>
                    <thead>
                      <tr>
                        <th>Output</th>
                        <th>Source</th>
                        <th>Generated value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bundleResult.provenance.map((item) => (
                        <tr
                          key={`${String(item.outputLine)}-${item.sourceFile}-${String(item.sourceLine)}`}
                        >
                          <td>{item.outputLine}</td>
                          <td>
                            <code>
                              {escapeTechnicalText(
                                `${item.sourceFile}:${String(item.sourceLine)}`,
                              )}
                            </code>
                          </td>
                          <td>{item.generatedIndex ?? '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>
            </article>
          )}
        </section>
      ) : null}

      {mode === 'template' && templateResult !== null ? (
        <section className="results" aria-labelledby="template-result-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Template rehearsal</p>
              <h2 id="template-result-title">Instantiated record plan</h2>
            </div>
            <StatusBadge tone={tone(templateResult.status)}>
              {templateResult.status}
            </StatusBadge>
          </div>
          <article className="result-panel">
            <div className="result-heading">
              <h3>
                {templateResult.providerId || 'Unknown provider'} /{' '}
                {templateResult.serviceId || 'unknown service'}
              </h3>
              <CopyButton
                text={templateResult.source}
                label="Copy record plan"
                disabled={templateResult.source === ''}
              />
            </div>
            {templateResult.diagnostics.length === 0 ? (
              <p>No template diagnostics.</p>
            ) : (
              <ul className="diagnostic-list">
                {templateResult.diagnostics.map((item, index) => (
                  <li key={`${item.path}-${String(index)}`}>
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
                    </StatusBadge>{' '}
                    <code>{item.path}</code> {item.message}
                  </li>
                ))}
              </ul>
            )}
            {templateResult.source === '' ? null : (
              <pre className="record-value technical-value" dir="ltr">
                {escapeTechnicalText(templateResult.source)}
              </pre>
            )}
          </article>
        </section>
      ) : null}

      {mode === 'export' && exports !== null ? (
        <section className="results" aria-labelledby="export-result-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Portable drafts</p>
              <h2 id="export-result-title">Configuration exports</h2>
            </div>
            <StatusBadge
              tone={
                exports.diagnostics.some((item) => item.severity === 'error')
                  ? 'error'
                  : exports.omittedRecords > 0
                    ? 'warning'
                    : 'pass'
              }
            >
              {exports.supportedRecords} exported · {exports.omittedRecords} omitted
            </StatusBadge>
          </div>
          {exports.diagnostics.length === 0 ? null : (
            <ul className="diagnostic-list">
              {exports.diagnostics.map((item, index) => (
                <li key={`${String(item.line)}-${String(index)}`}>
                  <StatusBadge tone={item.severity === 'error' ? 'error' : 'warning'}>
                    {item.severity}
                  </StatusBadge>{' '}
                  Line {item.line}: {item.message}
                </li>
              ))}
            </ul>
          )}
          <div className="result-grid">
            <article className="result-panel">
              <div className="result-heading">
                <h3>DNSControl draft</h3>
                <CopyButton text={exports.dnsControl} />
              </div>
              <pre className="record-value technical-value" dir="ltr">
                {escapeTechnicalText(exports.dnsControl)}
              </pre>
            </article>
            <article className="result-panel">
              <div className="result-heading">
                <h3>octoDNS YAML draft</h3>
                <CopyButton text={exports.octoDns} />
              </div>
              <pre className="record-value technical-value" dir="ltr">
                {escapeTechnicalText(exports.octoDns)}
              </pre>
            </article>
          </div>
          <p className="detail-note">
            These are migration drafts, not publish-ready guarantees. Run each target tool’s own
            formatter, validator, provider capability check, preview, and review workflow before
            applying a change.
          </p>
        </section>
      ) : null}
    </div>
  );
}
