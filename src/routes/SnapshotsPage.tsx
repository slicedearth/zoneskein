import { useEffect, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import {
  deleteSnapshot,
  disableAndEraseSnapshots,
  enableSnapshots,
  listSnapshots,
  saveSnapshot,
  snapshotFragment,
  snapshotFromFragment,
  snapshotsEnabled,
  snapshotsErasurePending,
  subscribeSnapshotState,
} from '../core/snapshots/store';
import {
  SNAPSHOT_TOOLS,
  type SnapshotInput,
  type SnapshotRecord,
  type SnapshotTool,
} from '../core/snapshots/types';
import {
  bytesBase64,
  escapeTechnicalText,
  hasUnsafeTechnicalText,
} from '../core/technical-text';

function snapshotDisplay(value: string): string {
  return escapeTechnicalText(value);
}

function snapshotSafeCopy(value: string): string {
  return hasUnsafeTechnicalText(value) ? escapeTechnicalText(value) : value;
}

function snapshotRawBase64(value: string): string {
  return bytesBase64(new TextEncoder().encode(value));
}

export function SnapshotsPage() {
  const [enabled, setEnabled] = useState(snapshotsEnabled);
  const [records, setRecords] = useState<readonly SnapshotRecord[]>([]);
  const [title, setTitle] = useState('');
  const [tool, setTool] = useState<SnapshotTool>('other');
  const [content, setContent] = useState('');
  const [message, setMessage] = useState('');
  const [shareLink, setShareLink] = useState('');
  const [storageBusy, setStorageBusy] = useState(false);
  const [erasurePending, setErasurePending] = useState(snapshotsErasurePending);
  const [imported, setImported] = useState<SnapshotInput | null>(() =>
    snapshotFromFragment(window.location.hash),
  );

  async function refresh() {
    setRecords(await listSnapshots());
  }

  useEffect(() => {
    let active = true;
    if (enabled) {
      void listSnapshots()
        .then((values) => {
          if (active) setRecords(values);
        })
        .catch((cause: unknown) => {
          if (active)
            setMessage(
              cause instanceof Error ? cause.message : 'Local snapshots could not be loaded.',
            );
        });
    }
    return () => {
      active = false;
    };
  }, [enabled]);

  useEffect(
    () =>
      subscribeSnapshotState(() => {
        const nextEnabled = snapshotsEnabled();
        setErasurePending(snapshotsErasurePending());
        setEnabled(nextEnabled);
        if (!nextEnabled) setRecords([]);
      }),
    [],
  );

  useEffect(() => {
    const updateImportedFragment = () => {
      setImported(snapshotFromFragment(window.location.hash));
    };
    window.addEventListener('hashchange', updateImportedFragment);
    return () => window.removeEventListener('hashchange', updateImportedFragment);
  }, []);

  function enable() {
    try {
      enableSnapshots();
      setEnabled(true);
      setErasurePending(false);
      setMessage('Local snapshot storage is enabled on this browser.');
    } catch (cause) {
      setMessage(
        cause instanceof Error ? cause.message : 'Local snapshots could not be enabled.',
      );
    }
  }

  async function disable() {
    setStorageBusy(true);
    setEnabled(false);
    setErasurePending(true);
    setRecords([]);
    setMessage('Erasing local snapshots…');
    try {
      await disableAndEraseSnapshots(() => {
        setMessage(
          'Erasure is waiting for another ZoneSkein tab to release local snapshot storage.',
        );
      });
      setEnabled(false);
      setErasurePending(false);
      setRecords([]);
      setMessage('Local snapshots and the opt-in preference were erased.');
    } catch (cause) {
      setEnabled(false);
      setErasurePending(snapshotsErasurePending());
      setRecords([]);
      setMessage(
        cause instanceof Error
          ? `${cause.message} Local snapshots remain disabled; retry erasure before enabling them again.`
          : 'Local snapshots remain disabled, but erasure could not be confirmed. Retry erasure before enabling them again.',
      );
    } finally {
      setStorageBusy(false);
    }
  }

  async function save(input: SnapshotInput) {
    try {
      await saveSnapshot(input);
      setTitle('');
      setContent('');
      setMessage('Snapshot saved in this browser.');
      await refresh();
    } catch (cause) {
      setMessage(cause instanceof Error ? cause.message : 'Snapshot could not be saved.');
    }
  }

  async function importCurrentFragment() {
    const current = snapshotFromFragment(window.location.hash);
    if (current === null) {
      setImported(null);
      setMessage('The current URL fragment does not contain a valid report to import.');
      return;
    }
    setImported(current);
    await save(current);
  }

  function createShare(input: SnapshotInput) {
    try {
      const url = new URL(window.location.href);
      url.hash = snapshotFragment(input).slice(1);
      setShareLink(url.toString());
      setMessage(
        'Share link created. Its report contents are visible to anyone who receives it and may remain in browser history.',
      );
    } catch (cause) {
      setMessage(cause instanceof Error ? cause.message : 'Share link could not be created.');
    }
  }

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="Local snapshot vault" title="Keep evidence only when you choose.">
        Persistent storage is off by default. After you opt in, manual saves stay in IndexedDB
        on this browser. ZoneSkein never uploads them to an application backend.
      </ToolIntro>
      <article className="storage-control">
        <div>
          <StatusBadge tone={enabled ? 'pass' : erasurePending ? 'warning' : 'unknown'}>
            {enabled ? 'Enabled' : erasurePending ? 'Erasure pending' : 'Disabled by default'}
          </StatusBadge>
          <p>
            The opt-in preference contains no domain name. Snapshot content is stored only after
            a separate save action.
          </p>
        </div>
        {enabled || erasurePending ? (
          <button
            className="danger-button"
            type="button"
            disabled={storageBusy}
            onClick={() => void disable()}
          >
            {storageBusy
              ? 'Erasing…'
              : erasurePending
                ? 'Retry erasure'
                : 'Disable and erase all'}
          </button>
        ) : (
          <button className="primary-button" type="button" onClick={enable}>
            Enable local snapshots
          </button>
        )}
      </article>
      <div className="run-status" aria-live="polite">
        {message}
      </div>

      {imported === null ? null : (
        <article className="result-panel fragment-import">
          <div className="result-heading">
            <h3>Report received in this URL fragment</h3>
            <div className="export-actions">
              <StatusBadge tone="warning">Visible in browser history</StatusBadge>
              {hasUnsafeTechnicalText(imported.title) ||
              hasUnsafeTechnicalText(imported.content) ? (
                <StatusBadge tone="warning">Controls visibly escaped</StatusBadge>
              ) : null}
            </div>
          </div>
          <p>
            The hosting server does not receive URL fragments, but anyone with this link can
            read its contents. Importing into IndexedDB requires local snapshots to be enabled.
          </p>
          <dl className="metadata-grid">
            <div>
              <dt>Title</dt>
              <dd>
                <bdi className="technical-value" dir="ltr">
                  {snapshotDisplay(imported.title)}
                </bdi>
              </dd>
            </div>
            <div>
              <dt>Tool</dt>
              <dd>{imported.tool}</dd>
            </div>
            <div>
              <dt>Content</dt>
              <dd>{new TextEncoder().encode(imported.content).length} bytes</dd>
            </div>
          </dl>
          <div className="form-actions">
            <CopyButton
              label="Copy safe report"
              resolveText={() => {
                const current = snapshotFromFragment(window.location.hash);
                if (current === null)
                  throw new Error('The report fragment is no longer valid.');
                setImported(current);
                return snapshotSafeCopy(current.content);
              }}
              text={snapshotSafeCopy(imported.content)}
            />
            {hasUnsafeTechnicalText(imported.content) ? (
              <CopyButton
                label="Copy exact report as Base64"
                resolveText={() => {
                  const current = snapshotFromFragment(window.location.hash);
                  if (current === null)
                    throw new Error('The report fragment is no longer valid.');
                  setImported(current);
                  return snapshotRawBase64(current.content);
                }}
                text={snapshotRawBase64(imported.content)}
              />
            ) : null}
            <button
              className="quiet-button"
              type="button"
              disabled={!enabled || storageBusy}
              onClick={() => void importCurrentFragment()}
            >
              Import locally
            </button>
          </div>
        </article>
      )}

      <form
        className="workbench-form snapshot-form"
        onSubmit={(event) => {
          event.preventDefault();
          void save({ content, title, tool });
        }}
      >
        <div className="field-group">
          <label htmlFor="snapshot-title">Title</label>
          <input
            id="snapshot-title"
            value={title}
            onChange={(event) => setTitle(event.currentTarget.value)}
            maxLength={80}
            placeholder="Change review — 13 August"
            disabled={storageBusy}
          />
        </div>
        <div className="field-group">
          <label htmlFor="snapshot-tool">Source tool</label>
          <select
            id="snapshot-tool"
            value={tool}
            onChange={(event) => setTool(event.currentTarget.value as SnapshotTool)}
            disabled={storageBusy}
          >
            {SNAPSHOT_TOOLS.map((value) => (
              <option value={value} key={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
        <div className="field-group zone-source">
          <label htmlFor="snapshot-content">Report content</label>
          <textarea
            id="snapshot-content"
            value={content}
            onChange={(event) => setContent(event.currentTarget.value)}
            maxLength={262_144}
            rows={12}
            spellCheck={false}
            disabled={storageBusy}
          />
        </div>
        <div className="form-actions">
          <button className="primary-button" type="submit" disabled={!enabled || storageBusy}>
            Save locally
          </button>
          <button
            className="quiet-button"
            type="button"
            onClick={() => createShare({ content, title, tool })}
          >
            Create fragment share link
          </button>
        </div>
      </form>
      {shareLink === '' ? null : (
        <article className="conclusion-panel">
          <StatusBadge tone="warning">Sensitive link</StatusBadge>
          <p className="share-value">{shareLink}</p>
          <CopyButton label="Copy share link" text={shareLink} />
        </article>
      )}

      {enabled ? (
        <section className="results" aria-labelledby="stored-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">This browser</p>
              <h2 id="stored-title">Saved snapshots</h2>
            </div>
            <span>{records.length} / 100</span>
          </div>
          {records.length === 0 ? (
            <p className="empty-note">No local snapshots.</p>
          ) : (
            <div className="snapshot-list">
              {records.map((record) => (
                <article className="result-panel" key={record.id}>
                  <div className="result-heading">
                    <div>
                      <p className="step-label">{record.tool}</p>
                      <h3>
                        <bdi className="technical-value" dir="ltr">
                          {snapshotDisplay(record.title)}
                        </bdi>
                      </h3>
                    </div>
                    <div>
                      {hasUnsafeTechnicalText(record.title) ||
                      hasUnsafeTechnicalText(record.content) ? (
                        <StatusBadge tone="warning">Controls visibly escaped</StatusBadge>
                      ) : null}
                      <time dateTime={record.createdAt}>
                        {new Date(record.createdAt).toLocaleString()}
                      </time>
                    </div>
                  </div>
                  <pre className="snapshot-preview technical-value" dir="ltr">
                    {snapshotDisplay(record.content)}
                  </pre>
                  <div className="form-actions">
                    <CopyButton
                      label="Copy safe report"
                      text={snapshotSafeCopy(record.content)}
                    />
                    {hasUnsafeTechnicalText(record.content) ? (
                      <CopyButton
                        label="Copy exact report as Base64"
                        text={snapshotRawBase64(record.content)}
                      />
                    ) : null}
                    <button
                      className="quiet-button"
                      type="button"
                      onClick={() => createShare(record)}
                    >
                      Create share link
                    </button>
                    <button
                      className="danger-button"
                      type="button"
                      disabled={storageBusy}
                      onClick={() => {
                        void (async () => {
                          try {
                            await deleteSnapshot(record.id);
                            await refresh();
                            setMessage('Snapshot deleted from this browser.');
                          } catch (cause) {
                            setMessage(
                              cause instanceof Error
                                ? cause.message
                                : 'Snapshot could not be deleted.',
                            );
                          }
                        })();
                      }}
                    >
                      Delete
                    </button>
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>
      ) : null}
    </div>
  );
}
