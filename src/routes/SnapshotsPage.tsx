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
} from '../core/snapshots/store';
import {
  SNAPSHOT_TOOLS,
  type SnapshotInput,
  type SnapshotRecord,
  type SnapshotTool,
} from '../core/snapshots/types';

export function SnapshotsPage() {
  const [enabled, setEnabled] = useState(snapshotsEnabled);
  const [records, setRecords] = useState<readonly SnapshotRecord[]>([]);
  const [title, setTitle] = useState('');
  const [tool, setTool] = useState<SnapshotTool>('other');
  const [content, setContent] = useState('');
  const [message, setMessage] = useState('');
  const [shareLink, setShareLink] = useState('');
  const [imported] = useState<SnapshotInput | null>(() =>
    snapshotFromFragment(window.location.hash),
  );

  async function refresh() {
    setRecords(await listSnapshots());
  }

  useEffect(() => {
    let active = true;
    if (enabled) {
      void listSnapshots().then((values) => {
        if (active) setRecords(values);
      });
    }
    return () => {
      active = false;
    };
  }, [enabled]);

  function enable() {
    enableSnapshots();
    setEnabled(true);
    setMessage('Local snapshot storage is enabled on this browser.');
  }

  async function disable() {
    await disableAndEraseSnapshots();
    setEnabled(false);
    setRecords([]);
    setMessage('Local snapshots and the opt-in preference were erased.');
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
          <StatusBadge tone={enabled ? 'pass' : 'unknown'}>
            {enabled ? 'Enabled' : 'Disabled by default'}
          </StatusBadge>
          <p>
            The opt-in preference contains no domain name. Snapshot content is stored only after
            a separate save action.
          </p>
        </div>
        {enabled ? (
          <button className="danger-button" type="button" onClick={() => void disable()}>
            Disable and erase all
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
            <StatusBadge tone="warning">Visible in browser history</StatusBadge>
          </div>
          <p>
            The hosting server does not receive URL fragments, but anyone with this link can
            read its contents. Importing into IndexedDB requires local snapshots to be enabled.
          </p>
          <dl className="metadata-grid">
            <div>
              <dt>Title</dt>
              <dd>{imported.title}</dd>
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
            <CopyButton label="Copy report" text={imported.content} />
            <button
              className="quiet-button"
              type="button"
              disabled={!enabled}
              onClick={() => void save(imported)}
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
          />
        </div>
        <div className="field-group">
          <label htmlFor="snapshot-tool">Source tool</label>
          <select
            id="snapshot-tool"
            value={tool}
            onChange={(event) => setTool(event.currentTarget.value as SnapshotTool)}
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
          />
        </div>
        <div className="form-actions">
          <button className="primary-button" type="submit" disabled={!enabled}>
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
                      <h3>{record.title}</h3>
                    </div>
                    <time dateTime={record.createdAt}>
                      {new Date(record.createdAt).toLocaleString()}
                    </time>
                  </div>
                  <pre className="snapshot-preview">{record.content}</pre>
                  <div className="form-actions">
                    <CopyButton text={record.content} />
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
                      onClick={() => {
                        void (async () => {
                          await deleteSnapshot(record.id);
                          await refresh();
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
