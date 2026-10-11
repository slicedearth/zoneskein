import { useEffect, useRef, useState } from 'react';

import { StatusBadge, type StatusTone } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import {
  analyseChangeWorkspace,
  CHANGE_WORKSPACE_LIMITS,
  createBlankChangeWorkspace,
  decodeChangeWorkspace,
  editChangeWorkspace,
  encodeChangeWorkspace,
  parseChangeWorkspace,
  type ActiveChangeWorkspace,
  type ChangeWorkspace,
  type ChangeWorkspaceCodecError,
  type ChangeWorkspaceEditPatch,
  type ChangeWorkspaceIntegrityProvenance,
  type ChangeWorkspaceZoneInput,
  type ChangeWorkspaceZoneState,
  type DecodedChangeWorkspace,
} from '../core/project';
import { escapeTechnicalText } from '../core/technical-text';
import {
  WORKSPACE_EXAMPLES,
  workspaceExampleFile,
  type WorkspaceExampleId,
} from '../core/project/examples';
import { workspaceValidationReport } from '../core/project/report';
import { RequestLifetime } from '../core/request-lifetime';

export interface ChangeWorkspaceChangeLabInput {
  readonly current: string;
  readonly intended: string;
  readonly origin?: string;
}

export interface ChangeWorkspacePageProps {
  readonly initialActiveWorkspace?: ActiveChangeWorkspace | undefined;
  readonly initialWorkspace?: ChangeWorkspace | undefined;
  readonly onOpenChangeLab?: (input: ChangeWorkspaceChangeLabInput) => void;
  readonly onActiveWorkspaceChange?: (active: ActiveChangeWorkspace) => void;
  readonly onWorkspaceChange?: (workspace: ChangeWorkspace) => void;
}

type ZoneStateStatus = ChangeWorkspaceZoneState['status'];

interface WorkspaceDraft {
  readonly currentOrigin: string;
  readonly currentReason: string;
  readonly currentSource: string;
  readonly currentStatus: ZoneStateStatus;
  readonly intendedOrigin: string;
  readonly intendedReason: string;
  readonly intendedSource: string;
  readonly intendedStatus: ZoneStateStatus;
  readonly title: string;
}

interface InitialWorkspaceState {
  readonly error: string;
  readonly workspace: ChangeWorkspace | null;
}

const FILE_LIMIT_LABEL = `${String(CHANGE_WORKSPACE_LIMITS.fileOctets)} bytes`;

function codecMessage(error: ChangeWorkspaceCodecError): string {
  return `${error.message}${error.path === undefined ? '' : ` (${error.path})`}`;
}

function initialiseWorkspace(initial: ChangeWorkspace | undefined): InitialWorkspaceState {
  if (initial !== undefined) {
    const parsed = parseChangeWorkspace(initial);
    if (parsed.ok) return { error: '', workspace: parsed.value };
  }
  const created = createBlankChangeWorkspace();
  if (created.ok) {
    return {
      error:
        initial === undefined
          ? ''
          : 'The supplied in-memory workspace was invalid, so a new local workspace was created.',
      workspace: created.value,
    };
  }
  return { error: codecMessage(created.error), workspace: null };
}

function reason(state: ChangeWorkspaceZoneState): string {
  return state.incompleteReasons.join(' ');
}

function draftFrom(workspace: ChangeWorkspace): WorkspaceDraft {
  return {
    currentOrigin: workspace.current.origin ?? '',
    currentReason: reason(workspace.current),
    currentSource: workspace.current.source,
    currentStatus: workspace.current.status,
    intendedOrigin: workspace.intended.origin ?? '',
    intendedReason: reason(workspace.intended),
    intendedSource: workspace.intended.source,
    intendedStatus: workspace.intended.status,
    title: workspace.title,
  };
}

function zoneState(
  status: ZoneStateStatus,
  source: string,
  origin: string,
  incompleteReason: string,
): ChangeWorkspaceZoneInput | null {
  if (status === 'unavailable') {
    const explanation = incompleteReason.trim();
    if (explanation === '') return null;
    return {
      incompleteReasons: [explanation],
      origin: null,
      source: '',
      status,
    };
  }
  if (status === 'partial') {
    const explanation = incompleteReason.trim();
    if (explanation === '') return null;
    return {
      incompleteReasons: [explanation],
      origin: origin.trim() === '' ? null : origin.trim(),
      source,
      status,
    };
  }
  return {
    incompleteReasons: [],
    origin: origin.trim() === '' ? null : origin.trim(),
    source,
    status,
  };
}

function sameZoneState(
  state: ChangeWorkspaceZoneState,
  input: ChangeWorkspaceZoneInput,
): boolean {
  return (
    state.status === input.status &&
    state.source === input.source &&
    state.origin === input.origin &&
    state.incompleteReasons.length === input.incompleteReasons.length &&
    state.incompleteReasons.every((item, index) => item === input.incompleteReasons[index])
  );
}

function filename(title: string): string {
  const stem = title
    .normalize('NFKD')
    .replaceAll(/[\u0300-\u036f]/gu, '')
    .toLowerCase()
    .replaceAll(/[^a-z0-9]+/gu, '-')
    .replaceAll(/^-+|-+$/gu, '')
    .slice(0, 48)
    .replaceAll(/-+$/gu, '');
  return `zoneskein-${stem === '' ? 'change-workspace' : stem}.zoneskein.json`;
}

function riskTone(risk: ChangeWorkspace['analysis']['risk']): StatusTone {
  if (risk === 'critical' || risk === 'high') return 'error';
  if (risk === 'moderate') return 'warning';
  if (risk === 'low') return 'pass';
  return risk === 'information' ? 'information' : 'unknown';
}

function zoneTone(status: ZoneStateStatus): StatusTone {
  if (status === 'complete') return 'pass';
  if (status === 'partial') return 'warning';
  return 'unknown';
}

function integrityLabel(value: ChangeWorkspaceIntegrityProvenance): string {
  if (value.state === 'digest-match') {
    return `SHA-256 internally consistent: ${value.digest}`;
  }
  if (value.state === 'mismatch-accepted') return 'SHA-256 mismatch explicitly accepted';
  return 'Not checked for this session';
}

function integrityWarning(value: ChangeWorkspaceIntegrityProvenance): string {
  if (value.state !== 'mismatch-accepted') return '';
  return `This workspace descends from data explicitly accepted after a SHA-256 mismatch. Claimed ${value.claimedDigest}; calculated ${value.calculatedDigest}. Local edits and reanalysis do not erase that import provenance.`;
}

function afterLocalMutation(
  value: ChangeWorkspaceIntegrityProvenance,
): ChangeWorkspaceIntegrityProvenance {
  return value.state === 'mismatch-accepted' ? value : { state: 'not-checked' };
}

function dateLabel(value: string | null): string {
  if (value === null) return 'Not established';
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value));
}

export function ChangeWorkspacePage({
  initialActiveWorkspace,
  initialWorkspace,
  onActiveWorkspaceChange,
  onOpenChangeLab,
  onWorkspaceChange,
}: ChangeWorkspacePageProps) {
  const [initial] = useState<InitialWorkspaceState>(() =>
    initialiseWorkspace(initialActiveWorkspace?.workspace ?? initialWorkspace),
  );
  const [workspace, setWorkspace] = useState<ChangeWorkspace | null>(initial.workspace);
  const [draft, setDraft] = useState<WorkspaceDraft | null>(() =>
    initial.workspace === null ? null : draftFrom(initial.workspace),
  );
  const [error, setError] = useState(initial.error);
  const [status, setStatus] = useState('');
  const [importBusy, setImportBusy] = useState(false);
  const [pendingImport, setPendingImport] = useState<DecodedChangeWorkspace | null>(null);
  const [exampleId, setExampleId] = useState<WorkspaceExampleId>('origins');
  const [recomputedInSession, setRecomputedInSession] = useState(false);
  const [quarantined, setQuarantined] = useState<DecodedChangeWorkspace | null>(null);
  const [mismatchAcknowledged, setMismatchAcknowledged] = useState(false);
  const [integrity, setIntegrity] = useState<ChangeWorkspaceIntegrityProvenance>(() =>
    initial.error === '' && initialActiveWorkspace !== undefined
      ? initialActiveWorkspace.integrity
      : { state: 'not-checked' },
  );
  const lifetime = useRef(new RequestLifetime());
  const objectUrls = useRef(new Set<string>());
  const importInput = useRef<HTMLInputElement>(null);
  const summaryHeading = useRef<HTMLHeadingElement>(null);
  const nextFocus = useRef<'summary' | 'import' | null>(null);

  useEffect(() => {
    if (nextFocus.current === 'summary') summaryHeading.current?.focus();
    if (nextFocus.current === 'import') importInput.current?.focus();
    nextFocus.current = null;
  }, [workspace, importBusy, pendingImport, quarantined]);

  useEffect(() => {
    const requests = lifetime.current;
    const urls = objectUrls.current;
    requests.enter();
    return () => {
      requests.leave();
      for (const url of urls) URL.revokeObjectURL(url);
      urls.clear();
    };
  }, []);

  function isCurrent(sequence: number): boolean {
    return lifetime.current.isCurrent(sequence);
  }

  function activateWorkspace(
    next: ChangeWorkspace,
    announcement: string,
    nextIntegrity: ChangeWorkspaceIntegrityProvenance = integrity,
  ) {
    if (!lifetime.current.active) return;
    lifetime.current.invalidate();
    setImportBusy(false);
    setWorkspace(next);
    setRecomputedInSession(false);
    setDraft(draftFrom(next));
    setError('');
    setStatus(announcement);
    setQuarantined(null);
    setPendingImport(null);
    setMismatchAcknowledged(false);
    setIntegrity(nextIntegrity);
    onActiveWorkspaceChange?.({ integrity: nextIntegrity, workspace: next });
    onWorkspaceChange?.(next);
  }

  function createNew(announcement: string) {
    const created = createBlankChangeWorkspace();
    if (!created.ok) {
      setError(codecMessage(created.error));
      return;
    }
    activateWorkspace(created.value, announcement, { state: 'not-checked' });
  }

  function updateDraft<Key extends keyof WorkspaceDraft>(key: Key, value: WorkspaceDraft[Key]) {
    setDraft((current) => (current === null ? current : { ...current, [key]: value }));
  }

  const hasUnappliedEdits =
    workspace !== null &&
    draft !== null &&
    JSON.stringify(draft) !== JSON.stringify(draftFrom(workspace));

  function cancelImport() {
    lifetime.current.invalidate();
    setImportBusy(false);
    setPendingImport(null);
    setQuarantined(null);
    setMismatchAcknowledged(false);
    setError('');
    setStatus('Import cancelled. The active workspace and unapplied edits were retained.');
  }

  function acceptImport() {
    if (pendingImport?.integrity.status !== 'match') return;
    nextFocus.current = 'summary';
    activateWorkspace(
      pendingImport.workspace,
      'Workspace imported after strict schema and digest validation. Stored analysis is supplied historical data until local reanalysis.',
      { digest: pendingImport.integrity.digest, state: 'digest-match' },
    );
  }

  async function loadExample() {
    cancelImport();
    const sequence = lifetime.current.capture();
    setImportBusy(true);
    try {
      const file = await workspaceExampleFile(exampleId);
      if (!isCurrent(sequence)) return;
      const decoded = await decodeChangeWorkspace(new TextEncoder().encode(file));
      if (!isCurrent(sequence)) return;
      if (!decoded.ok) {
        setError(codecMessage(decoded.error));
        return;
      }
      if (decoded.value.integrity.status === 'mismatch') setQuarantined(decoded.value);
      else setPendingImport(decoded.value);
      setStatus(
        'Synthetic example prepared locally. Review it before replacement; no resolver was contacted.',
      );
    } catch (cause) {
      if (isCurrent(sequence))
        setError(cause instanceof Error ? cause.message : 'Example could not be prepared.');
    } finally {
      if (isCurrent(sequence)) setImportBusy(false);
    }
  }

  function applyEdits() {
    if (workspace === null || draft === null) return;
    const current = zoneState(
      draft.currentStatus,
      draft.currentSource,
      draft.currentOrigin,
      draft.currentReason,
    );
    if (current === null) {
      setError('Explain why the current zone state is unavailable or partial.');
      return;
    }
    const intended = zoneState(
      draft.intendedStatus,
      draft.intendedSource,
      draft.intendedOrigin,
      draft.intendedReason,
    );
    if (intended === null) {
      setError('Explain why the intended zone state is unavailable or partial.');
      return;
    }
    const title = draft.title.trim();
    const patch: ChangeWorkspaceEditPatch = {
      ...(sameZoneState(workspace.current, current) ? {} : { current }),
      ...(sameZoneState(workspace.intended, intended) ? {} : { intended }),
      ...(title === workspace.title ? {} : { title }),
    };
    if (Object.keys(patch).length === 0) {
      setDraft(draftFrom(workspace));
      setError('');
      setStatus('No workspace edits were waiting to be applied.');
      return;
    }
    const edited = editChangeWorkspace(workspace, patch);
    if (!edited.ok) {
      setError(codecMessage(edited.error));
      return;
    }
    const zoneChanged = patch.current !== undefined || patch.intended !== undefined;
    activateWorkspace(
      edited.value,
      zoneChanged
        ? 'Workspace edits applied. Stored analysis was invalidated and must be run again.'
        : 'Workspace title updated without changing the stored analysis.',
      afterLocalMutation(integrity),
    );
  }

  function reanalyse() {
    if (workspace === null) return;
    if (workspace.current.status === 'unavailable') {
      setError(
        'Comparison is blocked because the current zone state is unavailable. Supply it or keep the result explicitly unknown.',
      );
      return;
    }
    if (workspace.intended.status === 'unavailable') {
      setError('Comparison is blocked because the intended zone state is unavailable.');
      return;
    }
    const analysed = analyseChangeWorkspace(workspace);
    if (!analysed.ok) {
      setError(codecMessage(analysed.error));
      return;
    }
    activateWorkspace(
      analysed.value,
      analysed.value.analysis.status === 'complete'
        ? `Analysis complete with ${String(analysed.value.analysis.changes.length)} classified changes.`
        : 'Analysis remains partial. Review the stated incomplete reasons.',
      afterLocalMutation(integrity),
    );
    setRecomputedInSession(true);
  }

  async function importFile(event: React.ChangeEvent<HTMLInputElement>) {
    const input = event.currentTarget;
    const file = input.files?.[0];
    input.value = '';
    if (file === undefined) return;
    const sequence = lifetime.current.invalidate();
    setError('');
    setStatus('');
    setQuarantined(null);
    setMismatchAcknowledged(false);
    setPendingImport(null);
    setImportBusy(false);
    if (file.size > CHANGE_WORKSPACE_LIMITS.fileOctets) {
      setError(`Workspace file is too large. The limit is ${FILE_LIMIT_LABEL}.`);
      return;
    }
    setImportBusy(true);
    try {
      const bytes = await file.arrayBuffer();
      if (!isCurrent(sequence)) return;
      const decoded = await decodeChangeWorkspace(new Uint8Array(bytes));
      if (!isCurrent(sequence)) return;
      if (!decoded.ok) {
        setError(codecMessage(decoded.error));
        return;
      }
      if (decoded.value.integrity.status === 'mismatch') {
        setQuarantined(decoded.value);
        setError(
          'The imported SHA-256 digest does not match its contents. The workspace is quarantined and has not replaced the active workspace.',
        );
        return;
      }
      setPendingImport(decoded.value);
      setStatus(
        'Import validated. Review and explicitly replace the active workspace, or cancel.',
      );
    } catch (cause) {
      if (isCurrent(sequence)) {
        setError(
          cause instanceof Error ? cause.message : 'The workspace file could not be read.',
        );
      }
    } finally {
      if (isCurrent(sequence)) setImportBusy(false);
    }
  }

  function acceptMismatch() {
    if (quarantined?.integrity.status !== 'mismatch' || !mismatchAcknowledged) return;
    nextFocus.current = 'summary';
    activateWorkspace(
      quarantined.workspace,
      'Altered workspace accepted with a persistent warning.',
      {
        calculatedDigest: quarantined.integrity.calculatedDigest,
        claimedDigest: quarantined.integrity.claimedDigest,
        state: 'mismatch-accepted',
      },
    );
  }

  async function exportWorkspace(report = false) {
    if (workspace === null) return;
    const sequence = lifetime.current.capture();
    setError('');
    const encoded = await encodeChangeWorkspace(workspace);
    if (!isCurrent(sequence)) return;
    if (!encoded.ok) {
      setError(codecMessage(encoded.error));
      return;
    }
    const url = URL.createObjectURL(
      new Blob(
        [
          report
            ? workspaceValidationReport(
                workspace,
                encoded.value,
                integrity,
                recomputedInSession,
              )
            : encoded.value,
        ],
        { type: 'application/json;charset=utf-8' },
      ),
    );
    objectUrls.current.add(url);
    try {
      const link = document.createElement('a');
      link.download = report
        ? filename(workspace.title).replace('.zoneskein.json', '.validation.json')
        : filename(workspace.title);
      link.href = url;
      link.rel = 'noopener';
      document.body.append(link);
      link.click();
      link.remove();
      setStatus(
        `${report ? 'Validation report' : 'Workspace'} exported as ${link.download} with a fresh internally consistent digest.${
          integrity.state === 'mismatch-accepted'
            ? ' The active session still retains its accepted-mismatch provenance.'
            : ''
        }`,
      );
    } finally {
      URL.revokeObjectURL(url);
      objectUrls.current.delete(url);
    }
  }

  function openChangeLab() {
    if (
      workspace === null ||
      workspace.current.status === 'unavailable' ||
      workspace.intended.status === 'unavailable'
    )
      return;
    onActiveWorkspaceChange?.({ integrity, workspace });
    onWorkspaceChange?.(workspace);
    const origin = workspace.intended.origin ?? workspace.current.origin;
    onOpenChangeLab?.({
      current: workspace.current.source,
      intended: workspace.intended.source,
      ...(origin === null ? {} : { origin }),
    });
  }

  if (workspace === null || draft === null) {
    return (
      <div className="tool-page">
        <ToolIntro eyebrow="Local Change Workspace" title="Start a portable DNS change thread.">
          Workspaces remain local unless you explicitly export one.
        </ToolIntro>
        <p className="form-error" role="alert">
          {error}
        </p>
        <button
          className="primary-button"
          type="button"
          onClick={() => createNew('New workspace created.')}
        >
          Create workspace
        </button>
      </div>
    );
  }

  return (
    <div className="tool-page">
      <ToolIntro
        eyebrow="Local Change Workspace"
        title="Keep the whole DNS change on one thread."
      >
        Create, edit, analyse, import, and export one bounded workspace in memory. Nothing is
        saved to browser storage, placed in a URL fragment, uploaded, published, or queried
        automatically.
      </ToolIntro>

      <details className="method-note">
        <summary>Try a synthetic offline example</summary>
        <div className="field-group">
          <label htmlFor="workspace-example">Example scenario</label>
          <select
            id="workspace-example"
            value={exampleId}
            onChange={(event) => setExampleId(event.currentTarget.value as WorkspaceExampleId)}
          >
            {WORKSPACE_EXAMPLES.map((example) => (
              <option key={example.id} value={example.id}>
                {example.title}
              </option>
            ))}
          </select>
        </div>
        <p>{WORKSPACE_EXAMPLES.find((example) => example.id === exampleId)?.expected}</p>
        <p>
          Cancel to keep your current work, or use New workspace afterwards to reset. Examples
          stay in memory.
        </p>
        <button
          className="quiet-button"
          type="button"
          disabled={importBusy}
          onClick={() => void loadExample()}
        >
          Prepare offline example
        </button>
      </details>

      <article className="method-note workspace-boundary-note">
        <h2>Local, unencrypted, and not authenticated</h2>
        <p>
          Workspace content stays in this tab unless you export it. The exported JSON is not
          encrypted, and its SHA-256 digest checks consistency rather than authorship or
          authorisation. Unprovided input stays explicitly unknown.
        </p>
        <details>
          <summary>Read the integrity and import boundaries</summary>
          <p>
            A digest mismatch shows that the content no longer matches the included digest. A
            match shows internal consistency only: anyone modifying the file can recompute the
            digest, so it provides no authenticity, authorisation, or tamper resistance. Import
            validation checks structure and internal consistency; it does not reproduce or
            endorse stored analysis. Treat imported analysis as supplied historical data until
            you run local reanalysis. Imported resolver endpoints are displayed only as inert
            provenance text and are never contacted by this page. Use workspace content only
            when you are authorised to process and disclose it. File contents and edits remain
            in this tab's memory until you export them or leave the page.
          </p>
        </details>
      </article>

      {integrityWarning(integrity) === '' ? null : (
        <p className="snapshot-warning" role="status">
          {integrityWarning(integrity)}
        </p>
      )}

      <form
        className="workbench-form workspace-form"
        aria-busy={importBusy}
        onSubmit={(event) => event.preventDefault()}
      >
        <div className="field-group">
          <label htmlFor="workspace-title">Workspace title</label>
          <input
            id="workspace-title"
            value={draft.title}
            maxLength={CHANGE_WORKSPACE_LIMITS.titleCharacters}
            onChange={(event) => updateDraft('title', event.currentTarget.value)}
          />
        </div>
        <div className="field-group">
          <label htmlFor="workspace-file">Import workspace file</label>
          <input
            id="workspace-file"
            ref={importInput}
            type="file"
            accept=".json,application/json"
            disabled={importBusy}
            onChange={(event) => void importFile(event)}
          />
        </div>

        <fieldset className="record-picker workspace-zone-fields">
          <legend>Current zone state</legend>
          <div className="field-group">
            <label htmlFor="current-status">Availability</label>
            <select
              id="current-status"
              value={draft.currentStatus}
              onChange={(event) =>
                updateDraft('currentStatus', event.currentTarget.value as ZoneStateStatus)
              }
            >
              <option value="unavailable">Unavailable / unknown</option>
              <option value="complete">Complete supplied state</option>
              <option value="partial">Partial supplied state</option>
            </select>
          </div>
          {draft.currentStatus === 'unavailable' ? (
            <div className="field-group">
              <label htmlFor="current-reason">Why current state is unavailable</label>
              <input
                id="current-reason"
                value={draft.currentReason}
                maxLength={CHANGE_WORKSPACE_LIMITS.messageOctets}
                onChange={(event) => updateDraft('currentReason', event.currentTarget.value)}
              />
            </div>
          ) : (
            <>
              <div className="field-group">
                <label htmlFor="current-origin">Current origin (optional)</label>
                <input
                  id="current-origin"
                  value={draft.currentOrigin}
                  maxLength={CHANGE_WORKSPACE_LIMITS.shortStringOctets}
                  spellCheck={false}
                  onChange={(event) => updateDraft('currentOrigin', event.currentTarget.value)}
                />
              </div>
              <div className="field-group zone-source">
                <label htmlFor="current-source">Current BIND-style zone text</label>
                <textarea
                  id="current-source"
                  value={draft.currentSource}
                  maxLength={CHANGE_WORKSPACE_LIMITS.zoneCharacters}
                  rows={12}
                  spellCheck={false}
                  onChange={(event) => updateDraft('currentSource', event.currentTarget.value)}
                />
              </div>
              {draft.currentStatus === 'partial' ? (
                <div className="field-group zone-source">
                  <label htmlFor="current-reason">Why current state is partial</label>
                  <input
                    id="current-reason"
                    value={draft.currentReason}
                    maxLength={CHANGE_WORKSPACE_LIMITS.messageOctets}
                    onChange={(event) =>
                      updateDraft('currentReason', event.currentTarget.value)
                    }
                  />
                </div>
              ) : null}
            </>
          )}
        </fieldset>

        <fieldset className="record-picker workspace-zone-fields">
          <legend>Intended zone state</legend>
          <div className="field-group">
            <label htmlFor="intended-status">Availability</label>
            <select
              id="intended-status"
              value={draft.intendedStatus}
              onChange={(event) =>
                updateDraft('intendedStatus', event.currentTarget.value as ZoneStateStatus)
              }
            >
              <option value="unavailable">Unavailable / unknown</option>
              <option value="complete">Complete supplied state</option>
              <option value="partial">Partial supplied state</option>
            </select>
          </div>
          {draft.intendedStatus === 'unavailable' ? (
            <div className="field-group">
              <label htmlFor="intended-reason">Why intended state is unavailable</label>
              <input
                id="intended-reason"
                value={draft.intendedReason}
                maxLength={CHANGE_WORKSPACE_LIMITS.messageOctets}
                onChange={(event) => updateDraft('intendedReason', event.currentTarget.value)}
              />
            </div>
          ) : (
            <>
              <div className="field-group">
                <label htmlFor="intended-origin">Intended origin (optional)</label>
                <input
                  id="intended-origin"
                  value={draft.intendedOrigin}
                  maxLength={CHANGE_WORKSPACE_LIMITS.shortStringOctets}
                  spellCheck={false}
                  onChange={(event) => updateDraft('intendedOrigin', event.currentTarget.value)}
                />
              </div>
              <div className="field-group zone-source">
                <label htmlFor="intended-source">Intended BIND-style zone text</label>
                <textarea
                  id="intended-source"
                  value={draft.intendedSource}
                  maxLength={CHANGE_WORKSPACE_LIMITS.zoneCharacters}
                  rows={12}
                  spellCheck={false}
                  onChange={(event) => updateDraft('intendedSource', event.currentTarget.value)}
                />
              </div>
              {draft.intendedStatus === 'partial' ? (
                <div className="field-group zone-source">
                  <label htmlFor="intended-reason">Why intended state is partial</label>
                  <input
                    id="intended-reason"
                    value={draft.intendedReason}
                    maxLength={CHANGE_WORKSPACE_LIMITS.messageOctets}
                    onChange={(event) =>
                      updateDraft('intendedReason', event.currentTarget.value)
                    }
                  />
                </div>
              ) : null}
            </>
          )}
        </fieldset>

        {error === '' ? null : (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <div className="form-actions">
          <button className="primary-button" type="button" onClick={applyEdits}>
            Apply edits
          </button>
          <button
            className="quiet-button"
            type="button"
            disabled={
              hasUnappliedEdits ||
              importBusy ||
              pendingImport !== null ||
              workspace.current.status === 'unavailable' ||
              workspace.intended.status === 'unavailable'
            }
            onClick={reanalyse}
          >
            Reanalyse
          </button>
          <button
            className="quiet-button"
            type="button"
            disabled={hasUnappliedEdits || importBusy || pendingImport !== null}
            onClick={() => void exportWorkspace()}
          >
            Export JSON
          </button>
          <button
            className="quiet-button"
            type="button"
            disabled={hasUnappliedEdits || importBusy || pendingImport !== null}
            onClick={() => void exportWorkspace(true)}
          >
            Export validation report
          </button>
          {onOpenChangeLab === undefined ? null : (
            <button
              className="quiet-button"
              type="button"
              disabled={
                hasUnappliedEdits ||
                importBusy ||
                pendingImport !== null ||
                workspace.current.status === 'unavailable' ||
                workspace.intended.status === 'unavailable'
              }
              onClick={openChangeLab}
            >
              Open in Change Lab
            </button>
          )}
          <button
            className="quiet-button"
            type="button"
            onClick={() => createNew('New blank workspace created in memory.')}
          >
            New workspace
          </button>
          <button
            className="danger-button"
            type="button"
            onClick={() =>
              createNew('Workspace cleared and replaced with a new blank workspace.')
            }
          >
            Clear workspace
          </button>
        </div>
      </form>

      {hasUnappliedEdits ? (
        <p className="snapshot-warning" role="status">
          Unapplied edits. Apply them before analysing, exporting or opening Change Lab.
        </p>
      ) : null}
      {pendingImport === null ? null : (
        <article className="result-panel" aria-labelledby="replacement-title">
          <h2 id="replacement-title">Import ready for review</h2>
          <p>
            Replace the active workspace with “
            {escapeTechnicalText(pendingImport.workspace.title)}”? This discards the active
            workspace and any unapplied edits in this tab. The matching digest establishes
            internal consistency, not authorship.
          </p>
          <button className="primary-button" type="button" onClick={acceptImport}>
            Replace active workspace
          </button>
        </article>
      )}
      {importBusy || pendingImport !== null || quarantined !== null ? (
        <button
          className="quiet-button"
          type="button"
          onClick={() => {
            nextFocus.current = 'import';
            cancelImport();
          }}
        >
          Cancel import
        </button>
      ) : null}

      <div className="run-status" role="status" aria-live="polite" aria-atomic="true">
        {importBusy ? 'Reading and validating the selected local file…' : status}
      </div>

      {quarantined?.integrity.status === 'mismatch' ? (
        <article className="result-panel unsafe-output" aria-labelledby="mismatch-title">
          <div className="result-heading">
            <h2 id="mismatch-title">Digest mismatch quarantine</h2>
            <StatusBadge tone="error">Not active</StatusBadge>
          </div>
          <p>
            Claimed digest: <code>{quarantined.integrity.claimedDigest}</code>
            <br />
            Calculated digest: <code>{quarantined.integrity.calculatedDigest}</code>
          </p>
          <label className="check-control">
            <input
              type="checkbox"
              checked={mismatchAcknowledged}
              onChange={(event) => setMismatchAcknowledged(event.currentTarget.checked)}
            />
            I understand that this file was altered and has no proof of authenticity.
          </label>
          <button
            className="danger-button"
            type="button"
            disabled={!mismatchAcknowledged}
            onClick={acceptMismatch}
          >
            Accept altered workspace
          </button>
        </article>
      ) : null}

      <section className="results" aria-labelledby="workspace-summary-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Active in-memory workspace</p>
            <h2 id="workspace-summary-title" ref={summaryHeading} tabIndex={-1}>
              <bdi className="technical-value" dir="ltr">
                {escapeTechnicalText(workspace.title)}
              </bdi>
            </h2>
          </div>
          <StatusBadge tone={riskTone(workspace.analysis.risk)}>
            {workspace.analysis.status === 'not-run'
              ? 'Analysis not run'
              : workspace.analysis.status === 'partial'
                ? 'Overall risk unknown'
                : `${workspace.analysis.risk ?? 'unknown'} risk`}
          </StatusBadge>
        </div>
        <article className="result-panel">
          <dl className="metadata-grid">
            <div>
              <dt>Current state</dt>
              <dd>
                <StatusBadge tone={zoneTone(workspace.current.status)}>
                  {workspace.current.status}
                </StatusBadge>
              </dd>
            </div>
            <div>
              <dt>Intended state</dt>
              <dd>
                <StatusBadge tone={zoneTone(workspace.intended.status)}>
                  {workspace.intended.status}
                </StatusBadge>
              </dd>
            </div>
            <div>
              <dt>Integrity</dt>
              <dd>{integrityLabel(integrity)}</dd>
            </div>
            <div>
              <dt>Evidence runs</dt>
              <dd>{String(workspace.evidence.runs.length)}</dd>
            </div>
          </dl>
          {workspace.current.status === 'unavailable' ? (
            <p className="snapshot-warning">
              The current state is unknown: {reason(workspace.current)} Comparison remains
              blocked; absence is not treated as an empty zone.
            </p>
          ) : null}
          {workspace.intended.status === 'unavailable' ? (
            <p className="snapshot-warning">
              The intended state is unknown: {reason(workspace.intended)} Analysis and Change
              Lab hand-off remain blocked.
            </p>
          ) : null}
          {workspace.analysis.status === 'not-run' ? (
            <p className="empty-note">
              No stored comparison applies to these zone states. Apply any edits, then reanalyse
              locally.
            </p>
          ) : (
            <>
              <p className="method-note">
                This is stored analysis supplied with or captured into the workspace. It is not
                treated as a fresh local conclusion until you select Reanalyse.
              </p>
              <p>
                {String(workspace.analysis.changes.length)} classified changes and{' '}
                {String(workspace.analysis.findings.length)} preflight findings.
              </p>
              {workspace.analysis.incompleteReasons.length === 0 ? null : (
                <ul className="warning-list">
                  {workspace.analysis.incompleteReasons.map((item) => (
                    <li key={item}>
                      <bdi className="technical-value" dir="ltr">
                        {escapeTechnicalText(item)}
                      </bdi>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </article>

        {workspace.analysis.findings.length === 0 ? null : (
          <article className="result-panel">
            <h3>Preflight findings</h3>
            <ul className="diagnostic-list">
              {workspace.analysis.findings.map((finding) => (
                <li key={`${finding.code}-${finding.message}`}>
                  <StatusBadge tone={riskTone(finding.risk)}>{finding.risk}</StatusBadge>
                  <bdi className="technical-value" dir="ltr">
                    <strong>{escapeTechnicalText(finding.code)}</strong> —{' '}
                    {escapeTechnicalText(finding.message)}
                  </bdi>
                </li>
              ))}
            </ul>
          </article>
        )}

        {workspace.analysis.status === 'not-run' ? null : (
          <article className="result-panel">
            <h3>Timing evidence</h3>
            <dl className="metadata-grid">
              <div>
                <dt>Planned publication</dt>
                <dd>{dateLabel(workspace.analysis.timing.plannedAt)}</dd>
              </div>
              <div>
                <dt>Previous TTL</dt>
                <dd>
                  {workspace.analysis.timing.previousTtlSeconds === null
                    ? 'Not established'
                    : `${String(workspace.analysis.timing.previousTtlSeconds)} seconds`}
                </dd>
              </div>
              <div>
                <dt>Preparation deadline</dt>
                <dd>{dateLabel(workspace.analysis.timing.preparationDeadline)}</dd>
              </div>
              <div>
                <dt>Rollback cache horizon</dt>
                <dd>{dateLabel(workspace.analysis.timing.rollbackCacheHorizon)}</dd>
              </div>
              <div>
                <dt>Earliest if lowered now</dt>
                <dd>{dateLabel(workspace.analysis.timing.safeChangeAtIfLoweredNow)}</dd>
              </div>
            </dl>
          </article>
        )}

        {workspace.analysis.changes.length === 0 ? null : (
          <article className="result-panel">
            <h3>Analysed changes</h3>
            <div
              className="table-scroll"
              tabIndex={0}
              role="region"
              aria-label="Analysed workspace changes"
            >
              <table className="change-records-table">
                <caption>Changes retained in this workspace</caption>
                <thead>
                  <tr>
                    <th>Risk</th>
                    <th>Owner / type</th>
                    <th>Category</th>
                    <th>Explanation</th>
                  </tr>
                </thead>
                <tbody>
                  {workspace.analysis.changes.map((change, index) => (
                    <tr
                      key={`${change.owner}-${change.type}-${change.category}-${String(index)}`}
                    >
                      <td>
                        <StatusBadge tone={riskTone(change.risk)}>{change.risk}</StatusBadge>
                      </td>
                      <td>
                        <code className="technical-value" dir="ltr">
                          {escapeTechnicalText(change.owner)}
                        </code>
                        <br />
                        {change.type}
                      </td>
                      <td>
                        {change.category}
                        {change.disruptive ? (
                          <>
                            <br />
                            <StatusBadge tone="warning">Potentially disruptive</StatusBadge>
                          </>
                        ) : null}
                      </td>
                      <td>
                        <bdi className="technical-value" dir="ltr">
                          {escapeTechnicalText(change.explanation)}
                        </bdi>
                        <details>
                          <summary>Impact reasons and rollback</summary>
                          <ul>
                            {change.reasons.map((item) => (
                              <li key={item}>
                                <bdi className="technical-value" dir="ltr">
                                  {escapeTechnicalText(item)}
                                </bdi>
                              </li>
                            ))}
                          </ul>
                          <p>
                            <bdi className="technical-value" dir="ltr">
                              {escapeTechnicalText(change.rollback)}
                            </bdi>
                          </p>
                        </details>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </article>
        )}

        {workspace.analysis.phases.length === 0 ? null : (
          <article className="result-panel">
            <h3>Staged rollout</h3>
            <ol className="rollout-phases">
              {workspace.analysis.phases.map((phase) => (
                <li key={phase.id}>
                  <h4>
                    <bdi className="technical-value" dir="ltr">
                      {escapeTechnicalText(phase.title)}
                    </bdi>
                  </h4>
                  <ul>
                    {phase.actions.map((action) => (
                      <li key={action}>
                        <bdi className="technical-value" dir="ltr">
                          {escapeTechnicalText(action)}
                        </bdi>
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ol>
          </article>
        )}

        {workspace.analysis.guidance.length === 0 ? null : (
          <article className="result-panel">
            <h3>Change guidance</h3>
            <ul className="guidance-list">
              {workspace.analysis.guidance.map((item) => (
                <li key={item}>
                  <bdi className="technical-value" dir="ltr">
                    {escapeTechnicalText(item)}
                  </bdi>
                </li>
              ))}
            </ul>
          </article>
        )}

        {workspace.evidence.runs.length === 0 ? null : (
          <article className="result-panel">
            <div className="result-heading">
              <h3>Imported resolver provenance</h3>
              <StatusBadge tone="information">Inert text</StatusBadge>
            </div>
            <p className="empty-note">
              These historical endpoints and observations are data only. Opening this page or
              importing this file never sends a request to them.
            </p>
            <ul className="diagnostic-list">
              {workspace.evidence.runs.flatMap((run) =>
                run.resolvers.map((resolver) => (
                  <li key={`${run.id}-${resolver.id}`}>
                    <StatusBadge tone={resolver.status === 'complete' ? 'pass' : 'warning'}>
                      {resolver.status}
                    </StatusBadge>
                    <span className="technical-value" dir="ltr">
                      <strong>{escapeTechnicalText(resolver.label)}</strong> —{' '}
                      <code>{escapeTechnicalText(resolver.endpoint)}</code> —{' '}
                      {String(resolver.questions.length)} retained questions
                    </span>
                  </li>
                )),
              )}
            </ul>
          </article>
        )}
      </section>
    </div>
  );
}
