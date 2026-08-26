import { useState } from 'react';

import { saveSnapshot, snapshotsEnabled } from '../core/snapshots/store';
import type { SnapshotTool } from '../core/snapshots/types';

interface SnapshotButtonProps {
  readonly content: string;
  readonly title: string;
  readonly tool: SnapshotTool;
}

type SnapshotSaveState = 'idle' | 'pending' | 'disabled' | 'saved' | 'failed';

interface SnapshotButtonState {
  readonly content: string;
  readonly state: SnapshotSaveState;
  readonly title: string;
  readonly tool: SnapshotTool;
}

export function SnapshotButton({ content, title, tool }: SnapshotButtonProps) {
  const [result, setResult] = useState<SnapshotButtonState>({
    content,
    state: 'idle',
    title,
    tool,
  });
  const state =
    result.content === content && result.title === title && result.tool === tool
      ? result.state
      : 'idle';

  function matchesCurrent(
    candidate: typeof result,
    requested: {
      readonly content: string;
      readonly title: string;
      readonly tool: SnapshotTool;
    },
  ): boolean {
    return (
      candidate.content === requested.content &&
      candidate.title === requested.title &&
      candidate.tool === requested.tool
    );
  }

  async function save() {
    if (state === 'pending') return;
    if (!snapshotsEnabled()) {
      setResult({ content, state: 'disabled', title, tool });
      return;
    }
    const requested = { content, title, tool };
    setResult({ ...requested, state: 'pending' });
    try {
      await saveSnapshot(requested);
      setResult((current) =>
        matchesCurrent(current, requested) && current.state === 'pending'
          ? { ...requested, state: 'saved' }
          : current,
      );
    } catch {
      setResult((current) =>
        matchesCurrent(current, requested) && current.state === 'pending'
          ? { ...requested, state: 'failed' }
          : current,
      );
    }
  }

  const visible =
    state === 'disabled'
      ? 'Enable snapshots first'
      : state === 'pending'
        ? 'Saving…'
        : state === 'saved'
          ? 'Saved locally'
          : state === 'failed'
            ? 'Save failed'
            : 'Save snapshot';
  return (
    <span>
      <button
        className="quiet-button"
        type="button"
        disabled={state === 'pending'}
        aria-busy={state === 'pending'}
        onClick={() => void save()}
      >
        {visible}
      </button>
      <span className="visually-hidden" role="status" aria-live="polite">
        {state === 'disabled'
          ? 'Local snapshots are disabled.'
          : state === 'pending'
            ? 'Saving the snapshot locally.'
            : state === 'saved'
              ? 'Snapshot saved locally.'
              : state === 'failed'
                ? 'Snapshot could not be saved.'
                : ''}
      </span>
    </span>
  );
}
