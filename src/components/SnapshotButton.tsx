import { useState } from 'react';

import { saveSnapshot, snapshotsEnabled } from '../core/snapshots/store';
import type { SnapshotTool } from '../core/snapshots/types';

interface SnapshotButtonProps {
  readonly content: string;
  readonly title: string;
  readonly tool: SnapshotTool;
}

export function SnapshotButton({ content, title, tool }: SnapshotButtonProps) {
  const [state, setState] = useState<'idle' | 'disabled' | 'saved' | 'failed'>('idle');

  async function save() {
    if (!snapshotsEnabled()) {
      setState('disabled');
      return;
    }
    try {
      await saveSnapshot({ content, title, tool });
      setState('saved');
    } catch {
      setState('failed');
    }
  }

  const visible =
    state === 'disabled'
      ? 'Enable snapshots first'
      : state === 'saved'
        ? 'Saved locally'
        : state === 'failed'
          ? 'Save failed'
          : 'Save snapshot';
  return (
    <span>
      <button className="quiet-button" type="button" onClick={() => void save()}>
        {visible}
      </button>
      <span className="visually-hidden" role="status" aria-live="polite">
        {state === 'disabled'
          ? 'Local snapshots are disabled.'
          : state === 'saved'
            ? 'Snapshot saved locally.'
            : state === 'failed'
              ? 'Snapshot could not be saved.'
              : ''}
      </span>
    </span>
  );
}
