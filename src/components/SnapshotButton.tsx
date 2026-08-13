import { useState } from 'react';

import { saveSnapshot, snapshotsEnabled } from '../core/snapshots/store';
import type { SnapshotTool } from '../core/snapshots/types';

interface SnapshotButtonProps {
  readonly content: string;
  readonly title: string;
  readonly tool: SnapshotTool;
}

export function SnapshotButton({ content, title, tool }: SnapshotButtonProps) {
  const [message, setMessage] = useState('Save snapshot');

  async function save() {
    if (!snapshotsEnabled()) {
      setMessage('Enable snapshots first');
      return;
    }
    try {
      await saveSnapshot({ content, title, tool });
      setMessage('Saved locally');
    } catch {
      setMessage('Save failed');
    }
  }

  return (
    <button className="quiet-button" type="button" onClick={() => void save()}>
      {message}
    </button>
  );
}
