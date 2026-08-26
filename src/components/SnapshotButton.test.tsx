import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { saveSnapshot, snapshotsEnabled } from '../core/snapshots/store';
import { SnapshotButton } from './SnapshotButton';

vi.mock('../core/snapshots/store', () => ({
  saveSnapshot: vi.fn(),
  snapshotsEnabled: vi.fn(),
}));

describe('SnapshotButton', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(snapshotsEnabled).mockReturnValue(true);
    vi.mocked(saveSnapshot).mockResolvedValue({
      content: 'evidence',
      createdAt: '2026-08-13T00:00:00.000Z',
      id: 'fixture',
      schemaVersion: 1,
      title: 'Report',
      tool: 'lookup',
    });
  });

  it('announces a successful local save through a polite status region', async () => {
    render(<SnapshotButton content="evidence" title="Report" tool="lookup" />);

    fireEvent.click(screen.getByRole('button', { name: 'Save snapshot' }));

    await waitFor(() => expect(saveSnapshot).toHaveBeenCalledOnce());
    expect(screen.getByRole('status')).toHaveTextContent('Snapshot saved locally.');
    expect(screen.getByRole('button', { name: 'Saved locally' })).toBeInTheDocument();
  });

  it('announces that explicit snapshot opt-in is still required', () => {
    vi.mocked(snapshotsEnabled).mockReturnValue(false);
    render(<SnapshotButton content="evidence" title="Report" tool="lookup" />);

    fireEvent.click(screen.getByRole('button', { name: 'Save snapshot' }));

    expect(screen.getByRole('status')).toHaveTextContent('Local snapshots are disabled.');
    expect(saveSnapshot).not.toHaveBeenCalled();
  });

  it('disables duplicate submissions and ignores a stale completion after content changes', async () => {
    let resolveSave: (() => void) | undefined;
    vi.mocked(saveSnapshot).mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveSave = () =>
            resolve({
              content: 'first',
              createdAt: '2026-08-26T00:00:00.000Z',
              id: '11111111-1111-4111-8111-111111111111',
              schemaVersion: 1,
              title: 'Report',
              tool: 'lookup',
            });
        }),
    );
    const view = render(<SnapshotButton content="first" title="Report" tool="lookup" />);

    fireEvent.click(screen.getByRole('button', { name: 'Save snapshot' }));
    expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Saving…' }));
    expect(saveSnapshot).toHaveBeenCalledTimes(1);

    view.rerender(<SnapshotButton content="second" title="Report" tool="lookup" />);
    expect(await screen.findByRole('button', { name: 'Save snapshot' })).toBeEnabled();
    resolveSave?.();
    await Promise.resolve();
    expect(screen.getByRole('button', { name: 'Save snapshot' })).toBeEnabled();
  });
});
