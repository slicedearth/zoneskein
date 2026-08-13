import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  disableAndEraseSnapshots,
  enableSnapshots,
  listSnapshots,
  snapshotFromFragment,
  snapshotsEnabled,
  subscribeSnapshotState,
} from '../core/snapshots/store';
import { SnapshotsPage } from './SnapshotsPage';

vi.mock('../core/snapshots/store', () => ({
  deleteSnapshot: vi.fn(),
  disableAndEraseSnapshots: vi.fn(),
  enableSnapshots: vi.fn(),
  listSnapshots: vi.fn(),
  saveSnapshot: vi.fn(),
  snapshotFragment: vi.fn(() => '#report=fixture'),
  snapshotFromFragment: vi.fn(),
  snapshotsEnabled: vi.fn(),
  subscribeSnapshotState: vi.fn(() => () => undefined),
}));

describe('local snapshot controls', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.history.replaceState({}, '', '/snapshots/');
    vi.mocked(snapshotFromFragment).mockReturnValue(null);
    vi.mocked(snapshotsEnabled).mockReturnValue(true);
    vi.mocked(listSnapshots).mockResolvedValue([]);
    vi.mocked(disableAndEraseSnapshots).mockResolvedValue();
    vi.mocked(subscribeSnapshotState).mockReturnValue(() => undefined);
  });

  it('announces blocked erasure and claims success only after deletion completes', async () => {
    let release: (() => void) | undefined;
    vi.mocked(disableAndEraseSnapshots).mockImplementation(
      (onBlocked) =>
        new Promise<void>((resolve) => {
          release = resolve;
          onBlocked?.();
        }),
    );
    render(<SnapshotsPage />);

    fireEvent.click(screen.getByRole('button', { name: 'Disable and erase all' }));

    expect(
      await screen.findByText(
        'Erasure is waiting for another ZoneSkein tab to release local snapshot storage.',
      ),
    ).toBeVisible();
    expect(screen.getByRole('button', { name: 'Erasing…' })).toBeDisabled();
    expect(screen.queryByText(/opt-in preference were erased/iu)).not.toBeInTheDocument();

    release?.();
    expect(
      await screen.findByText('Local snapshots and the opt-in preference were erased.'),
    ).toBeVisible();
    expect(screen.getByRole('button', { name: 'Enable local snapshots' })).toBeVisible();
  });

  it('retains the enabled controls and surfaces a rejected erasure', async () => {
    vi.mocked(disableAndEraseSnapshots).mockRejectedValue(
      new Error('The browser refused to erase local snapshots.'),
    );
    render(<SnapshotsPage />);

    fireEvent.click(screen.getByRole('button', { name: 'Disable and erase all' }));

    expect(
      await screen.findByText('The browser refused to erase local snapshots.'),
    ).toBeVisible();
    expect(screen.getByRole('button', { name: 'Disable and erase all' })).toBeEnabled();
  });

  it('surfaces a rejected opt-in without claiming storage is enabled', async () => {
    vi.mocked(snapshotsEnabled).mockReturnValue(false);
    vi.mocked(enableSnapshots).mockImplementation(() => {
      throw new Error('Browser storage did not allow local snapshots.');
    });
    render(<SnapshotsPage />);

    fireEvent.click(screen.getByRole('button', { name: 'Enable local snapshots' }));

    expect(
      await screen.findByText('Browser storage did not allow local snapshots.'),
    ).toBeVisible();
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Enable local snapshots' })).toBeVisible(),
    );
  });
});
