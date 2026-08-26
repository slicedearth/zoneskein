import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  disableAndEraseSnapshots,
  enableSnapshots,
  listSnapshots,
  saveSnapshot,
  snapshotFromFragment,
  snapshotsEnabled,
  snapshotsErasurePending,
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
  snapshotsErasurePending: vi.fn(),
  subscribeSnapshotState: vi.fn(() => () => undefined),
}));

describe('local snapshot controls', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.history.replaceState({}, '', '/snapshots/');
    vi.mocked(snapshotFromFragment).mockReturnValue(null);
    vi.mocked(snapshotsEnabled).mockReturnValue(true);
    vi.mocked(snapshotsErasurePending).mockReturnValue(false);
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
    let pending = false;
    vi.mocked(snapshotsErasurePending).mockImplementation(() => pending);
    vi.mocked(disableAndEraseSnapshots).mockImplementation(() => {
      pending = true;
      return Promise.reject(new Error('The browser refused to erase local snapshots.'));
    });
    render(<SnapshotsPage />);

    fireEvent.click(screen.getByRole('button', { name: 'Disable and erase all' }));

    expect(
      await screen.findByText(/The browser refused to erase local snapshots/iu),
    ).toBeVisible();
    expect(screen.getByRole('button', { name: 'Retry erasure' })).toBeEnabled();
    expect(
      screen.queryByRole('button', { name: 'Enable local snapshots' }),
    ).not.toBeInTheDocument();
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

  it('rebinds fragment display, copy, and import actions to the current hash', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    const reports: Record<
      string,
      { content: string; title: string; tool: 'dnssec' | 'lookup' } | undefined
    > = {
      '#report=a': { content: 'Report A', title: 'Title A', tool: 'lookup' as const },
      '#report=b': { content: 'Report B', title: 'Title B', tool: 'dnssec' as const },
    };
    vi.mocked(snapshotFromFragment).mockImplementation((fragment) => reports[fragment] ?? null);
    vi.mocked(saveSnapshot).mockResolvedValue({
      content: 'Report B',
      createdAt: '2026-08-26T00:00:00.000Z',
      id: 'snapshot-b',
      schemaVersion: 1,
      title: 'Title B',
      tool: 'dnssec',
    });
    window.history.replaceState({}, '', '/snapshots/#report=a');
    render(<SnapshotsPage />);

    expect(screen.getByText('Title A')).toBeVisible();

    window.history.replaceState({}, '', '/snapshots/#report=b');
    fireEvent.click(screen.getByRole('button', { name: 'Copy safe report' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('Report B'));
    expect(await screen.findByText('Title B')).toBeVisible();
    expect(screen.queryByText('Title A')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Import locally' }));
    await waitFor(() => expect(saveSnapshot).toHaveBeenCalledWith(reports['#report=b']));

    window.history.replaceState({}, '', '/snapshots/#report=invalid');
    fireEvent.click(screen.getByRole('button', { name: 'Copied' }));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Copy failed' })).toBeVisible(),
    );
    expect(writeText).toHaveBeenCalledTimes(1);

    window.dispatchEvent(new HashChangeEvent('hashchange'));
    await waitFor(() => expect(screen.queryByText('Title B')).not.toBeInTheDocument());
    expect(screen.queryByRole('button', { name: 'Copy safe report' })).not.toBeInTheDocument();

    window.history.replaceState({}, '', '/snapshots/');
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    expect(
      screen.queryByText(/Report received in this URL fragment/iu),
    ).not.toBeInTheDocument();
  });

  it('shows fragment controls as escapes and offers exact bytes only as Base64', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    vi.mocked(snapshotFromFragment).mockReturnValue({
      content: 'line' + String.fromCodePoint(0x202e) + 'log',
      title: String.raw`Literal \u{2066}; actual ` + String.fromCodePoint(0x2066) + 'hidden',
      tool: 'lookup',
    });
    window.history.replaceState({}, '', '/snapshots/#report=unsafe');
    render(<SnapshotsPage />);

    expect(
      screen.getByText(String.raw`Literal \\u{2066}; actual \u{2066}hidden`),
    ).toHaveAttribute('dir', 'ltr');
    expect(screen.getByText('Controls visibly escaped')).toBeVisible();
    expect(document.body.textContent).not.toContain(String.fromCodePoint(0x202e));

    fireEvent.click(screen.getByRole('button', { name: 'Copy safe report' }));
    fireEvent.click(screen.getByRole('button', { name: 'Copy exact report as Base64' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(2));
    expect(writeText.mock.calls[0]?.[0]).toBe('line\\u{202E}log');
    expect(writeText.mock.calls[1]?.[0]).toBe('bGluZeKArmxvZw==');
  });
});
