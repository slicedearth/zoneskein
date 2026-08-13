import 'fake-indexeddb/auto';

import { beforeEach, describe, expect, it } from 'vitest';

import {
  deleteSnapshot,
  disableAndEraseSnapshots,
  enableSnapshots,
  listSnapshots,
  saveSnapshot,
  snapshotFragment,
  snapshotFromFragment,
  snapshotsEnabled,
} from './store';

function memoryStorage(): Storage {
  const values = new Map<string, string>();
  return {
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    get length() {
      return values.size;
    },
    removeItem: (key) => values.delete(key),
    setItem: (key, value) => values.set(key, value),
  };
}

describe('explicit local snapshots', () => {
  beforeEach(async () => {
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      value: memoryStorage(),
    });
    await disableAndEraseSnapshots();
  });

  it('does not save until the user enables storage', async () => {
    expect(snapshotsEnabled()).toBe(false);
    await expect(
      saveSnapshot({ content: '{}', title: 'DNSSEC evidence', tool: 'dnssec' }),
    ).rejects.toThrow('Enable local snapshots');
  });

  it('saves, lists, deletes, and erases snapshots in IndexedDB', async () => {
    enableSnapshots();
    const saved = await saveSnapshot({
      content: '{}',
      title: 'DNSSEC evidence',
      tool: 'dnssec',
    });
    expect(await listSnapshots()).toEqual([saved]);
    await deleteSnapshot(saved.id);
    expect(await listSnapshots()).toEqual([]);
    await saveSnapshot({ content: 'record', title: 'Lookup', tool: 'lookup' });
    await disableAndEraseSnapshots();
    expect(snapshotsEnabled()).toBe(false);
    expect(await listSnapshots()).toEqual([]);
  });

  it('round-trips bounded state through a URL fragment', () => {
    const input = { content: 'v=spf1 -all', title: 'SPF report', tool: 'spf' } as const;
    const fragment = snapshotFragment(input);
    expect(fragment).toMatch(/^#report=/u);
    expect(snapshotFromFragment(fragment)).toEqual(input);
    expect(snapshotFromFragment('#report=not!base64')).toBeNull();
  });
});
