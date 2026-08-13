import 'fake-indexeddb/auto';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  deleteSnapshot,
  disableAndEraseSnapshots,
  enableSnapshots,
  listSnapshots,
  MAX_SHARE_OCTETS,
  MAX_SNAPSHOT_CONTENT_OCTETS,
  saveSnapshot,
  snapshotFragment,
  snapshotFromFragment,
  snapshotsEnabled,
} from './store';

const DATABASE_NAME = 'zoneskein-snapshots-v1';

function openSnapshotDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB open failed.'));
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = () => {
      const store = request.result.createObjectStore('snapshots', { keyPath: 'id' });
      store.createIndex('createdAt', 'createdAt');
    };
  });
}

async function injectRows(rows: readonly unknown[]): Promise<void> {
  const database = await openSnapshotDatabase();
  const transaction = database.transaction('snapshots', 'readwrite');
  for (const row of rows) transaction.objectStore('snapshots').put(row);
  await new Promise<void>((resolve, reject) => {
    transaction.onabort = () =>
      reject(transaction.error ?? new Error('IndexedDB transaction was aborted.'));
    transaction.onerror = () =>
      reject(transaction.error ?? new Error('IndexedDB transaction failed.'));
    transaction.oncomplete = () => resolve();
  });
  database.close();
}

async function storedRowCount(): Promise<number> {
  const database = await openSnapshotDatabase();
  const request = database.transaction('snapshots').objectStore('snapshots').count();
  const count = await new Promise<number>((resolve, reject) => {
    request.onerror = () => reject(request.error ?? new Error('IndexedDB count failed.'));
    request.onsuccess = () => resolve(request.result);
  });
  database.close();
  return count;
}

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

  it('accepts the maximum share payload and rejects one octet more', () => {
    const template = { content: '', title: 'Boundary', tool: 'other' } as const;
    const overhead = new TextEncoder().encode(JSON.stringify(template)).length;
    const input = {
      ...template,
      content: 'x'.repeat(MAX_SHARE_OCTETS - overhead),
    };

    expect(snapshotFromFragment(snapshotFragment(input))).toEqual(input);
    expect(() => snapshotFragment({ ...input, content: `${input.content}x` })).toThrow(
      'Shareable report state exceeds',
    );
  });

  it('rejects oversized encoded state before attempting Base64 decoding', () => {
    const decode = vi.spyOn(globalThis, 'atob');
    const maximumEncodedCharacters = Math.ceil((MAX_SHARE_OCTETS * 4) / 3);

    expect(
      snapshotFromFragment(`#report=${'A'.repeat(maximumEncodedCharacters + 1)}`),
    ).toBeNull();
    expect(decode).not.toHaveBeenCalled();
    decode.mockRestore();
  });

  it('rejects non-canonical, invalid UTF-8, and schema-expanded fragments', () => {
    const expanded = btoa(
      JSON.stringify({
        content: 'record',
        extra: 'not allowed',
        title: 'Report',
        tool: 'other',
      }),
    )
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replace(/=+$/u, '');

    expect(snapshotFromFragment('#report=AB')).toBeNull();
    expect(snapshotFromFragment('#report=_w')).toBeNull();
    expect(snapshotFromFragment(`#report=${expanded}`)).toBeNull();
  });

  it('deletes corrupt stored rows and returns only validated snapshots', async () => {
    enableSnapshots();
    const saved = await saveSnapshot({ content: 'safe', title: 'Valid', tool: 'lookup' });
    await injectRows([
      {
        content: 'do not expose',
        createdAt: '2026-08-14T00:00:00.000Z',
        extra: 'unexpected',
        id: '11111111-1111-4111-8111-111111111111',
        schemaVersion: 1,
        title: 'Expanded schema',
        tool: 'lookup',
      },
      {
        content: 'x'.repeat(MAX_SNAPSHOT_CONTENT_OCTETS + 1),
        createdAt: '2026-08-14T00:00:01.000Z',
        id: '22222222-2222-4222-8222-222222222222',
        schemaVersion: 1,
        title: 'Oversized',
        tool: 'lookup',
      },
      {
        content: 'do not expose',
        createdAt: 'not-a-date',
        id: '33333333-3333-4333-8333-333333333333',
        schemaVersion: 1,
        title: 'Bad timestamp',
        tool: 'lookup',
      },
    ]);

    expect(await listSnapshots()).toEqual([saved]);
    expect(await storedRowCount()).toBe(1);
  });

  it('fails closed when the stored row count exceeds its fixed bound', async () => {
    enableSnapshots();
    await injectRows(
      Array.from({ length: 101 }, (_, index) => ({
        content: String(index),
        createdAt: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
        id: `${String(index).padStart(8, '0')}-0000-4000-8000-000000000000`,
        schemaVersion: 1,
        title: `Row ${String(index)}`,
        tool: 'other',
      })),
    );

    expect(await listSnapshots()).toEqual([]);
  });
});
