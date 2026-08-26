import { deleteDB, openDB, type DBSchema, type IDBPDatabase } from 'idb';

import {
  SNAPSHOT_TOOLS,
  type SnapshotInput,
  type SnapshotRecord,
  type SnapshotTool,
} from './types';

const DATABASE_NAME = 'zoneskein-snapshots-v1';
const ENABLED_KEY = 'zoneskein-snapshots-enabled';
const EPOCH_KEY = 'zoneskein-snapshots-epoch-v1';
const ERASURE_KEY = 'zoneskein-snapshots-erasure-v1';
const CONTROL_CHANNEL_NAME = 'zoneskein-snapshots-control-v1';
const MAX_SNAPSHOTS = 100;
export const MAX_SNAPSHOT_CONTENT_OCTETS = 262_144;
const MAX_TITLE_CHARACTERS = 80;
export const MAX_SHARE_OCTETS = 16_384;
const MAX_SHARE_CHARACTERS = Math.ceil((MAX_SHARE_OCTETS * 4) / 3);
const REPORT_FRAGMENT_PREFIX = '#report=';
const MAX_UUID_CHARACTERS = 36;
const MAX_TIMESTAMP_CHARACTERS = 24;
const MAX_TITLE_OCTETS = MAX_TITLE_CHARACTERS * 3;
const MAX_TOOL_OCTETS = Math.max(...SNAPSHOT_TOOLS.map((tool) => tool.length));
const MAX_STORED_RECORD_OCTETS =
  MAX_SNAPSHOT_CONTENT_OCTETS +
  MAX_TITLE_OCTETS +
  MAX_TOOL_OCTETS +
  MAX_UUID_CHARACTERS +
  MAX_TIMESTAMP_CHARACTERS;
const MAX_STORED_COLLECTION_OCTETS = MAX_SNAPSHOTS * MAX_STORED_RECORD_OCTETS;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const SNAPSHOT_INPUT_KEYS = ['content', 'title', 'tool'] as const;
const SNAPSHOT_RECORD_KEYS = [
  'content',
  'createdAt',
  'id',
  'schemaVersion',
  'title',
  'tool',
] as const;

interface SnapshotDatabase extends DBSchema {
  snapshots: {
    key: string;
    value: SnapshotRecord;
    indexes: { createdAt: string };
  };
}

type SnapshotControlMessage =
  { action: 'close-databases'; version: 1 } | { action: 'state-changed'; version: 1 };

const activeDatabases = new Set<IDBPDatabase<SnapshotDatabase>>();
const stateListeners = new Set<() => void>();
let controlChannel: BroadcastChannel | null | undefined;
let storageListenerInstalled = false;

function storage(): Storage | null {
  try {
    return typeof window === 'undefined' ? null : window.localStorage;
  } catch {
    return null;
  }
}

function closeDatabase(db: IDBPDatabase<SnapshotDatabase>): void {
  if (!activeDatabases.delete(db)) return;
  db.close();
}

function closeActiveDatabases(): void {
  for (const db of activeDatabases) closeDatabase(db);
}

function isControlMessage(value: unknown): value is SnapshotControlMessage {
  if (value === null || typeof value !== 'object') return false;
  const candidate = value as { action?: unknown; version?: unknown };
  return (
    candidate.version === 1 &&
    (candidate.action === 'close-databases' || candidate.action === 'state-changed')
  );
}

function notifyStateListeners(): void {
  for (const listener of stateListeners) listener();
}

function ensureControlChannel(): BroadcastChannel | null {
  if (controlChannel !== undefined) return controlChannel;
  if (typeof window === 'undefined' || typeof window.BroadcastChannel === 'undefined') {
    controlChannel = null;
    return null;
  }
  try {
    controlChannel = new window.BroadcastChannel(CONTROL_CHANNEL_NAME);
    controlChannel.addEventListener('message', (event: MessageEvent<unknown>) => {
      if (!isControlMessage(event.data)) return;
      if (event.data.action === 'close-databases') closeActiveDatabases();
      else notifyStateListeners();
    });
    return controlChannel;
  } catch {
    controlChannel = null;
    return null;
  }
}

function publishControlMessage(message: SnapshotControlMessage): void {
  try {
    ensureControlChannel()?.postMessage(message);
  } catch {
    // Cross-tab coordination is best effort; IndexedDB still reports blocked deletion.
  }
}

function ensureStorageListener(): void {
  if (storageListenerInstalled || typeof window === 'undefined') return;
  window.addEventListener('storage', (event) => {
    if (event.key === ENABLED_KEY || event.key === EPOCH_KEY || event.key === ERASURE_KEY)
      notifyStateListeners();
  });
  storageListenerInstalled = true;
}

async function database(): Promise<IDBPDatabase<SnapshotDatabase>> {
  ensureControlChannel();
  const holder: { opened?: IDBPDatabase<SnapshotDatabase> } = {};
  const opened = await openDB<SnapshotDatabase>(DATABASE_NAME, 1, {
    blocking() {
      if (holder.opened !== undefined) closeDatabase(holder.opened);
    },
    upgrade(db) {
      const store = db.createObjectStore('snapshots', { keyPath: 'id' });
      store.createIndex('createdAt', 'createdAt');
    },
  });
  holder.opened = opened;
  activeDatabases.add(opened);
  return opened;
}

function isTool(value: unknown): value is SnapshotTool {
  return typeof value === 'string' && SNAPSHOT_TOOLS.includes(value as SnapshotTool);
}

function hasExactKeys(value: object, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function isSnapshotInput(value: unknown): value is SnapshotInput {
  if (value === null || typeof value !== 'object') return false;
  const candidate = value as Partial<Record<keyof SnapshotInput, unknown>>;
  return (
    hasExactKeys(value, SNAPSHOT_INPUT_KEYS) &&
    typeof candidate.content === 'string' &&
    typeof candidate.title === 'string' &&
    isTool(candidate.tool)
  );
}

function validateInput(value: unknown): SnapshotInput {
  if (!isSnapshotInput(value)) {
    throw new Error('Snapshot fields do not match the supported schema.');
  }
  const input = value;
  if (input.title.length > MAX_TITLE_CHARACTERS) {
    throw new Error(
      `Snapshot titles must contain 1–${String(MAX_TITLE_CHARACTERS)} characters.`,
    );
  }
  const title = input.title.trim();
  if (title.length === 0) {
    throw new Error(
      `Snapshot titles must contain 1–${String(MAX_TITLE_CHARACTERS)} characters.`,
    );
  }
  if (input.content.length === 0) throw new Error('Snapshot content cannot be empty.');
  if (input.content.length > MAX_SNAPSHOT_CONTENT_OCTETS) {
    throw new Error(
      `Snapshot content exceeds ${String(MAX_SNAPSHOT_CONTENT_OCTETS)} UTF-8 octets.`,
    );
  }
  if (encoder.encode(input.content).length > MAX_SNAPSHOT_CONTENT_OCTETS) {
    throw new Error(
      `Snapshot content exceeds ${String(MAX_SNAPSHOT_CONTENT_OCTETS)} UTF-8 octets.`,
    );
  }
  return { content: input.content, title, tool: input.tool };
}

function isCanonicalTimestamp(value: string): boolean {
  if (
    value.length !== MAX_TIMESTAMP_CHARACTERS ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
  )
    return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function parseStoredSnapshot(value: unknown): SnapshotRecord | null {
  if (value === null || typeof value !== 'object' || !hasExactKeys(value, SNAPSHOT_RECORD_KEYS))
    return null;
  const candidate = value as Partial<Record<keyof SnapshotRecord, unknown>>;
  if (
    candidate.schemaVersion !== 1 ||
    typeof candidate.id !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      candidate.id,
    ) ||
    typeof candidate.createdAt !== 'string' ||
    !isCanonicalTimestamp(candidate.createdAt)
  )
    return null;
  try {
    const input = validateInput({
      content: candidate.content,
      title: candidate.title,
      tool: candidate.tool,
    });
    if (input.title !== candidate.title) return null;
    return {
      ...input,
      createdAt: candidate.createdAt,
      id: candidate.id,
      schemaVersion: 1,
    };
  } catch {
    return null;
  }
}

function storedRecordOctets(record: SnapshotRecord): number {
  return (
    encoder.encode(record.content).length +
    encoder.encode(record.title).length +
    encoder.encode(record.tool).length +
    encoder.encode(record.id).length +
    encoder.encode(record.createdAt).length
  );
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function base64UrlToBytes(value: string): Uint8Array | null {
  if (
    value.length === 0 ||
    value.length > MAX_SHARE_CHARACTERS ||
    value.length % 4 === 1 ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  )
    return null;
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return bytesToBase64Url(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
}

export function snapshotsEnabled(): boolean {
  return snapshotWriteEpoch() !== null;
}

export function snapshotsErasurePending(): boolean {
  const target = storage();
  if (target === null) return false;
  try {
    return target.getItem(ERASURE_KEY) !== null;
  } catch {
    return false;
  }
}

function snapshotWriteEpoch(): string | null {
  const target = storage();
  if (target === null) return null;
  try {
    if (target.getItem(ERASURE_KEY) !== null || target.getItem(ENABLED_KEY) !== 'true')
      return null;
    return target.getItem(EPOCH_KEY) ?? 'legacy-enabled';
  } catch {
    return null;
  }
}

function newEpoch(): string {
  try {
    return crypto.randomUUID();
  } catch {
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  }
}

function assertSnapshotWriteEpoch(expected: string): void {
  if (snapshotWriteEpoch() !== expected)
    throw new Error('Local snapshot storage changed while this operation was running.');
}

async function abortTransaction(transaction: {
  abort(): void;
  readonly done: Promise<unknown>;
}) {
  transaction.abort();
  await transaction.done.catch(() => undefined);
}

export function enableSnapshots(): void {
  const target = storage();
  if (target === null) throw new Error('Browser storage is unavailable.');
  if (snapshotsErasurePending())
    throw new Error('Finish erasing local snapshots before enabling storage again.');
  const epoch = newEpoch();
  try {
    target.setItem(EPOCH_KEY, epoch);
    target.setItem(ENABLED_KEY, 'true');
  } catch {
    try {
      target.removeItem(ENABLED_KEY);
      target.removeItem(EPOCH_KEY);
    } catch {
      // A failed rollback still cannot appear enabled unless both reads succeed later.
    }
    throw new Error('Browser storage did not allow local snapshots.');
  }
  notifyStateListeners();
  publishControlMessage({ action: 'state-changed', version: 1 });
}

export function subscribeSnapshotState(listener: () => void): () => void {
  ensureControlChannel();
  ensureStorageListener();
  stateListeners.add(listener);
  return () => stateListeners.delete(listener);
}

export async function disableAndEraseSnapshots(onBlocked?: () => void): Promise<void> {
  const target = storage();
  if (target === null)
    throw new Error(
      'Browser storage is unavailable, so snapshot erasure could not start safely.',
    );
  try {
    target.setItem(ERASURE_KEY, newEpoch());
  } catch {
    throw new Error('Browser storage did not allow snapshot erasure to start safely.');
  }
  try {
    target.removeItem(ENABLED_KEY);
    target.removeItem(EPOCH_KEY);
  } catch {
    // The erasure marker takes precedence over stale opt-in values.
  }
  notifyStateListeners();
  publishControlMessage({ action: 'state-changed', version: 1 });

  closeActiveDatabases();
  publishControlMessage({ action: 'close-databases', version: 1 });

  const db = await database();
  try {
    const transaction = db.transaction('snapshots', 'readwrite');
    await transaction.store.clear();
    await transaction.done;
  } finally {
    closeDatabase(db);
  }

  closeActiveDatabases();
  publishControlMessage({ action: 'close-databases', version: 1 });
  await deleteDB(DATABASE_NAME, {
    blocked() {
      onBlocked?.();
    },
  });

  try {
    target.removeItem(ERASURE_KEY);
  } catch {
    throw new Error(
      'Snapshots were erased, but the browser did not allow the erasure marker to be cleared.',
    );
  }
  notifyStateListeners();
  publishControlMessage({ action: 'state-changed', version: 1 });
}

export async function saveSnapshot(input: SnapshotInput): Promise<SnapshotRecord> {
  const epoch = snapshotWriteEpoch();
  if (epoch === null) throw new Error('Enable local snapshots before saving.');
  const validated = validateInput(input);
  const db = await database();
  try {
    const record: SnapshotRecord = {
      ...validated,
      createdAt: new Date().toISOString(),
      id: crypto.randomUUID(),
      schemaVersion: 1,
    };
    const transaction = db.transaction('snapshots', 'readwrite');
    try {
      assertSnapshotWriteEpoch(epoch);
    } catch (cause) {
      await abortTransaction(transaction);
      throw cause;
    }
    await transaction.store.put(record);
    const index = transaction.store.index('createdAt');
    const count = await transaction.store.count();
    if (count > MAX_SNAPSHOTS) {
      let cursor = await index.openCursor();
      let excess = count - MAX_SNAPSHOTS;
      while (cursor !== null && excess > 0) {
        await cursor.delete();
        excess -= 1;
        cursor = await cursor.continue();
      }
    }
    try {
      assertSnapshotWriteEpoch(epoch);
    } catch (cause) {
      await abortTransaction(transaction);
      throw cause;
    }
    await transaction.done;
    return record;
  } finally {
    closeDatabase(db);
  }
}

export async function listSnapshots(): Promise<readonly SnapshotRecord[]> {
  if (!snapshotsEnabled()) return [];
  const db = await database();
  try {
    const transaction = db.transaction('snapshots', 'readwrite');
    const count = await transaction.store.count();
    if (count > MAX_SNAPSHOTS) {
      await transaction.done;
      return [];
    }

    const values: SnapshotRecord[] = [];
    let totalOctets = 0;
    let unsafeCollection = false;
    let cursor = await transaction.store.openCursor();
    while (cursor !== null) {
      const record = parseStoredSnapshot(cursor.value);
      if (record === null) await cursor.delete();
      else {
        const octets = storedRecordOctets(record);
        if (octets > MAX_STORED_COLLECTION_OCTETS - totalOctets) unsafeCollection = true;
        else {
          totalOctets += octets;
          values.push(record);
        }
      }
      cursor = await cursor.continue();
    }
    await transaction.done;
    if (unsafeCollection) return [];
    return values.sort(
      (left, right) =>
        right.createdAt.localeCompare(left.createdAt) || right.id.localeCompare(left.id),
    );
  } finally {
    closeDatabase(db);
  }
}

export async function deleteSnapshot(id: string): Promise<void> {
  const epoch = snapshotWriteEpoch();
  if (epoch === null) throw new Error('Local snapshots are disabled.');
  const db = await database();
  try {
    const transaction = db.transaction('snapshots', 'readwrite');
    try {
      assertSnapshotWriteEpoch(epoch);
    } catch (cause) {
      await abortTransaction(transaction);
      throw cause;
    }
    await transaction.store.delete(id);
    try {
      assertSnapshotWriteEpoch(epoch);
    } catch (cause) {
      await abortTransaction(transaction);
      throw cause;
    }
    await transaction.done;
  } finally {
    closeDatabase(db);
  }
}

export function snapshotFragment(input: SnapshotInput): string {
  const validated = validateInput({
    content: input.content,
    title: input.title,
    tool: input.tool,
  });
  const json = JSON.stringify(validated);
  if (encoder.encode(json).length > MAX_SHARE_OCTETS) {
    throw new Error(
      `Shareable report state exceeds the ${String(MAX_SHARE_OCTETS)}-octet limit.`,
    );
  }
  return `${REPORT_FRAGMENT_PREFIX}${bytesToBase64Url(encoder.encode(json))}`;
}

export function snapshotFromFragment(fragment: string): SnapshotInput | null {
  if (
    !fragment.startsWith(REPORT_FRAGMENT_PREFIX) ||
    fragment.length <= REPORT_FRAGMENT_PREFIX.length ||
    fragment.length > REPORT_FRAGMENT_PREFIX.length + MAX_SHARE_CHARACTERS
  )
    return null;
  const bytes = base64UrlToBytes(fragment.slice(REPORT_FRAGMENT_PREFIX.length));
  if (bytes === null || bytes.length > MAX_SHARE_OCTETS) return null;
  try {
    const value: unknown = JSON.parse(decoder.decode(bytes));
    return validateInput(value);
  } catch {
    return null;
  }
}
