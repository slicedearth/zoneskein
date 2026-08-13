import { deleteDB, openDB, type DBSchema, type IDBPDatabase } from 'idb';

import {
  SNAPSHOT_TOOLS,
  type SnapshotInput,
  type SnapshotRecord,
  type SnapshotTool,
} from './types';

const DATABASE_NAME = 'zoneskein-snapshots-v1';
const ENABLED_KEY = 'zoneskein-snapshots-enabled';
const MAX_SNAPSHOTS = 100;
export const MAX_SNAPSHOT_CONTENT_OCTETS = 262_144;
const MAX_TITLE_CHARACTERS = 80;
const MAX_SHARE_OCTETS = 16_384;
const encoder = new TextEncoder();

interface SnapshotDatabase extends DBSchema {
  snapshots: {
    key: string;
    value: SnapshotRecord;
    indexes: { createdAt: string };
  };
}

function storage(): Storage | null {
  try {
    return typeof window === 'undefined' ? null : window.localStorage;
  } catch {
    return null;
  }
}

function database(): Promise<IDBPDatabase<SnapshotDatabase>> {
  return openDB<SnapshotDatabase>(DATABASE_NAME, 1, {
    upgrade(db) {
      const store = db.createObjectStore('snapshots', { keyPath: 'id' });
      store.createIndex('createdAt', 'createdAt');
    },
  });
}

function isTool(value: unknown): value is SnapshotTool {
  return typeof value === 'string' && SNAPSHOT_TOOLS.includes(value as SnapshotTool);
}

function isSnapshotInput(value: unknown): value is SnapshotInput {
  if (value === null || typeof value !== 'object') return false;
  const candidate = value as Partial<Record<keyof SnapshotInput, unknown>>;
  return (
    typeof candidate.content === 'string' &&
    typeof candidate.title === 'string' &&
    isTool(candidate.tool)
  );
}

function validateInput(input: SnapshotInput): SnapshotInput {
  const title = input.title.trim();
  if (title.length === 0 || title.length > MAX_TITLE_CHARACTERS) {
    throw new Error(
      `Snapshot titles must contain 1–${String(MAX_TITLE_CHARACTERS)} characters.`,
    );
  }
  if (input.content.length === 0) throw new Error('Snapshot content cannot be empty.');
  if (encoder.encode(input.content).length > MAX_SNAPSHOT_CONTENT_OCTETS) {
    throw new Error(
      `Snapshot content exceeds ${String(MAX_SNAPSHOT_CONTENT_OCTETS)} UTF-8 octets.`,
    );
  }
  return { content: input.content, title, tool: input.tool };
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function base64UrlToBytes(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) return null;
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

export function snapshotsEnabled(): boolean {
  return storage()?.getItem(ENABLED_KEY) === 'true';
}

export function enableSnapshots(): void {
  storage()?.setItem(ENABLED_KEY, 'true');
}

export async function disableAndEraseSnapshots(): Promise<void> {
  storage()?.removeItem(ENABLED_KEY);
  await deleteDB(DATABASE_NAME);
}

export async function saveSnapshot(input: SnapshotInput): Promise<SnapshotRecord> {
  if (!snapshotsEnabled()) throw new Error('Enable local snapshots before saving.');
  const validated = validateInput(input);
  const db = await database();
  const record: SnapshotRecord = {
    ...validated,
    createdAt: new Date().toISOString(),
    id: crypto.randomUUID(),
    schemaVersion: 1,
  };
  const transaction = db.transaction('snapshots', 'readwrite');
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
  await transaction.done;
  db.close();
  return record;
}

export async function listSnapshots(): Promise<readonly SnapshotRecord[]> {
  if (!snapshotsEnabled()) return [];
  const db = await database();
  const values = await db.getAllFromIndex('snapshots', 'createdAt');
  db.close();
  return values.toReversed();
}

export async function deleteSnapshot(id: string): Promise<void> {
  if (!snapshotsEnabled()) throw new Error('Local snapshots are disabled.');
  const db = await database();
  await db.delete('snapshots', id);
  db.close();
}

export function snapshotFragment(input: SnapshotInput): string {
  const validated = validateInput(input);
  const json = JSON.stringify(validated);
  if (encoder.encode(json).length > MAX_SHARE_OCTETS) {
    throw new Error(
      `Shareable report state exceeds the ${String(MAX_SHARE_OCTETS)}-octet limit.`,
    );
  }
  return `#report=${bytesToBase64Url(encoder.encode(json))}`;
}

export function snapshotFromFragment(fragment: string): SnapshotInput | null {
  if (!fragment.startsWith('#report=')) return null;
  const bytes = base64UrlToBytes(fragment.slice('#report='.length));
  if (bytes === null || bytes.length > MAX_SHARE_OCTETS) return null;
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return isSnapshotInput(value) ? validateInput(value) : null;
  } catch {
    return null;
  }
}
