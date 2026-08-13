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
    db.close();
  }
}

export async function deleteSnapshot(id: string): Promise<void> {
  if (!snapshotsEnabled()) throw new Error('Local snapshots are disabled.');
  const db = await database();
  await db.delete('snapshots', id);
  db.close();
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
