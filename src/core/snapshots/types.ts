export const SNAPSHOT_TOOLS = [
  'lookup',
  'dnssec',
  'spf',
  'zone-lint',
  'diff',
  'dmarc',
  'dkim',
  'caa',
  'other',
] as const;

export type SnapshotTool = (typeof SNAPSHOT_TOOLS)[number];

export interface SnapshotInput {
  readonly content: string;
  readonly title: string;
  readonly tool: SnapshotTool;
}

export interface SnapshotRecord extends SnapshotInput {
  readonly createdAt: string;
  readonly id: string;
  readonly schemaVersion: 1;
}
