import type { ZoneRecord } from '../zone/types';

export type DiffCategory =
  'added' | 'removed' | 'value-changed' | 'priority-changed' | 'ttl-only' | 'formatting-only';

export interface DnsChange {
  readonly after?: ZoneRecord;
  readonly before?: ZoneRecord;
  readonly category: DiffCategory;
  readonly disruptive: boolean;
  readonly explanation: string;
  readonly owner: string;
  readonly type: string;
}

export interface DiffReport {
  readonly changes: readonly DnsChange[];
  readonly guidance: readonly string[];
}
