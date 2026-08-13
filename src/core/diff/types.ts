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
  readonly incompleteReasons: readonly string[];
  readonly status: 'complete' | 'incomplete';
}

export type ChangeRisk = 'information' | 'low' | 'moderate' | 'high' | 'critical';

export interface ChangeImpact {
  readonly changeIndex: number;
  readonly reasons: readonly string[];
  readonly risk: ChangeRisk;
  readonly rollback: string;
}

export interface ChangePreflightFinding {
  readonly code: string;
  readonly message: string;
  readonly risk: ChangeRisk;
}

export interface ChangeTiming {
  readonly plannedAt?: string;
  readonly previousTtlSeconds?: number;
  readonly preparationDeadline?: string;
  readonly rollbackCacheHorizon?: string;
  readonly safeChangeAtIfLoweredNow?: string;
}

export interface RolloutPhase {
  readonly actions: readonly string[];
  readonly id: 'prepare' | 'wait' | 'publish' | 'verify' | 'observe' | 'restore';
  readonly title: string;
}

export interface DnsChangePlan {
  readonly findings: readonly ChangePreflightFinding[];
  readonly impacts: readonly ChangeImpact[];
  readonly incompleteReasons: readonly string[];
  readonly phases: readonly RolloutPhase[];
  readonly risk: ChangeRisk;
  readonly status: 'complete' | 'incomplete';
  readonly timing: ChangeTiming;
}
