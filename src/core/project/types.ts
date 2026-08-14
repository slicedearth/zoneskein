export const CHANGE_WORKSPACE_FORMAT = 'zoneskein-project-v1' as const;

export type ChangeWorkspaceFormat = typeof CHANGE_WORKSPACE_FORMAT;
export type ChangeWorkspaceCompleteness = 'complete' | 'partial';
export type ChangeWorkspaceRisk = 'information' | 'low' | 'moderate' | 'high' | 'critical';
export type ChangeWorkspaceAnalysisStatus = 'not-run' | ChangeWorkspaceCompleteness;
export type ChangeWorkspaceEvidenceStatus = 'none' | ChangeWorkspaceCompleteness;
export type ChangeWorkspaceResolverId = 'cloudflare' | 'google' | 'quad9' | 'custom';
export type ChangeWorkspaceQuestionStatus =
  | 'answer'
  | 'no-data'
  | 'name-error'
  | 'refused'
  | 'server-failure'
  | 'timeout'
  | 'network-error'
  | 'malformed-response'
  | 'cancelled';

export type ChangeWorkspaceChangeCategory =
  'added' | 'removed' | 'value-changed' | 'priority-changed' | 'ttl-only' | 'formatting-only';

export interface ChangeWorkspaceZoneState {
  readonly format: 'bind-zone-text';
  readonly incompleteReasons: readonly string[];
  readonly origin: string | null;
  readonly source: string;
  readonly status: 'unavailable' | ChangeWorkspaceCompleteness;
}

export interface ChangeWorkspaceAnalysedChange {
  readonly after: string | null;
  readonly before: string | null;
  readonly category: ChangeWorkspaceChangeCategory;
  readonly disruptive: boolean;
  readonly explanation: string;
  readonly owner: string;
  readonly reasons: readonly string[];
  readonly risk: ChangeWorkspaceRisk;
  readonly rollback: string;
  readonly type: string;
}

export interface ChangeWorkspaceFinding {
  readonly code: string;
  readonly message: string;
  readonly risk: ChangeWorkspaceRisk;
}

export interface ChangeWorkspaceTiming {
  readonly plannedAt: string | null;
  readonly preparationDeadline: string | null;
  readonly previousTtlSeconds: number | null;
  readonly rollbackCacheHorizon: string | null;
  readonly safeChangeAtIfLoweredNow: string | null;
}

export type ChangeWorkspacePhaseId =
  'prepare' | 'wait' | 'publish' | 'verify' | 'observe' | 'restore';

export interface ChangeWorkspaceRolloutPhase {
  readonly actions: readonly string[];
  readonly id: ChangeWorkspacePhaseId;
  readonly title: string;
}

export interface ChangeWorkspaceAnalysis {
  readonly analysedAt: string | null;
  readonly changes: readonly ChangeWorkspaceAnalysedChange[];
  readonly findings: readonly ChangeWorkspaceFinding[];
  readonly guidance: readonly string[];
  readonly incompleteReasons: readonly string[];
  readonly phases: readonly ChangeWorkspaceRolloutPhase[];
  readonly risk: ChangeWorkspaceRisk | null;
  readonly status: ChangeWorkspaceAnalysisStatus;
  readonly timing: ChangeWorkspaceTiming;
}

export interface ChangeWorkspaceQuestionObservation {
  readonly authenticatedData: boolean | null;
  readonly className: 'IN';
  readonly error: string | null;
  readonly id: string;
  readonly name: string;
  readonly observedAt: string;
  readonly records: readonly string[];
  readonly responseCode: number | null;
  readonly status: ChangeWorkspaceQuestionStatus;
  readonly type: string;
}

export interface ChangeWorkspaceResolverObservation {
  readonly endpoint: string;
  readonly id: string;
  readonly incompleteReasons: readonly string[];
  readonly label: string;
  readonly questions: readonly ChangeWorkspaceQuestionObservation[];
  readonly resolverId: ChangeWorkspaceResolverId;
  readonly status: ChangeWorkspaceCompleteness;
}

export interface ChangeWorkspaceObservationRun {
  readonly completedAt: string;
  readonly id: string;
  readonly incompleteReasons: readonly string[];
  readonly resolvers: readonly ChangeWorkspaceResolverObservation[];
  readonly startedAt: string;
  readonly status: ChangeWorkspaceCompleteness;
}

export interface ChangeWorkspaceEvidence {
  readonly incompleteReasons: readonly string[];
  readonly runs: readonly ChangeWorkspaceObservationRun[];
  readonly status: ChangeWorkspaceEvidenceStatus;
}

export interface ChangeWorkspace {
  readonly analysis: ChangeWorkspaceAnalysis;
  readonly createdAt: string;
  readonly current: ChangeWorkspaceZoneState;
  readonly evidence: ChangeWorkspaceEvidence;
  readonly id: string;
  readonly intended: ChangeWorkspaceZoneState;
  readonly title: string;
  readonly updatedAt: string;
}

export interface ChangeWorkspaceIntegrity {
  readonly algorithm: 'SHA-256';
  readonly authenticity: 'none';
  readonly digest: string;
}

export interface ChangeWorkspaceEnvelope {
  readonly format: ChangeWorkspaceFormat;
  readonly integrity: ChangeWorkspaceIntegrity;
  readonly workspace: ChangeWorkspace;
}

export type ChangeWorkspaceIntegrityCheck =
  | {
      readonly algorithm: 'SHA-256';
      readonly authenticity: 'none';
      readonly digest: string;
      readonly status: 'match';
    }
  | {
      readonly algorithm: 'SHA-256';
      readonly authenticity: 'none';
      readonly calculatedDigest: string;
      readonly claimedDigest: string;
      readonly status: 'mismatch';
    };

export interface DecodedChangeWorkspace {
  readonly format: ChangeWorkspaceFormat;
  readonly integrity: ChangeWorkspaceIntegrityCheck;
  readonly workspace: ChangeWorkspace;
}

export type ChangeWorkspaceCodecErrorCode =
  | 'crypto-unavailable'
  | 'duplicate-key'
  | 'file-too-large'
  | 'invalid-json'
  | 'invalid-schema'
  | 'invalid-utf8'
  | 'resource-limit'
  | 'unsupported-value';

export interface ChangeWorkspaceCodecError {
  readonly code: ChangeWorkspaceCodecErrorCode;
  readonly message: string;
  readonly path?: string;
}
