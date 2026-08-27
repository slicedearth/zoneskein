export const EVIDENCE_BUNDLE_SCHEMA = 'zoneskein-evidence-v1' as const;

export type EvidenceBundleStatus = 'complete' | 'partial' | 'unavailable';
export type EvidenceNodeKind =
  'subject' | 'record' | 'target' | 'policy' | 'resolver' | 'authority' | 'uncertainty';
export type EvidenceNodeStatus = 'observed' | 'validated' | 'warning' | 'error' | 'unknown';
export type EvidenceLinkKind =
  'observed-by' | 'publishes' | 'points-to' | 'depends-on' | 'served-by' | 'qualifies';

export interface EvidenceNode {
  readonly detail: string;
  readonly id: string;
  readonly kind: EvidenceNodeKind;
  readonly label: string;
  readonly observedAt?: string;
  readonly source?: string;
  readonly status: EvidenceNodeStatus;
  readonly ttlSeconds?: number;
  readonly uncertainty?: string;
}

export interface EvidenceLink {
  readonly kind: EvidenceLinkKind;
  readonly label: string;
  readonly source: string;
  readonly target: string;
}

export interface EvidenceBundle {
  readonly capturedAt: string;
  readonly incompleteReasons: readonly string[];
  readonly links: readonly EvidenceLink[];
  readonly nodes: readonly EvidenceNode[];
  readonly schema: typeof EVIDENCE_BUNDLE_SCHEMA;
  readonly status: EvidenceBundleStatus;
  readonly subject: string;
}
