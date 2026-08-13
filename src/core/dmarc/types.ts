export interface DmarcDiagnostic {
  readonly code: string;
  readonly message: string;
  readonly severity: 'information' | 'warning' | 'error';
}

export interface DmarcTag {
  readonly name: string;
  readonly value: string;
}

export interface DmarcDestination {
  readonly authorizationName?: string;
  readonly domain?: string;
  readonly external: boolean;
  readonly kind: 'aggregate' | 'forensic';
  readonly uri: string;
}

export type DmarcDisposition = 'none' | 'quarantine' | 'reject';

export interface DmarcPolicyAssessment {
  readonly appliedDisposition: DmarcDisposition;
  readonly context:
    | 'direct-author-domain'
    | 'existing-inherited-subdomain'
    | 'non-existent-inherited-subdomain';
  readonly declaredDisposition?: DmarcDisposition;
  readonly fallbackToNone: boolean;
  readonly reason: string;
  readonly selectedTag: 'p' | 'sp' | 'np';
  readonly testing: boolean;
}

export interface DmarcPolicy {
  readonly applicable: boolean;
  readonly assessmentPolicyInvalid: boolean;
  readonly destinations: readonly DmarcDestination[];
  readonly diagnostics: readonly DmarcDiagnostic[];
  readonly effectiveDisposition?: DmarcDisposition;
  readonly fallbackToNone: boolean;
  readonly psd?: 'n' | 'y' | 'u';
  readonly record: string;
  readonly tags: readonly DmarcTag[];
  readonly valid: boolean;
}

export interface DmarcDiscoveryObservation {
  readonly domain: string;
  readonly policy?: DmarcPolicy;
}

export interface DmarcSelection {
  readonly organizationalDomain?: string;
  readonly selected?: DmarcDiscoveryObservation & { readonly policy: DmarcPolicy };
  readonly source: 'direct' | 'organizational' | 'public-suffix' | 'none';
}
