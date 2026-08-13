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

export interface DmarcPolicy {
  readonly destinations: readonly DmarcDestination[];
  readonly diagnostics: readonly DmarcDiagnostic[];
  readonly record: string;
  readonly tags: readonly DmarcTag[];
  readonly valid: boolean;
}
