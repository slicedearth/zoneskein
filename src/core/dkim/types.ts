export interface DkimDiagnostic {
  readonly code: string;
  readonly message: string;
  readonly severity: 'information' | 'warning' | 'error';
}

export interface DkimKeyRecord {
  readonly diagnostics: readonly DkimDiagnostic[];
  readonly hashAlgorithms: readonly string[];
  readonly keyBytes?: Uint8Array;
  readonly keyType: string;
  readonly notes?: string;
  readonly record: string;
  readonly revoked: boolean;
  readonly services: readonly string[];
  readonly tags: Readonly<Record<string, string>>;
  readonly testing: boolean;
  readonly valid: boolean;
}

export interface DkimKeyInspection {
  readonly bits?: number;
  readonly message: string;
  readonly status: 'valid' | 'weak' | 'revoked' | 'invalid' | 'unsupported';
}
