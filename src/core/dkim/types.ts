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
  readonly selectorFlags: readonly string[];
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

export type DkimCanonicalisation = 'simple' | 'relaxed';
export type DkimVerificationStatus =
  'pass' | 'fail' | 'temperror' | 'permerror' | 'unsupported';

export interface DkimMessageHeader {
  readonly name: string;
  readonly raw: string;
  readonly value: string;
}

export interface DkimMessage {
  readonly body: string;
  readonly headers: readonly DkimMessageHeader[];
  readonly lineEndingsNormalised: boolean;
  readonly sourceOctets: number;
}

export interface DkimSignature {
  readonly algorithm: string;
  readonly bodyCanonicalisation: DkimCanonicalisation;
  readonly bodyHash: string;
  readonly domain: string;
  readonly headerCanonicalisation: DkimCanonicalisation;
  readonly headerNames: readonly string[];
  readonly identity?: string;
  readonly length?: number;
  readonly queryMethods: readonly string[];
  readonly selector: string;
  readonly signatureData: string;
  readonly signedAt?: number;
  readonly expiresAt?: number;
  readonly tags: Readonly<Record<string, string>>;
  readonly valid: boolean;
  readonly diagnostics: readonly DkimDiagnostic[];
}

export interface DkimSignatureVerification {
  readonly algorithm: string;
  readonly bodyHashMatches: boolean;
  readonly bodyCanonicalisation: DkimCanonicalisation;
  readonly canonicalBodyOctets: number;
  readonly domain: string;
  readonly expiresAt?: number;
  readonly headerCanonicalisation: DkimCanonicalisation;
  readonly identity?: string;
  readonly keyBits?: number;
  readonly keyName: string;
  readonly keyTesting?: boolean;
  readonly length?: number;
  readonly reason: string;
  readonly selector: string;
  readonly signedAt?: number;
  readonly signedHeaders: readonly string[];
  readonly status: DkimVerificationStatus;
}
