export type SpfQualifier = '+' | '-' | '~' | '?';

export type SpfMechanismName =
  'all' | 'include' | 'a' | 'mx' | 'ptr' | 'ip4' | 'ip6' | 'exists';

export type SpfModifierName = 'redirect' | 'exp';

export interface SourceLocation {
  readonly end: number;
  readonly start: number;
}

export interface SpfCidr {
  readonly ipv4?: number;
  readonly ipv6?: number;
}

export interface SpfMechanism {
  readonly argument?: string;
  readonly cidr?: SpfCidr;
  readonly kind: 'mechanism';
  readonly location: SourceLocation;
  readonly macro: boolean;
  readonly name: SpfMechanismName;
  readonly original: string;
  readonly qualifier: SpfQualifier;
}

export interface SpfModifier {
  readonly kind: 'modifier';
  readonly location: SourceLocation;
  readonly macro: boolean;
  readonly name: SpfModifierName;
  readonly original: string;
  readonly value: string;
}

export interface SpfUnknownTerm {
  readonly kind: 'unknown';
  readonly location: SourceLocation;
  readonly original: string;
}

export type SpfTerm = SpfMechanism | SpfModifier | SpfUnknownTerm;

export type SpfDiagnosticSeverity = 'information' | 'warning' | 'error';

export interface SpfDiagnostic {
  readonly code: string;
  readonly location?: SourceLocation;
  readonly message: string;
  readonly severity: SpfDiagnosticSeverity;
  readonly sourceDomain?: string;
}

export interface SpfPolicy {
  readonly diagnostics: readonly SpfDiagnostic[];
  readonly record: string;
  readonly sourceDomain: string;
  readonly terms: readonly SpfTerm[];
  readonly validVersion: boolean;
}

export type SpfLookupType = 'TXT' | 'A' | 'AAAA' | 'MX';
export type SpfLookupStatus = 'answer' | 'nodata' | 'nxdomain' | 'servfail' | 'error';

export interface SpfLookupResult {
  readonly error?: string;
  readonly messageBytes: number;
  readonly status: SpfLookupStatus;
  readonly ttl?: number;
  readonly values: readonly string[];
}

export interface SpfDnsClient {
  lookup(domain: string, type: SpfLookupType): Promise<SpfLookupResult>;
}

export interface SpfResolution {
  readonly domain: string;
  readonly kind: 'a' | 'mx' | 'exists';
  readonly networks: readonly string[];
  readonly targets: readonly string[];
  readonly termIndex: number;
  readonly ttl?: number;
  readonly void: boolean;
}

export interface SpfGraphNode {
  readonly domain: string;
  readonly messageBytes: number;
  readonly policy?: SpfPolicy;
  readonly resolutions: readonly SpfResolution[];
  readonly status: SpfLookupStatus | 'multiple-policy';
  readonly ttl?: number;
  readonly txtOctets: number;
}

export interface SpfGraphEdge {
  readonly from: string;
  readonly kind: 'include' | 'redirect';
  readonly to: string;
}

export interface SpfAnalysis {
  readonly diagnostics: readonly SpfDiagnostic[];
  readonly edges: readonly SpfGraphEdge[];
  readonly maximumDepth: number;
  readonly maximumLookupTerms: number;
  readonly maximumVoidLookups: number;
  readonly nodes: readonly SpfGraphNode[];
  readonly rootDomain: string;
  readonly totalResponseBytes: number;
}

export interface SpfProvenance {
  readonly mechanism: string;
  readonly network: string;
  readonly path: readonly string[];
  readonly sourceRecord: string;
  readonly sourceTtl?: number;
}

export interface SpfSnapshot {
  readonly bindRecord?: string;
  readonly blockers: readonly string[];
  readonly chunks: readonly string[];
  readonly earliestSourceExpiry?: string;
  readonly estimatedResponseBytes?: number;
  readonly generatedAt: string;
  readonly markdown?: string;
  readonly networks: readonly string[];
  readonly provenance: readonly SpfProvenance[];
  readonly recommendedRecheck?: string;
  readonly safe: boolean;
  readonly terminal?: string;
  readonly value?: string;
  readonly warnings: readonly string[];
}
