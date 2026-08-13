export type ZoneSeverity = 'information' | 'warning' | 'error';

export interface ZoneDiagnostic {
  readonly column: number;
  readonly line: number;
  readonly message: string;
  readonly rule: string;
  readonly severity: ZoneSeverity;
  readonly suggestion?: string;
}

export interface ZoneToken {
  readonly column: number;
  readonly line: number;
  readonly quoted: boolean;
  readonly raw: string;
  readonly value: string;
}

export interface ZoneRecord {
  readonly className: string;
  readonly column: number;
  readonly line: number;
  readonly original: string;
  readonly owner: string;
  readonly ownerToken: string;
  readonly rdata: readonly ZoneToken[];
  readonly ttl?: number;
  readonly type: string;
}

export interface ZoneDocument {
  readonly diagnostics: readonly ZoneDiagnostic[];
  readonly origin?: string;
  readonly records: readonly ZoneRecord[];
  readonly source: string;
}

export interface ZoneParseOptions {
  readonly maximumTtl?: number;
  readonly minimumTtl?: number;
  readonly origin?: string;
}
