export const DNS_RECORD_TYPES = [
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'NS',
  'TXT',
  'SOA',
  'CAA',
  'SRV',
  'PTR',
  'DS',
  'DNSKEY',
  'RRSIG',
  'NSEC',
  'NSEC3',
  'TLSA',
  'ZONEMD',
  'HTTPS',
  'SVCB',
] as const;

export type DnsRecordType = (typeof DNS_RECORD_TYPES)[number];
export type DnsSection = 'answer' | 'authority' | 'additional';

export interface ValidatedDnsName {
  readonly ascii: string;
  readonly absolute: string;
  readonly display: string;
  readonly hadRootDot: boolean;
  readonly unicode: boolean;
}

export interface DnsQuestion {
  readonly name: ValidatedDnsName;
  readonly type: DnsRecordType;
}

export interface DnsQueryOptions {
  readonly checkingDisabled: boolean;
  readonly dnssecOk: boolean;
  readonly signal?: AbortSignal;
}

export interface DnsFlags {
  readonly authoritativeAnswer: boolean;
  readonly authenticatedData: boolean;
  readonly checkingDisabled: boolean;
  readonly recursionAvailable: boolean;
  readonly recursionDesired: boolean;
  readonly truncated: boolean;
}

export interface DnsRecord {
  readonly canonicalOwnerWire?: Uint8Array;
  readonly class: string;
  readonly data: unknown;
  readonly owner: string;
  readonly rawRdata: Uint8Array;
  readonly section: DnsSection;
  readonly ttl: number;
  readonly type: string;
  readonly typeCode: number;
}

export interface DnsExtendedError {
  readonly code: number;
  readonly name: string;
  readonly text?: string;
}

export interface DnsEdns {
  readonly dnssecOk: boolean;
  readonly extendedErrors: readonly DnsExtendedError[];
  readonly extendedResponseCode: number;
  readonly udpPayloadSize: number;
  readonly version: number;
}

export interface DnsMessage {
  readonly answers: readonly DnsRecord[];
  readonly authorities: readonly DnsRecord[];
  readonly additionals: readonly DnsRecord[];
  readonly edns?: DnsEdns;
  readonly flags: DnsFlags;
  readonly id: number;
  readonly messageBytes: number;
  readonly negativeCacheTtl?: number;
  readonly questions: readonly {
    readonly canonicalNameWire?: Uint8Array;
    readonly class: string;
    readonly name: string;
    readonly type: string;
  }[];
  readonly raw: Uint8Array;
  readonly responseCode: string;
}

export type ResolverId = 'google' | 'cloudflare' | 'quad9' | 'quad9-relay';

export interface ResolverRelayDefinition {
  readonly operator: string;
  readonly upstreamEndpoint: string;
  readonly upstreamLabel: string;
  readonly upstreamPrivacyUrl: string;
}

export interface ResolverDefinition {
  readonly endpoint: string;
  readonly httpMethod: 'GET' | 'POST';
  readonly id: ResolverId;
  readonly label: string;
  readonly privacyUrl: string;
  readonly relay?: ResolverRelayDefinition;
  readonly selectionNote?: string;
  readonly transportNote?: string;
}

export interface DnsResponse {
  readonly cache: 'hit' | 'miss' | 'shared';
  readonly message: DnsMessage;
  readonly question: DnsQuestion;
  readonly queryTimeMs: number;
  readonly receivedAt: string;
  readonly resolver: ResolverDefinition;
}

export type DnsQueryErrorCode =
  | 'aborted'
  | 'budget-exhausted'
  | 'cooldown'
  | 'http-error'
  | 'invalid-response'
  | 'rate-limited'
  | 'timeout'
  | 'transport-error';

export class DnsQueryError extends Error {
  readonly code: DnsQueryErrorCode;
  readonly retryAfterMs?: number;

  constructor(code: DnsQueryErrorCode, message: string, retryAfterMs?: number) {
    super(message);
    this.name = 'DnsQueryError';
    this.code = code;
    if (retryAfterMs !== undefined) this.retryAfterMs = retryAfterMs;
  }
}

export interface DnsResolver {
  readonly definition: ResolverDefinition;
  query(question: DnsQuestion, options: DnsQueryOptions): Promise<DnsResponse>;
}
