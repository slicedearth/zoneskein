import type { DnsRecord } from '../dns/types';

export interface DnskeyInfo {
  readonly algorithm: number;
  readonly flags: number;
  readonly key: Uint8Array;
  readonly keyTag: number;
  readonly protocol: number;
  readonly record: DnsRecord;
  readonly revoked: boolean;
  readonly secureEntryPoint: boolean;
  readonly zoneKey: boolean;
}

export interface DsInfo {
  readonly algorithm: number;
  readonly digest: Uint8Array;
  readonly digestType: number;
  readonly keyTag: number;
  readonly record: DnsRecord;
}

export type SignatureTimeState = 'current' | 'expired' | 'not-yet-valid';

export interface RrsigInfo {
  readonly algorithm: number;
  readonly expiration: number;
  readonly inception: number;
  readonly keyTag: number;
  readonly labels: number;
  readonly originalTtl: number;
  readonly record: DnsRecord;
  readonly signature: Uint8Array;
  readonly signerName: string;
  readonly timeState: SignatureTimeState;
  readonly typeCovered: string;
}

export type SignatureVerificationStatus =
  'verified' | 'invalid' | 'missing-key' | 'unsupported' | 'outside-validity';

export interface SignatureVerification {
  readonly algorithm: number;
  readonly keyTag: number;
  readonly message: string;
  readonly status: SignatureVerificationStatus;
}

export interface DsMatch {
  readonly digestType: number;
  readonly dnskey: DnskeyInfo;
  readonly ds: DsInfo;
  readonly matches: boolean;
}
