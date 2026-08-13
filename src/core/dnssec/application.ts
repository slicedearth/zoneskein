import type { DnsRecord, DnsRecordType, DnsResponse } from '../dns/types';
import { parseRrsig } from './records';
import type { DnskeyInfo, SignatureVerification } from './types';
import { verifyRrset } from './verify';
import { boundRrset, wireQuestionMatches } from './wire-evidence';
import { DnssecWorkBudget } from './work-budget';

export const DNSSEC_APPLICATION_TYPES = [
  'A',
  'AAAA',
  'CAA',
  'CNAME',
  'HTTPS',
  'MX',
  'NS',
  'PTR',
  'SOA',
  'SRV',
  'SVCB',
  'TLSA',
  'TXT',
] as const;

export type DnssecApplicationType = (typeof DNSSEC_APPLICATION_TYPES)[number];
export type DnssecApplicationState = 'secure' | 'bogus' | 'unsupported' | 'incomplete';

export interface DnssecApplicationResult {
  readonly explanation: string;
  readonly owner: string;
  readonly records: readonly DnsRecord[];
  readonly state: DnssecApplicationState;
  readonly type: DnssecApplicationType;
  readonly verifications: readonly SignatureVerification[];
  readonly wildcardExpanded: boolean;
}

function absolute(name: string): string {
  const normalized = name.toLowerCase().replace(/\.$/u, '');
  return normalized === '' ? '.' : `${normalized}.`;
}

function questionMatches(
  response: DnsResponse,
  owner: string,
  responseQuestionType: DnsRecordType,
): boolean {
  const decoded = response.message.questions[0];
  return (
    response.message.id === 0 &&
    !response.message.flags.truncated &&
    wireQuestionMatches(response, owner, responseQuestionType) &&
    response.message.questions.length === 1 &&
    decoded?.class.toUpperCase() === 'IN' &&
    absolute(decoded.name) === absolute(owner) &&
    decoded.type === responseQuestionType &&
    absolute(response.question.name.absolute) === absolute(owner) &&
    response.question.type === responseQuestionType
  );
}

function ownerLabelCount(name: string): number {
  return name.replace(/\.$/u, '').split('.').filter(Boolean).length;
}

function failedState(verifications: readonly SignatureVerification[]): DnssecApplicationState {
  if (verifications.some((verification) => verification.status === 'resource-limit'))
    return 'incomplete';
  return verifications.length > 0 &&
    verifications.every((verification) => verification.status === 'unsupported')
    ? 'unsupported'
    : 'bogus';
}

export async function validateApplicationRrset(
  response: DnsResponse,
  owner: string,
  type: DnssecApplicationType,
  trustedKeys: readonly DnskeyInfo[],
  now = Math.floor(Date.now() / 1000),
  budget = new DnssecWorkBudget(),
  responseQuestionType: DnsRecordType = type,
): Promise<DnssecApplicationResult> {
  const target = absolute(owner);
  const base = { owner: target, type } as const;
  if (!questionMatches(response, target, responseQuestionType))
    return {
      ...base,
      explanation: 'The decoded DNS response does not match the requested application RRset.',
      records: [],
      state: 'incomplete',
      verifications: [],
      wildcardExpanded: false,
    };
  if (response.message.responseCode !== 'NOERROR')
    return {
      ...base,
      explanation: `The ${type} question returned ${response.message.responseCode}; complete authenticated name-error validation is not yet available.`,
      records: [],
      state: 'incomplete',
      verifications: [],
      wildcardExpanded: false,
    };

  const rrset = boundRrset(response, 'answer', target, type);
  if (rrset === null)
    return {
      ...base,
      explanation:
        'The original DNS packet could not be bound to one lossless canonical application RRset.',
      records: [],
      state: 'incomplete',
      verifications: [],
      wildcardExpanded: false,
    };
  const records = rrset.filter((record) => record.type === type);
  if (records.length === 0) {
    const alias = response.message.answers.find(
      (record) =>
        record.class.toUpperCase() === 'IN' &&
        (record.type === 'CNAME' || record.type === 'DNAME'),
    );
    return {
      ...base,
      explanation:
        alias === undefined
          ? `No exact ${type} RRset was returned; complete authenticated NODATA validation is not yet available.`
          : `The answer crosses a ${alias.type} alias; the target RRset is not treated as locally validated until every alias step is authenticated.`,
      records: [],
      state: 'incomplete',
      verifications: [],
      wildcardExpanded: false,
    };
  }

  const signatures = rrset.flatMap((record) => {
    const parsed = parseRrsig(record, now);
    return parsed?.typeCovered === type ? [parsed] : [];
  });
  if (
    type === 'CNAME' &&
    signatures.length === 0 &&
    response.message.answers.some(
      (record) => record.class.toUpperCase() === 'IN' && record.type === 'DNAME',
    )
  )
    return {
      ...base,
      explanation: `The answer contains an unsigned CNAME synthesised from a DNAME; it remains incomplete until the DNAME signature and substitution are authenticated.`,
      records,
      state: 'incomplete',
      verifications: [],
      wildcardExpanded: false,
    };
  const verifications = await verifyRrset(rrset, type, trustedKeys, now, budget);
  const ownerLabels = ownerLabelCount(target);
  const exactOwnerVerified = signatures.some(
    (signature, index) =>
      signature.labels === ownerLabels && verifications[index]?.status === 'verified',
  );
  const wildcardExpanded =
    !exactOwnerVerified &&
    signatures.some(
      (signature, index) =>
        signature.labels < ownerLabels && verifications[index]?.status === 'verified',
    );
  if (!verifications.some((verification) => verification.status === 'verified')) {
    const state = failedState(verifications);
    return {
      ...base,
      explanation:
        state === 'incomplete'
          ? `The ${type} RRset exceeded the local cryptographic work bound.`
          : state === 'unsupported'
            ? `The ${type} RRset uses a signature algorithm unavailable to this browser validator.`
            : `No current ${type} signature verified with the authenticated zone keys.`,
      records,
      state,
      verifications,
      wildcardExpanded,
    };
  }
  if (wildcardExpanded)
    return {
      ...base,
      explanation: `The wildcard-expanded ${type} signature verified, but the answer remains incomplete until the closest-encloser and next-closer denial proofs are authenticated.`,
      records,
      state: 'incomplete',
      verifications,
      wildcardExpanded: true,
    };
  return {
    ...base,
    explanation: `The exact positive ${type} RRset verified locally with the authenticated zone keys.`,
    records,
    state: 'secure',
    verifications,
    wildcardExpanded: false,
  };
}
