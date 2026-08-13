import type { DnsResponse } from '../dns/types';
import type { DsMatch, SignatureVerification } from './types';

export type DnssecConclusionCode =
  | 'resolver-validated'
  | 'parent-ds-matches'
  | 'local-dnskey-signature'
  | 'likely-bogus'
  | 'unsigned'
  | 'indeterminate'
  | 'query-failed';

export interface DnssecConclusion {
  readonly code: DnssecConclusionCode;
  readonly explanation: string;
  readonly label: string;
  readonly tone: 'pass' | 'information' | 'warning' | 'error' | 'unknown';
}

export interface DnssecEvidenceInput {
  readonly checkingDnskey?: DnsResponse;
  readonly dsMatches: readonly DsMatch[];
  readonly publishedDsCount: number;
  readonly signatures: readonly SignatureVerification[];
  readonly validatingDnskey?: DnsResponse;
  readonly validatingDs?: DnsResponse;
}

export function classifyDnssecEvidence(input: DnssecEvidenceInput): DnssecConclusion {
  const validatingCode = input.validatingDnskey?.message.responseCode;
  const checkingCode = input.checkingDnskey?.message.responseCode;
  const checkingHasKeys = input.checkingDnskey?.message.answers.some(
    (record) => record.type === 'DNSKEY',
  );
  if (validatingCode === 'SERVFAIL' && checkingCode === 'NOERROR' && checkingHasKeys === true) {
    return {
      code: 'likely-bogus',
      explanation:
        'The validating path returned SERVFAIL while checking-disabled retrieval exposed DNSSEC material. That pattern is consistent with a bogus chain, but resolver policy or transient failure can look similar.',
      label: 'Likely bogus',
      tone: 'error',
    };
  }

  const authenticatedDenial =
    input.validatingDs?.message.responseCode === 'NOERROR' &&
    input.validatingDs.message.flags.authenticatedData &&
    input.publishedDsCount === 0 &&
    input.validatingDs.message.authorities.some(
      (record) => record.type === 'NSEC' || record.type === 'NSEC3',
    );
  if (authenticatedDenial) {
    return {
      code: 'unsigned',
      explanation:
        'The resolver authenticated an NSEC or NSEC3 denial for the child DS RRset. This is evidence that the delegation is currently unsigned.',
      label: 'Unsigned delegation',
      tone: 'information',
    };
  }

  const matchingDs = input.dsMatches.some((match) => match.matches);
  const verifiedDnskey = input.signatures.some((signature) => signature.status === 'verified');
  if (matchingDs && verifiedDnskey) {
    return {
      code: 'local-dnskey-signature',
      explanation:
        'A published parent DS matches a returned child DNSKEY, and this browser verified a signature over the returned DNSKEY RRset. The parent DS RRset itself still relies on the selected resolver’s validation path.',
      label: 'DS match + local DNSKEY signature',
      tone: 'pass',
    };
  }
  if (matchingDs) {
    return {
      code: 'parent-ds-matches',
      explanation:
        'A SHA-256 or SHA-384 digest calculated locally from a returned DNSKEY matches a published parent DS record. This does not by itself validate every zone signature.',
      label: 'Parent DS matches child DNSKEY',
      tone: 'pass',
    };
  }
  if (input.validatingDnskey?.message.flags.authenticatedData === true) {
    return {
      code: 'resolver-validated',
      explanation:
        'The selected recursive resolver set the Authenticated Data flag on the checking-enabled response. ZoneSkein did not independently establish the entire path to the root.',
      label: 'Resolver validated',
      tone: 'pass',
    };
  }
  if (input.validatingDnskey === undefined && input.checkingDnskey === undefined) {
    return {
      code: 'query-failed',
      explanation: 'Neither DNSKEY retrieval path produced a DNS response.',
      label: 'Query failed',
      tone: 'error',
    };
  }
  return {
    code: 'indeterminate',
    explanation:
      input.publishedDsCount > 0
        ? 'Published DS records were returned, but none could be matched to the returned DNSKEY set using supported digest algorithms.'
        : 'The available responses do not contain enough authenticated evidence to classify this delegation as signed or unsigned.',
    label: 'Indeterminate',
    tone: 'unknown',
  };
}
