// RFC 9905 retains algorithms 5 and 7 for legacy RRSIG validation, but forbids
// using their DS records to establish a secure delegation.
const VERIFIABLE_RRSIG_ALGORITHMS = new Set([5, 7, 8, 10, 13, 14, 15]);

const ACCEPTABLE_DS_TRUST_PATH_ALGORITHMS = new Set([8, 10, 13, 14, 15]);

const VALIDATABLE_DS_DIGEST_TYPES = new Set([1, 2, 4]);

export function canVerifyRrsigAlgorithm(algorithm: number): boolean {
  return VERIFIABLE_RRSIG_ALGORITHMS.has(algorithm);
}

export function canEstablishDsTrustPath(algorithm: number): boolean {
  return ACCEPTABLE_DS_TRUST_PATH_ALGORITHMS.has(algorithm);
}

export function canValidateDsDigestType(digestType: number): digestType is 1 | 2 | 4 {
  return VALIDATABLE_DS_DIGEST_TYPES.has(digestType);
}

export function isDeprecatedSha1DnssecAlgorithm(algorithm: number): boolean {
  return algorithm === 5 || algorithm === 7;
}

export function isDeprecatedDsDigestForAuthoring(digestType: number): boolean {
  return digestType === 1;
}
