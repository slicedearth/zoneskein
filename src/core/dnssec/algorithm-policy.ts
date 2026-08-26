// RFC 9905 retains algorithms 5 and 7 for legacy RRSIG validation, but forbids
// using their DS records to establish a secure delegation.
const VERIFIABLE_RRSIG_ALGORITHMS = new Set([5, 7, 8, 10, 13, 14, 15, 16]);

const ACCEPTABLE_DS_TRUST_PATH_ALGORITHMS = new Set([8, 10, 13, 14, 15, 16]);

const VALIDATABLE_DS_DIGEST_TYPES = new Set([1, 2, 4]);

// A shorter RSA modulus is rejected before Web Crypto sees the key. The floor
// retains interoperability with deployed legacy DNSSEC while excluding the
// 512-bit example keys retained only as canonicalisation fixtures.
export const DNSSEC_RSA_MINIMUM_MODULUS_BITS = 1024;

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
