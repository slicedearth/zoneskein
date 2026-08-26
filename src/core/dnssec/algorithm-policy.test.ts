import { describe, expect, it } from 'vitest';

import {
  canEstablishDsTrustPath,
  canValidateDsDigestType,
  canVerifyRrsigAlgorithm,
  DNSSEC_RSA_MINIMUM_MODULUS_BITS,
  isDeprecatedDsDigestForAuthoring,
  isDeprecatedSha1DnssecAlgorithm,
} from './algorithm-policy';

describe('DNSSEC algorithm policy', () => {
  it('applies the interoperable 1,024-bit minimum to every RSA validation algorithm', () => {
    expect(DNSSEC_RSA_MINIMUM_MODULUS_BITS).toBe(1024);
  });

  it.each([5, 7])(
    'retains legacy algorithm %s for RRSIG verification but rejects it as a DS trust path',
    (algorithm) => {
      expect(canVerifyRrsigAlgorithm(algorithm)).toBe(true);
      expect(canEstablishDsTrustPath(algorithm)).toBe(false);
      expect(isDeprecatedSha1DnssecAlgorithm(algorithm)).toBe(true);
    },
  );

  it.each([8, 10, 13, 14, 15, 16])(
    'accepts supported modern algorithm %s for signatures and DS trust paths',
    (algorithm) => {
      expect(canVerifyRrsigAlgorithm(algorithm)).toBe(true);
      expect(canEstablishDsTrustPath(algorithm)).toBe(true);
      expect(isDeprecatedSha1DnssecAlgorithm(algorithm)).toBe(false);
    },
  );

  it('retains SHA-1 DS digests for validation but prohibits new authoring', () => {
    expect(canValidateDsDigestType(1)).toBe(true);
    expect(isDeprecatedDsDigestForAuthoring(1)).toBe(true);
    expect(canValidateDsDigestType(2)).toBe(true);
    expect(canValidateDsDigestType(4)).toBe(true);
    expect(isDeprecatedDsDigestForAuthoring(2)).toBe(false);
  });
});
