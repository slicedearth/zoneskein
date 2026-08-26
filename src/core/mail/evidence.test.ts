import { describe, expect, it } from 'vitest';

import type { DkimSignatureVerification } from '../dkim/types';
import {
  decodeMailAuthenticationEvidence,
  encodeMailAuthenticationEvidence,
  evidenceFromDkim,
  evidenceFromSpf,
  MAIL_AUTHENTICATION_EVIDENCE_LIMITS,
} from './evidence';

const CAPTURED = '2026-08-26T00:00:00.000Z';

function signature(
  domain: string,
  status: DkimSignatureVerification['status'] = 'pass',
  keyTesting = false,
): DkimSignatureVerification {
  return {
    algorithm: 'ed25519-sha256',
    bodyCanonicalisation: 'relaxed',
    bodyHashMatches: true,
    canonicalBodyOctets: 4,
    domain,
    headerCanonicalisation: 'relaxed',
    keyName: `key._domainkey.${domain}`,
    keyTesting,
    reason: 'Fixture result.',
    selector: 'key',
    signedHeaders: ['from'],
    status,
  };
}

describe('mail-authentication evidence transfer', () => {
  it('exports only passing production DKIM domains and no message or identity data', () => {
    const evidence = evidenceFromDkim(
      [
        signature('Signer.Example.'),
        signature('testing.example', 'pass', true),
        signature('failed.example', 'fail'),
        { ...signature('signer.example'), identity: 'private-user@signer.example' },
      ],
      CAPTURED,
      'google',
      true,
    );

    expect(evidence?.dkim).toEqual([
      {
        capturedAt: CAPTURED,
        domain: 'signer.example',
        reconstructed: true,
        resolverId: 'google',
        source: 'dkim-message',
      },
    ]);
    if (evidence === null) throw new Error('Expected passing evidence.');
    const encoded = encodeMailAuthenticationEvidence(evidence);
    expect(encoded).not.toContain('private-user');
    expect(encoded).not.toContain('testing.example');
    expect(encoded).not.toContain('failed.example');
    expect(decodeMailAuthenticationEvidence(encoded)).toEqual({ ok: true, value: evidence });
  });

  it('keeps independently captured SPF and DKIM runs as separate hand-offs', () => {
    const dkim = evidenceFromDkim([signature('signer.example')], CAPTURED, 'cloudflare', false);
    const spf = evidenceFromSpf(
      {
        capturedAt: '2026-08-26T00:01:00.000Z',
        domain: 'bounce.example',
        identitySource: 'mail-from',
        result: 'pass',
      },
      'quad9-relay',
    );
    if (dkim === null || spf === null) throw new Error('Expected valid fixtures.');

    expect(dkim).toMatchObject({
      createdAt: CAPTURED,
      dkim: [{ domain: 'signer.example' }],
    });
    expect(dkim.spf).toBeUndefined();
    expect(spf).toMatchObject({
      createdAt: '2026-08-26T00:01:00.000Z',
      dkim: [],
      spf: { domain: 'bounce.example', result: 'pass' },
    });
  });

  it.each(['none', 'neutral', 'fail', 'softfail', 'temperror', 'permerror'] as const)(
    'omits the unauthenticated SPF domain for %s evidence',
    (result) => {
      const evidence = evidenceFromSpf(
        {
          capturedAt: CAPTURED,
          domain: 'private-helo.example',
          identitySource: 'helo',
          result,
        },
        'google',
      );

      expect(evidence?.spf).toEqual({
        capturedAt: CAPTURED,
        resolverId: 'google',
        result,
        source: 'spf-sender',
      });
      if (evidence === null) throw new Error('Expected non-pass SPF evidence.');
      expect(
        decodeMailAuthenticationEvidence(encodeMailAuthenticationEvidence(evidence)),
      ).toEqual({ ok: true, value: evidence });
    },
  );

  it('retains the authenticated identity source for a null-path SPF pass', () => {
    const evidence = evidenceFromSpf(
      {
        capturedAt: CAPTURED,
        domain: 'helo.example',
        identitySource: 'helo',
        result: 'pass',
      },
      'google',
    );

    expect(evidence?.spf).toMatchObject({
      domain: 'helo.example',
      identitySource: 'helo',
      result: 'pass',
    });
  });

  it('rejects oversized, ambiguous, malformed and expansive JSON before use', () => {
    expect(
      decodeMailAuthenticationEvidence(
        'x'.repeat(MAIL_AUTHENTICATION_EVIDENCE_LIMITS.jsonOctets + 1),
      ),
    ).toMatchObject({ ok: false });
    const duplicate = decodeMailAuthenticationEvidence(
      '{"createdAt":"2026-08-26T00:00:00.000Z","createdAt":"2026-08-27T00:00:00.000Z"}',
    );
    expect(duplicate.ok).toBe(false);
    if (!duplicate.ok) expect(duplicate.error).toMatch(/unique/iu);
    expect(decodeMailAuthenticationEvidence('{"evidenceSchema":')).toMatchObject({ ok: false });

    const deep = `${'{"a":'.repeat(10)}null${'}'.repeat(10)}`;
    const expansive = decodeMailAuthenticationEvidence(deep);
    expect(expansive.ok).toBe(false);
    if (!expansive.ok) expect(expansive.error).toMatch(/depth/iu);
  });

  it('rejects unknown keys, invalid domains, duplicate domains and forged timestamps', () => {
    const base = evidenceFromDkim([signature('signer.example')], CAPTURED, 'google', false);
    if (base === null) throw new Error('Expected valid fixture.');
    const parsed = JSON.parse(encodeMailAuthenticationEvidence(base)) as Record<
      string,
      unknown
    >;
    expect(
      decodeMailAuthenticationEvidence(JSON.stringify({ ...parsed, rawMessage: 'secret' })),
    ).toMatchObject({ ok: false });

    const dkim = parsed['dkim'] as Record<string, unknown>[];
    expect(
      decodeMailAuthenticationEvidence(
        JSON.stringify({ ...parsed, dkim: [{ ...dkim[0], domain: 'https://example.test' }] }),
      ),
    ).toMatchObject({ ok: false });
    const duplicateDomain = decodeMailAuthenticationEvidence(
      JSON.stringify({ ...parsed, dkim: [dkim[0], dkim[0]] }),
    );
    expect(duplicateDomain.ok).toBe(false);
    if (!duplicateDomain.ok) expect(duplicateDomain.error).toMatch(/repeats/iu);
    const forgedTime = decodeMailAuthenticationEvidence(
      JSON.stringify({ ...parsed, createdAt: '2026-08-25T00:00:00.000Z' }),
    );
    expect(forgedTime.ok).toBe(false);
    if (!forgedTime.ok) expect(forgedTime.error).toMatch(/must not precede/iu);
    const empty = decodeMailAuthenticationEvidence(JSON.stringify({ ...parsed, dkim: [] }));
    expect(empty.ok).toBe(false);
    if (!empty.ok) expect(empty.error).toMatch(/at least one/iu);
  });

  it('rejects pass evidence without identity provenance and non-pass evidence with a domain', () => {
    const passing = evidenceFromSpf(
      {
        capturedAt: CAPTURED,
        domain: 'sender.example',
        identitySource: 'mail-from',
        result: 'pass',
      },
      'google',
    );
    if (passing?.spf === undefined) throw new Error('Expected passing SPF evidence.');
    const missingSource = {
      ...passing,
      spf: { ...passing.spf, identitySource: undefined },
    };
    const nonPassWithDomain = {
      ...passing,
      spf: { ...passing.spf, result: 'fail' },
    };

    expect(decodeMailAuthenticationEvidence(JSON.stringify(missingSource))).toMatchObject({
      ok: false,
    });
    expect(decodeMailAuthenticationEvidence(JSON.stringify(nonPassWithDomain))).toMatchObject({
      ok: false,
    });
  });
});
