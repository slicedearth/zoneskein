import { describe, expect, it } from 'vitest';

import { parseDmarcRecord } from './parser';
import {
  dmarcAlignmentModes,
  evaluateDmarcAlignment,
  type DmarcAlignmentInput,
} from './alignment';

function evaluate(overrides: Partial<DmarcAlignmentInput> = {}) {
  return evaluateDmarcAlignment({
    adkim: 'strict',
    aspf: 'strict',
    dkimDomains: [],
    fromDomain: 'mail.example.com',
    spf: { domain: 'bounce.example.net', result: 'fail' },
    ...overrides,
  });
}

describe('DMARC identifier alignment', () => {
  it('derives strict modes and RFC relaxed defaults from parsed policy tags', () => {
    expect(
      dmarcAlignmentModes(
        parseDmarcRecord('v=DMARC1; p=reject; adkim=s; aspf=s', 'example.com'),
      ),
    ).toEqual({ adkim: 'strict', aspf: 'strict' });
    expect(dmarcAlignmentModes(parseDmarcRecord('v=DMARC1; p=none', 'example.com'))).toEqual({
      adkim: 'relaxed',
      aspf: 'relaxed',
    });
    expect(
      dmarcAlignmentModes(parseDmarcRecord('v=DMARC1; p=none; adkim=invalid', 'example.com'))
        .adkim,
    ).toBe('relaxed');
  });

  it('accepts any passing DKIM d= domain that has strict alignment', () => {
    const result = evaluate({
      dkimDomains: ['unrelated.example.net', 'MAIL.EXAMPLE.COM.'],
    });

    expect(result.result).toBe('pass');
    expect(result.fromDomain).toBe('mail.example.com');
    expect(result.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          domain: 'mail.example.com',
          method: 'dkim',
          status: 'aligned',
        }),
      ]),
    );
  });

  it('keeps reconstructed unbound DKIM evidence conditional until explicitly acknowledged', () => {
    const provenance = {
      capturedAt: '2026-08-26T00:00:00.000Z',
      correlation: 'unbound' as const,
      reconstructed: true,
      resolverId: 'google',
      source: 'dkim-message' as const,
    };
    const qualified = evaluate({
      dkimDomains: ['mail.example.com'],
      dkimEvidence: [{ domain: 'mail.example.com', provenance }],
    });
    const acknowledged = evaluate({
      dkimDomains: ['mail.example.com'],
      dkimEvidence: [{ domain: 'mail.example.com', provenance }],
      evidenceAcknowledged: true,
    });

    expect(qualified.result).toBe('indeterminate');
    expect(qualified.reason).toMatch(/explicitly acknowledged/iu);
    expect(qualified.evidence[0]).toMatchObject({
      acknowledged: false,
      provenance,
      status: 'aligned',
    });
    expect(qualified.evidence[0]?.qualification).toMatch(/line endings were reconstructed/iu);
    expect(acknowledged.result).toBe('pass');
    expect(acknowledged.reason).toMatch(/conditionally passes/iu);
    expect(acknowledged.evidence[0]?.acknowledged).toBe(true);
  });

  it('retains HELO-derived SPF provenance in a conditional alignment decision', () => {
    const result = evaluate({
      spf: {
        domain: 'mail.example.com',
        provenance: {
          capturedAt: '2026-08-26T00:00:00.000Z',
          correlation: 'unbound',
          identitySource: 'helo',
          resolverId: 'cloudflare',
          source: 'spf-sender',
        },
        result: 'pass',
      },
    });

    expect(result.result).toBe('indeterminate');
    expect(result.evidence.at(-1)).toMatchObject({
      provenance: { identitySource: 'helo', source: 'spf-sender' },
      status: 'aligned',
    });
    expect(result.evidence.at(-1)?.qualification).toMatch(/HELO-derived/iu);
  });

  it('rejects provenance attributed to the wrong authentication method', () => {
    const result = evaluate({
      dkimDomains: ['mail.example.com'],
      dkimEvidence: [
        {
          domain: 'mail.example.com',
          provenance: {
            capturedAt: '2026-08-26T00:00:00.000Z',
            correlation: 'unbound',
            resolverId: 'google',
            source: 'spf-sender',
          },
        },
      ],
    });

    expect(result.result).toBe('permerror');
    expect(result.reason).toMatch(/provenance is malformed/iu);
  });

  it('keeps future-dated imported evidence visibly qualified', () => {
    const result = evaluate({
      dkimDomains: ['mail.example.com'],
      dkimEvidence: [
        {
          domain: 'mail.example.com',
          provenance: {
            capturedAt: '2099-01-01T00:00:00.000Z',
            correlation: 'unbound',
            reconstructed: false,
            resolverId: 'google',
            source: 'dkim-message',
          },
        },
      ],
    });

    expect(result.result).toBe('indeterminate');
    expect(result.evidence[0]?.qualification).toContain('2099-01-01T00:00:00.000Z');
  });

  it('does not confuse a sibling domain with strict alignment', () => {
    const result = evaluate({ dkimDomains: ['news.example.com'] });

    expect(result.result).toBe('fail');
    expect(result.evidence[0]).toEqual(
      expect.objectContaining({ method: 'dkim', status: 'unaligned' }),
    );
  });

  it('establishes relaxed DKIM alignment only from independently selected boundaries', () => {
    const result = evaluate({
      adkim: 'relaxed',
      authenticatedOrganizationalDomains: {
        'signer.example.com': 'example.com',
      },
      dkimDomains: ['signer.example.com'],
      organizationalDomain: 'example.com',
    });

    expect(result.result).toBe('pass');
    expect(result.evidence[0]).toEqual(
      expect.objectContaining({
        organizationalDomain: 'example.com',
        status: 'aligned',
      }),
    );
  });

  it('rejects relaxed alignment when a deeper psd=n boundary separates the signer', () => {
    const result = evaluate({
      adkim: 'r',
      authenticatedOrganizationalDomains: {
        'signer.marketing.example.com': 'marketing.example.com',
      },
      dkimDomains: ['signer.marketing.example.com'],
      organizationalDomain: 'example.com',
    });

    expect(result.result).toBe('fail');
    expect(result.evidence[0]).toEqual(
      expect.objectContaining({
        organizationalDomain: 'marketing.example.com',
        status: 'unaligned',
      }),
    );
  });

  it('uses label boundaries rather than unsafe string suffixes', () => {
    const result = evaluate({
      adkim: 'relaxed',
      dkimDomains: ['attackerexample.com'],
      organizationalDomain: 'example.com',
    });

    expect(result.result).toBe('fail');
    expect(result.evidence[0]?.status).toBe('unaligned');
  });

  it('reuses the author boundary safely for the identical domain and boundary apex', () => {
    const exact = evaluate({
      adkim: 'relaxed',
      dkimDomains: ['mail.example.com'],
      organizationalDomain: 'example.com',
    });
    const apex = evaluate({
      adkim: 'relaxed',
      dkimDomains: ['example.com'],
      organizationalDomain: 'example.com',
    });

    expect(exact.result).toBe('pass');
    expect(apex.result).toBe('pass');
  });

  it('fails closed when an author boundary required by relaxed alignment is unavailable', () => {
    const result = evaluate({
      adkim: 'relaxed',
      dkimDomains: ['mail.example.com'],
    });

    expect(result.result).toBe('indeterminate');
    expect(result.reason).toMatch(/boundary is unavailable/iu);
  });

  it('fails closed when a distinct authenticated identifier boundary is unavailable', () => {
    const result = evaluate({
      adkim: 'relaxed',
      dkimDomains: ['signer.example.com'],
      organizationalDomain: 'example.com',
    });

    expect(result.result).toBe('indeterminate');
    expect(result.reason).toMatch(/independently selected/iu);
  });

  it('preserves temporary and permanent independent boundary discovery failures', () => {
    const temporary = evaluate({
      adkim: 'relaxed',
      authenticatedOrganizationalDomainStatuses: {
        'signer.example.com': 'temperror',
      },
      dkimDomains: ['signer.example.com'],
      organizationalDomain: 'example.com',
    });
    const permanent = evaluate({
      adkim: 'relaxed',
      authenticatedOrganizationalDomainStatuses: {
        'signer.example.com': 'permerror',
      },
      dkimDomains: ['signer.example.com'],
      organizationalDomain: 'example.com',
    });

    expect(temporary.result).toBe('temperror');
    expect(permanent.result).toBe('permerror');
  });

  it('preserves an author boundary discovery error when relaxed alignment needs it', () => {
    const result = evaluate({
      adkim: 'relaxed',
      dkimDomains: ['mail.example.com'],
      organizationalDomainStatus: 'temperror',
    });

    expect(result.result).toBe('temperror');
  });

  it('does not require an organisational boundary for strict comparison', () => {
    expect(evaluate({ dkimDomains: ['mail.example.com'] }).result).toBe('pass');
  });

  it('uses only a passing SPF MAIL FROM identity for alignment', () => {
    const pass = evaluate({
      aspf: 'relaxed',
      authenticatedOrganizationalDomains: {
        'bounce.example.com': 'example.com',
      },
      organizationalDomain: 'example.com',
      spf: { domain: 'bounce.example.com', result: 'pass' },
    });
    const nonPass = evaluate({
      organizationalDomain: 'example.com',
      spf: { domain: 'mail.example.com', result: 'softfail' },
    });

    expect(pass.result).toBe('pass');
    expect(pass.evidence.at(-1)).toEqual(
      expect.objectContaining({ method: 'spf', status: 'aligned' }),
    );
    expect(nonPass.result).toBe('fail');
    expect(nonPass.evidence.at(-1)).toEqual(
      expect.objectContaining({ authenticated: false, status: 'not-authenticated' }),
    );
  });

  it('does not accept a passing SPF domain that is merely a HELO-like unaligned identity', () => {
    const result = evaluate({
      spf: { domain: 'helo.example.net', result: 'pass' },
    });

    expect(result.result).toBe('fail');
    expect(result.evidence.at(-1)?.status).toBe('unaligned');
  });

  it('distinguishes SPF temporary and permanent errors when no other method passes', () => {
    expect(evaluate({ spf: { result: 'temperror' } }).result).toBe('temperror');
    expect(evaluate({ spf: { result: 'permerror' } }).result).toBe('permerror');
  });

  it('lets an aligned DKIM identifier establish DMARC pass despite an SPF error', () => {
    for (const result of ['temperror', 'permerror'] as const) {
      const evaluation = evaluate({
        dkimDomains: ['mail.example.com'],
        spf: { result },
      });
      expect(evaluation.result).toBe('pass');
    }
  });

  it('returns permerror for malformed domains and inconsistent boundary evidence', () => {
    expect(evaluate({ fromDomain: '_mail.example.com' }).result).toBe('permerror');
    expect(evaluate({ dkimDomains: ['https://mail.example.com'] }).result).toBe('permerror');
    expect(
      evaluate({
        dkimDomains: ['mail.example.com'],
        organizationalDomain: 'example.net',
      }).result,
    ).toBe('permerror');
    expect(
      evaluate({
        adkim: 'relaxed',
        authenticatedOrganizationalDomains: {
          'signer.example.com': 'unrelated.example.net',
        },
        dkimDomains: ['signer.example.com'],
        organizationalDomain: 'example.com',
      }).result,
    ).toBe('permerror');
  });

  it('requires a domain for an SPF pass and rejects unknown runtime result values', () => {
    expect(evaluate({ spf: { result: 'pass' } }).result).toBe('permerror');
    expect(
      evaluate({
        spf: { result: 'unknown' } as unknown as DmarcAlignmentInput['spf'],
      }).result,
    ).toBe('permerror');
  });

  it('normalises internationalised author domains before strict comparison', () => {
    const result = evaluate({
      dkimDomains: ['xn--bcher-kva.example'],
      fromDomain: 'bücher.example',
    });

    expect(result.result).toBe('pass');
    expect(result.fromDomain).toBe('xn--bcher-kva.example');
  });

  it('bounds passing DKIM work to the verifier signature limit', () => {
    const domains = Array.from({ length: 21 }, (_, index) => `s${String(index)}.example.com`);
    const result = evaluate({ dkimDomains: domains });

    expect(result.result).toBe('permerror');
    expect(result.reason).toMatch(/20-signature/iu);
    expect(result.evidence).toHaveLength(1);
  });

  it('accepts the compact r and s settings and defaults absent tags to relaxed', () => {
    const compact = evaluate({
      adkim: 's',
      aspf: 's',
      dkimDomains: ['mail.example.com'],
    });
    const defaults = evaluateDmarcAlignment({
      dkimDomains: ['mail.example.com'],
      fromDomain: 'mail.example.com',
      organizationalDomain: 'example.com',
      spf: { result: 'none' },
    });

    expect(compact).toEqual(expect.objectContaining({ adkim: 'strict', aspf: 'strict' }));
    expect(defaults).toEqual(
      expect.objectContaining({ adkim: 'relaxed', aspf: 'relaxed', result: 'pass' }),
    );
  });
});
