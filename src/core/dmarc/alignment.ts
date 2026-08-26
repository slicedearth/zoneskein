import { validateDnsName } from '../dns/names';

import type { DmarcPolicy } from './types';

const MAX_PASSING_DKIM_DOMAINS = 20;

export type DmarcAlignmentMode = 'relaxed' | 'strict';
export type DmarcAlignmentSetting = DmarcAlignmentMode | 'r' | 's';

export type DmarcSpfResult =
  'none' | 'neutral' | 'pass' | 'fail' | 'softfail' | 'temperror' | 'permerror';

export type DmarcAlignmentResult =
  'pass' | 'fail' | 'temperror' | 'permerror' | 'indeterminate';

export type DmarcIdentifierStatus =
  'aligned' | 'unaligned' | 'not-authenticated' | 'temperror' | 'permerror' | 'indeterminate';

export type DmarcBoundaryStatus = 'complete' | 'temperror' | 'permerror' | 'indeterminate';

export interface DmarcAuthenticationProvenance {
  readonly capturedAt?: string;
  readonly correlation: 'unbound';
  readonly identitySource?: 'helo' | 'mail-from';
  readonly reconstructed?: boolean;
  readonly resolverId?: string;
  readonly source: 'dkim-message' | 'manual' | 'spf-sender';
}

export interface DmarcDkimAuthentication {
  readonly domain: string;
  readonly provenance?: DmarcAuthenticationProvenance;
}

export interface DmarcSpfAuthentication {
  /** The RFC5321.MailFrom domain, including the synthetic postmaster@HELO identity for a null path. */
  readonly domain?: string;
  readonly provenance?: DmarcAuthenticationProvenance;
  readonly result: DmarcSpfResult;
}

export interface DmarcAlignmentInput {
  /** Defaults to relaxed alignment, as specified for an absent adkim tag. */
  readonly adkim?: DmarcAlignmentSetting;
  /** Defaults to relaxed alignment, as specified for an absent aspf tag. */
  readonly aspf?: DmarcAlignmentSetting;
  /**
   * Boundaries independently selected by tree walk for authenticated identifiers.
   * Keys may be the supplied domain or its normalised A-label form.
   */
  readonly authenticatedOrganizationalDomains?: Readonly<Record<string, string>>;
  /** Discovery status for each independently walked authenticated identifier. */
  readonly authenticatedOrganizationalDomainStatuses?: Readonly<
    Record<string, DmarcBoundaryStatus>
  >;
  /** Prior-evidence metadata associated with each supplied DKIM domain. */
  readonly dkimEvidence?: readonly DmarcDkimAuthentication[];
  /** The d= domains from DKIM signatures that have already passed verification. */
  readonly dkimDomains: readonly string[];
  /** Explicit acknowledgement that qualified prior evidence belongs to this assessment context. */
  readonly evidenceAcknowledged?: boolean;
  /** The single domain extracted from RFC5322.From. */
  readonly fromDomain: string;
  /** The boundary selected by tree walk for fromDomain. */
  readonly organizationalDomain?: string;
  /** Defaults to complete with a boundary and indeterminate without one. */
  readonly organizationalDomainStatus?: DmarcBoundaryStatus;
  readonly spf: DmarcSpfAuthentication;
}

export interface DmarcIdentifierEvidence {
  readonly acknowledged?: boolean;
  readonly authenticated: boolean;
  readonly domain?: string;
  readonly method: 'dkim' | 'spf';
  readonly mode: DmarcAlignmentMode;
  readonly organizationalDomain?: string;
  readonly provenance?: DmarcAuthenticationProvenance;
  readonly qualification?: string;
  readonly reason: string;
  readonly status: DmarcIdentifierStatus;
}

export interface DmarcAlignmentEvaluation {
  readonly adkim: DmarcAlignmentMode;
  readonly aspf: DmarcAlignmentMode;
  readonly evidence: readonly DmarcIdentifierEvidence[];
  readonly fromDomain?: string;
  readonly organizationalDomain?: string;
  readonly reason: string;
  readonly result: DmarcAlignmentResult;
}

interface NormalisedDomain {
  readonly normalised: string;
  readonly supplied: string;
}

function normaliseMode(value: unknown): DmarcAlignmentMode | null {
  if (value === undefined || value === 'r' || value === 'relaxed') return 'relaxed';
  if (value === 's' || value === 'strict') return 'strict';
  return null;
}

function isBoundaryStatus(value: unknown): value is DmarcBoundaryStatus {
  return (
    value === 'complete' ||
    value === 'temperror' ||
    value === 'permerror' ||
    value === 'indeterminate'
  );
}

function normaliseDomain(value: unknown): NormalisedDomain | null {
  if (typeof value !== 'string' || value !== value.trim() || value.includes('://')) return null;
  const parsed = validateDnsName(value);
  if (!parsed.ok || parsed.value.ascii === '') return null;
  if (
    parsed.value.ascii
      .split('.')
      .some((label) => !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))
  )
    return null;
  return { normalised: parsed.value.ascii, supplied: value };
}

function isAuthenticationProvenance(
  value: unknown,
  method: DmarcIdentifierEvidence['method'],
): value is DmarcAuthenticationProvenance {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const item = value as Readonly<Record<string, unknown>>;
  const allowed = new Set([
    'capturedAt',
    'correlation',
    'identitySource',
    'reconstructed',
    'resolverId',
    'source',
  ]);
  if (Object.keys(item).some((key) => !allowed.has(key)) || item['correlation'] !== 'unbound')
    return false;
  const source = item['source'];
  if (source !== 'dkim-message' && source !== 'manual' && source !== 'spf-sender') return false;
  if (
    source !== 'manual' &&
    ((method === 'dkim' && source !== 'dkim-message') ||
      (method === 'spf' && source !== 'spf-sender'))
  )
    return false;
  const timestamp = item['capturedAt'];
  if (timestamp !== undefined) {
    if (typeof timestamp !== 'string') return false;
    const time = Date.parse(timestamp);
    if (!Number.isFinite(time) || new Date(time).toISOString() !== timestamp) return false;
  }
  if (
    item['identitySource'] !== undefined &&
    item['identitySource'] !== 'helo' &&
    item['identitySource'] !== 'mail-from'
  )
    return false;
  if (item['reconstructed'] !== undefined && typeof item['reconstructed'] !== 'boolean')
    return false;
  const resolver = item['resolverId'];
  if (
    resolver !== undefined &&
    (typeof resolver !== 'string' || resolver.length < 1 || resolver.length > 64)
  )
    return false;
  if (source === 'manual')
    return (
      timestamp === undefined &&
      resolver === undefined &&
      item['identitySource'] === undefined &&
      item['reconstructed'] === undefined
    );
  if (timestamp === undefined || resolver === undefined) return false;
  if (source === 'dkim-message')
    return typeof item['reconstructed'] === 'boolean' && item['identitySource'] === undefined;
  return item['reconstructed'] === undefined;
}

function qualifiedEvidence(
  evidence: DmarcIdentifierEvidence,
  provenance: DmarcAuthenticationProvenance | undefined,
  acknowledged: boolean,
): DmarcIdentifierEvidence {
  if (provenance === undefined) return evidence;
  if (!isAuthenticationProvenance(provenance, evidence.method))
    return {
      ...evidence,
      authenticated: false,
      reason: 'Prior authentication provenance is malformed, so it cannot support alignment.',
      status: 'permerror',
    };
  const source =
    provenance.source === 'manual'
      ? 'This authentication result was entered manually and was not reverified.'
      : `This ${provenance.source === 'dkim-message' ? 'DKIM' : 'SPF'} result was captured${provenance.capturedAt === undefined ? '' : ` at ${provenance.capturedAt}`}${provenance.resolverId === undefined ? '' : ` through resolver ${provenance.resolverId}`}.`;
  const reconstruction =
    provenance.reconstructed === true
      ? ' Its message line endings were reconstructed before verification.'
      : '';
  const identity =
    provenance.identitySource === 'helo'
      ? ' Its authenticated SPF identity was HELO-derived for a null reverse path.'
      : '';
  return {
    ...evidence,
    acknowledged,
    provenance,
    qualification: `${source}${reconstruction}${identity} It is not cryptographically bound to the visible From domain or a common message context.`,
  };
}

function withinDomain(domain: string, boundary: string): boolean {
  return domain === boundary || domain.endsWith(`.${boundary}`);
}

function policyMode(policy: Pick<DmarcPolicy, 'tags'>, name: 'adkim' | 'aspf') {
  const matching = policy.tags.filter((tag) => tag.name === name);
  if (matching.length !== 1) return 'relaxed';
  return matching[0]?.value === 's' ? 'strict' : 'relaxed';
}

/** Resolve policy tag values, including the RFC defaults, into evaluator modes. */
export function dmarcAlignmentModes(
  policy: Pick<DmarcPolicy, 'tags'>,
): Readonly<{ adkim: DmarcAlignmentMode; aspf: DmarcAlignmentMode }> {
  return {
    adkim: policyMode(policy, 'adkim'),
    aspf: policyMode(policy, 'aspf'),
  };
}

function permanentInputError(
  adkim: DmarcAlignmentMode,
  aspf: DmarcAlignmentMode,
  reason: string,
  fromDomain?: string,
  organizationalDomain?: string,
  evidence: readonly DmarcIdentifierEvidence[] = [],
): DmarcAlignmentEvaluation {
  return {
    adkim,
    aspf,
    evidence,
    ...(fromDomain === undefined ? {} : { fromDomain }),
    ...(organizationalDomain === undefined ? {} : { organizationalDomain }),
    reason,
    result: 'permerror',
  };
}

function mappedBoundary(
  boundaries: Readonly<Record<string, string>> | undefined,
  domain: NormalisedDomain,
): unknown {
  if (boundaries === undefined) return undefined;
  if (Object.hasOwn(boundaries, domain.supplied)) return boundaries[domain.supplied];
  if (Object.hasOwn(boundaries, domain.normalised)) return boundaries[domain.normalised];
  return undefined;
}

function mappedBoundaryStatus(
  statuses: Readonly<Record<string, DmarcBoundaryStatus>> | undefined,
  domain: NormalisedDomain,
): unknown {
  if (statuses === undefined) return undefined;
  if (Object.hasOwn(statuses, domain.supplied)) return statuses[domain.supplied];
  if (Object.hasOwn(statuses, domain.normalised)) return statuses[domain.normalised];
  return undefined;
}

function unavailableBoundaryEvidence(
  method: DmarcIdentifierEvidence['method'],
  mode: DmarcAlignmentMode,
  domain: string,
  status: Exclude<DmarcBoundaryStatus, 'complete'>,
  reason: string,
): DmarcIdentifierEvidence {
  return {
    authenticated: true,
    domain,
    method,
    mode,
    reason,
    status,
  };
}

function alignedReason(
  method: DmarcIdentifierEvidence['method'],
  domain: string,
  mode: DmarcAlignmentMode,
  fromDomain: string,
): string {
  const name = method === 'dkim' ? 'DKIM signing' : 'SPF MAIL FROM';
  return `The ${name} domain ${domain} has ${mode} alignment with the RFC5322.From domain ${fromDomain}.`;
}

function assessAuthenticatedDomain(
  method: DmarcIdentifierEvidence['method'],
  suppliedDomain: unknown,
  mode: DmarcAlignmentMode,
  fromDomain: string,
  authorBoundary: string | undefined,
  authorBoundaryStatus: DmarcBoundaryStatus,
  boundaries: Readonly<Record<string, string>> | undefined,
  boundaryStatuses: Readonly<Record<string, DmarcBoundaryStatus>> | undefined,
): DmarcIdentifierEvidence {
  const domain = normaliseDomain(suppliedDomain);
  if (domain === null)
    return {
      authenticated: false,
      method,
      mode,
      reason: `A purported passing ${method.toUpperCase()} domain is malformed.`,
      status: 'permerror',
    };

  if (mode === 'strict') {
    const aligned = domain.normalised === fromDomain;
    return {
      authenticated: true,
      domain: domain.normalised,
      method,
      mode,
      reason: aligned
        ? alignedReason(method, domain.normalised, mode, fromDomain)
        : `The ${method.toUpperCase()} domain ${domain.normalised} is not identical to the RFC5322.From domain ${fromDomain}.`,
      status: aligned ? 'aligned' : 'unaligned',
    };
  }

  if (authorBoundary === undefined) {
    const status = authorBoundaryStatus === 'complete' ? 'permerror' : authorBoundaryStatus;
    return unavailableBoundaryEvidence(
      method,
      mode,
      domain.normalised,
      status,
      status === 'temperror'
        ? 'Relaxed alignment cannot be established because discovery of the RFC5322.From organisational-domain boundary had a temporary error.'
        : status === 'permerror'
          ? 'Relaxed alignment cannot be established because discovery of the RFC5322.From organisational-domain boundary had a permanent error.'
          : 'Relaxed alignment cannot be established because the RFC5322.From organisational-domain boundary is unavailable.',
    );
  }

  if (!withinDomain(domain.normalised, authorBoundary))
    return {
      authenticated: true,
      domain: domain.normalised,
      method,
      mode,
      reason: `The ${method.toUpperCase()} domain ${domain.normalised} is outside the RFC5322.From organisational-domain boundary ${authorBoundary}.`,
      status: 'unaligned',
    };

  if (domain.normalised === fromDomain || domain.normalised === authorBoundary)
    return {
      authenticated: true,
      domain: domain.normalised,
      method,
      mode,
      organizationalDomain: authorBoundary,
      reason: alignedReason(method, domain.normalised, mode, fromDomain),
      status: 'aligned',
    };

  const suppliedBoundary = mappedBoundary(boundaries, domain);
  if (suppliedBoundary === undefined) {
    const discoveryStatus = mappedBoundaryStatus(boundaryStatuses, domain);
    if (discoveryStatus !== undefined && !isBoundaryStatus(discoveryStatus))
      return unavailableBoundaryEvidence(
        method,
        mode,
        domain.normalised,
        'permerror',
        `The boundary discovery status for ${domain.normalised} is not recognised.`,
      );
    const status =
      discoveryStatus === 'complete' ? 'permerror' : (discoveryStatus ?? 'indeterminate');
    return unavailableBoundaryEvidence(
      method,
      mode,
      domain.normalised,
      status,
      status === 'temperror'
        ? `Relaxed alignment for ${domain.normalised} cannot be established because its independent boundary discovery had a temporary error.`
        : status === 'permerror'
          ? `Relaxed alignment for ${domain.normalised} cannot be established because its independent boundary discovery had a permanent error.`
          : `Relaxed alignment for ${domain.normalised} cannot be established without that identifier’s independently selected organisational-domain boundary.`,
    );
  }

  const identifierBoundary = normaliseDomain(suppliedBoundary);
  if (
    identifierBoundary === null ||
    !withinDomain(domain.normalised, identifierBoundary.normalised)
  )
    return {
      authenticated: true,
      domain: domain.normalised,
      method,
      mode,
      reason: `The supplied organisational-domain boundary for ${domain.normalised} is malformed or is not its DNS ancestor.`,
      status: 'permerror',
    };

  const aligned = identifierBoundary.normalised === authorBoundary;
  return {
    authenticated: true,
    domain: domain.normalised,
    method,
    mode,
    organizationalDomain: identifierBoundary.normalised,
    reason: aligned
      ? alignedReason(method, domain.normalised, mode, fromDomain)
      : `The ${method.toUpperCase()} organisational-domain boundary ${identifierBoundary.normalised} differs from the RFC5322.From boundary ${authorBoundary}.`,
    status: aligned ? 'aligned' : 'unaligned',
  };
}

function isSpfResult(value: unknown): value is DmarcSpfResult {
  return (
    value === 'none' ||
    value === 'neutral' ||
    value === 'pass' ||
    value === 'fail' ||
    value === 'softfail' ||
    value === 'temperror' ||
    value === 'permerror'
  );
}

function assessSpfIdentifier(
  spf: DmarcSpfAuthentication,
  mode: DmarcAlignmentMode,
  fromDomain: string,
  authorBoundary: string | undefined,
  authorBoundaryStatus: DmarcBoundaryStatus,
  boundaries: Readonly<Record<string, string>> | undefined,
  boundaryStatuses: Readonly<Record<string, DmarcBoundaryStatus>> | undefined,
): DmarcIdentifierEvidence {
  if (!isSpfResult(spf.result))
    return {
      authenticated: false,
      method: 'spf',
      mode,
      reason: 'The supplied SPF result is not recognised.',
      status: 'permerror',
    };

  if (spf.domain !== undefined && normaliseDomain(spf.domain) === null)
    return {
      authenticated: false,
      method: 'spf',
      mode,
      reason: 'The supplied SPF MAIL FROM domain is malformed.',
      status: 'permerror',
    };

  if (spf.result === 'pass') {
    if (spf.domain === undefined)
      return {
        authenticated: false,
        method: 'spf',
        mode,
        reason: 'An SPF pass needs its authenticated MAIL FROM domain.',
        status: 'permerror',
      };
    return assessAuthenticatedDomain(
      'spf',
      spf.domain,
      mode,
      fromDomain,
      authorBoundary,
      authorBoundaryStatus,
      boundaries,
      boundaryStatuses,
    );
  }

  const normalised =
    spf.domain === undefined ? undefined : normaliseDomain(spf.domain)?.normalised;
  if (spf.result === 'temperror' || spf.result === 'permerror')
    return {
      authenticated: false,
      ...(normalised === undefined ? {} : { domain: normalised }),
      method: 'spf',
      mode,
      reason: `SPF returned ${spf.result}; it did not establish an authenticated MAIL FROM identifier.`,
      status: spf.result,
    };

  return {
    authenticated: false,
    ...(normalised === undefined ? {} : { domain: normalised }),
    method: 'spf',
    mode,
    reason: `SPF returned ${spf.result}; it supplies no authenticated MAIL FROM identifier for DMARC.`,
    status: 'not-authenticated',
  };
}

function assessSpf(
  spf: DmarcSpfAuthentication,
  mode: DmarcAlignmentMode,
  fromDomain: string,
  authorBoundary: string | undefined,
  authorBoundaryStatus: DmarcBoundaryStatus,
  boundaries: Readonly<Record<string, string>> | undefined,
  boundaryStatuses: Readonly<Record<string, DmarcBoundaryStatus>> | undefined,
  acknowledged: boolean,
): DmarcIdentifierEvidence {
  return qualifiedEvidence(
    assessSpfIdentifier(
      spf,
      mode,
      fromDomain,
      authorBoundary,
      authorBoundaryStatus,
      boundaries,
      boundaryStatuses,
    ),
    spf.provenance,
    acknowledged,
  );
}

function finalEvaluation(
  adkim: DmarcAlignmentMode,
  aspf: DmarcAlignmentMode,
  fromDomain: string,
  organizationalDomain: string | undefined,
  evidence: readonly DmarcIdentifierEvidence[],
  evidenceAcknowledged: boolean,
): DmarcAlignmentEvaluation {
  const base = {
    adkim,
    aspf,
    evidence,
    fromDomain,
    ...(organizationalDomain === undefined ? {} : { organizationalDomain }),
  };
  const aligned = evidence.find(
    (item) => item.status === 'aligned' && item.qualification === undefined,
  );
  if (aligned !== undefined)
    return {
      ...base,
      reason: `DMARC passes. ${aligned.reason}`,
      result: 'pass',
    };

  const qualifiedAligned = evidence.find((item) => item.status === 'aligned');
  if (qualifiedAligned !== undefined) {
    if (!evidenceAcknowledged)
      return {
        ...base,
        reason: `DMARC is indeterminate until the prior evidence qualification is explicitly acknowledged. ${qualifiedAligned.reason} ${qualifiedAligned.qualification ?? ''}`,
        result: 'indeterminate',
      };
    return {
      ...base,
      reason: `DMARC conditionally passes using explicitly acknowledged prior evidence. ${qualifiedAligned.reason} ${qualifiedAligned.qualification ?? ''}`,
      result: 'pass',
    };
  }

  const permanentError = evidence.find((item) => item.status === 'permerror');
  if (permanentError !== undefined)
    return {
      ...base,
      reason: `DMARC cannot be decided because of a permanent evaluation error. ${permanentError.reason}`,
      result: 'permerror',
    };

  const temporaryError = evidence.find((item) => item.status === 'temperror');
  if (temporaryError !== undefined)
    return {
      ...base,
      reason: `DMARC cannot be decided because of a temporary evaluation error. ${temporaryError.reason}`,
      result: 'temperror',
    };

  const indeterminate = evidence.find((item) => item.status === 'indeterminate');
  if (indeterminate !== undefined)
    return {
      ...base,
      reason: `DMARC is indeterminate. ${indeterminate.reason}`,
      result: 'indeterminate',
    };

  return {
    ...base,
    reason: `DMARC fails because no passing DKIM or SPF authenticated identifier aligns with the RFC5322.From domain ${fromDomain}.`,
    result: 'fail',
  };
}

/** Evaluate DMARC identifier alignment without performing DNS or cryptographic work. */
export function evaluateDmarcAlignment(input: DmarcAlignmentInput): DmarcAlignmentEvaluation {
  const adkim = normaliseMode(input.adkim);
  const aspf = normaliseMode(input.aspf);
  const outputAdkim = adkim ?? 'relaxed';
  const outputAspf = aspf ?? 'relaxed';
  if (adkim === null || aspf === null)
    return permanentInputError(
      outputAdkim,
      outputAspf,
      'adkim and aspf must each select relaxed or strict alignment.',
    );

  const fromDomain = normaliseDomain(input.fromDomain);
  if (fromDomain === null)
    return permanentInputError(
      adkim,
      aspf,
      'The RFC5322.From domain is malformed, so DMARC alignment cannot be evaluated.',
    );

  let organizationalDomain: string | undefined;
  if (input.organizationalDomain !== undefined) {
    const boundary = normaliseDomain(input.organizationalDomain);
    if (boundary === null || !withinDomain(fromDomain.normalised, boundary.normalised))
      return permanentInputError(
        adkim,
        aspf,
        'The supplied RFC5322.From organisational-domain boundary is malformed or is not its DNS ancestor.',
        fromDomain.normalised,
      );
    organizationalDomain = boundary.normalised;
  }
  const organizationalDomainStatus =
    input.organizationalDomainStatus ??
    (organizationalDomain === undefined ? 'indeterminate' : 'complete');
  if (!isBoundaryStatus(organizationalDomainStatus))
    return permanentInputError(
      adkim,
      aspf,
      'The RFC5322.From boundary discovery status is not recognised.',
      fromDomain.normalised,
      organizationalDomain,
    );
  if ((organizationalDomainStatus === 'complete') !== (organizationalDomain !== undefined))
    return permanentInputError(
      adkim,
      aspf,
      'The RFC5322.From boundary and its discovery status are inconsistent.',
      fromDomain.normalised,
      organizationalDomain,
    );

  const rawBoundaries: unknown = input.authenticatedOrganizationalDomains;
  if (
    rawBoundaries !== undefined &&
    (typeof rawBoundaries !== 'object' ||
      rawBoundaries === null ||
      Array.isArray(rawBoundaries))
  )
    return permanentInputError(
      adkim,
      aspf,
      'Authenticated organisational-domain boundaries must be supplied as a domain map.',
      fromDomain.normalised,
      organizationalDomain,
    );
  const boundaries = rawBoundaries as Readonly<Record<string, string>> | undefined;
  const rawBoundaryStatuses: unknown = input.authenticatedOrganizationalDomainStatuses;
  if (
    rawBoundaryStatuses !== undefined &&
    (typeof rawBoundaryStatuses !== 'object' ||
      rawBoundaryStatuses === null ||
      Array.isArray(rawBoundaryStatuses))
  )
    return permanentInputError(
      adkim,
      aspf,
      'Authenticated boundary statuses must be supplied as a domain map.',
      fromDomain.normalised,
      organizationalDomain,
    );
  const boundaryStatuses = rawBoundaryStatuses as
    Readonly<Record<string, DmarcBoundaryStatus>> | undefined;

  const rawDkimDomains: unknown = input.dkimDomains;
  if (!Array.isArray(rawDkimDomains))
    return permanentInputError(
      adkim,
      aspf,
      'Passing DKIM signing domains must be supplied as a bounded list.',
      fromDomain.normalised,
      organizationalDomain,
    );
  const dkimDomainsInput = rawDkimDomains as readonly unknown[];
  if (dkimDomainsInput.length > MAX_PASSING_DKIM_DOMAINS)
    return permanentInputError(
      adkim,
      aspf,
      `The input exceeds the ${String(MAX_PASSING_DKIM_DOMAINS)}-signature DMARC work limit.`,
      fromDomain.normalised,
      organizationalDomain,
      [
        {
          authenticated: false,
          method: 'dkim',
          mode: adkim,
          reason: `More than ${String(MAX_PASSING_DKIM_DOMAINS)} passing DKIM domains were supplied.`,
          status: 'permerror',
        },
      ],
    );

  if (
    input.evidenceAcknowledged !== undefined &&
    typeof input.evidenceAcknowledged !== 'boolean'
  )
    return permanentInputError(
      adkim,
      aspf,
      'The prior-evidence acknowledgement must be a boolean.',
      fromDomain.normalised,
      organizationalDomain,
    );
  const evidenceAcknowledged = input.evidenceAcknowledged === true;
  const rawDkimEvidence: unknown = input.dkimEvidence;
  if (rawDkimEvidence !== undefined && !Array.isArray(rawDkimEvidence))
    return permanentInputError(
      adkim,
      aspf,
      'DKIM prior evidence must be supplied as a bounded list.',
      fromDomain.normalised,
      organizationalDomain,
    );
  const dkimEvidenceInput: readonly unknown[] =
    rawDkimEvidence === undefined
      ? dkimDomainsInput.map((domain) => ({ domain }))
      : (rawDkimEvidence as readonly unknown[]);
  if (
    dkimEvidenceInput.length !== dkimDomainsInput.length ||
    dkimEvidenceInput.some((entry, index) => {
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) return true;
      return (entry as Readonly<Record<string, unknown>>)['domain'] !== dkimDomainsInput[index];
    })
  )
    return permanentInputError(
      adkim,
      aspf,
      'DKIM domains and their prior-evidence metadata are inconsistent.',
      fromDomain.normalised,
      organizationalDomain,
    );
  const dkimEvidence = dkimEvidenceInput as readonly DmarcDkimAuthentication[];

  const rawSpf: unknown = input.spf;
  if (typeof rawSpf !== 'object' || rawSpf === null)
    return permanentInputError(
      adkim,
      aspf,
      'SPF authentication evidence is missing.',
      fromDomain.normalised,
      organizationalDomain,
    );

  const evidence = [
    ...dkimEvidence.map((entry) =>
      qualifiedEvidence(
        assessAuthenticatedDomain(
          'dkim',
          entry.domain,
          adkim,
          fromDomain.normalised,
          organizationalDomain,
          organizationalDomainStatus,
          boundaries,
          boundaryStatuses,
        ),
        entry.provenance,
        evidenceAcknowledged,
      ),
    ),
    assessSpf(
      input.spf,
      aspf,
      fromDomain.normalised,
      organizationalDomain,
      organizationalDomainStatus,
      boundaries,
      boundaryStatuses,
      evidenceAcknowledged,
    ),
  ];
  return finalEvaluation(
    adkim,
    aspf,
    fromDomain.normalised,
    organizationalDomain,
    evidence,
    evidenceAcknowledged,
  );
}
