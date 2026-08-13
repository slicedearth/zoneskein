import type {
  DmarcDestination,
  DmarcDiagnostic,
  DmarcDiscoveryObservation,
  DmarcDisposition,
  DmarcPolicy,
  DmarcPolicyAssessment,
  DmarcSelection,
  DmarcTag,
} from './types';
import {
  dmarcReportAuthorizationName,
  dmarcReportDestinationHost,
} from './report-authorization';

const MAX_DMARC_RECORD_CHARACTERS = 8_192;
const MAX_DMARC_TAGS = 64;
const MAX_REPORT_URI_CHARACTERS = 2_048;

function diagnostic(
  code: string,
  message: string,
  severity: DmarcDiagnostic['severity'] = 'error',
): DmarcDiagnostic {
  return { code, message, severity };
}

function reportDestination(
  uri: string,
  kind: DmarcDestination['kind'],
  policyDomain: string,
  organizationalDomain: string,
  diagnostics: DmarcDiagnostic[],
): { readonly destination: DmarcDestination; readonly valid: boolean } {
  const sizeLimit = /!\d+[kmgt]?$/iu.exec(uri);
  const withoutLimit = sizeLimit === null ? uri : uri.slice(0, -sizeLimit[0].length);
  if (sizeLimit !== null)
    diagnostics.push(
      diagnostic(
        'report-size-limit-obsolete',
        `${uri} uses an obsolete report-size suffix; current receivers ignore it.`,
        'warning',
      ),
    );
  let parsed: URL;
  if (withoutLimit.length === 0 || withoutLimit.length > MAX_REPORT_URI_CHARACTERS) {
    diagnostics.push(
      diagnostic('report-uri-invalid', `${uri} exceeds the bounded reporting URI length.`),
    );
    return { destination: { external: false, kind, uri }, valid: false };
  }
  try {
    parsed = new URL(withoutLimit);
  } catch {
    diagnostics.push(diagnostic('report-uri-invalid', `${uri} is not a valid reporting URI.`));
    return { destination: { external: false, kind, uri }, valid: false };
  }
  if (!withoutLimit.toLowerCase().startsWith('mailto:')) {
    diagnostics.push(
      diagnostic(
        'report-uri-scheme',
        `${uri} does not use the interoperable mailto reporting scheme.`,
        'warning',
      ),
    );
  }
  const domain = dmarcReportDestinationHost(withoutLimit);
  if (domain === null) {
    if (parsed.protocol !== 'mailto:')
      return { destination: { external: false, kind, uri }, valid: true };
    diagnostics.push(
      diagnostic('report-uri-invalid', `${uri} is not a valid reporting mailbox.`),
    );
    return { destination: { external: false, kind, uri }, valid: false };
  }
  // A descendant can publish a deeper psd=n boundary. Without an independent
  // tree walk, only the selected organisational-domain apex is proven internal.
  const external = domain !== organizationalDomain;
  const authorizationName = external
    ? dmarcReportAuthorizationName(policyDomain, withoutLimit)
    : null;
  return {
    destination: {
      ...(authorizationName === null ? {} : { authorizationName }),
      domain,
      external,
      kind,
      uri,
    },
    valid: true,
  };
}

export function dmarcDiscoveryNames(domain: string): readonly string[] {
  const normalized = domain.toLowerCase().replace(/\.$/u, '');
  const labels = normalized.split('.').filter(Boolean);
  const suffixes =
    labels.length <= 8
      ? Array.from({ length: labels.length }, (_, index) => labels.slice(index).join('.'))
      : [
          normalized,
          ...Array.from({ length: 7 }, (_, index) => labels.slice(-7 + index).join('.')),
        ];
  return suffixes.map((name) => `_dmarc.${name}`);
}

export function isDmarcRecord(value: string): boolean {
  return /^[vV]\s*=\s*DMARC1(?:\s*;|\s*$)/u.test(value.trimStart());
}

function validDmarcValue(value: string): boolean {
  if (value.length === 0) return false;
  return Array.from(value).every((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code >= 0x20 && code <= 0x7e && code !== 0x3b;
  });
}

function invalidBoundedPolicy(record: string, diagnosticItem: DmarcDiagnostic): DmarcPolicy {
  return {
    applicable: false,
    assessmentPolicyInvalid: false,
    destinations: [],
    diagnostics: [diagnosticItem],
    fallbackToNone: false,
    record,
    tags: [],
    valid: false,
  };
}

function policyTag(policy: DmarcPolicy, name: 'p' | 'sp' | 'np'): string | undefined {
  return policy.tags.find((tag) => tag.name === name)?.value;
}

function reducedTestingDisposition(dispositionValue: DmarcDisposition): DmarcDisposition {
  if (dispositionValue === 'reject') return 'quarantine';
  if (dispositionValue === 'quarantine') return 'none';
  return 'none';
}

/** Select the RFC 9989 assessment policy for one discovered author-domain context. */
export function assessDmarcPolicy(
  policy: DmarcPolicy,
  context: DmarcPolicyAssessment['context'],
): DmarcPolicyAssessment | undefined {
  if (!policy.applicable) return undefined;

  let selectedTag: DmarcPolicyAssessment['selectedTag'] = 'p';
  if (context === 'existing-inherited-subdomain' && policyTag(policy, 'sp') !== undefined)
    selectedTag = 'sp';
  else if (context === 'non-existent-inherited-subdomain') {
    if (policyTag(policy, 'np') !== undefined) selectedTag = 'np';
    else if (policyTag(policy, 'sp') !== undefined) selectedTag = 'sp';
  }

  const declaredDisposition = disposition(policyTag(policy, selectedTag));
  const assessmentDisposition = policy.fallbackToNone
    ? 'none'
    : (declaredDisposition ?? policy.effectiveDisposition ?? 'none');
  const testing = policy.tags.some(
    (tag) => tag.name === 't' && tag.value.toLowerCase() === 'y',
  );
  const appliedDisposition = testing
    ? reducedTestingDisposition(assessmentDisposition)
    : assessmentDisposition;
  const contextLabel =
    context === 'direct-author-domain'
      ? 'the direct Author Domain'
      : context === 'existing-inherited-subdomain'
        ? 'an existing inherited subdomain'
        : 'a non-existent inherited subdomain';
  const fallbackReason = policy.fallbackToNone
    ? ' An invalid p, sp, or np tag triggers the valid-rua p=none fallback.'
    : declaredDisposition === undefined
      ? ' The selected tag is absent, so the valid p policy or its none default applies.'
      : '';
  const testingReason = testing
    ? ` Testing mode reduces ${assessmentDisposition} to ${appliedDisposition} for assessment without changing reporting.`
    : '';

  return {
    appliedDisposition,
    context,
    ...(declaredDisposition === undefined ? {} : { declaredDisposition }),
    fallbackToNone: policy.fallbackToNone,
    reason: `The ${selectedTag} tag is selected for ${contextLabel}.${fallbackReason}${testingReason}`,
    selectedTag,
    testing,
  };
}

function disposition(value: string | undefined): DmarcDisposition | undefined {
  const normalized = value?.toLowerCase();
  return normalized === 'none' || normalized === 'quarantine' || normalized === 'reject'
    ? normalized
    : undefined;
}

export function selectDmarcPolicy(
  authorDomain: string,
  observations: readonly DmarcDiscoveryObservation[],
): DmarcSelection {
  type ApplicableObservation = DmarcDiscoveryObservation & { readonly policy: DmarcPolicy };
  const isApplicable = (
    observation: DmarcDiscoveryObservation | undefined,
  ): observation is ApplicableObservation => observation?.policy?.applicable === true;
  const applicable = observations.filter((observation): observation is ApplicableObservation =>
    isApplicable(observation),
  );
  const direct = applicable.find((observation) => observation.domain === authorDomain);
  let organizationalDomain: string | undefined;
  let inherited: (typeof applicable)[number] | undefined;
  let publicSuffix: (typeof applicable)[number] | undefined;

  for (let index = 0; index < observations.length; index += 1) {
    const observation = observations[index];
    if (!isApplicable(observation)) continue;
    if (observation.policy.psd === 'n') {
      organizationalDomain = observation.domain;
      inherited = observation;
      break;
    }
    if (observation.policy.psd === 'y') {
      const child = observations[index - 1];
      organizationalDomain = child?.domain;
      inherited = isApplicable(child) ? child : undefined;
      publicSuffix = observation;
      break;
    }
  }

  if (organizationalDomain === undefined) {
    const leastSpecific = applicable.at(-1);
    organizationalDomain = leastSpecific?.domain;
    inherited = leastSpecific;
  }
  if (direct !== undefined)
    return {
      ...(organizationalDomain === undefined ? {} : { organizationalDomain }),
      selected: direct,
      source: 'direct',
    };
  if (inherited !== undefined)
    return {
      ...(organizationalDomain === undefined ? {} : { organizationalDomain }),
      selected: inherited,
      source: 'organizational',
    };
  if (publicSuffix !== undefined)
    return {
      ...(organizationalDomain === undefined ? {} : { organizationalDomain }),
      selected: publicSuffix,
      source: 'public-suffix',
    };
  return {
    ...(organizationalDomain === undefined ? {} : { organizationalDomain }),
    source: 'none',
  };
}

export function parseDmarcRecord(
  record: string,
  policyDomain: string,
  organizationalDomain = policyDomain,
): DmarcPolicy {
  const diagnostics: DmarcDiagnostic[] = [];
  const tags: DmarcTag[] = [];
  const seen = new Set<string>();
  if (record.length > MAX_DMARC_RECORD_CHARACTERS)
    return invalidBoundedPolicy(
      record,
      diagnostic(
        'record-too-long',
        `The DMARC record exceeds the ${String(MAX_DMARC_RECORD_CHARACTERS)}-character parser limit.`,
      ),
    );
  const segments = record
    .split(';')
    .map((segment) => segment.trim())
    .filter(Boolean);
  if (segments.length > MAX_DMARC_TAGS)
    return invalidBoundedPolicy(
      record,
      diagnostic(
        'tag-limit',
        `The DMARC record exceeds the ${String(MAX_DMARC_TAGS)}-tag parser limit.`,
      ),
    );
  for (const segment of segments) {
    const equals = segment.indexOf('=');
    if (equals < 1) {
      diagnostics.push(diagnostic('tag-malformed', `Malformed DMARC tag segment: ${segment}.`));
      continue;
    }
    const name = segment.slice(0, equals).trim().toLowerCase();
    const value = segment.slice(equals + 1).trim();
    if (!/^[a-z]+$/u.test(name)) {
      diagnostics.push(diagnostic('tag-name-invalid', `DMARC tag name ${name} is malformed.`));
      continue;
    }
    if (!validDmarcValue(value)) {
      diagnostics.push(
        diagnostic('tag-value-invalid', `DMARC tag ${name} has a malformed value.`),
      );
      continue;
    }
    if (seen.has(name))
      diagnostics.push(
        diagnostic('tag-duplicate', `DMARC tag ${name} appears more than once.`),
      );
    seen.add(name);
    tags.push({ name, value });
  }
  const map = new Map(tags.map((tag) => [tag.name, tag.value]));
  const firstSegment = segments[0];
  const firstEquals = firstSegment?.indexOf('=') ?? -1;
  const validVersion =
    firstSegment !== undefined &&
    firstEquals > 0 &&
    firstSegment.slice(0, firstEquals).trim().toLowerCase() === 'v' &&
    firstSegment.slice(firstEquals + 1).trim() === 'DMARC1';
  if (!validVersion) {
    diagnostics.push(diagnostic('version-invalid', 'v=DMARC1 must be the first DMARC tag.'));
  }
  const policy = disposition(map.get('p'));
  const subdomainPolicy = map.get('sp');
  if (subdomainPolicy !== undefined && disposition(subdomainPolicy) === undefined) {
    diagnostics.push(
      diagnostic('subdomain-policy-invalid', 'sp must be none, quarantine, or reject.'),
    );
  }
  const nonExistentPolicy = map.get('np');
  if (nonExistentPolicy !== undefined && disposition(nonExistentPolicy) === undefined)
    diagnostics.push(
      diagnostic('nonexistent-policy-invalid', 'np must be none, quarantine, or reject.'),
    );
  const psd = map.get('psd')?.toLowerCase();
  if (psd !== undefined && psd !== 'n' && psd !== 'y' && psd !== 'u')
    diagnostics.push(diagnostic('psd-invalid', 'psd must be n, y, or u.'));
  const testing = map.get('t')?.toLowerCase();
  if (testing !== undefined && testing !== 'n' && testing !== 'y')
    diagnostics.push(diagnostic('testing-invalid', 't must be n or y.'));
  for (const alignment of ['adkim', 'aspf']) {
    const value = map.get(alignment);
    if (value !== undefined && value !== 'r' && value !== 's')
      diagnostics.push(diagnostic('alignment-invalid', `${alignment} must be r or s.`));
  }
  for (const historic of ['pct', 'rf', 'ri'])
    if (map.has(historic))
      diagnostics.push(
        diagnostic(
          'historic-tag',
          `${historic} is from the obsolete DMARC specification and is ignored by current receivers.`,
          'warning',
        ),
      );
  const failureOptions = map.get('fo');
  if (failureOptions !== undefined) {
    const values = failureOptions.split(':');
    if (
      values.some((value) => !['0', '1', 'd', 's'].includes(value)) ||
      new Set(values).size !== values.length ||
      (values.includes('0') && values.includes('1'))
    )
      diagnostics.push(
        diagnostic(
          'failure-options-invalid',
          'fo may contain unique 0, 1, d, and s values, but 0 and 1 are mutually exclusive.',
        ),
      );
  }
  const known = new Set([
    'v',
    'p',
    'sp',
    'np',
    't',
    'pct',
    'rua',
    'ruf',
    'ri',
    'fo',
    'adkim',
    'aspf',
    'rf',
    'psd',
  ]);
  for (const tag of tags.filter((item) => !known.has(item.name)))
    diagnostics.push(
      diagnostic(
        'tag-unknown',
        `Unknown DMARC tag ${tag.name} is ignored by this analyser.`,
        'information',
      ),
    );

  const destinationResults = [
    ...(map
      .get('rua')
      ?.split(',')
      .map((uri) =>
        reportDestination(
          uri.trim(),
          'aggregate',
          policyDomain,
          organizationalDomain,
          diagnostics,
        ),
      ) ?? []),
    ...(map
      .get('ruf')
      ?.split(',')
      .map((uri) =>
        reportDestination(
          uri.trim(),
          'forensic',
          policyDomain,
          organizationalDomain,
          diagnostics,
        ),
      ) ?? []),
  ];
  const destinations = destinationResults.map((result) => result.destination);
  const validAggregateDestination = destinationResults.some(
    (result) => result.valid && result.destination.kind === 'aggregate',
  );
  const invalidAssessmentPolicy = [
    ['p', map.get('p')],
    ['sp', subdomainPolicy],
    ['np', nonExistentPolicy],
  ].some(([, value]) => value !== undefined && disposition(value) === undefined);
  const fallbackToNone = invalidAssessmentPolicy && validAggregateDestination;
  const effectiveDisposition = invalidAssessmentPolicy
    ? fallbackToNone
      ? 'none'
      : undefined
    : (policy ?? 'none');
  if (map.get('p') !== undefined && policy === undefined)
    diagnostics.push(
      diagnostic(
        'policy-invalid',
        validAggregateDestination
          ? 'Invalid p is ignored; a valid rua makes the effective policy none.'
          : 'p must be none, quarantine, or reject.',
        'error',
      ),
    );
  else if (map.get('p') === undefined)
    diagnostics.push(
      diagnostic(
        'policy-default-none',
        'No p tag is published, so the assessment policy defaults to none.',
        'information',
      ),
    );
  if (invalidAssessmentPolicy && validAggregateDestination)
    diagnostics.push(
      diagnostic(
        'assessment-policy-fallback',
        'At least one p, sp, or np tag is invalid; a syntactically valid rua makes the record applicable as p=none.',
        'warning',
      ),
    );
  if (destinations.length > 10)
    diagnostics.push(
      diagnostic(
        'report-destination-limit',
        'More than ten report destinations exceeds ZoneSkein’s bounded authorisation check.',
        'warning',
      ),
    );
  return {
    applicable:
      validVersion &&
      effectiveDisposition !== undefined &&
      !diagnostics.some((item) => item.code === 'tag-duplicate'),
    assessmentPolicyInvalid: invalidAssessmentPolicy,
    destinations,
    diagnostics,
    ...(effectiveDisposition === undefined ? {} : { effectiveDisposition }),
    fallbackToNone,
    ...(psd === 'n' || psd === 'y' || psd === 'u' ? { psd } : {}),
    record,
    tags,
    valid: !diagnostics.some((item) => item.severity === 'error'),
  };
}
