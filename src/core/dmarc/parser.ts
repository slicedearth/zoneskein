import type {
  DmarcDestination,
  DmarcDiagnostic,
  DmarcDiscoveryObservation,
  DmarcDisposition,
  DmarcPolicy,
  DmarcSelection,
  DmarcTag,
} from './types';

function diagnostic(
  code: string,
  message: string,
  severity: DmarcDiagnostic['severity'] = 'error',
): DmarcDiagnostic {
  return { code, message, severity };
}

function withinDomain(name: string, boundary: string): boolean {
  return name === boundary || name.endsWith(`.${boundary}`);
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
    return { destination: { external: false, kind, uri }, valid: true };
  }
  const address = decodeURIComponent(parsed.pathname);
  const at = address.lastIndexOf('@');
  if (at < 1 || at === address.length - 1) {
    diagnostics.push(
      diagnostic('report-uri-invalid', `${uri} is not a valid reporting mailbox.`),
    );
    return { destination: { external: false, kind, uri }, valid: false };
  }
  const domain = address
    .slice(at + 1)
    .toLowerCase()
    .replace(/\.$/u, '');
  const external = !withinDomain(domain, organizationalDomain);
  return {
    destination: {
      ...(external ? { authorizationName: `${policyDomain}._report._dmarc.${domain}` } : {}),
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
  return /^v=DMARC1(?:\s*;|\s*$)/u.test(value.trimStart());
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
  for (const raw of record.split(';')) {
    const segment = raw.trim();
    if (segment === '') continue;
    const equals = segment.indexOf('=');
    if (equals < 1) {
      diagnostics.push(diagnostic('tag-malformed', `Malformed DMARC tag segment: ${segment}.`));
      continue;
    }
    const name = segment.slice(0, equals).trim().toLowerCase();
    const value = segment.slice(equals + 1).trim();
    if (!/^[a-z][a-z0-9-]*$/u.test(name))
      diagnostics.push(diagnostic('tag-name-invalid', `DMARC tag name ${name} is malformed.`));
    if (seen.has(name))
      diagnostics.push(
        diagnostic('tag-duplicate', `DMARC tag ${name} appears more than once.`),
      );
    seen.add(name);
    tags.push({ name, value });
  }
  const map = new Map(tags.map((tag) => [tag.name, tag.value]));
  const firstTag = tags[0];
  const validVersion = firstTag?.name === 'v' && firstTag.value === 'DMARC1';
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
  const effectiveDisposition = policy ?? (validAggregateDestination ? 'none' : undefined);
  if (map.get('p') !== undefined && policy === undefined)
    diagnostics.push(
      diagnostic(
        'policy-invalid',
        validAggregateDestination
          ? 'Invalid p is ignored; a valid rua makes the effective policy none.'
          : 'p must be none, quarantine, or reject.',
        validAggregateDestination ? 'warning' : 'error',
      ),
    );
  else if (map.get('p') === undefined)
    diagnostics.push(
      diagnostic(
        validAggregateDestination ? 'policy-default-none' : 'policy-required',
        validAggregateDestination
          ? 'No p tag is published; a valid rua makes the effective policy none.'
          : 'A record needs a valid p tag or at least one valid rua destination.',
        validAggregateDestination ? 'information' : 'error',
      ),
    );
  if (destinations.length > 10)
    diagnostics.push(
      diagnostic(
        'report-destination-limit',
        'More than ten report destinations exceeds ZoneSkein’s bounded authorization check.',
        'warning',
      ),
    );
  return {
    applicable:
      validVersion &&
      effectiveDisposition !== undefined &&
      !diagnostics.some((item) =>
        ['tag-duplicate', 'tag-malformed', 'tag-name-invalid'].includes(item.code),
      ),
    destinations,
    diagnostics,
    ...(effectiveDisposition === undefined ? {} : { effectiveDisposition }),
    ...(psd === 'n' || psd === 'y' || psd === 'u' ? { psd } : {}),
    record,
    tags,
    valid: !diagnostics.some((item) => item.severity === 'error'),
  };
}
