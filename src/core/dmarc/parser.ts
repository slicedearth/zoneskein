import { getDomain } from 'tldts';

import type { DmarcDestination, DmarcDiagnostic, DmarcPolicy, DmarcTag } from './types';

function diagnostic(
  code: string,
  message: string,
  severity: DmarcDiagnostic['severity'] = 'error',
): DmarcDiagnostic {
  return { code, message, severity };
}

function organizationalDomain(domain: string): string {
  return getDomain(domain, { allowPrivateDomains: true }) ?? domain.toLowerCase();
}

function reportDestination(
  uri: string,
  kind: DmarcDestination['kind'],
  policyDomain: string,
  diagnostics: DmarcDiagnostic[],
): DmarcDestination {
  const withoutLimit = uri.replace(/!\d+[kmgt]?$/iu, '');
  if (!withoutLimit.toLowerCase().startsWith('mailto:')) {
    diagnostics.push(
      diagnostic(
        'report-uri-scheme',
        `${uri} does not use the interoperable mailto reporting scheme.`,
        'warning',
      ),
    );
    return { external: false, kind, uri };
  }
  const address = withoutLimit.slice(7);
  const at = address.lastIndexOf('@');
  if (at < 1 || at === address.length - 1) {
    diagnostics.push(
      diagnostic('report-uri-invalid', `${uri} is not a valid reporting mailbox.`),
    );
    return { external: false, kind, uri };
  }
  const domain = address
    .slice(at + 1)
    .toLowerCase()
    .replace(/\.$/u, '');
  const external = organizationalDomain(domain) !== organizationalDomain(policyDomain);
  return {
    ...(external ? { authorizationName: `${policyDomain}._report._dmarc.${domain}` } : {}),
    domain,
    external,
    kind,
    uri,
  };
}

function validInteger(value: string, minimum: number, maximum: number): boolean {
  if (!/^\d+$/u.test(value)) return false;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= minimum && parsed <= maximum;
}

export function dmarcDiscoveryNames(domain: string): readonly string[] {
  const normalized = domain.toLowerCase().replace(/\.$/u, '');
  const organizational = organizationalDomain(normalized);
  return organizational === normalized
    ? [`_dmarc.${normalized}`]
    : [`_dmarc.${normalized}`, `_dmarc.${organizational}`];
}

export function parseDmarcRecord(record: string, policyDomain: string): DmarcPolicy {
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
    if (seen.has(name))
      diagnostics.push(
        diagnostic('tag-duplicate', `DMARC tag ${name} appears more than once.`),
      );
    seen.add(name);
    tags.push({ name, value });
  }
  const map = new Map(tags.map((tag) => [tag.name, tag.value]));
  const firstTag = tags[0];
  const validVersion = firstTag?.name === 'v' && firstTag.value.toUpperCase() === 'DMARC1';
  if (!validVersion) {
    diagnostics.push(diagnostic('version-invalid', 'v=DMARC1 must be the first DMARC tag.'));
  }
  const policy = map.get('p');
  if (
    policy === undefined ||
    !['none', 'quarantine', 'reject'].includes(policy.toLowerCase())
  ) {
    diagnostics.push(diagnostic('policy-invalid', 'p must be none, quarantine, or reject.'));
  }
  const subdomainPolicy = map.get('sp');
  if (
    subdomainPolicy !== undefined &&
    !['none', 'quarantine', 'reject'].includes(subdomainPolicy.toLowerCase())
  ) {
    diagnostics.push(
      diagnostic('subdomain-policy-invalid', 'sp must be none, quarantine, or reject.'),
    );
  }
  for (const alignment of ['adkim', 'aspf']) {
    const value = map.get(alignment);
    if (value !== undefined && value !== 'r' && value !== 's')
      diagnostics.push(diagnostic('alignment-invalid', `${alignment} must be r or s.`));
  }
  const percentage = map.get('pct');
  if (percentage !== undefined && !validInteger(percentage, 0, 100))
    diagnostics.push(
      diagnostic('percentage-invalid', 'pct must be an integer from 0 through 100.'),
    );
  const interval = map.get('ri');
  if (interval !== undefined && !validInteger(interval, 1, 4_294_967_295))
    diagnostics.push(
      diagnostic('interval-invalid', 'ri must be a positive integer number of seconds.'),
    );
  const failureOptions = map.get('fo');
  if (failureOptions !== undefined) {
    const values = failureOptions.split(':');
    if (
      values.some((value) => !['0', '1', 'd', 's'].includes(value)) ||
      new Set(values).size !== values.length
    )
      diagnostics.push(
        diagnostic(
          'failure-options-invalid',
          'fo may contain unique 0, 1, d, and s values separated by colons.',
        ),
      );
  }
  const known = new Set([
    'v',
    'p',
    'sp',
    'np',
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

  const destinations = [
    ...(map
      .get('rua')
      ?.split(',')
      .map((uri) => reportDestination(uri.trim(), 'aggregate', policyDomain, diagnostics)) ??
      []),
    ...(map
      .get('ruf')
      ?.split(',')
      .map((uri) => reportDestination(uri.trim(), 'forensic', policyDomain, diagnostics)) ??
      []),
  ];
  if (destinations.length > 10)
    diagnostics.push(
      diagnostic(
        'report-destination-limit',
        'More than ten report destinations exceeds ZoneSkein’s bounded authorization check.',
        'warning',
      ),
    );
  return {
    destinations,
    diagnostics,
    record,
    tags,
    valid: !diagnostics.some((item) => item.severity === 'error'),
  };
}
