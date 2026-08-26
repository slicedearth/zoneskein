import { validateDnsName } from '../dns/names';

const MAX_AUTHORIZATION_RECORDS = 32;
const MAX_AUTHORIZATION_RECORD_CHARACTERS = 8_192;
const MAX_AUTHORIZATION_TOTAL_CHARACTERS = 65_535;
const MAX_AUTHORIZATION_TAGS = 64;
const MAX_OVERRIDE_URIS = 10;
const MAX_URI_CHARACTERS = 2_048;

export type DmarcReportAuthorizationStatus = 'authorized' | 'unauthorized' | 'indeterminate';
export type DmarcReportAuthorizationTag = 'rua' | 'ruf';

export interface DmarcReportAuthorization {
  readonly authorized: boolean;
  readonly destinationHost?: string;
  readonly overrideUris: readonly string[];
  readonly reason: string;
  readonly selectedUris: readonly string[];
  readonly status: DmarcReportAuthorizationStatus;
  readonly validRecords: number;
}

interface BasicAuthorizationRecord {
  readonly override?: string;
}

function normaliseDomain(value: string): string | null {
  if (value !== value.trim() || value.includes('://')) return null;
  const parsed = validateDnsName(value);
  if (!parsed.ok || parsed.value.ascii === '') return null;
  if (
    parsed.value.ascii
      .split('.')
      .some((label) => !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))
  )
    return null;
  return parsed.value.ascii;
}

function withoutObsoleteSizeLimit(uri: string): string {
  return uri.replace(/!\d+[kmgt]?$/iu, '');
}

/** Extract and normalise the destination host used by DMARC reporting URI checks. */
export function dmarcReportDestinationHost(uri: string): string | null {
  if (uri.length === 0 || uri.length > MAX_URI_CHARACTERS || /\p{Cc}/u.test(uri)) return null;
  let parsed: URL;
  try {
    parsed = new URL(withoutObsoleteSizeLimit(uri));
  } catch {
    return null;
  }

  let host: string;
  if (parsed.protocol === 'mailto:') {
    if (
      parsed.search !== '' ||
      parsed.hash !== '' ||
      parsed.username !== '' ||
      parsed.password !== '' ||
      parsed.host !== ''
    )
      return null;
    let address: string;
    try {
      address = decodeURIComponent(parsed.pathname);
    } catch {
      return null;
    }
    const at = address.lastIndexOf('@');
    if (
      at < 1 ||
      at === address.length - 1 ||
      at !== address.indexOf('@') ||
      address.includes(',')
    )
      return null;
    host = address.slice(at + 1);
  } else {
    host = parsed.hostname;
  }
  return normaliseDomain(host);
}

/** Build the RFC 9990/9991 external reporting authorisation TXT owner name. */
export function dmarcReportAuthorizationName(
  policyDomain: string,
  destinationUri: string,
): string | null {
  const policy = normaliseDomain(policyDomain);
  const destination = dmarcReportDestinationHost(destinationUri);
  if (policy === null || destination === null) return null;
  const name = `${policy}._report._dmarc.${destination}`;
  if (new TextEncoder().encode(name).length > 253) return null;
  const parsed = validateDnsName(name);
  return parsed.ok && parsed.value.ascii !== '' ? parsed.value.ascii : null;
}

function parseBasicAuthorizationRecord(
  record: string,
  authorizationTag: DmarcReportAuthorizationTag,
): BasicAuthorizationRecord | null {
  const trimmed = record.trim();
  if (
    trimmed.length === 0 ||
    trimmed.length > MAX_AUTHORIZATION_RECORD_CHARACTERS ||
    /[^\x20-\x7e]/u.test(trimmed)
  )
    return null;

  const rawSegments = trimmed.split(';');
  if (rawSegments.at(-1)?.trim() === '') rawSegments.pop();
  if (rawSegments.length === 0 || rawSegments.length > MAX_AUTHORIZATION_TAGS) return null;
  const tags = new Map<string, string>();
  for (const segment of rawSegments) {
    const equals = segment.indexOf('=');
    if (equals < 1) return null;
    const rawName = segment.slice(0, equals).trim();
    const name = rawName.toLowerCase();
    const value = segment.slice(equals + 1).trim();
    if (
      !/^[A-Za-z]+$/u.test(rawName) ||
      value.length === 0 ||
      value.includes(';') ||
      Array.from(value).some((character) => {
        const code = character.codePointAt(0) ?? 0;
        return code < 0x20 || code === 0x7f;
      })
    )
      return null;
    if (tags.has(name)) return null;
    tags.set(name, value);
  }
  const first = rawSegments[0];
  if (first === undefined) return null;
  const firstEquals = first.indexOf('=');
  if (
    first.slice(0, firstEquals).trim().toLowerCase() !== 'v' ||
    first.slice(firstEquals + 1).trim() !== 'DMARC1'
  )
    return null;
  const override = tags.get(authorizationTag);
  return override === undefined ? {} : { override };
}

function parseOverrideUris(value: string, destinationHost: string): readonly string[] | null {
  const uris = value.split(',').map((uri) => uri.trim());
  if (uris.length === 0 || uris.length > MAX_OVERRIDE_URIS || uris.some((uri) => uri === ''))
    return null;
  for (const uri of uris) {
    if (uri.length > MAX_URI_CHARACTERS || dmarcReportDestinationHost(uri) !== destinationHost)
      return null;
  }
  return uris;
}

function notAuthorized(
  reason: string,
  destinationHost?: string,
  status: DmarcReportAuthorizationStatus = 'unauthorized',
  validRecords = 0,
): DmarcReportAuthorization {
  return {
    authorized: false,
    ...(destinationHost === undefined ? {} : { destinationHost }),
    overrideUris: [],
    reason,
    selectedUris: [],
    status,
    validRecords,
  };
}

/** Parse bounded RFC 9990/9991 external authorisation records and same-kind overrides. */
export function evaluateDmarcReportAuthorization(
  destinationUri: string,
  records: readonly string[],
  authorizationTag: DmarcReportAuthorizationTag = 'rua',
): DmarcReportAuthorization {
  const destinationHost = dmarcReportDestinationHost(destinationUri);
  if (destinationHost === null)
    return notAuthorized('The original reporting URI has no valid destination host.');
  const rawRecords: unknown = records;
  if (!Array.isArray(rawRecords))
    return notAuthorized(
      'The authorisation TXT response is not a bounded record list.',
      destinationHost,
      'indeterminate',
    );
  if (rawRecords.length > MAX_AUTHORIZATION_RECORDS)
    return notAuthorized(
      `The response exceeds the ${String(MAX_AUTHORIZATION_RECORDS)}-record authorisation limit.`,
      destinationHost,
      'indeterminate',
    );

  let total = 0;
  const valid: BasicAuthorizationRecord[] = [];
  for (const record of rawRecords) {
    if (typeof record !== 'string')
      return notAuthorized(
        'The authorisation TXT response contains a non-text value.',
        destinationHost,
        'indeterminate',
        valid.length,
      );
    total += record.length;
    if (
      record.length > MAX_AUTHORIZATION_RECORD_CHARACTERS ||
      total > MAX_AUTHORIZATION_TOTAL_CHARACTERS
    )
      return notAuthorized(
        'The authorisation TXT response exceeds its bounded character limit.',
        destinationHost,
        'indeterminate',
        valid.length,
      );
    const parsed = parseBasicAuthorizationRecord(record, authorizationTag);
    if (parsed !== null) valid.push(parsed);
  }
  if (valid.length === 0)
    return notAuthorized(
      'No basic-valid authorisation record with v=DMARC1 first was observed.',
      destinationHost,
    );

  const overrideSets: string[][] = [];
  for (const record of valid) {
    if (record.override === undefined) continue;
    const uris = parseOverrideUris(record.override, destinationHost);
    if (uris === null)
      return notAuthorized(
        `An authorisation record contains a malformed or cross-host ${authorizationTag} override, so the relationship fails closed.`,
        destinationHost,
        'unauthorized',
        valid.length,
      );
    overrideSets.push([...uris]);
  }
  const distinctOverrides = new Map(
    overrideSets.map((uris) => [uris.join('\u0000'), uris] as const),
  );
  if (distinctOverrides.size > 1)
    return notAuthorized(
      `Authorisation records contain conflicting ${authorizationTag} overrides, so no destination is selected.`,
      destinationHost,
      'unauthorized',
      valid.length,
    );

  const overrideUris = distinctOverrides.values().next().value ?? [];
  return {
    authorized: true,
    destinationHost,
    overrideUris,
    reason:
      overrideUris.length === 0
        ? `${String(valid.length)} basic-valid authorisation record${valid.length === 1 ? '' : 's'} confirmed the external destination.`
        : `The external destination is authorised and supplies a same-host ${authorizationTag} override.`,
    selectedUris: overrideUris.length === 0 ? [destinationUri] : overrideUris,
    status: 'authorized',
    validRecords: valid.length,
  };
}
