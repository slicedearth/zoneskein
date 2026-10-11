import { parseStrictIpAddress } from '../dns/ip';
import { validateDnsName } from '../dns/names';
import {
  isDeprecatedDsDigestForAuthoring,
  isDeprecatedSha1DnssecAlgorithm,
} from '../dnssec/algorithm-policy';
import { parseSpfRecord } from '../spf/parser';
import { canonicalMasterName } from './master-name';
import { parseTtl, parseZoneSnippet, ZONE_ANALYSIS_LIMITS } from './parser';
import { canonicalSvcbKey, decodeBase64, isValidEchConfigList, svcbKeyNumber } from './svcb';
import type {
  ZoneDiagnostic,
  ZoneDocument,
  ZoneParseOptions,
  ZoneRecord,
  ZoneToken,
} from './types';

const encoder = new TextEncoder();
const DNSSEC_COMPATIBLE_WITH_CNAME = new Set(['CNAME', 'RRSIG', 'NSEC', 'NSEC3']);
const MAX_LINT_RECORDS = ZONE_ANALYSIS_LIMITS.records;
const MAX_LINT_DIAGNOSTICS = ZONE_ANALYSIS_LIMITS.diagnostics;
const MAX_RDATA_FIELDS_PER_RECORD = 256;

function item(
  record: ZoneRecord,
  rule: string,
  severity: ZoneDiagnostic['severity'],
  message: string,
  token?: ZoneToken,
  suggestion?: string,
): ZoneDiagnostic {
  return {
    column: token?.column ?? record.column,
    line: token?.line ?? record.line,
    message,
    rule,
    severity,
    ...(suggestion === undefined ? {} : { suggestion }),
  };
}

function integer(token: ZoneToken | undefined, minimum: number, maximum: number): boolean {
  if (token === undefined || !/^\d+$/u.test(token.value)) return false;
  const value = Number(token.value);
  return Number.isInteger(value) && value >= minimum && value <= maximum;
}

function hexadecimalOctets(value: string): number | null {
  const compact = value.replaceAll(/\s+/gu, '');
  return /^(?:[0-9A-Fa-f]{2})+$/u.test(compact) ? compact.length / 2 : null;
}

function absoluteUri(value: string): boolean {
  if (!/^[A-Za-z][A-Za-z0-9+.-]*:/u.test(value)) return false;
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

function looksLikeIp(value: string): boolean {
  return parseStrictIpAddress(value.replace(/\.$/u, '')) !== null;
}

function validateOwner(record: ZoneRecord): readonly ZoneDiagnostic[] {
  if (record.owner === '@') return [];
  if (canonicalMasterName(record.owner, '.') !== null) return [];
  const candidate = record.owner.replace(/^\*\./u, '');
  const parsed = validateDnsName(candidate);
  return parsed.ok ? [] : [item(record, 'owner-invalid', 'error', parsed.error.message)];
}

function targetWarning(
  record: ZoneRecord,
  token: ZoneToken | undefined,
): ZoneDiagnostic | null {
  if (
    token === undefined ||
    token.value === '@' ||
    token.value.endsWith('.') ||
    looksLikeIp(token.value)
  )
    return null;
  return item(
    record,
    'target-relative',
    'warning',
    `The relative target ${token.value} changes meaning when expanded under the current origin.`,
    token,
    `Use ${token.value}. if this target is intended to be absolute.`,
  );
}

interface ParsedSvcParam {
  readonly identity: string;
  readonly key: string;
  readonly keyNumber: number | null;
  readonly token: ZoneToken;
  readonly value?: string;
}

function parsedSvcParam(token: ZoneToken): ParsedSvcParam | null {
  const equals = token.value.indexOf('=');
  const suppliedKey = (equals < 0 ? token.value : token.value.slice(0, equals)).toLowerCase();
  if (!/^(?:[a-z0-9][a-z0-9-]{0,62}|key(?:0|[1-9]\d{0,4}))$/u.test(suppliedKey)) return null;
  const keyNumber = svcbKeyNumber(suppliedKey);
  if (suppliedKey.startsWith('key') && keyNumber === null) return null;
  const key = canonicalSvcbKey(suppliedKey);
  return {
    identity: keyNumber === null ? key : `key${String(keyNumber)}`,
    key,
    keyNumber,
    token,
    ...(equals < 0 ? {} : { value: token.value.slice(equals + 1) }),
  };
}

function lintSvcb(record: ZoneRecord): readonly ZoneDiagnostic[] {
  const diagnostics: ZoneDiagnostic[] = [];
  const priority = record.rdata[0];
  const target = record.rdata[1];
  if (record.rdata.length < 2 || !integer(priority, 0, 65_535) || target === undefined) {
    return [
      item(
        record,
        'svcb-malformed',
        'error',
        `${record.type} requires a 0–65535 priority, target name, and optional SvcParams.`,
      ),
    ];
  }
  const targetNotice = targetWarning(record, target);
  if (targetNotice !== null) diagnostics.push(targetNotice);

  const parsed: ParsedSvcParam[] = [];
  for (const token of record.rdata.slice(2)) {
    const parameter = parsedSvcParam(token);
    if (parameter === null) {
      diagnostics.push(
        item(
          record,
          'svcb-key-invalid',
          'error',
          `SvcParam ${token.value} does not begin with a registered name or keyNNNN value.`,
          token,
        ),
      );
    } else parsed.push(parameter);
  }

  const seen = new Set<string>();
  for (const parameter of parsed) {
    if (seen.has(parameter.identity))
      diagnostics.push(
        item(
          record,
          'svcb-key-duplicate',
          'error',
          `SvcParam ${parameter.key} is repeated.`,
          parameter.token,
        ),
      );
    seen.add(parameter.identity);
    if (parameter.keyNumber === null)
      diagnostics.push(
        item(
          record,
          'svcb-key-unregistered',
          'warning',
          `SvcParam ${parameter.key} is not in the bundled registry view; use its keyNNNN form or confirm the current registration.`,
          parameter.token,
        ),
      );
    if (parameter.key === 'no-default-alpn' || parameter.key === 'ohttp') {
      if (parameter.value !== undefined && parameter.value !== '')
        diagnostics.push(
          item(
            record,
            'svcb-empty-required',
            'error',
            `${parameter.key} must have an empty value.`,
            parameter.token,
          ),
        );
    } else if (parameter.keyNumber !== null && parameter.value === undefined)
      diagnostics.push(
        item(
          record,
          'svcb-value-required',
          'error',
          `${parameter.key} requires a value.`,
          parameter.token,
        ),
      );
    if (
      parameter.key === 'port' &&
      (parameter.value === undefined ||
        !/^\d+$/u.test(parameter.value) ||
        Number(parameter.value) < 1 ||
        Number(parameter.value) > 65_535)
    )
      diagnostics.push(
        item(
          record,
          'svcb-port-invalid',
          'error',
          'port must be from 1 through 65535.',
          parameter.token,
        ),
      );
    if (parameter.key === 'alpn' && parameter.value !== undefined) {
      const protocols = parameter.value.split(',');
      if (
        protocols.some((protocol) => protocol === '') ||
        new Set(protocols).size !== protocols.length
      )
        diagnostics.push(
          item(
            record,
            'svcb-alpn-invalid',
            'error',
            'alpn requires unique, non-empty comma-separated protocol identifiers.',
            parameter.token,
          ),
        );
    }
    if (
      parameter.key === 'ech' &&
      (parameter.value === undefined || !isValidEchConfigList(parameter.value))
    )
      diagnostics.push(
        item(
          record,
          'svcb-ech-invalid',
          'error',
          'ech must contain a structurally valid Base64-encoded ECHConfigList.',
          parameter.token,
        ),
      );
    if (parameter.key === 'ipv4hint' || parameter.key === 'ipv6hint') {
      const family = parameter.key === 'ipv4hint' ? 'ipv4' : 'ipv6';
      if (
        parameter.value === undefined ||
        parameter.value
          .split(',')
          .some((address) => parseStrictIpAddress(address)?.kind() !== family)
      )
        diagnostics.push(
          item(
            record,
            'svcb-hint-invalid',
            'error',
            `${parameter.key} must contain comma-separated ${family === 'ipv4' ? 'IPv4' : 'IPv6'} addresses.`,
            parameter.token,
          ),
        );
    }
  }

  const numbered = parsed.flatMap((parameter) =>
    parameter.keyNumber === null ? [] : [parameter.keyNumber],
  );
  if (numbered.some((number, index) => index > 0 && number < (numbered[index - 1] ?? 0)))
    diagnostics.push(
      item(
        record,
        'svcb-parameter-order',
        'warning',
        'SvcParams are not in canonical increasing key order.',
      ),
    );

  const mandatory = parsed.find((parameter) => parameter.key === 'mandatory');
  if (mandatory !== undefined) {
    const required = (mandatory.value ?? '').split(',').filter(Boolean);
    const identities = required.map((key) => {
      const number = svcbKeyNumber(key.toLowerCase());
      return number === null ? key.toLowerCase() : `key${String(number)}`;
    });
    if (
      required.length === 0 ||
      new Set(identities).size !== identities.length ||
      identities.includes('key0') ||
      identities.some((identity) => !seen.has(identity))
    )
      diagnostics.push(
        item(
          record,
          'svcb-mandatory-inconsistent',
          'error',
          'mandatory must list unique other keys that also appear in this record.',
          mandatory.token,
        ),
      );
  }
  if (seen.has('key2') && !seen.has('key1'))
    diagnostics.push(
      item(
        record,
        'svcb-no-default-without-alpn',
        'error',
        'no-default-alpn requires an alpn parameter in the same record.',
      ),
    );

  const priorityValue = Number(priority?.value);
  if (priorityValue === 0 && parsed.length > 0)
    diagnostics.push(
      item(
        record,
        'svcb-alias-parameters',
        'error',
        'AliasMode priority 0 records must not contain SvcParams.',
      ),
    );
  if (priorityValue === 0 && target.value === '.')
    diagnostics.push(
      item(
        record,
        'svcb-alias-root-target',
        'error',
        'AliasMode priority 0 requires a non-root target name.',
        target,
      ),
    );
  return diagnostics;
}

function lintRecord(record: ZoneRecord, options: ZoneParseOptions): readonly ZoneDiagnostic[] {
  const diagnostics: ZoneDiagnostic[] = [...validateOwner(record)];
  if (record.rdata.length > MAX_RDATA_FIELDS_PER_RECORD) {
    diagnostics.push(
      item(
        record,
        'record-field-limit',
        'error',
        `Record linting is limited to ${String(MAX_RDATA_FIELDS_PER_RECORD)} data fields per record.`,
      ),
    );
    return diagnostics;
  }
  if (record.ttl !== undefined) {
    if (options.minimumTtl !== undefined && record.ttl < options.minimumTtl)
      diagnostics.push(
        item(
          record,
          'ttl-below-recommended',
          'warning',
          `TTL ${String(record.ttl)} is below the recommended minimum of ${String(options.minimumTtl)}.`,
        ),
      );
    if (options.maximumTtl !== undefined && record.ttl > options.maximumTtl)
      diagnostics.push(
        item(
          record,
          'ttl-above-recommended',
          'warning',
          `TTL ${String(record.ttl)} is above the recommended maximum of ${String(options.maximumTtl)}.`,
        ),
      );
  }

  if (/^TYPE\d{1,5}$/u.test(record.type)) {
    const length = record.rdata[1];
    const hexadecimal = record.rdata
      .slice(2)
      .map((token) => token.value)
      .join('');
    const octets = hexadecimalOctets(hexadecimal);
    if (
      record.rdata[0]?.value !== '#' ||
      length === undefined ||
      !/^\d+$/u.test(length.value) ||
      Number(length.value) > 65_535 ||
      octets === null ||
      octets !== Number(length.value)
    )
      diagnostics.push(
        item(
          record,
          'generic-rdata-malformed',
          'error',
          'RFC 3597 generic data requires \\# followed by an octet count and exactly that many hexadecimal octets.',
        ),
      );
  }

  if (record.type === 'A' || record.type === 'AAAA') {
    const address = record.rdata[0];
    if (
      address === undefined ||
      parseStrictIpAddress(address.value)?.kind() !== (record.type === 'A' ? 'ipv4' : 'ipv6')
    ) {
      diagnostics.push(
        item(
          record,
          'address-invalid',
          'error',
          `${record.type} requires one valid ${record.type === 'A' ? 'IPv4' : 'IPv6'} address.`,
          address,
        ),
      );
    }
    if (record.rdata.length !== 1)
      diagnostics.push(
        item(
          record,
          'field-count',
          'error',
          `${record.type} requires exactly one address field.`,
        ),
      );
  }

  if (record.type === 'MX') {
    if (!integer(record.rdata[0], 0, 65_535) || record.rdata.length !== 2)
      diagnostics.push(
        item(
          record,
          'mx-malformed',
          'error',
          'MX requires a 0–65535 preference and one target name.',
        ),
      );
    const target = record.rdata[1];
    if (target !== undefined && looksLikeIp(target.value))
      diagnostics.push(
        item(
          record,
          'target-ip-literal',
          'error',
          'MX target must be a DNS name, not an IP address.',
          target,
        ),
      );
    const warning = targetWarning(record, target);
    if (warning !== null) diagnostics.push(warning);
  }

  if (record.type === 'NS') {
    const target = record.rdata[0];
    if (record.rdata.length !== 1)
      diagnostics.push(
        item(record, 'ns-malformed', 'error', 'NS requires exactly one target name.'),
      );
    if (target !== undefined && looksLikeIp(target.value))
      diagnostics.push(
        item(
          record,
          'target-ip-literal',
          'error',
          'NS target must be a DNS name, not an IP address.',
          target,
        ),
      );
    const warning = targetWarning(record, target);
    if (warning !== null) diagnostics.push(warning);
  }

  if (record.type === 'SRV') {
    if (
      record.rdata.length !== 4 ||
      !integer(record.rdata[0], 0, 65_535) ||
      !integer(record.rdata[1], 0, 65_535) ||
      !integer(record.rdata[2], 0, 65_535)
    )
      diagnostics.push(
        item(
          record,
          'srv-malformed',
          'error',
          'SRV requires priority, weight, and port values from 0–65535 plus a target.',
        ),
      );
    const warning = targetWarning(record, record.rdata[3]);
    if (warning !== null) diagnostics.push(warning);
  }

  if (record.type === 'CAA') {
    const tag = record.rdata[1]?.value.toLowerCase();
    if (
      record.rdata.length !== 3 ||
      !integer(record.rdata[0], 0, 255) ||
      tag === undefined ||
      !/^[a-z0-9]+$/u.test(tag)
    )
      diagnostics.push(
        item(
          record,
          'caa-malformed',
          'error',
          'CAA requires flags 0–255, an alphanumeric tag, and a value.',
        ),
      );
  }

  if (record.type === 'DNSKEY') {
    const publicKey = record.rdata
      .slice(3)
      .map((token) => token.value)
      .join('');
    if (
      record.rdata.length < 4 ||
      !integer(record.rdata[0], 0, 65_535) ||
      record.rdata[1]?.value !== '3' ||
      !integer(record.rdata[2], 0, 255) ||
      decodeBase64(publicKey) === null
    )
      diagnostics.push(
        item(
          record,
          'dnskey-malformed',
          'error',
          'DNSKEY requires flags 0–65535, protocol 3, an algorithm 0–255, and non-empty Base64 key material.',
        ),
      );
    const algorithm = Number(record.rdata[2]?.value);
    if (Number.isInteger(algorithm) && isDeprecatedSha1DnssecAlgorithm(algorithm))
      diagnostics.push(
        item(
          record,
          'dnskey-algorithm-deprecated',
          'error',
          'RFC 9905 prohibits creating DNSKEY and RRSIG records with RSA/SHA-1 algorithms 5 or 7.',
          record.rdata[2],
        ),
      );
  }

  if (record.type === 'RRSIG') {
    const algorithm = Number(record.rdata[1]?.value);
    if (Number.isInteger(algorithm) && isDeprecatedSha1DnssecAlgorithm(algorithm))
      diagnostics.push(
        item(
          record,
          'rrsig-algorithm-deprecated',
          'error',
          'RFC 9905 prohibits creating RRSIG records with RSA/SHA-1 algorithms 5 or 7.',
          record.rdata[1],
        ),
      );
  }

  if (record.type === 'DS') {
    const algorithm = Number(record.rdata[1]?.value);
    const digestType = record.rdata[2];
    const digestOctets = hexadecimalOctets(
      record.rdata
        .slice(3)
        .map((token) => token.value)
        .join(''),
    );
    const expected =
      digestType?.value === '1'
        ? 20
        : digestType?.value === '2'
          ? 32
          : digestType?.value === '4'
            ? 48
            : undefined;
    if (
      record.rdata.length < 4 ||
      !integer(record.rdata[0], 0, 65_535) ||
      !integer(record.rdata[1], 0, 255) ||
      !integer(digestType, 0, 255) ||
      digestOctets === null ||
      (expected !== undefined && digestOctets !== expected)
    )
      diagnostics.push(
        item(
          record,
          'ds-malformed',
          'error',
          'DS requires a key tag, algorithm, digest type, and a hexadecimal digest of the required length.',
        ),
      );
    if (Number.isInteger(algorithm) && isDeprecatedSha1DnssecAlgorithm(algorithm))
      diagnostics.push(
        item(
          record,
          'ds-algorithm-deprecated',
          'error',
          'RFC 9905 prohibits creating DS records with RSA/SHA-1 algorithms 5 or 7.',
          record.rdata[1],
        ),
      );
    const digestTypeNumber = Number(digestType?.value);
    if (
      Number.isInteger(digestTypeNumber) &&
      isDeprecatedDsDigestForAuthoring(digestTypeNumber)
    )
      diagnostics.push(
        item(
          record,
          'ds-digest-deprecated',
          'error',
          'RFC 9905 prohibits creating new DS records with SHA-1 digest type 1.',
          digestType,
        ),
      );
  }

  if (record.type === 'SSHFP') {
    const fingerprintType = record.rdata[1];
    const octets = hexadecimalOctets(
      record.rdata
        .slice(2)
        .map((token) => token.value)
        .join(''),
    );
    const expected =
      fingerprintType?.value === '1' ? 20 : fingerprintType?.value === '2' ? 32 : null;
    if (
      record.rdata.length < 3 ||
      !integer(record.rdata[0], 1, 6) ||
      !integer(fingerprintType, 1, 2) ||
      octets === null ||
      expected === null ||
      octets !== expected
    )
      diagnostics.push(
        item(
          record,
          'sshfp-malformed',
          'error',
          'SSHFP requires an algorithm 1–6, fingerprint type 1 or 2, and a matching-length hexadecimal fingerprint.',
        ),
      );
  }

  if (record.type === 'TLSA') {
    const matchingType = record.rdata[2];
    const octets = hexadecimalOctets(
      record.rdata
        .slice(3)
        .map((token) => token.value)
        .join(''),
    );
    const expected =
      matchingType?.value === '1' ? 32 : matchingType?.value === '2' ? 64 : undefined;
    if (
      record.rdata.length < 4 ||
      !integer(record.rdata[0], 0, 3) ||
      !integer(record.rdata[1], 0, 1) ||
      !integer(matchingType, 0, 2) ||
      octets === null ||
      (expected !== undefined && octets !== expected)
    )
      diagnostics.push(
        item(
          record,
          'tlsa-malformed',
          'error',
          'TLSA requires valid usage, selector, matching type, and hexadecimal association data of the required length.',
        ),
      );
  }

  if (record.type === 'ZONEMD') {
    const hashAlgorithm = record.rdata[2];
    const digestOctets = hexadecimalOctets(
      record.rdata
        .slice(3)
        .map((token) => token.value)
        .join(''),
    );
    const expected =
      hashAlgorithm?.value === '1' ? 48 : hashAlgorithm?.value === '2' ? 64 : undefined;
    if (
      record.rdata.length < 4 ||
      !integer(record.rdata[0], 0, 0xffff_ffff) ||
      !integer(record.rdata[1], 0, 255) ||
      !integer(hashAlgorithm, 0, 255) ||
      digestOctets === null ||
      digestOctets < 12 ||
      (expected !== undefined && digestOctets !== expected)
    )
      diagnostics.push(
        item(
          record,
          'zonemd-malformed',
          'error',
          'ZONEMD requires an SOA serial, scheme, hash algorithm, and a full hexadecimal digest of at least 12 octets.',
        ),
      );
  }

  if (record.type === 'HTTPS' || record.type === 'SVCB') diagnostics.push(...lintSvcb(record));

  if (record.type === 'NAPTR') {
    const flags = record.rdata[2];
    const service = record.rdata[3];
    const expression = record.rdata[4];
    const replacement = record.rdata[5];
    if (
      record.rdata.length !== 6 ||
      !integer(record.rdata[0], 0, 65_535) ||
      !integer(record.rdata[1], 0, 65_535) ||
      flags?.quoted !== true ||
      service?.quoted !== true ||
      expression?.quoted !== true ||
      !/^[A-Za-z0-9]*$/u.test(flags.value)
    )
      diagnostics.push(
        item(
          record,
          'naptr-malformed',
          'error',
          'NAPTR requires order, preference, three quoted strings, and one replacement name.',
        ),
      );
    if (expression !== undefined && expression.value !== '' && replacement?.value !== '.')
      diagnostics.push(
        item(
          record,
          'naptr-regexp-replacement',
          'error',
          'A NAPTR record with a regular expression must use . as its replacement.',
          replacement,
        ),
      );
    const warning = targetWarning(record, replacement);
    if (warning !== null) diagnostics.push(warning);
  }

  if (record.type === 'URI') {
    const target = record.rdata[2];
    if (
      record.rdata.length !== 3 ||
      !integer(record.rdata[0], 0, 65_535) ||
      !integer(record.rdata[1], 0, 65_535) ||
      target?.quoted !== true ||
      !absoluteUri(target.value)
    )
      diagnostics.push(
        item(
          record,
          'uri-malformed',
          'error',
          'URI requires priority and weight values from 0–65535 plus one quoted absolute URI.',
          target,
        ),
      );
  }

  if (record.type === 'SOA') {
    const timings = record.rdata.slice(3);
    if (
      record.rdata.length !== 7 ||
      !integer(record.rdata[2], 0, 0xffff_ffff) ||
      timings.some((token) => parseTtl(token.value) === null)
    )
      diagnostics.push(
        item(
          record,
          'soa-malformed',
          'error',
          'SOA requires MNAME, RNAME, serial, refresh, retry, expire, and minimum fields.',
        ),
      );
    for (const target of record.rdata.slice(0, 2)) {
      const warning = targetWarning(record, target);
      if (warning !== null) diagnostics.push(warning);
    }
  }

  if (record.type === 'CNAME' || record.type === 'PTR') {
    if (record.rdata.length !== 1)
      diagnostics.push(
        item(
          record,
          'target-malformed',
          'error',
          `${record.type} requires exactly one target name.`,
        ),
      );
    const warning = targetWarning(record, record.rdata[0]);
    if (warning !== null) diagnostics.push(warning);
  }

  if (record.type === 'TXT') {
    if (record.rdata.length === 0 || record.rdata.some((token) => !token.quoted))
      diagnostics.push(
        item(
          record,
          'txt-unquoted',
          'warning',
          'TXT data should be represented as one or more quoted character-strings.',
        ),
      );
    for (const token of record.rdata.filter((value) => value.quoted)) {
      const octets = encoder.encode(token.value).length;
      if (octets > 255)
        diagnostics.push(
          item(
            record,
            'txt-chunk-too-long',
            'error',
            `TXT character-string is ${String(octets)} octets; the limit is 255.`,
            token,
          ),
        );
    }
  }
  return diagnostics;
}

function normalizedRdata(record: ZoneRecord): string | null {
  if (record.rdata.length > MAX_RDATA_FIELDS_PER_RECORD) return null;
  const values = record.rdata.map((token) => token.value);
  if (record.type === 'A' || record.type === 'AAAA')
    return (
      parseStrictIpAddress(values[0] ?? '')?.toNormalizedString() ?? JSON.stringify(values)
    );
  if (['CNAME', 'DNAME', 'NS', 'PTR'].includes(record.type))
    return JSON.stringify(values.map((value) => value.toLowerCase()));
  if (record.type === 'MX')
    return JSON.stringify([String(Number(values[0] ?? 0)), (values[1] ?? '').toLowerCase()]);
  if (record.type === 'SRV')
    return JSON.stringify([
      String(Number(values[0] ?? 0)),
      String(Number(values[1] ?? 0)),
      String(Number(values[2] ?? 0)),
      (values[3] ?? '').toLowerCase(),
    ]);
  if (record.type === 'SOA')
    return JSON.stringify([
      (values[0] ?? '').toLowerCase(),
      (values[1] ?? '').toLowerCase(),
      String(Number(values[2] ?? 0)),
      ...values.slice(3).map((value) => String(parseTtl(value) ?? value)),
    ]);
  if (record.type === 'CAA')
    return JSON.stringify([
      String(Number(values[0] ?? 0)),
      (values[1] ?? '').toLowerCase(),
      ...values.slice(2),
    ]);
  return JSON.stringify(values);
}

export function lintZoneSnippet(source: string, options: ZoneParseOptions = {}): ZoneDocument {
  const document = parseZoneSnippet(source, options);
  if (document.incomplete !== undefined) return document;
  let diagnosticsTruncated = document.diagnostics.length >= MAX_LINT_DIAGNOSTICS;
  const diagnostics: ZoneDiagnostic[] = document.diagnostics.slice(0, MAX_LINT_DIAGNOSTICS - 1);
  const addDiagnostic = (diagnostic: ZoneDiagnostic) => {
    if (diagnostics.length < MAX_LINT_DIAGNOSTICS - 1) diagnostics.push(diagnostic);
    else diagnosticsTruncated = true;
  };
  const records = document.records.slice(0, MAX_LINT_RECORDS);
  const firstOmitted = document.records[MAX_LINT_RECORDS];
  if (firstOmitted !== undefined)
    addDiagnostic(
      item(
        firstOmitted,
        'lint-record-limit',
        'warning',
        `Only the first ${String(MAX_LINT_RECORDS)} records were linted.`,
      ),
    );
  for (const record of records)
    for (const diagnostic of lintRecord(record, options)) addDiagnostic(diagnostic);

  const exact = new Map<string, ZoneRecord>();
  for (const record of records) {
    const rdata = normalizedRdata(record);
    if (rdata === null) continue;
    const key = `${record.owner}|${record.type}|${rdata}|${String(record.ttl ?? '')}`;
    const prior = exact.get(key);
    if (prior !== undefined)
      addDiagnostic(
        item(
          record,
          'record-duplicate',
          'warning',
          `Duplicate of the record on line ${String(prior.line)}.`,
        ),
      );
    else exact.set(key, record);
  }

  const owners = new Map<string, ZoneRecord[]>();
  for (const record of records) {
    const sameOwner = owners.get(record.owner);
    if (sameOwner === undefined) owners.set(record.owner, [record]);
    else sameOwner.push(record);
  }
  for (const [owner, records] of owners) {
    const cname = records.find((record) => record.type === 'CNAME');
    if (cname !== undefined) {
      const incompatible = records.filter(
        (record) => !DNSSEC_COMPATIBLE_WITH_CNAME.has(record.type),
      );
      if (incompatible.length > 0)
        addDiagnostic(
          item(
            cname,
            'cname-conflict',
            'error',
            `CNAME at ${owner} coexists with incompatible data types: ${[...new Set(incompatible.map((record) => record.type))].join(', ')}.`,
          ),
        );
      if (document.origin !== undefined && owner === document.origin)
        addDiagnostic(
          item(
            cname,
            'apex-cname',
            'warning',
            'A standard DNS zone apex cannot be a CNAME. Provider-specific ALIAS or ANAME flattening is outside standard DNS.',
          ),
        );
    }
    const spfRecords = records
      .filter((record) => record.type === 'TXT')
      .filter(
        (record) =>
          record.rdata.length <= MAX_RDATA_FIELDS_PER_RECORD &&
          record.rdata
            .map((token) => token.value)
            .join('')
            .toLowerCase()
            .startsWith('v=spf1'),
      );
    const duplicateSpf = spfRecords.at(1);
    if (duplicateSpf !== undefined)
      addDiagnostic(
        item(
          duplicateSpf,
          'spf-multiple',
          'error',
          `Multiple SPF policies are published at ${owner}.`,
        ),
      );
    for (const record of spfRecords) {
      const policy = parseSpfRecord(record.rdata.map((token) => token.value).join(''), owner);
      for (const spfDiagnostic of policy.diagnostics.filter(
        (entry) => entry.code === 'after-all',
      )) {
        addDiagnostic(item(record, 'spf-after-all', 'warning', spfDiagnostic.message));
      }
    }
  }
  if (document.origin !== undefined) {
    const apexSoa = records.find(
      (record) => record.owner === document.origin && record.type === 'SOA',
    );
    const soaSerial = apexSoa?.rdata[2]?.value;
    const zonemdTuples = new Map<string, ZoneRecord>();
    for (const record of records.filter((item) => item.type === 'ZONEMD')) {
      if (record.owner !== document.origin) {
        addDiagnostic(
          item(
            record,
            'zonemd-non-apex',
            'information',
            'A non-apex ZONEMD record has no verification meaning and is digested as ordinary zone data.',
          ),
        );
        continue;
      }
      if (soaSerial !== undefined && record.rdata[0]?.value !== soaSerial)
        addDiagnostic(
          item(
            record,
            'zonemd-serial-mismatch',
            'error',
            'The ZONEMD serial does not match the apex SOA serial.',
            record.rdata[0],
          ),
        );
      const scheme = record.rdata[1]?.value;
      const hash = record.rdata[2]?.value;
      if (scheme === undefined || hash === undefined) continue;
      const key = `${scheme}|${hash}`;
      const prior = zonemdTuples.get(key);
      if (prior === undefined) zonemdTuples.set(key, record);
      else
        addDiagnostic(
          item(
            record,
            'zonemd-tuple-duplicate',
            'error',
            `The scheme and hash tuple duplicates the apex ZONEMD record on line ${String(prior.line)}.`,
          ),
        );
    }
  }
  if (diagnosticsTruncated)
    diagnostics.push({
      column: 1,
      line: 1,
      message: `Only the first ${String(MAX_LINT_DIAGNOSTICS - 1)} diagnostics are shown.`,
      rule: 'lint-diagnostic-limit',
      severity: 'warning',
    });
  return { ...document, diagnostics };
}
