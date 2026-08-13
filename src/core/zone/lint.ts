import ipaddr from 'ipaddr.js';

import { validateDnsName } from '../dns/names';
import { parseSpfRecord } from '../spf/parser';
import { parseTtl, parseZoneSnippet } from './parser';
import type {
  ZoneDiagnostic,
  ZoneDocument,
  ZoneParseOptions,
  ZoneRecord,
  ZoneToken,
} from './types';

const encoder = new TextEncoder();
const DNSSEC_COMPATIBLE_WITH_CNAME = new Set(['CNAME', 'RRSIG', 'NSEC', 'NSEC3']);

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

function looksLikeIp(value: string): boolean {
  try {
    ipaddr.parse(value.replace(/\.$/u, ''));
    return true;
  } catch {
    return false;
  }
}

function validateOwner(record: ZoneRecord): readonly ZoneDiagnostic[] {
  if (record.owner === '@') return [];
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

function lintRecord(record: ZoneRecord, options: ZoneParseOptions): readonly ZoneDiagnostic[] {
  const diagnostics: ZoneDiagnostic[] = [...validateOwner(record)];
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

  if (record.type === 'A' || record.type === 'AAAA') {
    const address = record.rdata[0];
    try {
      if (
        address === undefined ||
        ipaddr.parse(address.value).kind() !== (record.type === 'A' ? 'ipv4' : 'ipv6')
      )
        throw new Error('family');
    } catch {
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
      record.rdata.length < 3 ||
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

  if (record.type === 'SOA') {
    const numeric = record.rdata.slice(2);
    if (record.rdata.length !== 7 || numeric.some((token) => parseTtl(token.value) === null))
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

function normalizedRdata(record: ZoneRecord): string {
  return record.rdata
    .map((token) => token.value)
    .join(' ')
    .toLowerCase();
}

export function lintZoneSnippet(source: string, options: ZoneParseOptions = {}): ZoneDocument {
  const document = parseZoneSnippet(source, options);
  const diagnostics: ZoneDiagnostic[] = [...document.diagnostics];
  for (const record of document.records) diagnostics.push(...lintRecord(record, options));

  const exact = new Map<string, ZoneRecord>();
  for (const record of document.records) {
    const key = `${record.owner}|${record.type}|${normalizedRdata(record)}|${String(record.ttl ?? '')}`;
    const prior = exact.get(key);
    if (prior !== undefined)
      diagnostics.push(
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
  for (const record of document.records)
    owners.set(record.owner, [...(owners.get(record.owner) ?? []), record]);
  for (const [owner, records] of owners) {
    const cname = records.find((record) => record.type === 'CNAME');
    if (cname !== undefined) {
      const incompatible = records.filter(
        (record) => !DNSSEC_COMPATIBLE_WITH_CNAME.has(record.type),
      );
      if (incompatible.length > 0)
        diagnostics.push(
          item(
            cname,
            'cname-conflict',
            'error',
            `CNAME at ${owner} coexists with incompatible data types: ${[...new Set(incompatible.map((record) => record.type))].join(', ')}.`,
          ),
        );
      if (document.origin !== undefined && owner === document.origin)
        diagnostics.push(
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
      .filter((record) =>
        record.rdata
          .map((token) => token.value)
          .join('')
          .toLowerCase()
          .startsWith('v=spf1'),
      );
    const duplicateSpf = spfRecords.at(1);
    if (duplicateSpf !== undefined)
      diagnostics.push(
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
        diagnostics.push(item(record, 'spf-after-all', 'warning', spfDiagnostic.message));
      }
    }
  }
  return { ...document, diagnostics };
}
