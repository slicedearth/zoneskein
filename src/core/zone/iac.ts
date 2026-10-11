import { canonicalMasterName } from './master-name';
import type { ZoneDocument, ZoneRecord } from './types';

export interface ZoneExportDiagnostic {
  readonly line: number;
  readonly message: string;
  readonly severity: 'warning' | 'error';
}

export interface ZoneInfrastructureExports {
  readonly diagnostics: readonly ZoneExportDiagnostic[];
  readonly dnsControl: string;
  readonly octoDns: string;
  readonly omittedRecords: number;
  readonly origin: string | null;
  readonly supportedRecords: number;
}

function relativeOwner(record: ZoneRecord, origin: string): string | null {
  const canonical = canonicalMasterName(record.owner, origin)?.absolute ?? null;
  if (canonical === null) return null;
  if (canonical === origin) return '@';
  return canonical.endsWith(`.${origin}`) ? canonical.slice(0, -(origin.length + 1)) : null;
}

function js(value: string): string {
  return JSON.stringify(value);
}

function yaml(value: string): string {
  for (const character of value) {
    if ((character.codePointAt(0) ?? 0) < 32) return JSON.stringify(value);
  }
  return `'${value.replaceAll("'", "''")}'`;
}

function ttl(record: ZoneRecord): number {
  return record.ttl ?? 3600;
}

function value(record: ZoneRecord, index: number): string | null {
  return record.rdata[index]?.value ?? null;
}

function integer(value: string | null, maximum: number): string | null {
  return value !== null && /^(?:0|[1-9]\d*)$/u.test(value) && Number(value) <= maximum
    ? value
    : null;
}

function target(record: ZoneRecord, index: number, origin: string): string | null {
  const raw = record.rdata[index]?.raw;
  return raw === undefined
    ? null
    : (canonicalMasterName(raw, record.origin ?? origin)?.absolute ?? null);
}

function dnsControlRecord(record: ZoneRecord, owner: string, origin: string): string | null {
  const modifier = `TTL(${String(ttl(record))})`;
  if (record.type === 'A' || record.type === 'AAAA') {
    const address = value(record, 0);
    return address === null
      ? null
      : `${record.type}(${js(owner)}, ${js(address)}, ${modifier})`;
  }
  if (['CNAME', 'NS', 'PTR'].includes(record.type)) {
    const destination = target(record, 0, origin);
    return destination === null
      ? null
      : `${record.type}(${js(owner)}, ${js(destination)}, ${modifier})`;
  }
  if (record.type === 'TXT') {
    const text = record.rdata.map((token) => token.value).join('');
    return `TXT(${js(owner)}, ${js(text)}, ${modifier})`;
  }
  if (record.type === 'MX') {
    const preference = integer(value(record, 0), 65_535);
    const exchange = target(record, 1, origin);
    return preference === null || exchange === null
      ? null
      : `MX(${js(owner)}, ${preference}, ${js(exchange)}, ${modifier})`;
  }
  if (record.type === 'SRV') {
    const priority = integer(value(record, 0), 65_535);
    const weight = integer(value(record, 1), 65_535);
    const port = integer(value(record, 2), 65_535);
    const destination = target(record, 3, origin);
    return priority === null || weight === null || port === null || destination === null
      ? null
      : `SRV(${js(owner)}, ${priority}, ${weight}, ${port}, ${js(destination)}, ${modifier})`;
  }
  if (record.type === 'CAA') {
    const [flags, tag, data] = record.rdata.map((token) => token.value);
    if (flags === undefined || tag === undefined || data === undefined) return null;
    const critical = flags === '128' ? ', CAA_CRITICAL' : flags === '0' ? '' : null;
    return critical === null
      ? null
      : `CAA(${js(owner)}, ${js(tag)}, ${js(data)}, ${modifier}${critical})`;
  }
  if (record.type === 'TLSA') {
    const [usage, selector, matching, ...association] = record.rdata.map(
      (token) => token.value,
    );
    return usage === undefined || selector === undefined || matching === undefined
      ? null
      : `TLSA(${js(owner)}, ${usage}, ${selector}, ${matching}, ${js(association.join(''))}, ${modifier})`;
  }
  return null;
}

function octoRecord(record: ZoneRecord, origin: string): readonly string[] | null {
  const heading = [`  - ttl: ${String(ttl(record))}`, `    type: ${record.type}`];
  if (['A', 'AAAA', 'CNAME', 'NS', 'PTR'].includes(record.type)) {
    const data = ['CNAME', 'NS', 'PTR'].includes(record.type)
      ? target(record, 0, origin)
      : value(record, 0);
    return data === null ? null : [...heading, `    value: ${yaml(data)}`];
  }
  if (record.type === 'TXT')
    return [
      ...heading,
      `    value: ${yaml(
        record.rdata
          .map((token) => token.value)
          .join('')
          .replaceAll(';', '\\;'),
      )}`,
    ];
  if (record.type === 'MX') {
    const preference = integer(value(record, 0), 65_535);
    const exchange = target(record, 1, origin);
    return preference === null || exchange === null
      ? null
      : [
          ...heading,
          '    value:',
          `      exchange: ${yaml(exchange)}`,
          `      preference: ${preference}`,
        ];
  }
  if (record.type === 'SRV') {
    const priority = integer(value(record, 0), 65_535);
    const weight = integer(value(record, 1), 65_535);
    const port = integer(value(record, 2), 65_535);
    const destination = target(record, 3, origin);
    return priority === null || weight === null || port === null || destination === null
      ? null
      : [
          ...heading,
          '    value:',
          `      port: ${port}`,
          `      priority: ${priority}`,
          `      target: ${yaml(destination)}`,
          `      weight: ${weight}`,
        ];
  }
  if (record.type === 'CAA') {
    const [flags, tag, data] = record.rdata.map((token) => token.value);
    return flags === undefined || tag === undefined || data === undefined
      ? null
      : [
          ...heading,
          '    value:',
          `      flags: ${flags}`,
          `      tag: ${yaml(tag)}`,
          `      value: ${yaml(data)}`,
        ];
  }
  return null;
}

function octoRrset(records: readonly (readonly string[])[]): readonly string[] {
  const first = records[0];
  if (first === undefined) return [];
  if (records.length === 1) return first;
  return [
    ...first.slice(0, 2),
    '    values:',
    ...records.flatMap((record) => {
      const scalar = record[2];
      if (scalar !== '    value:')
        return [`      - ${scalar?.slice('    value: '.length) ?? ''}`];
      return record
        .slice(3)
        .map((line, index) => `${index === 0 ? '      - ' : '        '}${line.trimStart()}`);
    }),
  ];
}

export function exportZoneInfrastructure(document: ZoneDocument): ZoneInfrastructureExports {
  const origin = document.origin ?? null;
  if (origin === null)
    return {
      diagnostics: [
        {
          line: 1,
          message: 'A complete absolute zone origin is required for portable exports.',
          severity: 'error',
        },
      ],
      dnsControl: '',
      octoDns: '',
      omittedRecords: document.records.length,
      origin: null,
      supportedRecords: 0,
    };
  const diagnostics: ZoneExportDiagnostic[] = [];
  const erroredLines = new Set(
    document.diagnostics
      .filter((diagnostic) => diagnostic.severity === 'error')
      .map((diagnostic) => diagnostic.line),
  );
  const dnsRecords: string[] = [];
  const octoRecords = new Map<string, Map<string, (readonly string[])[]>>();
  const rrsetTtls = new Map<string, Set<number>>();
  for (const record of document.records) {
    const key = JSON.stringify([
      canonicalMasterName(record.owner, origin)?.absolute,
      record.type,
    ]);
    const values = rrsetTtls.get(key) ?? new Set<number>();
    values.add(ttl(record));
    rrsetTtls.set(key, values);
  }
  let omitted = 0;
  for (const record of document.records) {
    const rrset = JSON.stringify([
      canonicalMasterName(record.owner, origin)?.absolute,
      record.type,
    ]);
    if ((rrsetTtls.get(rrset)?.size ?? 0) > 1) {
      omitted += 1;
      diagnostics.push({
        line: record.line,
        severity: 'error',
        message:
          'This RRset has inconsistent TTLs. The whole RRset is omitted rather than choosing a TTL.',
      });
      continue;
    }
    if (erroredLines.has(record.line)) {
      omitted += 1;
      diagnostics.push({
        line: record.line,
        message: 'This record has a lint error and is omitted from portable exports.',
        severity: 'warning',
      });
      continue;
    }
    const owner = relativeOwner(record, origin);
    if (owner === null) {
      omitted += 1;
      diagnostics.push({
        line: record.line,
        message: 'Out-of-zone records are not exported into this zone.',
        severity: 'warning',
      });
      continue;
    }
    const dnsRecord = dnsControlRecord(record, owner, origin);
    const octoRecordLines = octoRecord(record, origin);
    if (dnsRecord === null || octoRecordLines === null) {
      omitted += 1;
      diagnostics.push({
        line: record.line,
        message: `${record.type} is retained in the source but omitted because both portable exporters cannot represent it without provider-specific assumptions.`,
        severity: 'warning',
      });
      continue;
    }
    dnsRecords.push(`  ${dnsRecord}`);
    const ownerKey = owner === '@' ? '' : owner;
    const types = octoRecords.get(ownerKey) ?? new Map<string, (readonly string[])[]>();
    const group = types.get(record.type) ?? [];
    group.push([...octoRecordLines]);
    types.set(record.type, group);
    octoRecords.set(ownerKey, types);
  }
  const zoneName = origin.replace(/\.$/u, '');
  const dnsControl = [
    `D(${js(zoneName)}, REG_NONE,`,
    '  DnsProvider(DSP_PRIMARY),',
    ...dnsRecords.map((line, index) => `${line}${index === dnsRecords.length - 1 ? '' : ','}`),
    ');',
    '',
  ].join('\n');
  const octoDns = [
    '---',
    ...[...octoRecords.entries()].flatMap(([owner, records]) => [
      `${yaml(owner)}:`,
      ...[...records.values()].flatMap(octoRrset),
    ]),
    '',
  ].join('\n');
  return {
    diagnostics,
    dnsControl,
    octoDns,
    omittedRecords: omitted,
    origin,
    supportedRecords: dnsRecords.length,
  };
}
