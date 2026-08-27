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

function dnsControlRecord(record: ZoneRecord, owner: string): string | null {
  const modifier = `TTL(${String(ttl(record))})`;
  if (record.type === 'A' || record.type === 'AAAA') {
    const address = value(record, 0);
    return address === null
      ? null
      : `${record.type}(${js(owner)}, ${js(address)}, ${modifier})`;
  }
  if (['CNAME', 'NS', 'PTR'].includes(record.type)) {
    const target = value(record, 0);
    return target === null ? null : `${record.type}(${js(owner)}, ${js(target)}, ${modifier})`;
  }
  if (record.type === 'TXT') {
    const text = record.rdata.map((token) => token.value).join('');
    return `TXT(${js(owner)}, ${js(text)}, ${modifier})`;
  }
  if (record.type === 'MX') {
    const preference = integer(value(record, 0), 65_535);
    const exchange = value(record, 1);
    return preference === null || exchange === null
      ? null
      : `MX(${js(owner)}, ${preference}, ${js(exchange)}, ${modifier})`;
  }
  if (record.type === 'SRV') {
    const priority = integer(value(record, 0), 65_535);
    const weight = integer(value(record, 1), 65_535);
    const port = integer(value(record, 2), 65_535);
    const target = value(record, 3);
    return priority === null || weight === null || port === null || target === null
      ? null
      : `SRV(${js(owner)}, ${priority}, ${weight}, ${port}, ${js(target)}, ${modifier})`;
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

function octoRecord(record: ZoneRecord): readonly string[] | null {
  const heading = [`  - ttl: ${String(ttl(record))}`, `    type: ${record.type}`];
  if (['A', 'AAAA', 'CNAME', 'NS', 'PTR'].includes(record.type)) {
    const data = value(record, 0);
    return data === null ? null : [...heading, `    value: ${yaml(data)}`];
  }
  if (record.type === 'TXT')
    return [
      ...heading,
      `    value: ${yaml(record.rdata.map((token) => token.value).join(''))}`,
    ];
  if (record.type === 'MX') {
    const preference = integer(value(record, 0), 65_535);
    const exchange = value(record, 1);
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
    const target = value(record, 3);
    return priority === null || weight === null || port === null || target === null
      ? null
      : [
          ...heading,
          '    value:',
          `      port: ${port}`,
          `      priority: ${priority}`,
          `      target: ${yaml(target)}`,
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
  const octoRecords = new Map<string, string[][]>();
  let omitted = 0;
  for (const record of document.records) {
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
    const dnsRecord = dnsControlRecord(record, owner);
    const octoRecordLines = octoRecord(record);
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
    const group = octoRecords.get(owner === '@' ? '' : owner) ?? [];
    group.push([...octoRecordLines]);
    octoRecords.set(owner === '@' ? '' : owner, group);
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
      ...records.flat(),
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
