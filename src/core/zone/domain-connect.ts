import { parseStrictIpAddress } from '../dns/ip';
import { validateDnsName } from '../dns/names';
import { lintZoneSnippet } from './lint';
import { canonicalMasterName } from './master-name';

const MAX_TEMPLATE_CHARACTERS = 262_144;
const MAX_RECORDS = 512;
const MAX_VARIABLES = 64;
const MAX_VALUE_CHARACTERS = 4_096;

export interface DomainConnectDiagnostic {
  readonly message: string;
  readonly path: string;
  readonly severity: 'error' | 'warning' | 'information';
}

export interface DomainConnectRecordPreview {
  readonly essential: boolean;
  readonly index: number;
  readonly line: string | null;
  readonly type: string;
}

export interface DomainConnectPreview {
  readonly diagnostics: readonly DomainConnectDiagnostic[];
  readonly providerId: string;
  readonly records: readonly DomainConnectRecordPreview[];
  readonly serviceId: string;
  readonly source: string;
  readonly status: 'ready' | 'invalid' | 'partial';
  readonly unresolvedVariables: readonly string[];
}

function object(value: unknown): Readonly<Record<string, unknown>> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Readonly<Record<string, unknown>>)
    : null;
}

function stringField(
  value: unknown,
  path: string,
  diagnostics: DomainConnectDiagnostic[],
  required = true,
): string {
  if (typeof value === 'string' && value.length <= MAX_VALUE_CHARACTERS) return value;
  if (required)
    diagnostics.push({ message: 'Expected a bounded string.', path, severity: 'error' });
  return '';
}

function variableMap(value: unknown): Readonly<Record<string, string>> {
  const candidate = object(value);
  if (candidate === null || Object.keys(candidate).length > MAX_VARIABLES)
    throw new Error(
      `Variables must be an object with no more than ${String(MAX_VARIABLES)} entries.`,
    );
  const output = Object.create(null) as Record<string, string>;
  for (const [name, entry] of Object.entries(candidate)) {
    if (!/^[A-Za-z0-9._-]{1,64}$/u.test(name))
      throw new Error(`Variable name ${name} is invalid.`);
    if (typeof entry !== 'string' && typeof entry !== 'number' && typeof entry !== 'boolean')
      throw new Error(`Variable ${name} must be a string, number, or boolean.`);
    const rendered = String(entry);
    if (rendered.length > MAX_VALUE_CHARACTERS)
      throw new Error(`Variable ${name} exceeds the value safety limit.`);
    output[name] = rendered;
  }
  return output;
}

function replaceVariables(
  value: string,
  variables: Readonly<Record<string, string>>,
  unresolved: Set<string>,
): string {
  return value.replaceAll(/%([^%]{1,64})%/gu, (match, name: string) => {
    const replacement = Object.hasOwn(variables, name) ? variables[name] : undefined;
    if (replacement === undefined) {
      unresolved.add(name);
      return match;
    }
    return replacement;
  });
}

function numberField(
  value: unknown,
  path: string,
  variables: Readonly<Record<string, string>>,
  unresolved: Set<string>,
  diagnostics: DomainConnectDiagnostic[],
  maximum: number,
): number | null {
  const rendered = replaceVariables(
    typeof value === 'number' ? String(value) : typeof value === 'string' ? value : '',
    variables,
    unresolved,
  );
  if (/^\d+$/u.test(rendered) && Number(rendered) <= maximum) return Number(rendered);
  diagnostics.push({
    message: `Expected a whole number from 0 to ${String(maximum)} after substitution.`,
    path,
    severity: 'error',
  });
  return null;
}

function owner(value: string, domain: string): string | null {
  if (value === '' || value === '@') return '@';
  const absolute = canonicalMasterName(value, domain)?.absolute ?? null;
  if (absolute === null) return null;
  if (absolute === domain) return '@';
  return absolute.endsWith(`.${domain}`) ? absolute.slice(0, -(domain.length + 1)) : null;
}

function target(value: string, domain: string): string | null {
  if (value === '@') return domain;
  return canonicalMasterName(value, '.')?.absolute ?? null;
}

function quoted(value: string): string {
  let output = '';
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (character === '\\' || character === '"') output += `\\${character}`;
    else if (codePoint < 32 || codePoint === 127)
      output += `\\${codePoint.toString(10).padStart(3, '0')}`;
    else output += character;
  }
  return `"${output}"`;
}

function booleanEssential(value: unknown): boolean {
  return value === true || value === 'true' || value === '1';
}

function containsControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint !== undefined && (codePoint <= 31 || codePoint === 127)) return true;
  }
  return false;
}

export function previewDomainConnectTemplate(
  templateSource: string,
  domainInput: string,
  variableInput: unknown,
): DomainConnectPreview {
  const diagnostics: DomainConnectDiagnostic[] = [];
  if (templateSource.length === 0 || templateSource.length > MAX_TEMPLATE_CHARACTERS)
    throw new Error('The template is empty or exceeds the local safety limit.');
  let parsed: unknown;
  try {
    parsed = JSON.parse(templateSource);
  } catch (cause) {
    throw new Error('The template is not valid JSON.', { cause });
  }
  const root = object(parsed);
  if (root === null) throw new Error('The template root must be a JSON object.');
  const providerId = stringField(root['providerId'], 'providerId', diagnostics);
  stringField(root['providerName'], 'providerName', diagnostics);
  const serviceId = stringField(root['serviceId'], 'serviceId', diagnostics);
  stringField(root['serviceName'], 'serviceName', diagnostics);
  const rawRecords = root['records'];
  if (!Array.isArray(rawRecords) || rawRecords.length > MAX_RECORDS) {
    diagnostics.push({
      message: `Expected an array containing no more than ${String(MAX_RECORDS)} records.`,
      path: 'records',
      severity: 'error',
    });
  }
  const validatedDomain = validateDnsName(domainInput);
  const domain = validatedDomain.ok ? validatedDomain.value.absolute : '';
  if (domain === '')
    diagnostics.push({
      message: 'Supply a valid template domain.',
      path: 'domain',
      severity: 'error',
    });
  const suppliedVariables = variableMap(variableInput);
  const variables: Readonly<Record<string, string>> = {
    ...suppliedVariables,
    domain,
    fqdn: domain,
  };
  const unresolved = new Set<string>();
  const records: DomainConnectRecordPreview[] = [];

  const recordsToProcess =
    Array.isArray(rawRecords) && rawRecords.length <= MAX_RECORDS ? rawRecords : [];
  for (const [index, raw] of recordsToProcess.entries()) {
    const path = `records[${String(index)}]`;
    const record = object(raw);
    if (record === null) {
      diagnostics.push({ message: 'Record must be an object.', path, severity: 'error' });
      continue;
    }
    const rawType = stringField(record['type'], `${path}.type`, diagnostics).toUpperCase();
    const essential = booleanEssential(record['essential']);
    if (['REDIR301', 'REDIR302', 'APEXCNAME'].includes(rawType)) {
      diagnostics.push({
        message: `${rawType} is a provider action rather than a portable DNS resource record; it is retained as an explicit non-exportable step.`,
        path,
        severity: essential ? 'warning' : 'information',
      });
      records.push({ essential, index, line: null, type: rawType });
      continue;
    }
    const rawHost = rawType === 'SRV' ? record['name'] : record['host'];
    const hostText = replaceVariables(
      stringField(rawHost, `${path}.${rawType === 'SRV' ? 'name' : 'host'}`, diagnostics),
      variables,
      unresolved,
    );
    let ownerText = owner(hostText, domain);
    if (rawType === 'SRV') {
      const service = replaceVariables(
        stringField(record['service'], `${path}.service`, diagnostics),
        variables,
        unresolved,
      ).replace(/^_/u, '');
      const protocol = replaceVariables(
        stringField(record['protocol'], `${path}.protocol`, diagnostics),
        variables,
        unresolved,
      ).replace(/^_/u, '');
      if (
        !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u.test(service) ||
        !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u.test(protocol)
      )
        diagnostics.push({
          message: 'SRV service and protocol must each be one valid DNS label.',
          path,
          severity: 'error',
        });
      const suffix = ownerText === '@' ? '' : `.${ownerText ?? ''}`;
      ownerText =
        service === '' || protocol === '' ? null : `_${service}._${protocol}${suffix}`;
    }
    if (ownerText === null)
      diagnostics.push({
        message: 'Host is not a valid DNS owner after substitution.',
        path,
        severity: 'error',
      });

    let line: string | null = null;
    if (['A', 'AAAA'].includes(rawType)) {
      const value = replaceVariables(
        stringField(record['pointsTo'], `${path}.pointsTo`, diagnostics),
        variables,
        unresolved,
      );
      const expected = rawType === 'A' ? 'ipv4' : 'ipv6';
      if (parseStrictIpAddress(value)?.kind() !== expected)
        diagnostics.push({
          message: `${rawType} pointsTo is invalid after substitution.`,
          path,
          severity: 'error',
        });
      const ttl = numberField(
        record['ttl'],
        `${path}.ttl`,
        variables,
        unresolved,
        diagnostics,
        2_147_483_647,
      );
      if (ownerText !== null && ttl !== null)
        line = `${ownerText} ${String(ttl)} IN ${rawType} ${value}`;
    } else if (['CNAME', 'NS'].includes(rawType)) {
      const value = target(
        replaceVariables(
          stringField(record['pointsTo'], `${path}.pointsTo`, diagnostics),
          variables,
          unresolved,
        ),
        domain,
      );
      const ttl = numberField(
        record['ttl'],
        `${path}.ttl`,
        variables,
        unresolved,
        diagnostics,
        2_147_483_647,
      );
      if (value === null)
        diagnostics.push({
          message: `${rawType} target is invalid after substitution.`,
          path,
          severity: 'error',
        });
      if (ownerText !== null && value !== null && ttl !== null)
        line = `${ownerText} ${String(ttl)} IN ${rawType} ${value}`;
    } else if (rawType === 'TXT' || rawType === 'SPFM') {
      const key = rawType === 'TXT' ? 'data' : 'spfRules';
      let value = replaceVariables(
        stringField(record[key], `${path}.${key}`, diagnostics),
        variables,
        unresolved,
      );
      if (rawType === 'SPFM' && !/^v=spf1(?:\s|$)/iu.test(value)) value = `v=spf1 ${value}`;
      const ttl =
        rawType === 'SPFM'
          ? 3600
          : numberField(
              record['ttl'],
              `${path}.ttl`,
              variables,
              unresolved,
              diagnostics,
              2_147_483_647,
            );
      if (ownerText !== null && ttl !== null)
        line = `${ownerText} ${String(ttl)} IN TXT ${quoted(value)}`;
    } else if (rawType === 'MX') {
      const value = target(
        replaceVariables(
          stringField(record['pointsTo'], `${path}.pointsTo`, diagnostics),
          variables,
          unresolved,
        ),
        domain,
      );
      const ttl = numberField(
        record['ttl'],
        `${path}.ttl`,
        variables,
        unresolved,
        diagnostics,
        2_147_483_647,
      );
      const priority = numberField(
        record['priority'],
        `${path}.priority`,
        variables,
        unresolved,
        diagnostics,
        65_535,
      );
      if (value === null)
        diagnostics.push({
          message: 'MX target is invalid after substitution.',
          path,
          severity: 'error',
        });
      if (ownerText !== null && value !== null && ttl !== null && priority !== null)
        line = `${ownerText} ${String(ttl)} IN MX ${String(priority)} ${value}`;
    } else if (rawType === 'SRV') {
      const value = target(
        replaceVariables(
          stringField(record['target'], `${path}.target`, diagnostics),
          variables,
          unresolved,
        ),
        domain,
      );
      const ttl = numberField(
        record['ttl'],
        `${path}.ttl`,
        variables,
        unresolved,
        diagnostics,
        2_147_483_647,
      );
      const priority = numberField(
        record['priority'],
        `${path}.priority`,
        variables,
        unresolved,
        diagnostics,
        65_535,
      );
      const weight = numberField(
        record['weight'],
        `${path}.weight`,
        variables,
        unresolved,
        diagnostics,
        65_535,
      );
      const port = numberField(
        record['port'],
        `${path}.port`,
        variables,
        unresolved,
        diagnostics,
        65_535,
      );
      if (value === null)
        diagnostics.push({
          message: 'SRV target is invalid after substitution.',
          path,
          severity: 'error',
        });
      if (
        ownerText !== null &&
        value !== null &&
        ttl !== null &&
        priority !== null &&
        weight !== null &&
        port !== null
      )
        line = `${ownerText} ${String(ttl)} IN SRV ${String(priority)} ${String(weight)} ${String(port)} ${value}`;
    } else if (/^[A-Z][A-Z0-9-]{0,15}$/u.test(rawType)) {
      const data = replaceVariables(
        stringField(record['data'], `${path}.data`, diagnostics),
        variables,
        unresolved,
      );
      const typeCode = /^TYPE([1-9]\d{0,4})$/u.exec(rawType)?.[1];
      if (typeCode !== undefined && Number(typeCode) > 65_534)
        diagnostics.push({
          message: 'Generic record type numbers must be between 1 and 65534.',
          path,
          severity: 'error',
        });
      if (containsControlCharacter(data))
        diagnostics.push({
          message: 'Generic record data cannot contain line or control characters.',
          path,
          severity: 'error',
        });
      const ttl = numberField(
        record['ttl'],
        `${path}.ttl`,
        variables,
        unresolved,
        diagnostics,
        2_147_483_647,
      );
      if (ownerText !== null && ttl !== null)
        line = `${ownerText} ${String(ttl)} IN ${rawType} ${data}`;
    } else {
      diagnostics.push({
        message: `Record type ${rawType || '(empty)'} is unsupported.`,
        path,
        severity: 'error',
      });
    }
    records.push({ essential, index, line, type: rawType });
  }

  for (const name of unresolved)
    diagnostics.push({
      message: `No value was supplied for %${name}%.`,
      path: 'variables',
      severity: 'error',
    });
  const candidateSource =
    domain === ''
      ? records.flatMap((record) => record.line ?? []).join('\n')
      : [`$ORIGIN ${domain}`, ...records.flatMap((record) => record.line ?? [])].join('\n');
  if (candidateSource !== '') {
    const linted = lintZoneSnippet(candidateSource);
    for (const item of linted.diagnostics) {
      if (item.severity === 'information') continue;
      diagnostics.push({
        message: `Generated line ${String(item.line)}: ${item.message}`,
        path: 'records',
        severity: item.severity === 'error' ? 'error' : 'warning',
      });
    }
    if (linted.incomplete !== undefined)
      diagnostics.push({
        message: linted.incomplete.message,
        path: 'records',
        severity: 'error',
      });
  }
  const hasErrors = diagnostics.some((item) => item.severity === 'error');
  const hasWarnings = diagnostics.some((item) => item.severity === 'warning');
  const hasNonDns = records.some((record) => record.line === null);
  return {
    diagnostics,
    providerId,
    records,
    serviceId,
    source: hasErrors ? '' : candidateSource,
    status: hasErrors ? 'invalid' : hasNonDns || hasWarnings ? 'partial' : 'ready',
    unresolvedVariables: [...unresolved].sort(),
  };
}
