export interface CaaInput {
  readonly flags: number;
  readonly tag: string;
  readonly value: string;
}

export interface CaaDiagnostic {
  readonly code: string;
  readonly message: string;
  readonly severity: 'information' | 'warning' | 'error';
}

export interface CaaPolicy {
  readonly diagnostics: readonly CaaDiagnostic[];
  readonly properties: readonly CaaProperty[];
  readonly records: readonly CaaInput[];
}

export interface CaaParameter {
  readonly name: string;
  readonly value: string;
}

export interface CaaProperty {
  readonly issuer?: string;
  readonly parameters: readonly CaaParameter[];
  readonly record: CaaInput;
}

function isIssuerDomain(value: string): boolean {
  if (value.length > 253 || value.endsWith('.')) return false;
  const labels = value.split('.');
  return labels.every(
    (label) =>
      label.length > 0 &&
      label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/iu.test(label),
  );
}

function parseIssuerProperty(record: CaaInput, diagnostics: CaaDiagnostic[]): CaaProperty {
  const segments = record.value.split(';');
  const issuer = segments.shift()?.trim() ?? '';
  const parameters: CaaParameter[] = [];
  const seen = new Set<string>();
  for (const segment of segments) {
    const value = segment.trim();
    if (value === '') continue;
    const equals = value.indexOf('=');
    const name = value.slice(0, equals).trim().toLowerCase();
    const parameterValue = value.slice(equals + 1).trim();
    if (equals < 1 || !/^[a-z0-9-]+$/u.test(name) || parameterValue === '') {
      diagnostics.push({
        code: 'issuer-parameter-invalid',
        message: `${record.tag} contains a malformed issuer parameter: ${value}.`,
        severity: 'error',
      });
      continue;
    }
    if (seen.has(name))
      diagnostics.push({
        code: 'issuer-parameter-duplicate',
        message: `${record.tag} repeats the ${name} issuer parameter.`,
        severity: 'error',
      });
    seen.add(name);
    parameters.push({ name, value: parameterValue });
  }

  if (issuer !== '' && !isIssuerDomain(issuer))
    diagnostics.push({
      code: 'issuer-invalid',
      message: `${record.tag} does not contain a valid issuer-domain-name.`,
      severity: 'error',
    });
  if (issuer === '' && record.value.trim() !== ';')
    diagnostics.push({
      code: 'issuer-empty-ambiguous',
      message: `${record.tag} should use a single semicolon when intentionally prohibiting issuance.`,
      severity: 'warning',
    });

  for (const parameter of parameters) {
    if (parameter.name === 'accounturi') {
      try {
        const uri = new URL(parameter.value);
        if (uri.protocol === '') throw new Error('scheme');
      } catch {
        diagnostics.push({
          code: 'accounturi-invalid',
          message: 'accounturi must contain an absolute account URI.',
          severity: 'error',
        });
      }
    } else if (parameter.name === 'validationmethods') {
      const methods = parameter.value.split(',');
      if (
        methods.length === 0 ||
        methods.some((method) => !/^[a-z0-9-]+$/iu.test(method.trim()))
      )
        diagnostics.push({
          code: 'validationmethods-invalid',
          message:
            'validationmethods must be a comma-separated list of validation method labels.',
          severity: 'error',
        });
    } else if (
      record.tag.toLowerCase() === 'issue' ||
      record.tag.toLowerCase() === 'issuewild'
    ) {
      diagnostics.push({
        code: 'issuer-parameter-unknown',
        message: `The ${parameter.name} issuer parameter is CA-defined; confirm that the named CA supports it.`,
        severity: 'information',
      });
    }
  }
  return {
    ...(issuer === '' ? {} : { issuer }),
    parameters,
    record,
  };
}

export function parseCaaPolicy(records: readonly CaaInput[]): CaaPolicy {
  const diagnostics: CaaDiagnostic[] = [];
  const properties: CaaProperty[] = [];
  for (const record of records) {
    const tag = record.tag.toLowerCase();
    if (!Number.isInteger(record.flags) || record.flags < 0 || record.flags > 255)
      diagnostics.push({
        code: 'flags-invalid',
        message: 'CAA flags must be an integer from 0 through 255.',
        severity: 'error',
      });
    if ((record.flags & 0x7f) !== 0)
      diagnostics.push({
        code: 'flags-reserved',
        message: `CAA flags ${String(record.flags)} set reserved bits.`,
        severity: 'warning',
      });
    if (!/^[a-z0-9]{1,15}$/u.test(tag))
      diagnostics.push({
        code: 'tag-invalid',
        message: `CAA tag ${record.tag} is malformed.`,
        severity: 'error',
      });
    if (!['issue', 'issuewild', 'issuemail', 'iodef'].includes(tag))
      diagnostics.push({
        code: 'tag-unknown',
        message: `Unknown CAA tag ${record.tag}${(record.flags & 0x80) !== 0 ? ' is marked critical' : ''}.`,
        severity: (record.flags & 0x80) !== 0 ? 'error' : 'information',
      });
    if (tag === 'issue' || tag === 'issuewild' || tag === 'issuemail')
      properties.push(parseIssuerProperty(record, diagnostics));
    else properties.push({ parameters: [], record });
    if (tag === 'iodef') {
      try {
        const uri = new URL(record.value);
        if (!['mailto:', 'https:', 'http:'].includes(uri.protocol)) throw new Error('scheme');
        if (uri.protocol === 'http:')
          diagnostics.push({
            code: 'iodef-insecure',
            message: 'An HTTP iodef endpoint is valid but exposes incident reports in transit.',
            severity: 'warning',
          });
      } catch {
        diagnostics.push({
          code: 'iodef-invalid',
          message: 'iodef should contain an HTTP, HTTPS, or mailto URI.',
          severity: 'warning',
        });
      }
    }
  }
  if (!records.some((record) => record.tag.toLowerCase() === 'issue'))
    diagnostics.push({
      code: 'issue-absent',
      message:
        'No issue property is present; certificate issuance is not explicitly constrained here.',
      severity: 'information',
    });
  if (!records.some((record) => record.tag.toLowerCase() === 'issuemail'))
    diagnostics.push({
      code: 'issuemail-absent',
      message:
        'No issuemail property is present; this RRset does not constrain S/MIME issuance.',
      severity: 'information',
    });
  return { diagnostics, properties, records };
}

export function caaParentNames(domain: string, maximumDepth = 20): readonly string[] {
  const labels = domain.toLowerCase().replace(/\.$/u, '').split('.').filter(Boolean);
  return Array.from({ length: Math.min(labels.length, maximumDepth) }, (_, index) =>
    labels.slice(index).join('.'),
  );
}

export function buildCaaRecord(
  owner: string,
  issuer: string,
  options: {
    readonly accountUri?: string;
    readonly critical: boolean;
    readonly tag: 'issue' | 'issuewild' | 'issuemail';
    readonly validationMethods?: readonly string[];
  },
): string {
  const flags = options.critical ? 128 : 0;
  const parameters = [
    ...(options.accountUri?.trim() ? [`accounturi=${options.accountUri.trim()}`] : []),
    ...(options.validationMethods !== undefined && options.validationMethods.length > 0
      ? [`validationmethods=${options.validationMethods.join(',')}`]
      : []),
  ];
  const value =
    issuer.trim() === '' && parameters.length === 0
      ? ';'
      : [issuer.trim(), ...parameters].join('; ');
  const escaped = value.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
  return `${owner} IN CAA ${String(flags)} ${options.tag} "${escaped}"`;
}
