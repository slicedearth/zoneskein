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
  readonly records: readonly CaaInput[];
}

export function parseCaaPolicy(records: readonly CaaInput[]): CaaPolicy {
  const diagnostics: CaaDiagnostic[] = [];
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
    if (!/^[a-z0-9]+$/u.test(tag))
      diagnostics.push({
        code: 'tag-invalid',
        message: `CAA tag ${record.tag} is malformed.`,
        severity: 'error',
      });
    if (!['issue', 'issuewild', 'iodef'].includes(tag))
      diagnostics.push({
        code: 'tag-unknown',
        message: `Unknown CAA tag ${record.tag}${(record.flags & 0x80) !== 0 ? ' is marked critical' : ''}.`,
        severity: (record.flags & 0x80) !== 0 ? 'error' : 'information',
      });
    if ((tag === 'issue' || tag === 'issuewild') && record.value.trim() !== ';') {
      const issuer = record.value.split(';')[0]?.trim() ?? '';
      if (issuer === '' || /\s/u.test(issuer))
        diagnostics.push({
          code: 'issuer-invalid',
          message: `${record.tag} does not contain a valid issuer-domain-name.`,
          severity: 'error',
        });
    }
    if (tag === 'iodef') {
      try {
        const uri = new URL(record.value);
        if (uri.protocol !== 'mailto:' && uri.protocol !== 'https:') throw new Error('scheme');
      } catch {
        diagnostics.push({
          code: 'iodef-invalid',
          message: 'iodef should contain an HTTPS or mailto URI.',
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
  return { diagnostics, records };
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
  options: { readonly critical: boolean; readonly tag: 'issue' | 'issuewild' },
): string {
  const flags = options.critical ? 128 : 0;
  const escaped = issuer.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
  return `${owner} IN CAA ${String(flags)} ${options.tag} "${escaped}"`;
}
