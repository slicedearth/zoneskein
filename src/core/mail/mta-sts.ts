export interface MtaStsPolicy {
  readonly diagnostics: readonly string[];
  readonly maxAge: number | null;
  readonly mode: 'enforce' | 'testing' | 'none' | null;
  readonly mx: readonly string[];
  readonly valid: boolean;
  readonly version: 'STSv1' | null;
}

function matchesMx(host: string, pattern: string): boolean {
  const value = host.toLowerCase().replace(/\.$/u, '');
  const expected = pattern.toLowerCase().replace(/\.$/u, '');
  return expected.startsWith('*.')
    ? value.endsWith(expected.slice(1)) && value !== expected.slice(2)
    : value === expected;
}

export function parseMtaStsPolicy(source: string): MtaStsPolicy {
  const diagnostics: string[] = [];
  if (source.length === 0 || source.length > 65_536)
    return {
      diagnostics: ['The policy is empty or exceeds 65,536 characters.'],
      maxAge: null,
      mode: null,
      mx: [],
      valid: false,
      version: null,
    };
  const fields = new Map<string, string[]>();
  for (const [index, raw] of source.replaceAll('\r\n', '\n').split('\n').entries()) {
    const line = raw.trim();
    if (line === '') continue;
    const separator = line.indexOf(':');
    if (separator < 1) {
      diagnostics.push(`Line ${String(index + 1)} is not a key: value field.`);
      continue;
    }
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    const list = fields.get(name) ?? [];
    list.push(value);
    fields.set(name, list);
  }
  const versionValue = fields.get('version');
  const modeValue = fields.get('mode');
  const ageValue = fields.get('max_age');
  const mx = fields.get('mx') ?? [];
  if (versionValue?.length !== 1 || versionValue[0] !== 'STSv1')
    diagnostics.push('version must appear exactly once with value STSv1.');
  const mode =
    modeValue?.length === 1 && ['enforce', 'testing', 'none'].includes(modeValue[0] ?? '')
      ? (modeValue[0] as 'enforce' | 'testing' | 'none')
      : null;
  if (mode === null)
    diagnostics.push('mode must appear exactly once as enforce, testing, or none.');
  const maxAge =
    ageValue?.length === 1 &&
    /^\d{1,10}$/u.test(ageValue[0] ?? '') &&
    Number(ageValue[0]) <= 31_557_600
      ? Number(ageValue[0])
      : null;
  if (maxAge === null)
    diagnostics.push('max_age must be a whole number no greater than 31,557,600 seconds.');
  if (mode !== 'none' && mx.length === 0)
    diagnostics.push('At least one mx pattern is required unless mode is none.');
  for (const pattern of mx)
    if (
      !/^(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/u.test(pattern) ||
      pattern.includes('..')
    )
      diagnostics.push(`MX pattern ${pattern} is invalid.`);
  for (const name of fields.keys())
    if (!['version', 'mode', 'mx', 'max_age'].includes(name))
      diagnostics.push(`Unknown policy field ${name}.`);
  return {
    diagnostics,
    maxAge,
    mode,
    mx,
    valid: diagnostics.length === 0,
    version: versionValue?.[0] === 'STSv1' ? 'STSv1' : null,
  };
}

export function mtaStsMxCoverage(
  policy: MtaStsPolicy,
  mxHosts: readonly string[],
): readonly { readonly covered: boolean; readonly host: string }[] {
  return mxHosts.map((host) => ({
    covered: policy.mx.some((pattern) => matchesMx(host, pattern)),
    host,
  }));
}

export function authorMtaStsPolicy(
  mode: 'enforce' | 'testing' | 'none',
  maxAge: number,
  mx: readonly string[],
): string {
  return [
    'version: STSv1',
    `mode: ${mode}`,
    ...mx.map((value) => `mx: ${value}`),
    `max_age: ${String(maxAge)}`,
    '',
  ].join('\n');
}
