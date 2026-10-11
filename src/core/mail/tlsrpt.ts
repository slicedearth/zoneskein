const MAX_JSON_CHARACTERS = 5 * 1024 * 1024;
const MAX_POLICIES = 10_000;
const MAX_FAILURES = 50_000;

export interface TlsReportFailure {
  readonly count: number;
  readonly receivingIp: string;
  readonly resultType: string;
  readonly sendingIp: string;
}

export interface TlsReportPolicy {
  readonly domain: string;
  readonly failed: number;
  readonly failures: readonly TlsReportFailure[];
  readonly policyType: string;
  readonly successful: number;
}

export interface TlsAggregateReport {
  readonly organisation: string;
  readonly policies: readonly TlsReportPolicy[];
  readonly reportId: string;
  readonly summary: { readonly failed: number; readonly successful: number };
}

function object(value: unknown): Readonly<Record<string, unknown>> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Readonly<Record<string, unknown>>)
    : null;
}

function string(value: unknown, maximum = 4_096): string {
  return typeof value === 'string' && value.length <= maximum ? value : '';
}

function count(value: unknown): number | null {
  return typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= 0xffff_ffff
    ? value
    : null;
}

export function parseTlsAggregateJson(source: string): TlsAggregateReport {
  if (source.length === 0 || source.length > MAX_JSON_CHARACTERS)
    throw new Error('The TLS report is empty or exceeds the local safety limit.');
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch (cause) {
    throw new Error('The TLS report is not valid JSON.', { cause });
  }
  const root = object(parsed);
  const rawPolicies = root?.['policies'];
  if (root === null || !Array.isArray(rawPolicies) || rawPolicies.length > MAX_POLICIES)
    throw new Error('The TLS report has an invalid or oversized policies collection.');
  let failuresSeen = 0;
  const policies: TlsReportPolicy[] = rawPolicies.map((value, index) => {
    const item = object(value);
    const policy = object(item?.['policy']);
    const summary = object(item?.['summary']);
    const rawFailures = item?.['failure-details'] ?? [];
    if (item === null || policy === null || summary === null || !Array.isArray(rawFailures))
      throw new Error(`TLS report policy ${String(index + 1)} is malformed.`);
    failuresSeen += rawFailures.length;
    if (failuresSeen > MAX_FAILURES)
      throw new Error('The TLS report exceeds the failure-detail safety limit.');
    const successful = count(summary['total-successful-session-count']);
    const failed = count(summary['total-failure-session-count']);
    if (successful === null || failed === null)
      throw new Error(`TLS report policy ${String(index + 1)} has invalid session totals.`);
    const domains = policy['policy-domain'];
    const policyStrings = policy['policy-string'];
    const failures: TlsReportFailure[] = rawFailures.map((failure) => {
      const detail = object(failure);
      const failedCount = count(detail?.['failed-session-count']);
      if (detail === null || failedCount === null)
        throw new Error('A TLS report failure detail is malformed.');
      return {
        count: failedCount,
        receivingIp: string(detail['receiving-ip']),
        resultType: string(detail['result-type']),
        sendingIp: string(detail['sending-mta-ip']),
      };
    });
    return {
      domain: string(domains),
      failed,
      failures,
      policyType:
        string(policy['policy-type']) || (Array.isArray(policyStrings) ? 'policy' : 'unknown'),
      successful,
    };
  });
  return {
    organisation: string(root['organization-name'] ?? root['organisation-name']),
    policies,
    reportId: string(root['report-id']),
    summary: policies.reduce(
      (sum, policy) => ({
        failed: sum.failed + policy.failed,
        successful: sum.successful + policy.successful,
      }),
      { failed: 0, successful: 0 },
    ),
  };
}

export interface TlsRptRecord {
  readonly diagnostics: readonly string[];
  readonly record: string;
  readonly rua: readonly string[];
  readonly valid: boolean;
}

export function parseTlsRptRecord(value: string): TlsRptRecord {
  const diagnostics: string[] = [];
  if (value.length === 0 || value.length > 65_536)
    return {
      diagnostics: ['The TLS-RPT record is empty or exceeds 65,536 characters.'],
      record: value,
      rua: [],
      valid: false,
    };
  const tags = new Map<string, string>();
  let firstTag = '';
  for (const segment of value
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)) {
    const equals = segment.indexOf('=');
    if (equals < 1) {
      diagnostics.push(`Malformed segment: ${segment}.`);
      continue;
    }
    const name = segment.slice(0, equals).toLowerCase();
    firstTag ||= name;
    if (tags.has(name)) diagnostics.push(`Tag ${name} is repeated.`);
    else tags.set(name, segment.slice(equals + 1).trim());
  }
  if (firstTag !== 'v' || tags.get('v') !== 'TLSRPTv1')
    diagnostics.push('v=TLSRPTv1 must be the first tag.');
  for (const tag of tags.keys())
    if (tag !== 'v' && tag !== 'rua') diagnostics.push(`Unknown TLS-RPT tag ${tag}.`);
  const rua = (tags.get('rua') ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  if (rua.length === 0 || rua.length > 10)
    diagnostics.push('rua must contain between one and ten report destinations.');
  for (const uri of rua) {
    if (/^mailto:[^\s@]+@[^\s@]+$/iu.test(uri)) continue;
    try {
      const url = new URL(uri);
      if (
        url.protocol !== 'https:' ||
        url.hostname === '' ||
        url.username !== '' ||
        url.password !== ''
      )
        throw new Error();
    } catch {
      diagnostics.push(`Report destination ${uri} is not a supported mailto or HTTPS URI.`);
    }
  }
  return { diagnostics, record: value, rua, valid: diagnostics.length === 0 };
}
