import type { DkimSignatureVerification } from '../dkim/types';
import type { DmarcSpfResult } from '../dmarc/alignment';
import { validateDnsName } from '../dns/names';
import type { ResolverId } from '../dns/types';
import type { SpfSenderEvaluation } from '../spf/sender-evaluator';

export const MAIL_AUTHENTICATION_EVIDENCE_SCHEMA =
  'zoneskein-mail-authentication-transfer-v1' as const;

export const MAIL_AUTHENTICATION_EVIDENCE_LIMITS = Object.freeze({
  dkimDomains: 20,
  jsonDepth: 8,
  jsonOctets: 16_384,
});

const RESOLVER_IDS = new Set<ResolverId>(['cloudflare', 'google', 'quad9', 'quad9-relay']);
const SPF_RESULTS = new Set<DmarcSpfResult>([
  'none',
  'neutral',
  'pass',
  'fail',
  'softfail',
  'temperror',
  'permerror',
]);
const encoder = new TextEncoder();

export interface DkimAuthenticationEvidence {
  readonly capturedAt: string;
  readonly domain: string;
  readonly reconstructed: boolean;
  readonly resolverId: ResolverId;
  readonly source: 'dkim-message';
}

export interface SpfAuthenticationEvidence {
  readonly capturedAt: string;
  readonly domain: string;
  readonly resolverId: ResolverId;
  readonly result: DmarcSpfResult;
  readonly source: 'spf-sender';
}

export interface MailAuthenticationEvidence {
  readonly createdAt: string;
  readonly dkim: readonly DkimAuthenticationEvidence[];
  readonly evidenceSchema: typeof MAIL_AUTHENTICATION_EVIDENCE_SCHEMA;
  readonly spf?: SpfAuthenticationEvidence;
}

export type MailAuthenticationEvidenceResult =
  | { readonly ok: true; readonly value: MailAuthenticationEvidence }
  | { readonly error: string; readonly ok: false };

function failure(error: string): MailAuthenticationEvidenceResult {
  return { error, ok: false };
}

function isoTimestamp(value: unknown): string | null {
  if (typeof value !== 'string' || value.length !== 24) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value ? value : null;
}

function canonicalDomain(value: unknown): string | null {
  if (typeof value !== 'string' || value !== value.trim() || value.includes('://')) return null;
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

function objectWithKeys(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): Readonly<Record<string, unknown>> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const record = value as Readonly<Record<string, unknown>>;
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(record);
  return required.every((key) => Object.hasOwn(record, key)) &&
    keys.every((key) => allowed.has(key))
    ? record
    : null;
}

function resolverId(value: unknown): ResolverId | null {
  return typeof value === 'string' && RESOLVER_IDS.has(value as ResolverId)
    ? (value as ResolverId)
    : null;
}

function freezeEvidence(
  createdAt: string,
  dkim: readonly DkimAuthenticationEvidence[],
  spf?: SpfAuthenticationEvidence,
): MailAuthenticationEvidence {
  const frozenDkim = Object.freeze(dkim.map((entry) => Object.freeze({ ...entry })));
  return Object.freeze({
    createdAt,
    dkim: frozenDkim,
    evidenceSchema: MAIL_AUTHENTICATION_EVIDENCE_SCHEMA,
    ...(spf === undefined ? {} : { spf: Object.freeze({ ...spf }) }),
  });
}

export function parseMailAuthenticationEvidence(
  value: unknown,
): MailAuthenticationEvidenceResult {
  const envelope = objectWithKeys(value, ['createdAt', 'dkim', 'evidenceSchema'], ['spf']);
  if (envelope === null)
    return failure('Mail-authentication evidence has an unexpected outer shape.');
  if (envelope['evidenceSchema'] !== MAIL_AUTHENTICATION_EVIDENCE_SCHEMA)
    return failure(`Evidence schema must be ${MAIL_AUTHENTICATION_EVIDENCE_SCHEMA}.`);
  const createdAt = isoTimestamp(envelope['createdAt']);
  if (createdAt === null)
    return failure('Evidence createdAt must be a canonical UTC timestamp.');
  const dkimInput = envelope['dkim'];
  if (!Array.isArray(dkimInput)) return failure('Evidence dkim must be an array.');
  if (dkimInput.length > MAIL_AUTHENTICATION_EVIDENCE_LIMITS.dkimDomains)
    return failure(
      `Evidence contains more than ${String(MAIL_AUTHENTICATION_EVIDENCE_LIMITS.dkimDomains)} DKIM domains.`,
    );

  const dkim: DkimAuthenticationEvidence[] = [];
  const domains = new Set<string>();
  let latestCapture = 0;
  for (const input of dkimInput) {
    const entry = objectWithKeys(input, [
      'capturedAt',
      'domain',
      'reconstructed',
      'resolverId',
      'source',
    ]);
    if (entry?.['source'] !== 'dkim-message')
      return failure('A DKIM evidence entry has an unexpected shape or source.');
    const capturedAt = isoTimestamp(entry['capturedAt']);
    const domain = canonicalDomain(entry['domain']);
    const resolver = resolverId(entry['resolverId']);
    if (
      capturedAt === null ||
      domain === null ||
      resolver === null ||
      typeof entry['reconstructed'] !== 'boolean'
    )
      return failure('A DKIM evidence entry contains an invalid field.');
    if (domains.has(domain)) return failure(`DKIM evidence repeats the domain ${domain}.`);
    domains.add(domain);
    latestCapture = Math.max(latestCapture, Date.parse(capturedAt));
    dkim.push({
      capturedAt,
      domain,
      reconstructed: entry['reconstructed'],
      resolverId: resolver,
      source: 'dkim-message',
    });
  }

  let spf: SpfAuthenticationEvidence | undefined;
  if (envelope['spf'] !== undefined) {
    const entry = objectWithKeys(envelope['spf'], [
      'capturedAt',
      'domain',
      'resolverId',
      'result',
      'source',
    ]);
    if (entry?.['source'] !== 'spf-sender')
      return failure('SPF evidence has an unexpected shape or source.');
    const capturedAt = isoTimestamp(entry['capturedAt']);
    const domain = canonicalDomain(entry['domain']);
    const resolver = resolverId(entry['resolverId']);
    const result = entry['result'];
    if (
      capturedAt === null ||
      domain === null ||
      resolver === null ||
      typeof result !== 'string' ||
      !SPF_RESULTS.has(result as DmarcSpfResult)
    )
      return failure('SPF evidence contains an invalid field.');
    latestCapture = Math.max(latestCapture, Date.parse(capturedAt));
    spf = {
      capturedAt,
      domain,
      resolverId: resolver,
      result: result as DmarcSpfResult,
      source: 'spf-sender',
    };
  }
  if (dkim.length === 0 && spf === undefined)
    return failure('Evidence must contain at least one DKIM domain or one SPF result.');
  if (Date.parse(createdAt) < latestCapture)
    return failure('Evidence createdAt must not precede its captured results.');
  return { ok: true, value: freezeEvidence(createdAt, dkim, spf) };
}

function inspectJson(text: string): string | null {
  let offset = 0;

  function skipWhitespace(): void {
    while (/^[\t\n\r ]$/u.test(text[offset] ?? '')) offset += 1;
  }

  function stringToken(): string | null {
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const character = text[offset];
      if (character === '"') {
        offset += 1;
        try {
          const parsed: unknown = JSON.parse(text.slice(start, offset));
          return typeof parsed === 'string' ? parsed : null;
        } catch {
          return null;
        }
      }
      if (character === '\\') {
        offset += text[offset + 1] === 'u' ? 6 : 2;
      } else offset += 1;
    }
    return null;
  }

  function value(depth: number): string | null {
    if (depth > MAIL_AUTHENTICATION_EVIDENCE_LIMITS.jsonDepth)
      return `Evidence JSON exceeds the ${String(MAIL_AUTHENTICATION_EVIDENCE_LIMITS.jsonDepth)}-level depth limit.`;
    skipWhitespace();
    const character = text[offset];
    if (character === '{') {
      offset += 1;
      skipWhitespace();
      const keys = new Set<string>();
      if (text[offset] === '}') {
        offset += 1;
        return null;
      }
      for (;;) {
        if (text[offset] !== '"') return 'Evidence contains malformed JSON.';
        const key = stringToken();
        if (key === null) return 'Evidence contains malformed JSON.';
        if (keys.has(key)) return 'Evidence JSON object keys must be unique.';
        keys.add(key);
        skipWhitespace();
        if (text[offset] !== ':') return 'Evidence contains malformed JSON.';
        offset += 1;
        const error = value(depth + 1);
        if (error !== null) return error;
        skipWhitespace();
        if (text[offset] === '}') {
          offset += 1;
          return null;
        }
        if (text[offset] !== ',') return 'Evidence contains malformed JSON.';
        offset += 1;
        skipWhitespace();
      }
    }
    if (character === '[') {
      offset += 1;
      skipWhitespace();
      if (text[offset] === ']') {
        offset += 1;
        return null;
      }
      for (;;) {
        const error = value(depth + 1);
        if (error !== null) return error;
        skipWhitespace();
        if (text[offset] === ']') {
          offset += 1;
          return null;
        }
        if (text[offset] !== ',') return 'Evidence contains malformed JSON.';
        offset += 1;
      }
    }
    if (character === '"')
      return stringToken() === null ? 'Evidence contains malformed JSON.' : null;
    const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(
      text.slice(offset),
    )?.[0];
    if (token === undefined) return 'Evidence contains malformed JSON.';
    offset += token.length;
    return null;
  }

  const error = value(0);
  if (error !== null) return error;
  skipWhitespace();
  return offset === text.length ? null : 'Evidence contains trailing JSON content.';
}

export function decodeMailAuthenticationEvidence(
  source: string,
): MailAuthenticationEvidenceResult {
  if (source.length > MAIL_AUTHENTICATION_EVIDENCE_LIMITS.jsonOctets)
    return failure(
      `Evidence exceeds the ${String(MAIL_AUTHENTICATION_EVIDENCE_LIMITS.jsonOctets)}-character safety limit.`,
    );
  if (encoder.encode(source).length > MAIL_AUTHENTICATION_EVIDENCE_LIMITS.jsonOctets)
    return failure(
      `Evidence exceeds the ${String(MAIL_AUTHENTICATION_EVIDENCE_LIMITS.jsonOctets)}-octet safety limit.`,
    );
  const syntaxError = inspectJson(source);
  if (syntaxError !== null) return failure(syntaxError);
  let parsed: unknown;
  try {
    parsed = JSON.parse(source) as unknown;
  } catch {
    return failure('Evidence contains malformed JSON.');
  }
  return parseMailAuthenticationEvidence(parsed);
}

export function encodeMailAuthenticationEvidence(value: MailAuthenticationEvidence): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function evidenceFromDkim(
  results: readonly DkimSignatureVerification[],
  capturedAt: string,
  resolver: ResolverId,
  reconstructed: boolean,
): MailAuthenticationEvidence | null {
  const domains = [
    ...new Set(
      results
        .filter((result) => result.status === 'pass' && result.keyTesting !== true)
        .map((result) => canonicalDomain(result.domain))
        .filter((domain): domain is string => domain !== null),
    ),
  ]
    .sort()
    .slice(0, MAIL_AUTHENTICATION_EVIDENCE_LIMITS.dkimDomains);
  if (domains.length === 0 || isoTimestamp(capturedAt) === null) return null;
  return freezeEvidence(
    capturedAt,
    domains.map((domain) => ({
      capturedAt,
      domain,
      reconstructed,
      resolverId: resolver,
      source: 'dkim-message',
    })),
  );
}

export function evidenceFromSpf(
  evaluation: Pick<SpfSenderEvaluation, 'capturedAt' | 'domain' | 'result'>,
  resolver: ResolverId,
): MailAuthenticationEvidence | null {
  const capturedAt = isoTimestamp(evaluation.capturedAt);
  const domain = canonicalDomain(evaluation.domain);
  if (capturedAt === null || domain === null || !SPF_RESULTS.has(evaluation.result))
    return null;
  return freezeEvidence(capturedAt, [], {
    capturedAt,
    domain,
    resolverId: resolver,
    result: evaluation.result,
    source: 'spf-sender',
  });
}

export function mergeMailAuthenticationEvidence(
  current: MailAuthenticationEvidence | null,
  incoming: MailAuthenticationEvidence,
): MailAuthenticationEvidence {
  if (current === null) return incoming;
  const dkim = incoming.dkim.length > 0 ? incoming.dkim : current.dkim;
  const spf = incoming.spf ?? current.spf;
  const latest = Math.max(
    Date.parse(current.createdAt),
    Date.parse(incoming.createdAt),
    ...dkim.map((entry) => Date.parse(entry.capturedAt)),
    ...(spf === undefined ? [] : [Date.parse(spf.capturedAt)]),
  );
  return freezeEvidence(new Date(latest).toISOString(), dkim, spf);
}
