import { parseStrictIpAddress } from '../dns/ip';
import { lexSpf, type SpfToken } from './lexer';
import type {
  SpfCidr,
  SpfDiagnostic,
  SpfMechanism,
  SpfMechanismName,
  SpfModifier,
  SpfModifierName,
  SpfPolicy,
  SpfQualifier,
  SpfTerm,
  SpfUnknownModifier,
} from './types';

const MECHANISMS = new Set<SpfMechanismName>([
  'all',
  'include',
  'a',
  'mx',
  'ptr',
  'ip4',
  'ip6',
  'exists',
]);
const MODIFIERS = new Set<SpfModifierName>(['redirect', 'exp']);

function diagnostic(
  code: string,
  message: string,
  token?: SpfToken,
  severity: SpfDiagnostic['severity'] = 'error',
): SpfDiagnostic {
  return {
    code,
    message,
    severity,
    ...(token === undefined ? {} : { location: token.location }),
  };
}

function topLevelSlash(value: string): number {
  let inMacro = false;
  for (let index = 0; index < value.length; index += 1) {
    if (!inMacro && value[index] === '%' && value[index + 1] === '{') {
      inMacro = true;
      index += 1;
      continue;
    }
    if (inMacro && value[index] === '}') {
      inMacro = false;
      continue;
    }
    if (!inMacro && value[index] === '/') return index;
  }
  return -1;
}

function cidrLength(value: string, maximum: number, family: string): number | string {
  if (!/^(?:0|[1-9][0-9]{0,2})$/u.test(value)) {
    return `${family} CIDR length must be a decimal integer.`;
  }
  const parsed = Number(value);
  return parsed <= maximum
    ? parsed
    : `${family} CIDR length must be between 0 and ${String(maximum)}.`;
}

function splitDualCidr(value: string): { base: string; cidr?: SpfCidr; error?: string } {
  const slash = topLevelSlash(value);
  if (slash < 0) return { base: value };
  const base = value.slice(0, slash);
  const suffix = value.slice(slash);
  const dual = /^\/([0-9]+)\/\/([0-9]+)$/u.exec(suffix);
  const ipv6Only = /^\/\/([0-9]+)$/u.exec(suffix);
  const ipv4Only = /^\/([0-9]+)$/u.exec(suffix);
  const ipv4Text = dual?.[1] ?? ipv4Only?.[1];
  const ipv6Text = dual?.[2] ?? ipv6Only?.[1];
  if (ipv4Text === undefined && ipv6Text === undefined) {
    return {
      base,
      error: 'Dual CIDR syntax must use /IPv4, //IPv6, or /IPv4//IPv6.',
    };
  }
  const ipv4 = ipv4Text === undefined ? undefined : cidrLength(ipv4Text, 32, 'IPv4');
  if (typeof ipv4 === 'string') return { base, error: ipv4 };
  const ipv6 = ipv6Text === undefined ? undefined : cidrLength(ipv6Text, 128, 'IPv6');
  if (typeof ipv6 === 'string') return { base, error: ipv6 };
  return {
    base,
    cidr: { ...(ipv4 === undefined ? {} : { ipv4 }), ...(ipv6 === undefined ? {} : { ipv6 }) },
  };
}

function splitAddressCidr(
  value: string,
  family: 'ipv4' | 'ipv6',
): { base: string; cidr?: SpfCidr; error?: string } {
  const slash = topLevelSlash(value);
  if (slash < 0) return { base: value };
  const base = value.slice(0, slash);
  const suffix = value.slice(slash);
  const match = /^\/([0-9]+)$/u.exec(suffix);
  if (match?.[1] === undefined) {
    return { base, error: `${family.toUpperCase()} mechanisms accept one CIDR length only.` };
  }
  const maximum = family === 'ipv4' ? 32 : 128;
  const parsed = cidrLength(match[1], maximum, family === 'ipv4' ? 'IPv4' : 'IPv6');
  if (typeof parsed === 'string') return { base, error: parsed };
  return {
    base,
    cidr: family === 'ipv4' ? { ipv4: parsed } : { ipv6: parsed },
  };
}

function modifier(token: SpfToken): SpfModifier | SpfUnknownModifier | null {
  const equals = token.text.indexOf('=');
  if (equals < 1) return null;
  const name = token.text.slice(0, equals).toLowerCase();
  if (!/^[a-z][a-z0-9._-]*$/u.test(name)) return null;
  const value = token.text.slice(equals + 1);
  if (!MODIFIERS.has(name as SpfModifierName)) {
    return {
      kind: 'unknown-modifier',
      location: token.location,
      macro: value.includes('%'),
      name,
      original: token.text,
      value,
    };
  }
  return {
    kind: 'modifier',
    location: token.location,
    macro: value.includes('%'),
    name: name as SpfModifierName,
    original: token.text,
    value,
  };
}

function mechanism(token: SpfToken, diagnostics: SpfDiagnostic[]): SpfMechanism | null {
  let value = token.text;
  let qualifier: SpfQualifier = '+';
  const first = value[0];
  if (first === '+' || first === '-' || first === '~' || first === '?') {
    qualifier = first;
    value = value.slice(1);
  }
  const colon = value.indexOf(':');
  const rawName = (
    colon < 0 ? (value.split('/', 1)[0] ?? '') : value.slice(0, colon)
  ).toLowerCase();
  if (!MECHANISMS.has(rawName as SpfMechanismName)) return null;
  const name = rawName as SpfMechanismName;
  const valueAfterName = value.slice(rawName.length);
  const source = valueAfterName.startsWith(':') ? valueAfterName.slice(1) : valueAfterName;
  const split =
    name === 'a' || name === 'mx'
      ? splitDualCidr(source)
      : name === 'ip4'
        ? splitAddressCidr(source, 'ipv4')
        : name === 'ip6'
          ? splitAddressCidr(source, 'ipv6')
          : { base: source };
  if (split.error !== undefined)
    diagnostics.push(diagnostic('invalid-cidr', split.error, token));
  const argument = split.base === '' ? undefined : split.base;

  if (
    name !== 'a' &&
    name !== 'mx' &&
    name !== 'ip4' &&
    name !== 'ip6' &&
    topLevelSlash(source) >= 0
  ) {
    diagnostics.push(
      diagnostic('cidr-not-allowed', `${name} does not accept a CIDR length.`, token),
    );
  }

  if ((name === 'include' || name === 'exists') && argument === undefined) {
    diagnostics.push(
      diagnostic('missing-domain-spec', `${name} requires a domain specification.`, token),
    );
  }
  if (name === 'all' && (argument !== undefined || split.cidr !== undefined)) {
    diagnostics.push(
      diagnostic('all-argument', 'all does not accept an argument or CIDR length.', token),
    );
  }
  if ((name === 'ip4' || name === 'ip6') && argument === undefined) {
    diagnostics.push(
      diagnostic('missing-network', `${name} requires an address or network.`, token),
    );
  }
  if ((name === 'ip4' || name === 'ip6') && argument !== undefined) {
    const parsed = parseStrictIpAddress(argument);
    const expected = name === 'ip4' ? 'ipv4' : 'ipv6';
    if (parsed?.kind() !== expected) {
      diagnostics.push(
        diagnostic(
          'invalid-network',
          `${argument} is not a valid ${name} address or CIDR.`,
          token,
        ),
      );
    }
  }

  return {
    ...(argument === undefined ? {} : { argument }),
    ...(split.cidr === undefined ? {} : { cidr: split.cidr }),
    kind: 'mechanism',
    location: token.location,
    macro: argument?.includes('%') ?? false,
    name,
    original: token.text,
    qualifier,
  };
}

export function parseSpfRecord(record: string, sourceDomain: string): SpfPolicy {
  const diagnostics: SpfDiagnostic[] = [];
  if (record.length > 4096) {
    diagnostics.push(
      diagnostic(
        'record-too-long',
        'The SPF policy exceeds the 4096-character analysis limit.',
      ),
    );
  }
  for (let index = 0; index < Math.min(record.length, 4096); index += 1) {
    const codeUnit = record.charCodeAt(index);
    if (codeUnit < 0x20 || codeUnit > 0x7e) {
      diagnostics.push(
        diagnostic(
          'invalid-character',
          'SPF policies may contain printable ASCII characters separated only by ordinary spaces.',
          { location: { end: index + 1, start: index }, text: record[index] ?? '' },
        ),
      );
      break;
    }
  }
  const tokens = lexSpf(record.slice(0, 4096));
  const version = tokens[0];
  const validVersion = version?.text.toLowerCase() === 'v=spf1';
  if (!validVersion)
    diagnostics.push(
      diagnostic('invalid-version', 'An SPF policy must begin with v=spf1.', version),
    );
  const terms: SpfTerm[] = [];
  const seen = new Set<string>();
  const seenModifiers = new Set<SpfModifierName>();
  let allSeen = false;
  let redirectSeen = false;

  for (const token of tokens.slice(1)) {
    const parsedModifier = modifier(token);
    const parsedMechanism = parsedModifier === null ? mechanism(token, diagnostics) : null;
    const term: SpfTerm = parsedModifier ??
      parsedMechanism ?? { kind: 'unknown', location: token.location, original: token.text };
    terms.push(term);
    const duplicateKey = token.text.toLowerCase();
    if (seen.has(duplicateKey))
      diagnostics.push(
        diagnostic('duplicate-term', `Duplicate SPF term: ${token.text}.`, token, 'warning'),
      );
    seen.add(duplicateKey);
    if (term.kind === 'unknown')
      diagnostics.push(
        diagnostic('unknown-term', `Unsupported or malformed SPF term: ${token.text}.`, token),
      );
    if (term.kind === 'unknown-modifier')
      diagnostics.push(
        diagnostic(
          'unknown-modifier',
          `Unrecognised SPF modifier ${term.name} is preserved and ignored.`,
          token,
          'warning',
        ),
      );
    if (term.kind === 'modifier') {
      if (seenModifiers.has(term.name)) {
        diagnostics.push(
          diagnostic(
            'duplicate-modifier',
            `The ${term.name} modifier appears more than once.`,
            token,
          ),
        );
      }
      seenModifiers.add(term.name);
    }
    if (allSeen && term.kind === 'mechanism')
      diagnostics.push(
        diagnostic('after-all', 'Mechanisms after all are unreachable.', token, 'warning'),
      );
    if (term.kind === 'mechanism' && term.name === 'all') allSeen = true;
    if (term.kind === 'mechanism' && term.name === 'ptr')
      diagnostics.push(
        diagnostic(
          'ptr-discouraged',
          'ptr is expensive, context-dependent, and discouraged by SPF.',
          token,
          'warning',
        ),
      );
    if ((term.kind === 'mechanism' || term.kind === 'modifier') && term.macro)
      diagnostics.push(
        diagnostic(
          'macro-present',
          'This term uses an SPF macro and requires sender context.',
          token,
          'warning',
        ),
      );
    if (term.kind === 'modifier' && term.name === 'redirect') redirectSeen = true;
  }
  if (allSeen && redirectSeen)
    diagnostics.push(
      diagnostic(
        'all-with-redirect',
        'redirect is ignored when an all mechanism matches.',
        undefined,
        'warning',
      ),
    );
  if (!allSeen && !redirectSeen)
    diagnostics.push(
      diagnostic(
        'missing-terminal-policy',
        'The policy has no all mechanism or redirect modifier.',
        undefined,
        'warning',
      ),
    );

  return { diagnostics, record, sourceDomain, terms, validVersion };
}
