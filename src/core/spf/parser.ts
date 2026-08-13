import ipaddr from 'ipaddr.js';

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

function splitCidr(value: string): { base: string; cidr?: SpfCidr; error?: string } {
  const slash = value.indexOf('/');
  if (slash < 0) return { base: value };
  const base = value.slice(0, slash);
  const suffix = value.slice(slash + 1);
  const parts = suffix.split('/');
  if (parts.length > 2) return { base, error: 'CIDR suffix has too many separators.' };
  const first = parts[0] ?? '';
  const second = parts[1];
  let ipv4: number | undefined;
  let ipv6: number | undefined;
  if (first === '' && second === undefined) return { base, error: 'CIDR length is empty.' };
  if (first !== '') {
    const parsed = Number(first);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > 32) {
      return { base, error: 'IPv4 CIDR length must be between 0 and 32.' };
    }
    ipv4 = parsed;
  }
  if (second !== undefined) {
    const parsed = Number(second);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > 128) {
      return { base, error: 'IPv6 CIDR length must be between 0 and 128.' };
    }
    ipv6 = parsed;
  }
  return {
    base,
    cidr: { ...(ipv4 === undefined ? {} : { ipv4 }), ...(ipv6 === undefined ? {} : { ipv6 }) },
  };
}

function modifier(token: SpfToken): SpfModifier | null {
  const equals = token.text.indexOf('=');
  if (equals < 1) return null;
  const name = token.text.slice(0, equals).toLowerCase();
  if (!MODIFIERS.has(name as SpfModifierName)) return null;
  const value = token.text.slice(equals + 1);
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
  const split = splitCidr(
    valueAfterName.startsWith(':') ? valueAfterName.slice(1) : valueAfterName,
  );
  if (split.error !== undefined)
    diagnostics.push(diagnostic('invalid-cidr', split.error, token));
  const argument = split.base === '' ? undefined : split.base;

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
    try {
      const parsed = argument.includes('/')
        ? ipaddr.parseCIDR(argument)[0]
        : ipaddr.parse(argument);
      const expected = name === 'ip4' ? 'ipv4' : 'ipv6';
      if (parsed.kind() !== expected) throw new Error('Address family does not match.');
    } catch {
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
  const tokens = lexSpf(record.slice(0, 4096));
  const version = tokens[0];
  const validVersion = version?.text.toLowerCase() === 'v=spf1';
  if (!validVersion)
    diagnostics.push(
      diagnostic('invalid-version', 'An SPF policy must begin with v=spf1.', version),
    );
  const terms: SpfTerm[] = [];
  const seen = new Set<string>();
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
    if (term.kind !== 'unknown' && term.macro)
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
