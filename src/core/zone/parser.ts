import { validateDnsName } from '../dns/names';
import type {
  ZoneDiagnostic,
  ZoneDocument,
  ZoneParseOptions,
  ZoneRecord,
  ZoneToken,
} from './types';

const MAX_ZONE_CHARACTERS = 262_144;
const KNOWN_TYPES = new Set([
  'A',
  'AAAA',
  'CAA',
  'CNAME',
  'DNSKEY',
  'DS',
  'HTTPS',
  'MX',
  'NS',
  'NSEC',
  'NSEC3',
  'PTR',
  'RRSIG',
  'SOA',
  'SRV',
  'SVCB',
  'TLSA',
  'TXT',
]);

interface LogicalStatement {
  readonly column: number;
  readonly leadingWhitespace: boolean;
  readonly line: number;
  readonly original: string;
  readonly text: string;
}

function diagnostic(
  rule: string,
  severity: ZoneDiagnostic['severity'],
  message: string,
  line: number,
  column: number,
  suggestion?: string,
): ZoneDiagnostic {
  return {
    column,
    line,
    message,
    rule,
    severity,
    ...(suggestion === undefined ? {} : { suggestion }),
  };
}

function statements(
  source: string,
  diagnostics: ZoneDiagnostic[],
): readonly LogicalStatement[] {
  const values: LogicalStatement[] = [];
  let buffer = '';
  let original = '';
  let startLine = 1;
  let startColumn = 1;
  let line = 1;
  let column = 1;
  let quote = false;
  let escaped = false;
  let comment = false;
  let parentheses = 0;

  const finish = () => {
    if (buffer.trim() !== '') {
      values.push({
        column: startColumn,
        leadingWhitespace: /^\s/u.test(original),
        line: startLine,
        original,
        text: buffer,
      });
    }
    buffer = '';
    original = '';
  };

  for (const character of source) {
    if (original === '') {
      startLine = line;
      startColumn = column;
    }
    original += character;
    if (comment) {
      if (character === '\n') {
        comment = false;
        if (parentheses === 0) finish();
        else buffer += ' ';
      }
    } else if (escaped) {
      buffer += character;
      escaped = false;
    } else if (character === '\\' && quote) {
      buffer += character;
      escaped = true;
    } else if (character === '"') {
      buffer += character;
      quote = !quote;
    } else if (!quote && character === ';') {
      comment = true;
    } else if (!quote && character === '(') {
      parentheses += 1;
      buffer += ' ';
    } else if (!quote && character === ')') {
      if (parentheses === 0) {
        diagnostics.push(
          diagnostic(
            'syntax-parenthesis',
            'error',
            'Closing parenthesis has no opener.',
            line,
            column,
          ),
        );
      } else parentheses -= 1;
      buffer += ' ';
    } else if (character === '\n') {
      if (parentheses === 0) finish();
      else buffer += ' ';
    } else {
      buffer += character;
    }

    if (character === '\n') {
      line += 1;
      column = 1;
    } else column += 1;
  }
  finish();
  if (quote)
    diagnostics.push(
      diagnostic('syntax-quote', 'error', 'Unterminated quoted string.', line, column),
    );
  if (parentheses > 0)
    diagnostics.push(
      diagnostic(
        'syntax-parenthesis',
        'error',
        'Unterminated parenthesised record.',
        line,
        column,
      ),
    );
  return values;
}

function tokenLocation(
  statement: LogicalStatement,
  offset: number,
): { line: number; column: number } {
  const before = statement.text.slice(0, offset);
  const lines = before.split('\n');
  return {
    column: lines.length === 1 ? statement.column + offset : (lines.at(-1)?.length ?? 0) + 1,
    line: statement.line + lines.length - 1,
  };
}

function tokens(
  statement: LogicalStatement,
  diagnostics: ZoneDiagnostic[],
): readonly ZoneToken[] {
  const values: ZoneToken[] = [];
  let start = -1;
  let quote = false;
  let escaped = false;
  let decoded = '';

  const finish = (end: number) => {
    if (start < 0) return;
    const location = tokenLocation(statement, start);
    const raw = statement.text.slice(start, end);
    values.push({
      ...location,
      quoted: raw.startsWith('"'),
      raw,
      value: raw.startsWith('"') ? decoded : raw,
    });
    start = -1;
    decoded = '';
  };

  for (let index = 0; index <= statement.text.length; index += 1) {
    const character = statement.text[index];
    if (character === undefined) {
      finish(index);
      break;
    }
    if (start < 0 && /\s/u.test(character)) continue;
    if (start < 0) start = index;
    if (escaped) {
      decoded += character;
      escaped = false;
    } else if (quote && character === '\\') escaped = true;
    else if (character === '"') {
      quote = !quote;
      if (!quote) finish(index + 1);
    } else if (!quote && /\s/u.test(character)) finish(index);
    else decoded += character;
  }
  if (quote) {
    diagnostics.push(
      diagnostic(
        'syntax-quote',
        'error',
        'Unterminated quoted token.',
        statement.line,
        statement.column,
      ),
    );
  }
  return values;
}

export function parseTtl(value: string): number | null {
  if (/^\d+$/u.test(value)) {
    const seconds = Number(value);
    return Number.isSafeInteger(seconds) && seconds >= 0 && seconds <= 2_147_483_647
      ? seconds
      : null;
  }
  let total = 0;
  let offset = 0;
  const units: Readonly<Record<string, number>> = {
    d: 86_400,
    h: 3600,
    m: 60,
    s: 1,
    w: 604_800,
  };
  for (const match of value.toLowerCase().matchAll(/(\d+)([wdhms])/gu)) {
    if (match.index !== offset) return null;
    const amount = Number(match[1]);
    const unit = match[2] === undefined ? undefined : units[match[2]];
    if (!Number.isSafeInteger(amount) || unit === undefined) return null;
    total += amount * unit;
    offset = match.index + match[0].length;
  }
  return offset === value.length && offset > 0 && total <= 2_147_483_647 ? total : null;
}

function normalizeOrigin(value: string): string | null {
  const parsed = validateDnsName(value);
  return parsed.ok ? parsed.value.absolute : null;
}

function absoluteOwner(value: string, origin: string | undefined): string {
  if (value === '@') return origin ?? '@';
  if (value.endsWith('.')) return value.toLowerCase();
  return origin === undefined
    ? value.toLowerCase()
    : `${value.toLowerCase()}.${origin}`.replace('..', '.');
}

function looksLikeTtl(value: string): boolean {
  return parseTtl(value) !== null;
}

function isRecordPreamble(value: string): boolean {
  const upper = value.toUpperCase();
  return upper === 'IN' || KNOWN_TYPES.has(upper) || looksLikeTtl(value);
}

export function parseZoneSnippet(source: string, options: ZoneParseOptions = {}): ZoneDocument {
  const diagnostics: ZoneDiagnostic[] = [];
  if (source.length > MAX_ZONE_CHARACTERS) {
    return {
      diagnostics: [
        diagnostic(
          'input-size',
          'error',
          `Zone input exceeds the ${String(MAX_ZONE_CHARACTERS)}-character safety limit.`,
          1,
          1,
        ),
      ],
      records: [],
      source,
    };
  }
  let origin =
    options.origin === undefined || options.origin.trim() === ''
      ? undefined
      : (normalizeOrigin(options.origin) ?? undefined);
  if (options.origin !== undefined && options.origin.trim() !== '' && origin === undefined) {
    diagnostics.push(
      diagnostic(
        'origin-invalid',
        'error',
        'The supplied origin is not a valid DNS name.',
        1,
        1,
      ),
    );
  }
  let defaultTtl: number | undefined;
  let previousOwner: string | undefined;
  const records: ZoneRecord[] = [];

  for (const statement of statements(source, diagnostics)) {
    const parts = tokens(statement, diagnostics);
    const first = parts[0];
    if (first === undefined) continue;
    if (first.value.startsWith('$')) {
      const directive = first.value.toUpperCase();
      const argument = parts[1]?.value;
      if (directive === '$ORIGIN' && argument !== undefined) {
        const normalized = normalizeOrigin(argument);
        if (normalized === null)
          diagnostics.push(
            diagnostic(
              'origin-invalid',
              'error',
              '$ORIGIN is not a valid DNS name.',
              first.line,
              first.column,
            ),
          );
        else origin = normalized;
      } else if (directive === '$TTL' && argument !== undefined) {
        const ttl = parseTtl(argument);
        if (ttl === null)
          diagnostics.push(
            diagnostic(
              'ttl-invalid',
              'error',
              '$TTL value is invalid.',
              first.line,
              first.column,
            ),
          );
        else defaultTtl = ttl;
      } else
        diagnostics.push(
          diagnostic(
            'directive-unsupported',
            'warning',
            `Unsupported or incomplete directive ${first.value}.`,
            first.line,
            first.column,
          ),
        );
      continue;
    }

    let index = 0;
    const omittedOwner = statement.leadingWhitespace || isRecordPreamble(first.value);
    const ownerToken = omittedOwner ? '' : first.value;
    let owner: string;
    if (omittedOwner) {
      if (previousOwner === undefined) {
        diagnostics.push(
          diagnostic(
            'owner-missing',
            'error',
            'An inherited owner was used before any owner was declared.',
            first.line,
            first.column,
          ),
        );
        owner = '@';
      } else owner = previousOwner;
    } else {
      owner = absoluteOwner(first.value, origin);
      previousOwner = owner;
      index += 1;
    }

    let ttl = defaultTtl;
    let className = 'IN';
    while (index < parts.length) {
      const current = parts[index];
      if (current === undefined) break;
      if (current.value.toUpperCase() === 'IN') {
        className = 'IN';
        index += 1;
        continue;
      }
      const parsedTtl = parseTtl(current.value);
      if (parsedTtl !== null) {
        ttl = parsedTtl;
        index += 1;
        continue;
      }
      break;
    }
    const typeToken = parts[index];
    if (typeToken === undefined) {
      diagnostics.push(
        diagnostic(
          'record-incomplete',
          'error',
          'Record type is missing.',
          first.line,
          first.column,
        ),
      );
      continue;
    }
    const type = typeToken.value.toUpperCase();
    if (!KNOWN_TYPES.has(type))
      diagnostics.push(
        diagnostic(
          'type-unsupported',
          'warning',
          `Record type ${type} is outside the supported linting subset.`,
          typeToken.line,
          typeToken.column,
        ),
      );
    index += 1;
    records.push({
      className,
      column: first.column,
      line: first.line,
      original: statement.original.trimEnd(),
      owner,
      ownerToken,
      rdata: parts.slice(index),
      ...(ttl === undefined ? {} : { ttl }),
      type,
    });
  }

  return {
    diagnostics,
    ...(origin === undefined ? {} : { origin }),
    records,
    source,
  };
}
