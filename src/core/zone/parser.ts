import { validateDnsName } from '../dns/names';
import { canonicalMasterName } from './master-name';
import type {
  ZoneDiagnostic,
  ZoneDocument,
  ZoneParseOptions,
  ZoneRecord,
  ZoneResource,
  ZoneResourceLimit,
  ZoneToken,
} from './types';

export const ZONE_ANALYSIS_LIMITS = Object.freeze({
  changes: 4096,
  characters: 262_144,
  diagnostics: 4096,
  findings: 1024,
  records: 4096,
  statements: 8192,
  tokens: 32_768,
});

const KNOWN_TYPES = new Set([
  'A',
  'AAAA',
  'CAA',
  'CDNSKEY',
  'CDS',
  'CNAME',
  'DNSKEY',
  'DNAME',
  'DS',
  'DSYNC',
  'HTTPS',
  'MX',
  'NAPTR',
  'NS',
  'NSEC',
  'NSEC3',
  'PTR',
  'RRSIG',
  'SOA',
  'SRV',
  'CSYNC',
  'SSHFP',
  'SVCB',
  'TLSA',
  'TXT',
  'URI',
  'ZONEMD',
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

function limitMessage(resource: ZoneResource, limit: number): string {
  if (resource === 'characters')
    return `Zone input exceeds the ${String(limit)}-character safety limit.`;
  if (resource === 'diagnostics')
    return `Zone parsing exceeded the ${String(limit)}-diagnostic safety limit.`;
  if (resource === 'records')
    return `Zone parsing exceeded the ${String(limit)}-record safety limit.`;
  if (resource === 'statements')
    return `Zone parsing exceeded the ${String(limit)}-statement safety limit.`;
  return `Zone parsing exceeded the ${String(limit)}-token safety limit.`;
}

class ParseBudget {
  readonly diagnostics: ZoneDiagnostic[] = [];
  incomplete: ZoneResourceLimit | undefined;
  #tokens = 0;

  hasExceeded(): boolean {
    return this.incomplete !== undefined;
  }

  addDiagnostic(value: ZoneDiagnostic): boolean {
    if (this.incomplete !== undefined) return false;
    if (this.diagnostics.length >= ZONE_ANALYSIS_LIMITS.diagnostics) {
      this.exceed('diagnostics', ZONE_ANALYSIS_LIMITS.diagnostics, value.line, value.column);
      return false;
    }
    this.diagnostics.push(value);
    return true;
  }

  consumeToken(line: number, column: number): boolean {
    if (this.incomplete !== undefined) return false;
    if (this.#tokens >= ZONE_ANALYSIS_LIMITS.tokens) {
      this.exceed('tokens', ZONE_ANALYSIS_LIMITS.tokens, line, column);
      return false;
    }
    this.#tokens += 1;
    return true;
  }

  exceed(resource: ZoneResource, limit: number, line: number, column: number): void {
    if (this.incomplete !== undefined) return;
    const message = limitMessage(resource, limit);
    this.incomplete = { limit, message, resource };
    if (this.diagnostics.length >= ZONE_ANALYSIS_LIMITS.diagnostics) this.diagnostics.pop();
    this.diagnostics.push(
      diagnostic(
        resource === 'characters' ? 'input-size' : 'parser-resource-limit',
        'error',
        resource === 'characters'
          ? message
          : `${message} No partial parse result was retained.`,
        line,
        column,
      ),
    );
  }
}

function incompleteDocument(source: string, budget: ParseBudget): ZoneDocument {
  const incomplete = budget.incomplete;
  if (incomplete === undefined)
    throw new Error('An incomplete zone document requires a resource-limit reason.');
  return {
    diagnostics: budget.diagnostics,
    incomplete,
    records: [],
    source,
  };
}

function statements(source: string, budget: ParseBudget): readonly LogicalStatement[] {
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

  const finish = (): boolean => {
    if (buffer.trim() !== '') {
      if (values.length >= ZONE_ANALYSIS_LIMITS.statements) {
        budget.exceed('statements', ZONE_ANALYSIS_LIMITS.statements, startLine, startColumn);
        return false;
      }
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
    return true;
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
        if (parentheses === 0) {
          if (!finish()) break;
        } else buffer += ' ';
      }
    } else if (escaped) {
      buffer += character;
      escaped = false;
    } else if (character === '\\') {
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
        budget.addDiagnostic(
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
      if (parentheses === 0) {
        if (!finish()) break;
      } else buffer += ' ';
    } else {
      buffer += character;
    }

    if (budget.incomplete !== undefined) break;
    if (character === '\n') {
      line += 1;
      column = 1;
    } else column += 1;
  }
  if (budget.incomplete !== undefined) return values;
  if (!finish()) return values;
  if (quote)
    budget.addDiagnostic(
      diagnostic('syntax-quote', 'error', 'Unterminated quoted string.', line, column),
    );
  if (parentheses > 0)
    budget.addDiagnostic(
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

function tokens(statement: LogicalStatement, budget: ParseBudget): readonly ZoneToken[] {
  const values: ZoneToken[] = [];
  let start = -1;
  let startColumn = statement.column;
  let startLine = statement.line;
  let column = statement.column;
  let line = statement.line;
  let quote = false;
  let decoded = '';

  const finish = (end: number): boolean => {
    if (start < 0) return true;
    if (!budget.consumeToken(startLine, startColumn)) return false;
    const raw = statement.text.slice(start, end);
    values.push({
      column: startColumn,
      line: startLine,
      quoted: raw.startsWith('"'),
      raw,
      value: decoded,
    });
    start = -1;
    decoded = '';
    return true;
  };

  const advance = (character: string) => {
    if (character === '\n') {
      line += 1;
      column = 1;
    } else column += 1;
  };

  for (let index = 0; index <= statement.text.length; index += 1) {
    const character = statement.text[index];
    if (character === undefined) {
      finish(index);
      break;
    }
    if (start < 0 && /\s/u.test(character)) {
      advance(character);
      continue;
    }
    if (start < 0) {
      start = index;
      startColumn = column;
      startLine = line;
    }
    if (character === '\\') {
      const next = statement.text[index + 1];
      if (next === undefined) {
        budget.addDiagnostic(
          diagnostic(
            'escape-malformed',
            'error',
            'A trailing backslash does not escape a character.',
            line,
            column,
          ),
        );
        decoded += '\\';
        advance(character);
        continue;
      }
      if (!/\d/u.test(next)) {
        decoded += next;
        advance(character);
        advance(next);
        index += 1;
        continue;
      }
      const digits = statement.text.slice(index + 1, index + 4);
      if (!/^\d{3}$/u.test(digits)) {
        budget.addDiagnostic(
          diagnostic(
            'escape-decimal-malformed',
            'error',
            'A decimal escape must contain exactly three digits.',
            line,
            column,
          ),
        );
        decoded += next;
        advance(character);
        advance(next);
        index += 1;
        continue;
      }
      const octet = Number(digits);
      if (octet > 255) {
        budget.addDiagnostic(
          diagnostic(
            'escape-decimal-range',
            'error',
            `Decimal escape \\${digits} is outside the octet range \\000–\\255.`,
            line,
            column,
          ),
        );
        decoded += digits;
      } else decoded += String.fromCharCode(octet);
      advance(character);
      for (const digit of digits) advance(digit);
      index += 3;
    } else if (character === '"') {
      quote = !quote;
      advance(character);
      if (!quote && !finish(index + 1)) break;
    } else if (!quote && /\s/u.test(character)) {
      if (!finish(index)) break;
      advance(character);
    } else {
      decoded += character;
      advance(character);
    }
    if (budget.incomplete !== undefined) break;
  }
  if (budget.incomplete !== undefined) return values;
  if (quote) {
    budget.addDiagnostic(
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

/** The bounded master-file lexer, shared by parsing and local directive expansion. */
export function lexZoneStatements(source: string): {
  readonly diagnostics: readonly ZoneDiagnostic[];
  readonly statements: readonly (LogicalStatement & {
    readonly tokens: readonly ZoneToken[];
  })[];
} {
  const budget = new ParseBudget();
  if (source.length > ZONE_ANALYSIS_LIMITS.characters)
    budget.exceed('characters', ZONE_ANALYSIS_LIMITS.characters, 1, 1);
  const result = budget.hasExceeded()
    ? []
    : statements(source, budget).map((statement) => ({
        ...statement,
        tokens: budget.hasExceeded() ? [] : tokens(statement, budget),
      }));
  return { diagnostics: budget.diagnostics, statements: budget.hasExceeded() ? [] : result };
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
  return parsed.ok ? (canonicalMasterName(parsed.value.absolute)?.absolute ?? null) : null;
}

function absoluteOwner(value: string, origin: string | undefined): string | null {
  return canonicalMasterName(value, origin)?.absolute ?? null;
}

export function parseZoneSnippet(source: string, options: ZoneParseOptions = {}): ZoneDocument {
  const budget = new ParseBudget();
  if (source.length > ZONE_ANALYSIS_LIMITS.characters) {
    budget.exceed('characters', ZONE_ANALYSIS_LIMITS.characters, 1, 1);
    return incompleteDocument(source, budget);
  }
  let currentOrigin =
    options.origin === undefined || options.origin.trim() === ''
      ? undefined
      : (normalizeOrigin(options.origin) ?? undefined);
  let zoneOrigin = currentOrigin;
  if (
    options.origin !== undefined &&
    options.origin.trim() !== '' &&
    currentOrigin === undefined
  ) {
    budget.addDiagnostic(
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

  const logicalStatements = statements(source, budget);
  if (budget.hasExceeded()) return incompleteDocument(source, budget);
  for (const statement of logicalStatements) {
    const parts = tokens(statement, budget);
    if (budget.hasExceeded()) break;
    const first = parts[0];
    if (first === undefined) continue;
    if (!first.quoted && first.raw.startsWith('$')) {
      const directive = first.value.toUpperCase();
      const argument = parts[1];
      if (directive === '$ORIGIN' && argument !== undefined) {
        const normalized = canonicalMasterName(argument.raw, currentOrigin)?.absolute ?? null;
        if (normalized === null)
          budget.addDiagnostic(
            diagnostic(
              'origin-invalid',
              'error',
              '$ORIGIN is not a valid DNS name.',
              first.line,
              first.column,
            ),
          );
        else {
          currentOrigin = normalized;
          zoneOrigin ??= normalized;
        }
      } else if (directive === '$TTL' && argument !== undefined) {
        const ttl = parseTtl(argument.value);
        if (ttl === null)
          budget.addDiagnostic(
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
        budget.addDiagnostic(
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
    const omittedOwner = statement.leadingWhitespace;
    const ownerToken = omittedOwner ? '' : first.raw;
    let owner: string;
    if (omittedOwner) {
      if (previousOwner === undefined) {
        budget.addDiagnostic(
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
      const absolute = absoluteOwner(first.raw, currentOrigin);
      if (absolute === null) {
        if (currentOrigin !== undefined)
          budget.addDiagnostic(
            diagnostic(
              'owner-invalid',
              'error',
              'The record owner is not a valid master-file domain name.',
              first.line,
              first.column,
            ),
          );
        owner = first.raw.toLowerCase();
      } else owner = absolute;
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
      budget.addDiagnostic(
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
    if (!KNOWN_TYPES.has(type)) {
      const generic = /^TYPE(\d{1,5})$/u.exec(type);
      const code = Number(generic?.[1]);
      if (generic === null || !Number.isInteger(code) || code < 1 || code > 65_534)
        budget.addDiagnostic(
          diagnostic(
            'type-unsupported',
            'warning',
            `Record type ${type} is outside the supported linting subset.`,
            typeToken.line,
            typeToken.column,
          ),
        );
    }
    index += 1;
    if (records.length >= ZONE_ANALYSIS_LIMITS.records) {
      budget.exceed('records', ZONE_ANALYSIS_LIMITS.records, first.line, first.column);
      break;
    }
    records.push({
      className,
      column: first.column,
      line: first.line,
      original: statement.original.trimEnd(),
      ...(currentOrigin === undefined ? {} : { origin: currentOrigin }),
      owner,
      ownerToken,
      rdata: parts.slice(index),
      ...(ttl === undefined ? {} : { ttl }),
      type,
    });
  }

  if (budget.hasExceeded()) return incompleteDocument(source, budget);

  return {
    diagnostics: budget.diagnostics,
    ...(zoneOrigin === undefined ? {} : { origin: zoneOrigin }),
    records,
    source,
  };
}
