const fatalUtf8Decoder = new TextDecoder('utf-8', { fatal: true });
const defaultIgnorableCharacter = /^\p{Default_Ignorable_Code_Point}$/u;
const controlCharacter = /^\p{Cc}$/u;
const projectedTechnicalTextMarker = Symbol('projected-technical-text');

export interface TechnicalByteProjection {
  readonly display: string;
  readonly encoding: 'binary' | 'utf-8';
  readonly rawBase64: string;
  readonly rawHex: string;
}

export interface Base64TextEvidence {
  readonly encoding: 'base64';
  readonly octets: number;
  readonly value: string;
}

interface ProjectedTechnicalText {
  readonly [projectedTechnicalTextMarker]: true;
  readonly value: string;
}

function codePointEscape(codePoint: number): string {
  if (codePoint === 0x09) return '\\t';
  if (codePoint === 0x0a) return '\\n';
  if (codePoint === 0x0d) return '\\r';
  return '\\u{' + codePoint.toString(16).toUpperCase().padStart(4, '0') + '}';
}

function isUnsafeTechnicalCharacter(character: string, codePoint: number): boolean {
  return (
    controlCharacter.test(character) ||
    defaultIgnorableCharacter.test(character) ||
    codePoint === 0x2028 ||
    codePoint === 0x2029 ||
    codePoint === 0xfffd ||
    (codePoint >= 0xd800 && codePoint <= 0xdfff)
  );
}

/** Detect UTF-16 code units that cannot be represented as the same Unicode scalar in UTF-8. */
export function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const following = value.charCodeAt(index + 1);
      if (!(following >= 0xdc00 && following <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

/** Detect characters that can reorder, suppress, split, or replace technical evidence. */
export function hasUnsafeTechnicalText(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint !== undefined && isUnsafeTechnicalCharacter(character, codePoint))
      return true;
  }
  return false;
}

/**
 * Produce an injective, single-line projection for untrusted technical text.
 * Backslashes are doubled so literal escape-like text remains distinguishable
 * from the notation generated for an actual control character.
 */
export function escapeTechnicalText(value: string): string {
  let result = '';
  for (const character of value) {
    if (character === '\\') {
      result += '\\\\';
      continue;
    }
    const codePoint = character.codePointAt(0);
    result +=
      codePoint !== undefined && isUnsafeTechnicalCharacter(character, codePoint)
        ? codePointEscape(codePoint)
        : character;
  }
  return result;
}

export function bytesBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Preserve the canonical UTF-8 octets for text that passed strict DNS decoding. */
export function utf8Base64Evidence(value: string): Base64TextEvidence {
  if (hasUnpairedSurrogate(value)) {
    throw new Error('Exact UTF-8 evidence cannot encode an unpaired UTF-16 surrogate.');
  }
  const bytes = new TextEncoder().encode(value);
  return { encoding: 'base64', octets: bytes.length, value: bytesBase64(bytes) };
}

/** Mark an already escaped technical projection so evidence serialisation does not escape it twice. */
export function projectedTechnicalText(value: string): ProjectedTechnicalText {
  if (hasUnsafeTechnicalText(value)) {
    throw new Error('A projected technical value must not contain unsafe characters.');
  }
  return Object.freeze({ [projectedTechnicalTextMarker]: true as const, value });
}

function isProjectedTechnicalText(value: unknown): value is ProjectedTechnicalText {
  return typeof value === 'object' && value !== null && projectedTechnicalTextMarker in value;
}

export function bytesHex(bytes: Uint8Array): string {
  return [...bytes]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

/** Preserve valid UTF-8 while making malformed octets and visual controls explicit. */
export function projectTechnicalBytes(bytes: Uint8Array): TechnicalByteProjection {
  const rawBase64 = bytesBase64(bytes);
  const rawHex = bytesHex(bytes);
  try {
    return {
      display: escapeTechnicalText(fatalUtf8Decoder.decode(bytes)),
      encoding: 'utf-8',
      rawBase64,
      rawHex,
    };
  } catch {
    return {
      display: [...bytes]
        .map((byte) => '\\x' + byte.toString(16).padStart(2, '0').toUpperCase())
        .join(''),
      encoding: 'binary',
      rawBase64,
      rawHex,
    };
  }
}

/**
 * Encode untrusted text as a literal CommonMark/GFM code span. The delimiter is
 * longer than any attacker-controlled backtick run.
 */
function markdownCodeSpan(value: string, table: boolean): string {
  if (value === '') return '';
  const visible = escapeTechnicalText(value);
  if (/^ +$/u.test(visible)) return '&#32;'.repeat(visible.length);
  const backtickRuns = visible.match(/`+/gu) ?? [];
  const delimiter = '`'.repeat(Math.max(1, ...backtickRuns.map((run) => run.length + 1)));
  return delimiter + ' ' + (table ? visible.replaceAll('|', '\\|') : visible) + ' ' + delimiter;
}

export function markdownLiteral(value: string): string {
  return markdownCodeSpan(value, false);
}

/** Apply the same literal encoding while protecting a GFM table cell boundary. */
export function markdownTableLiteral(value: string): string {
  return markdownCodeSpan(value, true);
}

/**
 * Serialise human-facing evidence with one documented visible-string
 * projection and an explicit representation for any byte arrays.
 */
export function stringifyTechnicalEvidence(value: unknown, space = 2): string {
  return JSON.stringify(
    value,
    (_key, entry: unknown) => {
      if (isProjectedTechnicalText(entry)) return entry.value;
      if (typeof entry === 'string') {
        return escapeTechnicalText(entry);
      }
      if (entry instanceof Uint8Array) {
        return {
          encoding: 'base64',
          octets: entry.length,
          value: bytesBase64(entry),
        };
      }
      return entry;
    },
    space,
  );
}
