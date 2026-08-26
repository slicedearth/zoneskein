const textEncoder = new TextEncoder();

export interface CanonicalMasterName {
  readonly absolute: string;
  readonly labels: readonly Uint8Array[];
  readonly wire: Uint8Array;
}

interface ParsedPresentationName {
  readonly absolute: boolean;
  readonly labels: readonly Uint8Array[];
}

function join(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function canonicalLabel(bytes: readonly number[]): Uint8Array {
  return Uint8Array.from(bytes, (byte) => (byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte));
}

function parsePresentationName(raw: string): ParsedPresentationName | null {
  if (raw === '.') return { absolute: true, labels: [] };
  if (raw === '') return null;

  const labels: Uint8Array[] = [];
  let label: number[] = [];
  let absolute = false;
  for (let index = 0; index < raw.length;) {
    const character = raw[index];
    if (character === '"') return null;
    if (character === '.') {
      if (label.length === 0) return null;
      labels.push(canonicalLabel(label));
      label = [];
      index += 1;
      if (index === raw.length) absolute = true;
      continue;
    }
    if (character === '\\') {
      const next = raw[index + 1];
      if (next === undefined) return null;
      if (/\d/u.test(next)) {
        const digits = raw.slice(index + 1, index + 4);
        if (!/^\d{3}$/u.test(digits)) return null;
        const octet = Number(digits);
        if (octet > 255) return null;
        label.push(octet);
        index += 4;
        continue;
      }
      const codePoint = raw.codePointAt(index + 1);
      if (codePoint === undefined) return null;
      const literal = String.fromCodePoint(codePoint);
      label.push(...textEncoder.encode(literal));
      index += 1 + literal.length;
      continue;
    }
    const codePoint = raw.codePointAt(index);
    if (codePoint === undefined) return null;
    const literal = String.fromCodePoint(codePoint);
    label.push(...textEncoder.encode(literal));
    index += literal.length;
  }
  if (!absolute) {
    if (label.length === 0) return null;
    labels.push(canonicalLabel(label));
  }
  if (labels.some((item) => item.length === 0 || item.length > 63)) return null;
  return { absolute, labels };
}

function renderLabel(label: Uint8Array): string {
  let rendered = '';
  for (const byte of label) {
    const safe =
      (byte >= 0x61 && byte <= 0x7a) ||
      (byte >= 0x30 && byte <= 0x39) ||
      byte === 0x2a ||
      byte === 0x2d ||
      byte === 0x5f;
    rendered += safe ? String.fromCharCode(byte) : `\\${byte.toString(10).padStart(3, '0')}`;
  }
  return rendered;
}

function fromLabels(labels: readonly Uint8Array[]): CanonicalMasterName | null {
  if (labels.some((label) => label.length === 0 || label.length > 63)) return null;
  const wire = join([
    ...labels.map((label) => join([new Uint8Array([label.length]), label])),
    new Uint8Array([0]),
  ]);
  if (wire.length > 255) return null;
  return {
    absolute: labels.length === 0 ? '.' : `${labels.map(renderLabel).join('.')}.`,
    labels,
    wire,
  };
}

function absoluteOrigin(
  value: string | CanonicalMasterName | undefined,
): CanonicalMasterName | null {
  if (value === undefined) return null;
  if (typeof value !== 'string') return value;
  const parsed = parsePresentationName(value);
  return parsed?.absolute === true ? fromLabels(parsed.labels) : null;
}

/** Parse one raw master-file domain token without losing escaped separator provenance. */
export function canonicalMasterName(
  raw: string,
  origin?: string | CanonicalMasterName,
): CanonicalMasterName | null {
  const base = absoluteOrigin(origin);
  if (raw === '@') return base;
  const parsed = parsePresentationName(raw);
  if (parsed === null) return null;
  if (parsed.absolute) return fromLabels(parsed.labels);
  if (base === null) return null;
  return fromLabels([...parsed.labels, ...base.labels]);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

export function masterNameEquals(
  left: CanonicalMasterName,
  right: CanonicalMasterName,
): boolean {
  return equalBytes(left.wire, right.wire);
}

export function masterNameIsAtOrBelow(
  name: CanonicalMasterName,
  origin: CanonicalMasterName,
): boolean {
  if (name.labels.length < origin.labels.length) return false;
  const offset = name.labels.length - origin.labels.length;
  return origin.labels.every((label, index) => {
    const candidate = name.labels[offset + index];
    return candidate !== undefined && equalBytes(candidate, label);
  });
}
