import { canonicalMasterName, masterNameEquals } from './master-name';
import { parseZoneSnippet, ZONE_ANALYSIS_LIMITS } from './parser';
import { canonicalRecordRdata } from './zonemd';
import type { ZoneToken } from './types';

export interface ExpectedBindRecord {
  readonly owner: string;
  readonly type: string;
  readonly ttl?: number;
  readonly txtValue?: string;
  readonly txtChunks?: readonly string[];
  /** Intended semantic fields, captured before rendering BIND. Required for non-TXT. */
  readonly rdata?: readonly ZoneToken[];
}

/** Plain numeric/name fields or literal character-string octets, without parsing emitted BIND. */
export function intendedRdataTokens(
  fields: readonly (string | number | { readonly text: string })[],
): readonly ZoneToken[] {
  return fields.map((field) => {
    const quoted = typeof field === 'object';
    const value = quoted ? field.text : String(field);
    const raw = quoted
      ? `"${Array.from(new TextEncoder().encode(value), (byte) => `\\${String(byte).padStart(3, '0')}`).join('')}"`
      : value;
    return { column: 1, line: 1, quoted, raw, value };
  });
}

/** Offline, fail-closed check of the exact text offered for copying or download. */
export function verifyBindRecord(bind: string, expected: ExpectedBindRecord): string | null {
  if (bind.length > ZONE_ANALYSIS_LIMITS.characters)
    return 'Generated BIND exceeds the parser bound.';
  if (new TextDecoder().decode(new TextEncoder().encode(bind)) !== bind)
    return 'Generated BIND contains text that cannot survive UTF-8 roundtrip.';
  // A placeholder origin resolves @ without making a claim about a deployment zone.
  const origin = 'export.invalid.';
  const parsed = parseZoneSnippet(bind, { origin });
  const record = parsed.records[0];
  if (
    parsed.incomplete !== undefined ||
    parsed.diagnostics.some((item) => item.severity === 'error') ||
    parsed.records.length !== 1 ||
    record === undefined
  )
    return 'Generated BIND did not parse as exactly one complete record.';
  const owner = canonicalMasterName(record.owner);
  const intendedOwner = canonicalMasterName(expected.owner, origin);
  if (
    owner === null ||
    intendedOwner === null ||
    !masterNameEquals(owner, intendedOwner) ||
    record.type !== expected.type ||
    record.className !== 'IN' ||
    record.ttl !== expected.ttl
  )
    return 'Generated BIND changed the owner, type, class or TTL.';
  const encoded = canonicalRecordRdata(record);
  if (!encoded.ok) return `Generated BIND cannot be encoded exactly: ${encoded.reason}`;
  if (expected.type !== 'TXT' && expected.rdata === undefined)
    return 'Intended typed RDATA is required to verify non-TXT output.';
  if (expected.rdata !== undefined) {
    const intended = canonicalRecordRdata({ ...record, rdata: expected.rdata });
    if (!intended.ok) return `Intended RDATA cannot be encoded exactly: ${intended.reason}`;
    if (
      encoded.bytes.length !== intended.bytes.length ||
      encoded.bytes.some((byte, index) => byte !== intended.bytes[index])
    )
      return 'Generated BIND changed the intended canonical RDATA.';
  }
  if (
    expected.txtValue !== undefined &&
    record.rdata.map((token) => token.value).join('') !== expected.txtValue
  )
    return 'Generated TXT strings do not reproduce the intended value byte for byte.';
  if (
    expected.txtChunks !== undefined &&
    JSON.stringify(record.rdata.map((token) => token.value)) !==
      JSON.stringify(expected.txtChunks)
  )
    return 'Generated TXT character-string boundaries changed during parsing.';
  return null;
}
