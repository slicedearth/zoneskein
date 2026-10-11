import { canonicalMasterName, masterNameEquals } from './master-name';
import { parseZoneSnippet, ZONE_ANALYSIS_LIMITS } from './parser';
import { canonicalRecordRdata } from './zonemd';

export interface ExpectedBindRecord {
  readonly owner: string;
  readonly type: string;
  readonly ttl?: number;
  readonly txtValue?: string;
  readonly txtChunks?: readonly string[];
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
