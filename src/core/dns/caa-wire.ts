export interface CaaWireData {
  readonly flags: number;
  readonly issuerCritical: boolean;
  readonly tag: string;
  readonly value: string;
}

function safePresentation(bytes: Uint8Array): string {
  return [...bytes]
    .map((byte) =>
      byte >= 0x20 && byte <= 0x7e && byte !== 0x5c
        ? String.fromCharCode(byte)
        : `\\${String(byte).padStart(3, '0')}`,
    )
    .join('');
}

/** Parse CAA semantics only from the bounded RDATA octets covered by DNSSEC. */
export function parseCaaWireData(raw: Uint8Array): CaaWireData | null {
  const flags = raw[0];
  const tagLength = raw[1];
  if (
    flags === undefined ||
    tagLength === undefined ||
    tagLength < 1 ||
    tagLength > 15 ||
    2 + tagLength > raw.length
  )
    return null;
  const tag = raw.slice(2, 2 + tagLength);
  if (
    !tag.every(
      (byte) =>
        (byte >= 0x30 && byte <= 0x39) ||
        (byte >= 0x41 && byte <= 0x5a) ||
        (byte >= 0x61 && byte <= 0x7a),
    )
  )
    return null;
  return {
    flags,
    issuerCritical: Boolean(flags & 0x80),
    tag: safePresentation(tag),
    value: safePresentation(raw.slice(2 + tagLength)),
  };
}
