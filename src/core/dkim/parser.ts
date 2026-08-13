import type { DkimDiagnostic, DkimKeyInspection, DkimKeyRecord } from './types';

const encoder = new TextEncoder();

function diagnostic(
  code: string,
  message: string,
  severity: DkimDiagnostic['severity'] = 'error',
): DkimDiagnostic {
  return { code, message, severity };
}

function decodeBase64(value: string): Uint8Array | null {
  const compact = value.replaceAll(/[ \t\r\n]/gu, '');
  if (compact === '') return new Uint8Array();
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(compact) || compact.length % 4 === 1) return null;
  try {
    const binary = atob(compact);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.length);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function concatenate(...parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function derLength(length: number): Uint8Array {
  if (length < 0x80) return Uint8Array.of(length);
  const octets: number[] = [];
  for (let remaining = length; remaining > 0; remaining = Math.floor(remaining / 0x100))
    octets.unshift(remaining & 0xff);
  return Uint8Array.of(0x80 | octets.length, ...octets);
}

function derValue(tag: number, value: Uint8Array): Uint8Array {
  return concatenate(Uint8Array.of(tag), derLength(value.length), value);
}

function wrapPkcs1RsaPublicKey(key: Uint8Array): Uint8Array {
  const rsaEncryptionIdentifier = Uint8Array.of(
    0x30,
    0x0d,
    0x06,
    0x09,
    0x2a,
    0x86,
    0x48,
    0x86,
    0xf7,
    0x0d,
    0x01,
    0x01,
    0x01,
    0x05,
    0x00,
  );
  const bitString = derValue(0x03, concatenate(Uint8Array.of(0), key));
  return derValue(0x30, concatenate(rsaEncryptionIdentifier, bitString));
}

/** Import either interoperable DKIM RSA p= encoding: SPKI or bare PKCS #1 RSAPublicKey. */
export async function importDkimRsaPublicKey(
  keyBytes: Uint8Array,
  extractable = false,
): Promise<CryptoKey> {
  const algorithm = { hash: 'SHA-256', name: 'RSASSA-PKCS1-v1_5' } as const;
  try {
    return await crypto.subtle.importKey(
      'spki',
      asArrayBuffer(keyBytes),
      algorithm,
      extractable,
      ['verify'],
    );
  } catch {
    return crypto.subtle.importKey(
      'spki',
      asArrayBuffer(wrapPkcs1RsaPublicKey(keyBytes)),
      algorithm,
      extractable,
      ['verify'],
    );
  }
}

function rsaModulusBits(value: string): number {
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
  const bytes = decodeBase64(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='));
  const first = bytes?.[0];
  return bytes === null || first === undefined
    ? 0
    : (bytes.length - 1) * 8 + (32 - Math.clz32(first));
}

export function validateDkimSelector(selector: string): string | null {
  const value = selector.trim();
  if (value.length === 0 || encoder.encode(value).length > 253)
    return 'Selector must contain 1–253 octets.';
  const labels = value.split('.');
  if (
    labels.some(
      (label) =>
        encoder.encode(label).length === 0 ||
        encoder.encode(label).length > 63 ||
        !/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(label),
    )
  ) {
    return 'Selector components must be LDH DNS labels of at most 63 octets.';
  }
  return null;
}

export function parseDkimKeyRecord(record: string): DkimKeyRecord {
  const diagnostics: DkimDiagnostic[] = [];
  const tags: Record<string, string> = {};
  let firstTag: string | undefined;
  for (const segment of record.split(';')) {
    const value = segment.trim();
    if (value === '') continue;
    const equals = value.indexOf('=');
    if (equals < 1) {
      diagnostics.push(diagnostic('tag-malformed', `Malformed DKIM tag segment: ${value}.`));
      continue;
    }
    const name = value.slice(0, equals).trim();
    if (!/^[A-Za-z][A-Za-z0-9_]*$/u.test(name)) {
      diagnostics.push(diagnostic('tag-name', `DKIM tag name ${name} is invalid.`));
      continue;
    }
    firstTag ??= name;
    if (Object.hasOwn(tags, name))
      diagnostics.push(diagnostic('tag-duplicate', `DKIM tag ${name} appears more than once.`));
    tags[name] = value.slice(equals + 1).trim();
  }
  if (tags['v'] !== undefined && tags['v'] !== 'DKIM1')
    diagnostics.push(diagnostic('version-invalid', 'v must be DKIM1 when present.'));
  if (tags['v'] !== undefined && firstTag !== 'v')
    diagnostics.push(diagnostic('version-order', 'v must be the first DKIM key tag.'));
  const keyType = (tags['k'] ?? 'rsa').toLowerCase();
  if (!/^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(tags['k'] ?? 'rsa'))
    diagnostics.push(diagnostic('key-type-syntax', 'k must contain a valid key type name.'));
  if (keyType !== 'rsa' && keyType !== 'ed25519')
    diagnostics.push(
      diagnostic(
        'key-type-unsupported',
        `DKIM key type ${keyType} is not supported.`,
        'warning',
      ),
    );
  const publicKey = tags['p'];
  if (publicKey === undefined)
    diagnostics.push(
      diagnostic('public-key-missing', 'p containing the public key is required.'),
    );
  const keyBytes = publicKey === undefined ? null : decodeBase64(publicKey);
  if (keyBytes === null)
    diagnostics.push(diagnostic('public-key-base64', 'p is not valid Base64 key data.'));
  const flags = (tags['t'] ?? '')
    .toLowerCase()
    .split(':')
    .map((value) => value.trim())
    .filter(Boolean);
  const listSyntax =
    /^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?::[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$/u;
  const serviceListSyntax =
    /^(?:\*|[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?)(?::(?:\*|[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?))*$/u;
  if (tags['h'] !== undefined && !listSyntax.test(tags['h'].replaceAll(/[ \t]/gu, '')))
    diagnostics.push(
      diagnostic('hash-list-syntax', 'h must list one or more hash algorithms.'),
    );
  if (tags['s'] !== undefined && !serviceListSyntax.test(tags['s'].replaceAll(/[ \t]/gu, '')))
    diagnostics.push(
      diagnostic('service-list-syntax', 's must list one or more service types.'),
    );
  if (tags['t'] !== undefined && !listSyntax.test(tags['t'].replaceAll(/[ \t]/gu, '')))
    diagnostics.push(diagnostic('flag-list-syntax', 't must list one or more selector flags.'));
  const known = new Set(['v', 'h', 'k', 'n', 'p', 's', 't']);
  for (const name of Object.keys(tags).filter((item) => !known.has(item)))
    diagnostics.push(diagnostic('tag-unknown', `Unknown DKIM key tag ${name}.`, 'information'));
  return {
    diagnostics,
    hashAlgorithms:
      tags['h'] === undefined
        ? ['*']
        : tags['h']
            .toLowerCase()
            .split(':')
            .map((value) => value.trim())
            .filter(Boolean),
    ...(keyBytes === null ? {} : { keyBytes }),
    keyType,
    ...(tags['n'] === undefined ? {} : { notes: tags['n'] }),
    record,
    revoked: keyBytes?.length === 0,
    selectorFlags: flags,
    services: (tags['s'] ?? '*')
      .toLowerCase()
      .split(':')
      .map((value) => value.trim())
      .filter(Boolean),
    tags,
    testing: flags.includes('y'),
    valid: !diagnostics.some((item) => item.severity === 'error'),
  };
}

export async function inspectDkimKey(key: DkimKeyRecord): Promise<DkimKeyInspection> {
  if (key.revoked)
    return { message: 'The empty p value marks this selector as revoked.', status: 'revoked' };
  if (key.keyBytes === undefined)
    return { message: 'No decodable public key is available.', status: 'invalid' };
  try {
    if (key.keyType === 'ed25519') {
      if (key.keyBytes.length !== 32)
        return { message: 'An Ed25519 DKIM public key must be 32 bytes.', status: 'invalid' };
      await crypto.subtle.importKey(
        'raw',
        asArrayBuffer(key.keyBytes),
        { name: 'Ed25519' },
        false,
        ['verify'],
      );
      return {
        bits: 256,
        message: 'The Ed25519 public key is structurally valid.',
        status: 'valid',
      };
    }
    if (key.keyType !== 'rsa')
      return {
        message: `Local inspection does not support ${key.keyType}.`,
        status: 'unsupported',
      };
    const cryptoKey = await importDkimRsaPublicKey(key.keyBytes, true);
    const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);
    if (jwk.n === undefined)
      return { message: 'RSA modulus could not be inspected.', status: 'invalid' };
    const bits = rsaModulusBits(jwk.n);
    return bits < 1024
      ? {
          bits,
          message: 'RSA key is below 1024 bits and should not be used.',
          status: 'invalid',
        }
      : bits < 2048
        ? {
            bits,
            message: 'RSA key is structurally valid but below the preferred 2048-bit size.',
            status: 'weak',
          }
        : { bits, message: 'RSA public key is structurally valid.', status: 'valid' };
  } catch {
    return {
      message: 'The public key could not be imported by Web Crypto.',
      status: 'invalid',
    };
  }
}
