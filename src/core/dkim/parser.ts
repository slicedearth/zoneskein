import type { DkimDiagnostic, DkimKeyInspection, DkimKeyRecord } from './types';

function diagnostic(
  code: string,
  message: string,
  severity: DkimDiagnostic['severity'] = 'error',
): DkimDiagnostic {
  return { code, message, severity };
}

function decodeBase64(value: string): Uint8Array | null {
  if (value === '') return new Uint8Array();
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(value) || value.length % 4 === 1) return null;
  try {
    const binary = atob(value);
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

export function validateDkimSelector(selector: string): string | null {
  const value = selector.trim();
  if (value.length === 0 || value.length > 63) return 'Selector must contain 1–63 characters.';
  if (!/^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$/u.test(value)) {
    return 'Selector contains characters that are not valid in a DNS label.';
  }
  return null;
}

export function parseDkimKeyRecord(record: string): DkimKeyRecord {
  const diagnostics: DkimDiagnostic[] = [];
  const tags: Record<string, string> = {};
  for (const segment of record.split(';')) {
    const value = segment.trim();
    if (value === '') continue;
    const equals = value.indexOf('=');
    if (equals < 1) {
      diagnostics.push(diagnostic('tag-malformed', `Malformed DKIM tag segment: ${value}.`));
      continue;
    }
    const name = value.slice(0, equals).trim().toLowerCase();
    if (Object.hasOwn(tags, name))
      diagnostics.push(diagnostic('tag-duplicate', `DKIM tag ${name} appears more than once.`));
    tags[name] = value.slice(equals + 1).replaceAll(/\s+/gu, '');
  }
  if (tags['v'] !== undefined && tags['v'].toUpperCase() !== 'DKIM1')
    diagnostics.push(diagnostic('version-invalid', 'v must be DKIM1 when present.'));
  const keyType = (tags['k'] ?? 'rsa').toLowerCase();
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
  const flags = (tags['t'] ?? '').split(':').filter(Boolean);
  const known = new Set(['v', 'h', 'k', 'n', 'p', 's', 't']);
  for (const name of Object.keys(tags).filter((item) => !known.has(item)))
    diagnostics.push(diagnostic('tag-unknown', `Unknown DKIM key tag ${name}.`, 'information'));
  return {
    diagnostics,
    hashAlgorithms: (tags['h'] ?? 'sha256').split(':').filter(Boolean),
    ...(keyBytes === null ? {} : { keyBytes }),
    keyType,
    ...(tags['n'] === undefined ? {} : { notes: tags['n'] }),
    record,
    revoked: keyBytes?.length === 0,
    services: (tags['s'] ?? '*').split(':').filter(Boolean),
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
    const cryptoKey = await crypto.subtle.importKey(
      'spki',
      asArrayBuffer(key.keyBytes),
      { hash: 'SHA-256', name: 'RSASSA-PKCS1-v1_5' },
      true,
      ['verify'],
    );
    const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);
    if (jwk.n === undefined)
      return { message: 'RSA modulus could not be inspected.', status: 'invalid' };
    const bits = Math.max(0, Math.floor((jwk.n.replace(/=+$/u, '').length * 6) / 8) * 8);
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
