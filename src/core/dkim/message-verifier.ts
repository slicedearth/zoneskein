import { validateDnsName } from '../dns/names';
import {
  importDkimRsaPublicKey,
  inspectDkimKey,
  parseDkimKeyRecord,
  validateDkimSelector,
} from './parser';
import type {
  DkimCanonicalisation,
  DkimDiagnostic,
  DkimKeyRecord,
  DkimMessage,
  DkimMessageHeader,
  DkimSignature,
  DkimSignatureVerification,
} from './types';

export const MAX_DKIM_MESSAGE_BYTES = 1_048_576;
const MAX_HEADERS = 1000;
const MAX_HEADER_CHARACTERS = 65_536;
const MAX_SIGNATURES = 20;
const MAX_CLOCK_SKEW_SECONDS = 300;
const encoder = new TextEncoder();

export interface DkimKeyLookupResult {
  readonly error?: string;
  readonly records: readonly string[];
  readonly temporary: boolean;
}

export type DkimKeyLookup = (name: string) => Promise<DkimKeyLookupResult>;

function diagnostic(
  code: string,
  message: string,
  severity: DkimDiagnostic['severity'] = 'error',
): DkimDiagnostic {
  return { code, message, severity };
}

function networkLines(value: string): string {
  return value.replaceAll(/\r\n|\r|\n/gu, '\r\n');
}

function binaryString(bytes: Uint8Array): string {
  let value = '';
  const chunkSize = 32_768;
  for (let offset = 0; offset < bytes.length; offset += chunkSize)
    value += String.fromCharCode(...bytes.slice(offset, offset + chunkSize));
  return value;
}

function binaryBytes(value: string): Uint8Array {
  return Uint8Array.from(value, (character) => character.charCodeAt(0));
}

function decodeBase64(value: string): Uint8Array | null {
  const compact = value.replaceAll(/[ \t\r\n]/gu, '');
  if (compact === '' || !/^[A-Za-z0-9+/]+={0,2}$/u.test(compact) || compact.length % 4 === 1)
    return null;
  try {
    return Uint8Array.from(atob(compact), (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.length);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function base64(bytes: ArrayBuffer): string {
  let binary = '';
  for (const value of new Uint8Array(bytes)) binary += String.fromCharCode(value);
  return btoa(binary);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1)
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  return difference === 0;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  signal?.throwIfAborted();
}

export function parseDkimMessage(source: string | Uint8Array): DkimMessage {
  const sourceBytes = typeof source === 'string' ? encoder.encode(source) : source;
  if (sourceBytes.length > MAX_DKIM_MESSAGE_BYTES)
    throw new Error(
      `Message input exceeds the ${MAX_DKIM_MESSAGE_BYTES.toLocaleString()}-byte safety limit.`,
    );
  const original = binaryString(sourceBytes);
  const normalised = networkLines(original);
  const boundary = normalised.indexOf('\r\n\r\n');
  if (boundary < 0) throw new Error('The message needs a blank line between headers and body.');
  const headerBlock = normalised.slice(0, boundary);
  if (headerBlock.length > MAX_HEADER_CHARACTERS)
    throw new Error('The message header block exceeds the safety limit.');
  const rawHeaders: string[] = [];
  for (const line of headerBlock.split('\r\n')) {
    if (/^[ \t]/u.test(line)) {
      const index = rawHeaders.length - 1;
      const previous = rawHeaders[index];
      if (previous === undefined)
        throw new Error('A header continuation has no preceding field.');
      rawHeaders[index] = `${previous}\r\n${line}`;
    } else rawHeaders.push(line);
    if (rawHeaders.length > MAX_HEADERS)
      throw new Error('The message contains too many headers.');
  }
  const headers: DkimMessageHeader[] = rawHeaders.map((raw) => {
    const colon = raw.indexOf(':');
    if (colon <= 0 || !/^[!-9;-~]+$/u.test(raw.slice(0, colon)))
      throw new Error('The message contains a malformed header field.');
    return {
      name: raw.slice(0, colon),
      raw,
      value: raw.slice(colon + 1),
    };
  });
  return {
    body: normalised.slice(boundary + 4),
    headers,
    lineEndingsNormalised: normalised !== original,
    sourceOctets: sourceBytes.length,
  };
}

function tagList(value: string): {
  readonly diagnostics: readonly DkimDiagnostic[];
  readonly tags: Readonly<Record<string, string>>;
} {
  const diagnostics: DkimDiagnostic[] = [];
  const tags: Record<string, string> = {};
  const unfolded = value.replaceAll(/\r\n[ \t]+/gu, ' ');
  for (const segment of unfolded.split(';')) {
    if (segment.trim() === '') continue;
    const equals = segment.indexOf('=');
    if (equals < 1) {
      diagnostics.push(
        diagnostic('signature-tag-malformed', 'A DKIM signature tag is malformed.'),
      );
      continue;
    }
    const name = segment.slice(0, equals).trim();
    if (!/^[A-Za-z][A-Za-z0-9_]*$/u.test(name)) {
      diagnostics.push(
        diagnostic('signature-tag-name', `DKIM signature tag ${name} is invalid.`),
      );
      continue;
    }
    if (Object.hasOwn(tags, name))
      diagnostics.push(
        diagnostic('signature-tag-duplicate', `DKIM signature tag ${name} is repeated.`),
      );
    else tags[name] = segment.slice(equals + 1).trim();
  }
  return { diagnostics, tags };
}

function canonicalisation(value: string | undefined): {
  readonly body: DkimCanonicalisation;
  readonly header: DkimCanonicalisation;
} | null {
  const [header = 'simple', body = 'simple', extra] = (value ?? 'simple/simple')
    .toLowerCase()
    .split('/');
  return extra !== undefined ||
    (header !== 'simple' && header !== 'relaxed') ||
    (body !== 'simple' && body !== 'relaxed')
    ? null
    : { body, header };
}

function seconds(value: string | undefined): number | undefined | null {
  if (value === undefined) return undefined;
  if (!/^\d{1,12}$/u.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

const AUID_ATOM_PART = /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+$/u;

function decodeDkimQuotedPrintable(value: string): string | null {
  const compact = value.replaceAll(/[ \t]/gu, '');
  let decoded = '';
  for (let index = 0; index < compact.length; index += 1) {
    const character = compact.charAt(index);
    if (character === '=') {
      const hexadecimal = compact.slice(index + 1, index + 3);
      if (!/^[0-9A-F]{2}$/u.test(hexadecimal)) return null;
      decoded += String.fromCharCode(Number.parseInt(hexadecimal, 16));
      index += 2;
      continue;
    }
    const code = compact.charCodeAt(index);
    if (!((code >= 0x21 && code <= 0x3a) || code === 0x3c || (code >= 0x3e && code <= 0x7e)))
      return null;
    decoded += character;
  }
  return decoded;
}

function validAuidLocalPart(value: string): boolean {
  if (encoder.encode(value).length > 64) return false;
  const dotString = value.split('.');
  if (dotString.length > 0 && dotString.every((part) => AUID_ATOM_PART.test(part))) return true;
  if (!value.startsWith('"') || !value.endsWith('"')) return false;
  for (let index = 1; index < value.length - 1; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x5c) {
      index += 1;
      const escaped = value.charCodeAt(index);
      if (index >= value.length - 1 || escaped < 0x20 || escaped > 0x7e) return false;
      continue;
    }
    if (
      code === 0x20 ||
      code === 0x21 ||
      (code >= 0x23 && code <= 0x5b) ||
      (code >= 0x5d && code <= 0x7e)
    )
      continue;
    return false;
  }
  return true;
}

function parseAuid(
  value: string,
): { readonly domain: string; readonly identity: string } | null {
  const decoded = decodeDkimQuotedPrintable(value);
  if (decoded === null) return null;
  const separator = decoded.lastIndexOf('@');
  if (separator < 0) return null;
  const localPart = decoded.slice(0, separator);
  const domain = decoded.slice(separator + 1).toLowerCase();
  if (localPart !== '' && !validAuidLocalPart(localPart)) return null;
  const parsedDomain = validateDnsName(domain);
  if (
    !parsedDomain.ok ||
    domain !== parsedDomain.value.ascii ||
    !parsedDomain.value.ascii.includes('.') ||
    parsedDomain.value.ascii
      .split('.')
      .some((label) => !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))
  )
    return null;
  return {
    domain: parsedDomain.value.ascii,
    identity: `${localPart}@${parsedDomain.value.ascii}`,
  };
}

export function parseDkimSignature(header: DkimMessageHeader): DkimSignature {
  const parsed = tagList(header.value);
  const diagnostics = [...parsed.diagnostics];
  const tags = parsed.tags;
  const canonical = canonicalisation(tags['c']);
  if (canonical === null)
    diagnostics.push(
      diagnostic(
        'canonicalisation-unsupported',
        'c must use simple or relaxed canonicalisation.',
        'warning',
      ),
    );
  if (tags['v'] !== '1') diagnostics.push(diagnostic('signature-version', 'v must be 1.'));
  for (const required of ['a', 'b', 'bh', 'd', 'h', 's'])
    if (tags[required] === undefined)
      diagnostics.push(diagnostic('signature-required', `${required}= is required.`));
  const headerNames = (tags['h'] ?? '')
    .split(':')
    .map((name) => name.trim().toLowerCase())
    .filter(Boolean);
  if (headerNames.length === 0 || headerNames.some((name) => !/^[!-9;-~]+$/u.test(name)))
    diagnostics.push(diagnostic('signature-headers', 'h must list valid header field names.'));
  if (headerNames.length > MAX_HEADERS)
    diagnostics.push(
      diagnostic(
        'signature-header-limit',
        `h exceeds the ${String(MAX_HEADERS)}-field verification limit.`,
      ),
    );
  if (!headerNames.includes('from'))
    diagnostics.push(diagnostic('signature-from', 'h must sign the From header field.'));
  const algorithm = (tags['a'] ?? '').toLowerCase();
  if (
    tags['a'] !== undefined &&
    !/^[A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9]*$/u.test(tags['a'])
  )
    diagnostics.push(diagnostic('signature-algorithm-syntax', 'a has invalid syntax.'));
  if (tags['b'] !== undefined && decodeBase64(tags['b']) === null)
    diagnostics.push(diagnostic('signature-data-base64', 'b is not valid Base64 data.'));
  if (tags['bh'] !== undefined && decodeBase64(tags['bh']) === null)
    diagnostics.push(diagnostic('signature-body-hash-base64', 'bh is not valid Base64 data.'));
  const signedAt = seconds(tags['t']);
  const expiresAt = seconds(tags['x']);
  if (signedAt === null || expiresAt === null)
    diagnostics.push(
      diagnostic('signature-time', 't and x must be unsigned timestamps of at most 12 digits.'),
    );
  if (typeof signedAt === 'number' && typeof expiresAt === 'number' && expiresAt <= signedAt)
    diagnostics.push(diagnostic('signature-time-order', 'x must be later than t.'));
  const length = seconds(tags['l']);
  if (length === null)
    diagnostics.push(diagnostic('signature-length', 'l must be a bounded unsigned integer.'));
  const domain = (tags['d'] ?? '').toLowerCase();
  const selector = (tags['s'] ?? '').toLowerCase();
  const keyName = validateDnsName(`${selector}._domainkey.${domain}`);
  const domainLabels = domain.split('.');
  if (
    domain === '' ||
    selector === '' ||
    validateDkimSelector(selector) !== null ||
    /[^\x21-\x7e]/u.test(`${domain}${selector}`) ||
    domainLabels.length < 2 ||
    domainLabels.some((label) => !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label)) ||
    !keyName.ok
  )
    diagnostics.push(
      diagnostic('signature-key-name', 'd and s must form a valid DNS key name.'),
    );
  const identity = tags['i'] === undefined ? undefined : parseAuid(tags['i']);
  if (tags['i'] !== undefined) {
    if (
      identity === null ||
      identity === undefined ||
      (identity.domain !== domain && !identity.domain.endsWith(`.${domain}`))
    )
      diagnostics.push(
        diagnostic(
          'signature-identity',
          'i must contain one AUID whose domain is equal to or below d.',
        ),
      );
  }
  const queryMethods = (tags['q'] ?? 'dns/txt')
    .split(':')
    .map((value) => value.trim().toLowerCase());
  if (
    queryMethods.some((value) => !/^[a-z](?:[a-z0-9-]*[a-z0-9])?(?:\/[^\s;]*)?$/u.test(value))
  )
    diagnostics.push(diagnostic('signature-query-syntax', 'q has invalid query syntax.'));
  return {
    algorithm,
    bodyCanonicalisation: canonical?.body ?? 'simple',
    bodyHash: tags['bh'] ?? '',
    diagnostics,
    domain,
    ...(typeof expiresAt === 'number' ? { expiresAt } : {}),
    headerCanonicalisation: canonical?.header ?? 'simple',
    headerNames,
    ...(identity === null || identity === undefined ? {} : { identity: identity.identity }),
    ...(typeof length === 'number' ? { length } : {}),
    queryMethods,
    selector,
    signatureData: tags['b'] ?? '',
    ...(typeof signedAt === 'number' ? { signedAt } : {}),
    tags,
    valid: !diagnostics.some((item) => item.severity === 'error'),
  };
}

export function canonicaliseDkimBody(body: string, mode: DkimCanonicalisation): string {
  const lines = networkLines(body).split('\r\n');
  while (lines.at(-1) === '') lines.pop();
  if (mode === 'relaxed') {
    const canonical = lines.map((line) =>
      line.replaceAll(/[ \t]+/gu, ' ').replace(/[ \t]+$/u, ''),
    );
    while (canonical.at(-1) === '') canonical.pop();
    return canonical.length === 0 ? '' : `${canonical.join('\r\n')}\r\n`;
  }
  return `${lines.join('\r\n')}\r\n`;
}

export function canonicaliseDkimHeader(
  header: DkimMessageHeader,
  mode: DkimCanonicalisation,
): string {
  if (mode === 'simple') return `${header.raw}\r\n`;
  const value = header.value
    .replaceAll(/\r\n[ \t]+/gu, ' ')
    .replaceAll(/[ \t]+/gu, ' ')
    .replace(/^[ \t]+|[ \t]+$/gu, '');
  return `${header.name.toLowerCase()}:${value}\r\n`;
}

function skipDkimFws(value: string, start: number, end: number): number {
  let index = start;
  while (index < end) {
    const character = value[index];
    if (character === ' ' || character === '\t') {
      index += 1;
      continue;
    }
    if (
      character === '\r' &&
      value[index + 1] === '\n' &&
      (value[index + 2] === ' ' || value[index + 2] === '\t')
    ) {
      index += 3;
      continue;
    }
    break;
  }
  return index;
}

function signatureValueEnd(value: string, start: number, end: number): number {
  let index = start;
  while (index < end) {
    const codeUnit = value.charCodeAt(index);
    const base64Character =
      (codeUnit >= 0x41 && codeUnit <= 0x5a) ||
      (codeUnit >= 0x61 && codeUnit <= 0x7a) ||
      (codeUnit >= 0x30 && codeUnit <= 0x39) ||
      codeUnit === 0x2b ||
      codeUnit === 0x2f ||
      codeUnit === 0x3d;
    if (base64Character || value[index] === ' ' || value[index] === '\t') {
      index += 1;
      continue;
    }
    if (
      value[index] === '\r' &&
      value[index + 1] === '\n' &&
      (value[index + 2] === ' ' || value[index + 2] === '\t')
    ) {
      index += 3;
      continue;
    }
    break;
  }
  return index;
}

function signatureValueRange(
  value: string,
): { readonly end: number; readonly start: number } | null {
  let segmentStart = 0;
  while (segmentStart <= value.length) {
    const separator = value.indexOf(';', segmentStart);
    const segmentEnd = separator < 0 ? value.length : separator;
    let index = skipDkimFws(value, segmentStart, segmentEnd);
    if (value[index] === 'b') {
      index = skipDkimFws(value, index + 1, segmentEnd);
      if (value[index] === '=') {
        const start = index + 1;
        return { end: signatureValueEnd(value, start, segmentEnd), start };
      }
    }
    if (separator < 0) break;
    segmentStart = separator + 1;
  }
  return null;
}

function withoutSignatureValue(header: DkimMessageHeader): DkimMessageHeader {
  const range = signatureValueRange(header.value);
  const value =
    range === null
      ? header.value
      : `${header.value.slice(0, range.start)}${header.value.slice(range.end)}`;
  const colon = header.raw.indexOf(':');
  const raw = `${header.raw.slice(0, colon + 1)}${value}`;
  return { name: header.name, raw, value };
}

function selectedHeaders(
  message: DkimMessage,
  names: readonly string[],
  excluded: DkimMessageHeader,
): readonly DkimMessageHeader[] | null {
  const nextIndex = new Map<string, number>();
  const selected: DkimMessageHeader[] = [];
  for (const name of names) {
    let found = -1;
    for (
      let index = nextIndex.get(name) ?? message.headers.length - 1;
      index >= 0;
      index -= 1
    ) {
      const candidate = message.headers[index];
      if (candidate !== excluded && candidate?.name.toLowerCase() === name) {
        found = index;
        break;
      }
    }
    if (found < 0) continue;
    nextIndex.set(name, found - 1);
    const header = message.headers[found];
    if (header === undefined) return null;
    selected.push(header);
  }
  return selected;
}

async function importKey(key: DkimKeyRecord, algorithm: string): Promise<CryptoKey | null> {
  if (key.keyBytes === undefined) return null;
  if (algorithm === 'ed25519-sha256' && key.keyType === 'ed25519')
    return crypto.subtle.importKey(
      'raw',
      asArrayBuffer(key.keyBytes),
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
  if (algorithm === 'rsa-sha256' && key.keyType === 'rsa')
    return importDkimRsaPublicKey(key.keyBytes);
  return null;
}

export async function verifyDkimSignature(
  message: DkimMessage,
  signatureHeader: DkimMessageHeader,
  lookup: DkimKeyLookup,
  now = new Date(),
  signal?: AbortSignal,
): Promise<DkimSignatureVerification> {
  throwIfAborted(signal);
  const signature = parseDkimSignature(signatureHeader);
  const keyName = `${signature.selector}._domainkey.${signature.domain}`;
  const base = {
    algorithm: signature.algorithm,
    bodyHashMatches: false,
    bodyCanonicalisation: signature.bodyCanonicalisation,
    canonicalBodyOctets: 0,
    domain: signature.domain,
    ...(signature.expiresAt === undefined ? {} : { expiresAt: signature.expiresAt }),
    headerCanonicalisation: signature.headerCanonicalisation,
    ...(signature.identity === undefined ? {} : { identity: signature.identity }),
    keyName,
    ...(signature.length === undefined ? {} : { length: signature.length }),
    selector: signature.selector,
    ...(signature.signedAt === undefined ? {} : { signedAt: signature.signedAt }),
    signedHeaders: signature.headerNames,
  };
  if (!signature.valid)
    return {
      ...base,
      reason: signature.diagnostics.map((item) => item.message).join(' '),
      status: 'permerror',
    };
  if (signature.diagnostics.some((item) => item.code === 'canonicalisation-unsupported'))
    return {
      ...base,
      reason: 'The signature uses an unsupported canonicalisation algorithm.',
      status: 'unsupported',
    };
  if (signature.algorithm !== 'rsa-sha256' && signature.algorithm !== 'ed25519-sha256')
    return {
      ...base,
      reason: `Algorithm ${signature.algorithm} is not supported.`,
      status: 'unsupported',
    };
  if (!signature.queryMethods.includes('dns/txt'))
    return {
      ...base,
      reason: 'The signature offers no supported dns/txt key query method.',
      status: 'unsupported',
    };
  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (
    signature.signedAt !== undefined &&
    signature.signedAt > nowSeconds + MAX_CLOCK_SKEW_SECONDS
  )
    return {
      ...base,
      reason: 'The DKIM signature timestamp is more than five minutes in the future.',
      status: 'fail',
    };
  if (signature.expiresAt !== undefined && nowSeconds > signature.expiresAt)
    return { ...base, reason: 'The DKIM signature has expired.', status: 'fail' };
  const canonicalBody = canonicaliseDkimBody(message.body, signature.bodyCanonicalisation);
  const bodyBytes = binaryBytes(canonicalBody);
  if (signature.length !== undefined && signature.length > bodyBytes.length)
    return {
      ...base,
      canonicalBodyOctets: bodyBytes.length,
      reason: 'l exceeds the canonical message body length.',
      status: 'permerror',
    };
  const hashedBody =
    signature.length === undefined ? bodyBytes : bodyBytes.slice(0, signature.length);
  const expectedBodyHash = decodeBase64(signature.bodyHash);
  if (expectedBodyHash?.length !== 32)
    return {
      ...base,
      canonicalBodyOctets: bodyBytes.length,
      reason: 'bh must contain one 32-octet SHA-256 digest.',
      status: 'permerror',
    };
  const observedBodyHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', asArrayBuffer(hashedBody)),
  );
  throwIfAborted(signal);
  const bodyHashMatches = equalBytes(expectedBodyHash, observedBodyHash);
  const withBody = { ...base, bodyHashMatches, canonicalBodyOctets: bodyBytes.length };
  if (!bodyHashMatches)
    return {
      ...withBody,
      reason: 'The canonical body hash does not match bh.',
      status: 'fail',
    };
  const selected = selectedHeaders(message, signature.headerNames, signatureHeader);
  if (selected === null)
    return {
      ...withBody,
      reason: 'Signed message headers could not be selected safely.',
      status: 'permerror',
    };
  const fromHeaders = message.headers.filter((header) => header.name.toLowerCase() === 'from');
  if (fromHeaders.length !== 1)
    return {
      ...withBody,
      reason:
        fromHeaders.length === 0
          ? 'The message has no From header field to authenticate.'
          : 'The message has multiple From header fields and cannot be authenticated unambiguously.',
      status: 'permerror',
    };
  const headerInput = [
    ...selected.map((header) =>
      canonicaliseDkimHeader(header, signature.headerCanonicalisation),
    ),
    canonicaliseDkimHeader(
      withoutSignatureValue(signatureHeader),
      signature.headerCanonicalisation,
    ).slice(0, -2),
  ].join('');
  throwIfAborted(signal);
  const keyResult = await lookup(keyName);
  throwIfAborted(signal);
  if (keyResult.error !== undefined)
    return {
      ...withBody,
      reason: keyResult.error,
      status: keyResult.temporary ? 'temperror' : 'permerror',
    };
  if (keyResult.records.length !== 1)
    return {
      ...withBody,
      reason: `Expected one DKIM key record but observed ${String(keyResult.records.length)}.`,
      status: 'permerror',
    };
  const key = parseDkimKeyRecord(keyResult.records[0] ?? '');
  if (!key.valid || key.revoked)
    return {
      ...withBody,
      reason: key.revoked ? 'The DKIM key is revoked.' : 'The DKIM key record is invalid.',
      status: 'permerror',
    };
  const inspection = await inspectDkimKey(key);
  throwIfAborted(signal);
  const withKey = {
    ...withBody,
    ...(inspection.bits === undefined ? {} : { keyBits: inspection.bits }),
    ...(key.testing ? { keyTesting: true } : {}),
  };
  if (inspection.status === 'invalid' || inspection.status === 'revoked')
    return { ...withKey, reason: inspection.message, status: 'permerror' };
  if (inspection.status === 'unsupported')
    return { ...withKey, reason: inspection.message, status: 'unsupported' };
  if (!key.services.includes('*') && !key.services.includes('email'))
    return {
      ...withKey,
      reason: 'The DKIM key is not authorised for email.',
      status: 'permerror',
    };
  if (!key.hashAlgorithms.includes('*') && !key.hashAlgorithms.includes('sha256'))
    return {
      ...withKey,
      reason: 'The DKIM key does not permit SHA-256.',
      status: 'permerror',
    };
  const identityDomain = (signature.identity ?? `@${signature.domain}`)
    .slice((signature.identity ?? `@${signature.domain}`).lastIndexOf('@') + 1)
    .toLowerCase();
  if (key.selectorFlags.includes('s') && identityDomain !== signature.domain)
    return {
      ...withKey,
      reason: 'The key requires a strict AUID domain equal to the signing domain.',
      status: 'permerror',
    };
  try {
    const cryptoKey = await importKey(key, signature.algorithm);
    throwIfAborted(signal);
    const signatureBytes = decodeBase64(signature.signatureData);
    if (cryptoKey === null || signatureBytes === null)
      return {
        ...withKey,
        reason: 'The signature and key algorithms do not match.',
        status: 'permerror',
      };
    const algorithm =
      signature.algorithm === 'rsa-sha256'
        ? { name: 'RSASSA-PKCS1-v1_5' }
        : { name: 'Ed25519' };
    const headerBytes = binaryBytes(headerInput);
    const signedData =
      signature.algorithm === 'ed25519-sha256'
        ? new Uint8Array(await crypto.subtle.digest('SHA-256', asArrayBuffer(headerBytes)))
        : headerBytes;
    throwIfAborted(signal);
    const verified = await crypto.subtle.verify(
      algorithm,
      cryptoKey,
      asArrayBuffer(signatureBytes),
      asArrayBuffer(signedData),
    );
    throwIfAborted(signal);
    return {
      ...withKey,
      reason: verified
        ? `The body hash and message signature both verify${key.testing ? ' with a testing-mode key' : ''}${inspection.status === 'weak' ? ' using a legacy-size RSA key' : ''}.`
        : 'The message signature does not verify.',
      status: verified ? 'pass' : 'fail',
    };
  } catch (cause) {
    if (signal?.aborted === true) throw cause;
    return {
      ...withKey,
      reason: 'The DKIM public key could not be used by Web Crypto.',
      status: 'permerror',
    };
  }
}

export async function verifyDkimMessage(
  source: string | Uint8Array,
  lookup: DkimKeyLookup,
  now = new Date(),
  signal?: AbortSignal,
): Promise<readonly DkimSignatureVerification[]> {
  throwIfAborted(signal);
  const message = parseDkimMessage(source);
  return verifyParsedDkimMessage(message, lookup, now, signal);
}

export async function verifyParsedDkimMessage(
  message: DkimMessage,
  lookup: DkimKeyLookup,
  now = new Date(),
  signal?: AbortSignal,
): Promise<readonly DkimSignatureVerification[]> {
  throwIfAborted(signal);
  const signatures = message.headers.filter(
    (header) => header.name.toLowerCase() === 'dkim-signature',
  );
  if (signatures.length === 0) return [];
  if (signatures.length > MAX_SIGNATURES)
    throw new Error(`The message exceeds the ${String(MAX_SIGNATURES)}-signature work limit.`);
  const cache = new Map<string, Promise<DkimKeyLookupResult>>();
  const cachedLookup: DkimKeyLookup = (name) => {
    const existing = cache.get(name);
    if (existing !== undefined) return existing;
    const pending = lookup(name);
    cache.set(name, pending);
    return pending;
  };
  const results: DkimSignatureVerification[] = [];
  for (const header of signatures) {
    throwIfAborted(signal);
    results.push(await verifyDkimSignature(message, header, cachedLookup, now, signal));
  }
  return results;
}

export async function dkimBodyHash(body: string, mode: DkimCanonicalisation): Promise<string> {
  const binaryBody = binaryString(encoder.encode(body));
  return base64(
    await crypto.subtle.digest(
      'SHA-256',
      asArrayBuffer(binaryBytes(canonicaliseDkimBody(binaryBody, mode))),
    ),
  );
}
