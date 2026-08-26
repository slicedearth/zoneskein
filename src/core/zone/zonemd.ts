import { parseStrictIpAddress } from '../dns/ip';
import {
  canonicalMasterName,
  masterNameEquals,
  masterNameIsAtOrBelow,
  type CanonicalMasterName,
} from './master-name';
import { parseTtl } from './parser';
import { decodeBase64, svcbKeyNumber } from './svcb';
import type { ZoneDocument, ZoneRecord, ZoneToken } from './types';

const MAX_CANONICAL_ZONE_OCTETS = 2 * 1024 * 1024;
const MAX_RDATA_OCTETS = 65_535;

const TYPE_CODES: Readonly<Record<string, number>> = {
  A: 1,
  AAAA: 28,
  CAA: 257,
  CNAME: 5,
  DNAME: 39,
  DNSKEY: 48,
  DS: 43,
  HTTPS: 65,
  MX: 15,
  NAPTR: 35,
  NS: 2,
  NSEC: 47,
  NSEC3: 50,
  PTR: 12,
  RRSIG: 46,
  SOA: 6,
  SRV: 33,
  SSHFP: 44,
  SVCB: 64,
  TLSA: 52,
  TXT: 16,
  URI: 256,
  ZONEMD: 63,
};

const FATAL_PARSE_RULES = new Set([
  'directive-unsupported',
  'escape-decimal-malformed',
  'escape-decimal-range',
  'escape-malformed',
  'origin-invalid',
  'owner-invalid',
  'owner-missing',
  'record-incomplete',
  'syntax-parenthesis',
  'syntax-quote',
  'ttl-invalid',
]);

export type ZoneDigestState =
  'generated' | 'mismatch' | 'unavailable' | 'unsupported' | 'verified';

export interface ZoneDigestPublication {
  readonly digest?: string;
  readonly hashAlgorithm?: number;
  readonly hashName: string;
  readonly matches: boolean | null;
  readonly reason?: string;
  readonly scheme?: number;
  readonly serial?: number;
}

export interface ZoneDigestValue {
  readonly calculated: string;
  readonly hashAlgorithm: 1 | 2;
  readonly hashName: 'SHA-384' | 'SHA-512';
  readonly publications: readonly ZoneDigestPublication[];
}

export interface SuggestedZoneDigestRecord {
  readonly digest: string;
  readonly hashAlgorithm: 1 | 2;
  readonly hashName: 'SHA-384' | 'SHA-512';
  readonly text: string;
}

export interface ZoneDigestReport {
  readonly authentication: 'checksum-only' | 'covering-signature-present-but-unvalidated';
  readonly digests: readonly ZoneDigestValue[];
  readonly duplicatesOmitted: number;
  readonly explanation: string;
  readonly excludedApexRecords: number;
  readonly excludedOutOfZoneRecords: number;
  readonly includedRecords: number;
  readonly issues: readonly string[];
  readonly origin?: string;
  readonly serial?: number;
  readonly state: ZoneDigestState;
  readonly suggestedRecords: readonly SuggestedZoneDigestRecord[];
}

type EncodeResult =
  | { readonly bytes: Uint8Array; readonly ok: true }
  | { readonly ok: false; readonly reason: string };

interface CanonicalRecord {
  readonly owner: CanonicalMasterName;
  readonly rdata: Uint8Array;
  readonly ttl: number;
  readonly typeCode: number;
  readonly wire: Uint8Array;
}

interface ParsedPublication {
  digest?: string;
  hashAlgorithm?: number;
  matches: boolean | null;
  reason?: string;
  scheme?: number;
  serial?: number;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function success(bytes: Uint8Array): EncodeResult {
  return { bytes, ok: true };
}

function failure(reason: string): EncodeResult {
  return { ok: false, reason };
}

function uint8(value: number): Uint8Array {
  return new Uint8Array([value]);
}

function uint16(value: number): Uint8Array {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

function uint32(value: number): Uint8Array {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function readUint32(bytes: Uint8Array, offset: number): number | null {
  const first = bytes[offset];
  const second = bytes[offset + 1];
  const third = bytes[offset + 2];
  const fourth = bytes[offset + 3];
  return first === undefined ||
    second === undefined ||
    third === undefined ||
    fourth === undefined
    ? null
    : ((first << 24) | (second << 16) | (third << 8) | fourth) >>> 0;
}

function readUint16(bytes: Uint8Array, offset: number): number | null {
  const first = bytes[offset];
  const second = bytes[offset + 1];
  return first === undefined || second === undefined ? null : (first << 8) | second;
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

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function hex(bytes: Uint8Array): string {
  return [...bytes]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

function bytesKey(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function integer(value: string | undefined, maximum: number): number | null {
  if (value === undefined || !/^\d+$/u.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 && parsed <= maximum ? parsed : null;
}

function typeCode(type: string): number | null {
  const known = TYPE_CODES[type.toUpperCase()];
  if (known !== undefined) return known;
  const generic = /^TYPE(0|[1-9]\d{0,4})$/u.exec(type.toUpperCase());
  return generic?.[1] === undefined ? null : integer(generic[1], 65_535);
}

function isZonemdRecord(record: ZoneRecord): boolean {
  return typeCode(record.type) === 63;
}

function coversZonemd(record: ZoneRecord, fallbackOrigin?: string): boolean {
  if (typeCode(record.type) !== 46) return false;
  const encoded = encodeRdata(record, record.origin ?? fallbackOrigin);
  return encoded.ok && readUint16(encoded.bytes, 0) === 63;
}

function soaSerial(record: ZoneRecord): number | null {
  if (typeCode(record.type) !== 6) return null;
  if (record.type === 'SOA') return integer(record.rdata[2]?.value, 0xffff_ffff);
  const generic = genericWireRdata(record);
  if (!generic.ok) return null;
  const mname = canonicalWireName(generic.bytes, 0);
  const rname = mname === null ? null : canonicalWireName(generic.bytes, mname.next);
  return rname === null ? null : readUint32(generic.bytes, rname.next);
}

function decodeMasterText(raw: string): Uint8Array | null {
  const bytes: number[] = [];
  for (let index = 0; index < raw.length;) {
    const character = raw[index];
    if (character === '"') {
      index += 1;
      continue;
    }
    if (character === '\\') {
      const digits = raw.slice(index + 1, index + 4);
      if (/^\d{3}$/u.test(digits)) {
        const value = Number(digits);
        if (value > 255) return null;
        bytes.push(value);
        index += 4;
        continue;
      }
      const escaped = raw[index + 1];
      if (escaped === undefined) return null;
      bytes.push(...textEncoder.encode(escaped));
      index += 2;
      continue;
    }
    if (character === undefined) break;
    const codePoint = raw.codePointAt(index);
    if (codePoint === undefined) return null;
    const literal = String.fromCodePoint(codePoint);
    bytes.push(...textEncoder.encode(literal));
    index += literal.length;
  }
  return new Uint8Array(bytes);
}

function tokenBytes(token: ZoneToken | undefined): Uint8Array | null {
  return token === undefined ? null : decodeMasterText(token.raw);
}

function characterString(token: ZoneToken | undefined): Uint8Array | null {
  const value = tokenBytes(token);
  return value === null || value.length > 255 ? null : join([uint8(value.length), value]);
}

function hexadecimal(tokens: readonly ZoneToken[], allowEmpty = false): Uint8Array | null {
  const compact = tokens
    .map((token) => token.value)
    .join('')
    .replaceAll(/\s+/gu, '');
  if (allowEmpty && (compact === '' || compact === '-')) return new Uint8Array();
  if (!/^(?:[0-9A-Fa-f]{2})+$/u.test(compact)) return null;
  return Uint8Array.from(compact.match(/.{2}/gu) ?? [], (octet) => Number.parseInt(octet, 16));
}

function base64(tokens: readonly ZoneToken[]): Uint8Array | null {
  return decodeBase64(tokens.map((token) => token.value).join(''));
}

function encodedName(
  token: ZoneToken | undefined,
  origin: string | undefined,
): Uint8Array | null {
  return token === undefined ? null : (canonicalMasterName(token.raw, origin)?.wire ?? null);
}

function encodedAddress(
  token: ZoneToken | undefined,
  family: 'ipv4' | 'ipv6',
): Uint8Array | null {
  const parsed = token === undefined ? null : parseStrictIpAddress(token.value);
  return parsed?.kind() === family ? new Uint8Array(parsed.toByteArray()) : null;
}

function encodedTypeBitmap(tokens: readonly ZoneToken[]): Uint8Array | null {
  const codes = [...new Set(tokens.map((token) => typeCode(token.value)))];
  if (codes.some((code) => code === null)) return null;
  const windows = new Map<number, number[]>();
  for (const code of codes as number[]) {
    const window = code >>> 8;
    const values = windows.get(window);
    if (values === undefined) windows.set(window, [code & 0xff]);
    else values.push(code & 0xff);
  }
  const output: Uint8Array[] = [];
  for (const [window, values] of [...windows].sort(([left], [right]) => left - right)) {
    const last = Math.max(...values);
    const bitmap = new Uint8Array(Math.floor(last / 8) + 1);
    for (const value of values) {
      const index = Math.floor(value / 8);
      bitmap[index] = (bitmap[index] ?? 0) | (1 << (7 - (value % 8)));
    }
    output.push(uint8(window), uint8(bitmap.length), bitmap);
  }
  return join(output);
}

function base32hex(value: string): Uint8Array | null {
  const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
  const compact = value.toUpperCase().replaceAll('=', '');
  if (compact === '') return null;
  const output: number[] = [];
  let accumulator = 0;
  let bits = 0;
  for (const character of compact) {
    const number = alphabet.indexOf(character);
    if (number < 0) return null;
    accumulator = (accumulator << 5) | number;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      output.push((accumulator >>> bits) & 0xff);
      accumulator &= (1 << bits) - 1;
    }
  }
  return bits === 0 || accumulator === 0 ? new Uint8Array(output) : null;
}

function signatureTime(value: string | undefined): number | null {
  if (value === undefined) return null;
  if (/^\d{14}$/u.test(value)) {
    const year = Number(value.slice(0, 4));
    const month = Number(value.slice(4, 6));
    const day = Number(value.slice(6, 8));
    const hour = Number(value.slice(8, 10));
    const minute = Number(value.slice(10, 12));
    const second = Number(value.slice(12, 14));
    const milliseconds = Date.UTC(year, month - 1, day, hour, minute, second);
    const rendered = new Date(milliseconds)
      .toISOString()
      .replaceAll(/[-:TZ.]/gu, '')
      .slice(0, 14);
    const seconds = milliseconds / 1000;
    return rendered === value && seconds >= 0 && seconds <= 0xffff_ffff ? seconds : null;
  }
  return integer(value, 0xffff_ffff);
}

function asciiText(bytes: Uint8Array): string | null {
  if (bytes.some((byte) => byte > 0x7f)) return null;
  return textDecoder.decode(bytes);
}

function rawDelimiter(raw: string, delimiter: string): number {
  for (let index = 0; index < raw.length; index += 1) {
    if (raw[index] === '\\') {
      const digits = raw.slice(index + 1, index + 4);
      index += /^\d{3}$/u.test(digits) ? 3 : 1;
      continue;
    }
    if (raw[index] === delimiter) return index;
  }
  return -1;
}

function svcValueList(
  bytes: Uint8Array,
  allowEscapedItems: boolean,
): readonly Uint8Array[] | null {
  const items: Uint8Array[] = [];
  let item: number[] = [];
  for (let index = 0; index < bytes.length; index += 1) {
    const byte = bytes[index];
    if (byte === 0x5c) {
      const escaped = bytes[index + 1];
      if (!allowEscapedItems || (escaped !== 0x2c && escaped !== 0x5c)) return null;
      item.push(escaped);
      index += 1;
    } else if (byte === 0x2c) {
      if (item.length === 0) return null;
      items.push(new Uint8Array(item));
      item = [];
    } else if (byte !== undefined) item.push(byte);
  }
  if (item.length === 0) return null;
  items.push(new Uint8Array(item));
  return items;
}

function encodedSvcb(record: ZoneRecord, origin: string | undefined): EncodeResult {
  const priority = integer(record.rdata[0]?.value, 65_535);
  const target = encodedName(record.rdata[1], origin);
  if (priority === null || target === null)
    return failure(`${record.type} requires a priority and canonical target name.`);
  const parameters: { readonly key: number; readonly value: Uint8Array }[] = [];
  const seen = new Set<number>();
  let mandatoryKeys: readonly number[] | undefined;
  for (const token of record.rdata.slice(2)) {
    const equals = rawDelimiter(token.raw, '=');
    const rawKey = equals < 0 ? token.raw : token.raw.slice(0, equals);
    if (rawKey.includes('\\') || rawKey.includes('"'))
      return failure(`${record.type} contains an escaped or quoted SvcParam key.`);
    const keyBytes = decodeMasterText(rawKey);
    const keyText = keyBytes === null ? null : asciiText(keyBytes)?.toLowerCase();
    if (keyText === null || keyText === undefined)
      return failure(`${record.type} contains an invalid SvcParam key.`);
    const key = svcbKeyNumber(keyText);
    if (key === null || seen.has(key))
      return failure(`${record.type} contains an invalid or duplicate SvcParam key.`);
    seen.add(key);
    const rawValue = equals < 0 ? undefined : token.raw.slice(equals + 1);
    const decoded = rawValue === undefined ? undefined : decodeMasterText(rawValue);
    if (decoded === null) return failure(`${record.type} contains a malformed SvcParam value.`);
    let value: Uint8Array | null = null;
    if ([0, 3, 4, 6].includes(key) && rawValue?.includes('\\') === true)
      return failure(`${record.type} contains an escape where this SvcParam forbids one.`);
    if (key === 0 && decoded !== undefined) {
      const list = svcValueList(decoded, false);
      const required =
        list?.map((item) => {
          const text = asciiText(item);
          return text === null ? null : svcbKeyNumber(text.toLowerCase());
        }) ?? null;
      value =
        required === null || required.some((item) => item === null)
          ? null
          : join((required as number[]).sort((left, right) => left - right).map(uint16));
      if (value !== null) mandatoryKeys = required as number[];
    } else if (key === 1 && decoded !== undefined) {
      const protocols = svcValueList(decoded, true);
      const protocolKeys = protocols?.map(bytesKey) ?? [];
      value =
        protocols === null ||
        protocols.some((protocol) => protocol.length > 255) ||
        new Set(protocolKeys).size !== protocolKeys.length
          ? null
          : join(protocols.map((protocol) => join([uint8(protocol.length), protocol])));
    } else if (key === 2 || key === 8) {
      value = decoded === undefined || decoded.length === 0 ? new Uint8Array() : null;
    } else if (key === 3) {
      const portText = decoded === undefined ? null : asciiText(decoded);
      const port = portText === null ? null : integer(portText, 65_535);
      value = port === null ? null : uint16(port);
    } else if (key === 4 || key === 6) {
      const items = decoded === undefined ? null : svcValueList(decoded, false);
      const family = key === 4 ? 'ipv4' : 'ipv6';
      const encoded = (items ?? []).map((item) => {
        const address = asciiText(item);
        if (address === null) return null;
        const parsed = parseStrictIpAddress(address);
        return parsed?.kind() === family ? new Uint8Array(parsed.toByteArray()) : null;
      });
      value =
        items === null || encoded.some((address) => address === null)
          ? null
          : join(encoded as Uint8Array[]);
    } else if (key === 5 && decoded !== undefined) {
      const encoded = asciiText(decoded);
      value = encoded === null ? null : decodeBase64(encoded);
    } else if (equals >= 0) {
      value = decoded ?? null;
    }
    if (value === null || value.length > 65_535)
      return failure(`${record.type} contains an unsupported or malformed SvcParam value.`);
    parameters.push({ key, value });
  }
  if (
    mandatoryKeys?.some((key) => key === 0 || !seen.has(key)) === true ||
    new Set(mandatoryKeys ?? []).size !== (mandatoryKeys?.length ?? 0)
  ) {
    return failure(
      `${record.type} mandatory keys must be unique, present, and exclude mandatory.`,
    );
  }
  if (seen.has(2) && !seen.has(1))
    return failure(`${record.type} no-default-alpn requires an alpn parameter.`);
  parameters.sort((left, right) => left.key - right.key);
  return success(
    join([
      uint16(priority),
      target,
      ...parameters.map(({ key, value }) => join([uint16(key), uint16(value.length), value])),
    ]),
  );
}

function genericWireRdata(record: ZoneRecord): EncodeResult {
  if (!/^TYPE\d+$/u.test(record.type) || record.rdata[0]?.value !== '#')
    return failure(`Record type ${record.type} has no supported canonical encoder.`);
  const length = integer(record.rdata[1]?.value, 65_535);
  const data = hexadecimal(record.rdata.slice(2), true);
  return length === null || data?.length !== length
    ? failure(`Record type ${record.type} requires RFC 3597 \\# length hexadecimal RDATA.`)
    : success(data);
}

interface CanonicalWireName {
  readonly bytes: Uint8Array;
  readonly next: number;
}

function canonicalWireName(input: Uint8Array, offset: number): CanonicalWireName | null {
  const parts: Uint8Array[] = [];
  let cursor = offset;
  let nameOctets = 0;
  for (;;) {
    const length = input[cursor];
    if (length === undefined || (length & 0xc0) !== 0 || length > 63) return null;
    cursor += 1;
    nameOctets += 1;
    if (length === 0)
      return nameOctets <= 255 ? { bytes: join([...parts, uint8(0)]), next: cursor } : null;
    if (cursor + length > input.length || nameOctets + length > 255) return null;
    const label = input.slice(cursor, cursor + length);
    const canonical = Uint8Array.from(label, (byte) =>
      byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte,
    );
    parts.push(join([uint8(length), canonical]));
    cursor += length;
    nameOctets += length;
  }
}

function oneName(
  input: Uint8Array,
  offset: number,
  exactEnd: boolean,
  minimumTrailingOctets = 0,
): EncodeResult {
  const name = canonicalWireName(input, offset);
  if (
    name === null ||
    (exactEnd && name.next !== input.length) ||
    input.length - name.next < minimumTrailingOctets
  )
    return failure('Generic RDATA contains a malformed or compressed domain name.');
  return success(join([input.slice(0, offset), name.bytes, input.slice(name.next)]));
}

function twoNames(input: Uint8Array, offset: number, trailingOctets: number): EncodeResult {
  const first = canonicalWireName(input, offset);
  const second = first === null ? null : canonicalWireName(input, first.next);
  if (first === null || second === null || second.next + trailingOctets !== input.length)
    return failure('Generic RDATA contains malformed or compressed domain names.');
  return success(
    join([input.slice(0, offset), first.bytes, second.bytes, input.slice(second.next)]),
  );
}

function canonicaliseNaptr(input: Uint8Array): EncodeResult {
  if (input.length < 4) return failure('Generic NAPTR RDATA is truncated.');
  let offset = 4;
  for (let index = 0; index < 3; index += 1) {
    const length = input[offset];
    if (length === undefined || offset + 1 + length > input.length)
      return failure('Generic NAPTR RDATA contains a malformed character-string.');
    offset += 1 + length;
  }
  return oneName(input, offset, true);
}

function canonicaliseA6(input: Uint8Array): EncodeResult {
  const prefixLength = input[0];
  if (prefixLength === undefined || prefixLength > 128)
    return failure('Generic A6 RDATA is malformed.');
  const suffixOctets = Math.ceil((128 - prefixLength) / 8);
  const nameOffset = 1 + suffixOctets;
  const paddingBits = suffixOctets * 8 - (128 - prefixLength);
  const firstSuffix = input[1];
  if (
    paddingBits > 0 &&
    (firstSuffix === undefined || (firstSuffix & (0xff << (8 - paddingBits))) !== 0)
  ) {
    return failure('Generic A6 RDATA has non-zero leading padding bits.');
  }
  if (prefixLength === 0)
    return input.length === nameOffset
      ? success(input)
      : failure('Generic A6 RDATA has an invalid address length.');
  return oneName(input, nameOffset, true);
}

function canonicaliseGenericSvcb(input: Uint8Array): EncodeResult {
  if (input.length < 2) return failure('Generic service-binding RDATA is truncated.');
  const target = canonicalWireName(input, 2);
  if (target === null)
    return failure('Generic service-binding RDATA contains a malformed target name.');
  let offset = target.next;
  let previousKey = -1;
  while (offset < input.length) {
    const key = readUint16(input, offset);
    const length = readUint16(input, offset + 2);
    if (
      key === null ||
      length === null ||
      key <= previousKey ||
      offset + 4 + length > input.length
    ) {
      return failure(
        'Generic service-binding RDATA contains malformed or unordered parameters.',
      );
    }
    previousKey = key;
    offset += 4 + length;
  }
  return offset === input.length
    ? success(join([input.slice(0, 2), target.bytes, input.slice(target.next)]))
    : failure('Generic service-binding RDATA has trailing partial parameter data.');
}

function canonicaliseGenericRdata(type: number, input: Uint8Array): EncodeResult {
  if ([2, 3, 4, 5, 7, 8, 9, 12, 39].includes(type)) return oneName(input, 0, true);
  if ([14, 17].includes(type)) return twoNames(input, 0, 0);
  if ([15, 18, 21, 36].includes(type))
    return input.length < 2
      ? failure('Generic RDATA is truncated before its domain name.')
      : oneName(input, 2, true);
  if (type === 6) return twoNames(input, 0, 20);
  if (type === 24 || type === 46)
    return input.length < 18
      ? failure('Generic signature RDATA is truncated.')
      : oneName(input, 18, false, 1);
  if (type === 26)
    return input.length < 2 ? failure('Generic PX RDATA is truncated.') : twoNames(input, 2, 0);
  if (type === 30) return oneName(input, 0, false, 1);
  if (type === 47) return oneName(input, 0, false, 3);
  if (type === 33)
    return input.length < 6
      ? failure('Generic SRV RDATA is truncated.')
      : oneName(input, 6, true);
  if (type === 35) return canonicaliseNaptr(input);
  if (type === 38) return canonicaliseA6(input);
  if (type === 64 || type === 65) return canonicaliseGenericSvcb(input);
  return success(input);
}

function encodeRdata(record: ZoneRecord, origin: string | undefined): EncodeResult {
  if (/^TYPE\d+$/u.test(record.type)) {
    const raw = genericWireRdata(record);
    const code = typeCode(record.type);
    return !raw.ok || code === null ? raw : canonicaliseGenericRdata(code, raw.bytes);
  }
  const values = record.rdata.map((token) => token.value);
  if (record.type === 'A' || record.type === 'AAAA') {
    const value = encodedAddress(record.rdata[0], record.type === 'A' ? 'ipv4' : 'ipv6');
    return record.rdata.length === 1 && value !== null
      ? success(value)
      : failure(`${record.type} RDATA is malformed.`);
  }
  if (['CNAME', 'DNAME', 'NS', 'PTR'].includes(record.type)) {
    const value = encodedName(record.rdata[0], origin);
    return record.rdata.length === 1 && value !== null
      ? success(value)
      : failure(`${record.type} target name is malformed.`);
  }
  if (record.type === 'MX') {
    const preference = integer(values[0], 65_535);
    const exchange = encodedName(record.rdata[1], origin);
    return record.rdata.length === 2 && preference !== null && exchange !== null
      ? success(join([uint16(preference), exchange]))
      : failure('MX RDATA is malformed.');
  }
  if (record.type === 'SRV') {
    const numbers = values.slice(0, 3).map((value) => integer(value, 65_535));
    const target = encodedName(record.rdata[3], origin);
    return record.rdata.length === 4 &&
      numbers.every((value) => value !== null) &&
      target !== null
      ? success(join([...numbers.map(uint16), target]))
      : failure('SRV RDATA is malformed.');
  }
  if (record.type === 'SOA') {
    const mname = encodedName(record.rdata[0], origin);
    const rname = encodedName(record.rdata[1], origin);
    const serial = integer(values[2], 0xffff_ffff);
    const timers = values.slice(3).map((value) => parseTtl(value));
    return record.rdata.length === 7 &&
      mname !== null &&
      rname !== null &&
      serial !== null &&
      timers.every((value) => value !== null)
      ? success(join([mname, rname, uint32(serial), ...timers.map(uint32)]))
      : failure('SOA RDATA is malformed.');
  }
  if (record.type === 'TXT') {
    const chunks = record.rdata.map(characterString);
    return chunks.length > 0 && chunks.every((value) => value !== null)
      ? success(join(chunks))
      : failure('TXT RDATA contains an invalid character-string.');
  }
  if (record.type === 'CAA') {
    const flags = integer(values[0], 255);
    const tag = tokenBytes(record.rdata[1]);
    const value = tokenBytes(record.rdata[2]);
    return record.rdata.length === 3 &&
      flags !== null &&
      tag !== null &&
      tag.length > 0 &&
      tag.length <= 255 &&
      value !== null
      ? success(join([uint8(flags), uint8(tag.length), tag, value]))
      : failure('CAA RDATA is malformed.');
  }
  if (record.type === 'DNSKEY') {
    const flags = integer(values[0], 65_535);
    const protocol = integer(values[1], 255);
    const algorithm = integer(values[2], 255);
    const key = base64(record.rdata.slice(3));
    return flags !== null && protocol !== null && algorithm !== null && key !== null
      ? success(join([uint16(flags), uint8(protocol), uint8(algorithm), key]))
      : failure('DNSKEY RDATA is malformed.');
  }
  if (record.type === 'DS') {
    const keyTag = integer(values[0], 65_535);
    const algorithm = integer(values[1], 255);
    const digestType = integer(values[2], 255);
    const digest = hexadecimal(record.rdata.slice(3));
    return keyTag !== null && algorithm !== null && digestType !== null && digest !== null
      ? success(join([uint16(keyTag), uint8(algorithm), uint8(digestType), digest]))
      : failure('DS RDATA is malformed.');
  }
  if (record.type === 'SSHFP') {
    const algorithm = integer(values[0], 255);
    const fingerprintType = integer(values[1], 255);
    const fingerprint = hexadecimal(record.rdata.slice(2));
    return algorithm !== null && fingerprintType !== null && fingerprint !== null
      ? success(join([uint8(algorithm), uint8(fingerprintType), fingerprint]))
      : failure('SSHFP RDATA is malformed.');
  }
  if (record.type === 'TLSA') {
    const fields = values.slice(0, 3).map((value) => integer(value, 255));
    const association = hexadecimal(record.rdata.slice(3));
    return fields.every((value) => value !== null) && association !== null
      ? success(join([...fields.map(uint8), association]))
      : failure('TLSA RDATA is malformed.');
  }
  if (record.type === 'NAPTR') {
    const order = integer(values[0], 65_535);
    const preference = integer(values[1], 65_535);
    const strings = record.rdata.slice(2, 5).map(characterString);
    const replacement = encodedName(record.rdata[5], origin);
    return record.rdata.length === 6 &&
      order !== null &&
      preference !== null &&
      strings.every((value) => value !== null) &&
      replacement !== null
      ? success(join([uint16(order), uint16(preference), ...strings, replacement]))
      : failure('NAPTR RDATA is malformed.');
  }
  if (record.type === 'URI') {
    const priority = integer(values[0], 65_535);
    const weight = integer(values[1], 65_535);
    const target = tokenBytes(record.rdata[2]);
    return record.rdata.length === 3 && priority !== null && weight !== null && target !== null
      ? success(join([uint16(priority), uint16(weight), target]))
      : failure('URI RDATA is malformed.');
  }
  if (record.type === 'SVCB' || record.type === 'HTTPS') return encodedSvcb(record, origin);
  if (record.type === 'NSEC') {
    const next = encodedName(record.rdata[0], origin);
    const bitmap = encodedTypeBitmap(record.rdata.slice(1));
    return next !== null && bitmap !== null
      ? success(join([next, bitmap]))
      : failure('NSEC RDATA is malformed.');
  }
  if (record.type === 'NSEC3') {
    const algorithm = integer(values[0], 255);
    const flags = integer(values[1], 255);
    const iterations = integer(values[2], 65_535);
    const salt = hexadecimal(record.rdata.slice(3, 4), true);
    const next = values[4] === undefined ? null : base32hex(values[4]);
    const bitmap = encodedTypeBitmap(record.rdata.slice(5));
    return algorithm !== null &&
      flags !== null &&
      iterations !== null &&
      salt !== null &&
      salt.length <= 255 &&
      next !== null &&
      next.length <= 255 &&
      bitmap !== null
      ? success(
          join([
            uint8(algorithm),
            uint8(flags),
            uint16(iterations),
            uint8(salt.length),
            salt,
            uint8(next.length),
            next,
            bitmap,
          ]),
        )
      : failure('NSEC3 RDATA is malformed.');
  }
  if (record.type === 'RRSIG') {
    const covered = typeCode(values[0] ?? '');
    const algorithm = integer(values[1], 255);
    const labels = integer(values[2], 255);
    const originalTtl = values[3] === undefined ? null : parseTtl(values[3]);
    const expiration = signatureTime(values[4]);
    const inception = signatureTime(values[5]);
    const keyTag = integer(values[6], 65_535);
    const signer = encodedName(record.rdata[7], origin);
    const signature = base64(record.rdata.slice(8));
    return covered !== null &&
      algorithm !== null &&
      labels !== null &&
      originalTtl !== null &&
      expiration !== null &&
      inception !== null &&
      keyTag !== null &&
      signer !== null &&
      signature !== null
      ? success(
          join([
            uint16(covered),
            uint8(algorithm),
            uint8(labels),
            uint32(originalTtl),
            uint32(expiration),
            uint32(inception),
            uint16(keyTag),
            signer,
            signature,
          ]),
        )
      : failure('RRSIG RDATA is malformed.');
  }
  if (record.type === 'ZONEMD') {
    const serial = integer(values[0], 0xffff_ffff);
    const scheme = integer(values[1], 255);
    const algorithm = integer(values[2], 255);
    const digest = hexadecimal(record.rdata.slice(3));
    return serial !== null && scheme !== null && algorithm !== null && digest !== null
      ? success(join([uint32(serial), uint8(scheme), uint8(algorithm), digest]))
      : failure('ZONEMD RDATA is malformed.');
  }
  return failure(`Record type ${record.type} has no supported canonical encoder.`);
}

function compareNames(left: CanonicalMasterName, right: CanonicalMasterName): number {
  const length = Math.max(left.labels.length, right.labels.length);
  for (let offset = 1; offset <= length; offset += 1) {
    const leftLabel = left.labels.at(-offset);
    const rightLabel = right.labels.at(-offset);
    if (leftLabel === undefined) return rightLabel === undefined ? 0 : -1;
    if (rightLabel === undefined) return 1;
    const difference = compareBytes(leftLabel, rightLabel);
    if (difference !== 0) return difference;
  }
  return 0;
}

function compareRecords(left: CanonicalRecord, right: CanonicalRecord): number {
  return (
    compareNames(left.owner, right.owner) ||
    left.typeCode - right.typeCode ||
    compareBytes(left.rdata, right.rdata)
  );
}

function parsePublication(record: ZoneRecord): ParsedPublication {
  let serial: number | null;
  let scheme: number | null;
  let hashAlgorithm: number | null;
  let digestBytes: Uint8Array | null;
  if (record.type === 'ZONEMD') {
    serial = integer(record.rdata[0]?.value, 0xffff_ffff);
    scheme = integer(record.rdata[1]?.value, 255);
    hashAlgorithm = integer(record.rdata[2]?.value, 255);
    digestBytes = hexadecimal(record.rdata.slice(3));
  } else {
    const generic = genericWireRdata(record);
    serial = generic.ok ? readUint32(generic.bytes, 0) : null;
    scheme = generic.ok ? (generic.bytes[4] ?? null) : null;
    hashAlgorithm = generic.ok ? (generic.bytes[5] ?? null) : null;
    digestBytes = generic.ok && generic.bytes.length >= 6 ? generic.bytes.slice(6) : null;
  }
  const digest = digestBytes === null ? undefined : hex(digestBytes);
  const expectedLength = hashAlgorithm === 1 ? 48 : hashAlgorithm === 2 ? 64 : undefined;
  const reason =
    serial === null || scheme === null || hashAlgorithm === null || digestBytes === null
      ? 'The published ZONEMD RDATA is malformed.'
      : digestBytes.length < 12
        ? 'The published digest is shorter than 12 octets.'
        : expectedLength !== undefined && digestBytes.length !== expectedLength
          ? `The published digest is not ${String(expectedLength)} octets.`
          : undefined;
  return {
    ...(digest === undefined ? {} : { digest }),
    ...(hashAlgorithm === null ? {} : { hashAlgorithm }),
    matches: null,
    ...(reason === undefined ? {} : { reason }),
    ...(scheme === null ? {} : { scheme }),
    ...(serial === null ? {} : { serial }),
  };
}

function publicationName(value: ParsedPublication): string {
  return value.hashAlgorithm === 1
    ? 'SHA-384'
    : value.hashAlgorithm === 2
      ? 'SHA-512'
      : value.hashAlgorithm === undefined
        ? 'Malformed'
        : `Hash algorithm ${String(value.hashAlgorithm)}`;
}

function reportUnavailable(explanation: string, origin?: string): ZoneDigestReport {
  return {
    authentication: 'checksum-only',
    digests: [],
    duplicatesOmitted: 0,
    explanation,
    excludedApexRecords: 0,
    excludedOutOfZoneRecords: 0,
    includedRecords: 0,
    issues: [explanation],
    ...(origin === undefined ? {} : { origin }),
    state: 'unavailable',
    suggestedRecords: [],
  };
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(bytes.length);
  new Uint8Array(copy).set(bytes);
  return copy;
}

async function calculateDigest(
  algorithm: 'SHA-384' | 'SHA-512',
  input: Uint8Array,
): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest(algorithm, asArrayBuffer(input))));
}

export async function analyseZoneDigest(
  document: ZoneDocument,
  completeZone: boolean,
): Promise<ZoneDigestReport> {
  if (!completeZone)
    return reportUnavailable(
      'Zone digest calculation is disabled until the input is explicitly declared to be a complete standalone zone.',
      document.origin,
    );
  if (document.incomplete !== undefined)
    return reportUnavailable(document.incomplete.message, document.origin);
  const fatal = document.diagnostics.find((diagnostic) =>
    FATAL_PARSE_RULES.has(diagnostic.rule),
  );
  if (fatal !== undefined)
    return reportUnavailable(
      `Zone digest calculation stopped at line ${String(fatal.line)}: ${fatal.message}`,
      document.origin,
    );
  if (document.origin === undefined)
    return reportUnavailable('A valid zone origin is required for canonical zone digests.');
  const originValue = canonicalMasterName(document.origin);
  if (originValue === null)
    return reportUnavailable('The parsed zone origin cannot be represented canonically.');
  const origin = originValue.absolute;
  const ownerValues = new Map<ZoneRecord, CanonicalMasterName>();
  for (const record of document.records) {
    const owner = canonicalMasterName(record.owner);
    if (owner === null)
      return reportUnavailable(
        `Line ${String(record.line)} has an owner that cannot be represented canonically.`,
        origin,
      );
    ownerValues.set(record, owner);
  }
  const apexSoas = document.records.filter((record) => {
    const owner = ownerValues.get(record);
    return (
      owner !== undefined && masterNameEquals(owner, originValue) && typeCode(record.type) === 6
    );
  });
  if (apexSoas.length !== 1)
    return reportUnavailable(
      'A complete zone digest requires exactly one SOA record at the zone apex.',
      origin,
    );
  const soa = apexSoas[0];
  const serial = soa === undefined ? null : soaSerial(soa);
  if (soa === undefined || serial === null)
    return reportUnavailable('The apex SOA serial is malformed.', origin);

  const coveringSignatures = document.records.filter((record) => {
    const owner = ownerValues.get(record);
    return (
      owner !== undefined &&
      masterNameEquals(owner, originValue) &&
      coversZonemd(record, origin)
    );
  });
  const apexPublications = document.records.filter((record) => {
    const owner = ownerValues.get(record);
    return (
      owner !== undefined && masterNameEquals(owner, originValue) && isZonemdRecord(record)
    );
  });
  const publications = apexPublications.map(parsePublication);
  const tupleCounts = new Map<string, number>();
  for (const publication of publications) {
    if (publication.scheme === undefined || publication.hashAlgorithm === undefined) continue;
    const key = `${String(publication.scheme)}|${String(publication.hashAlgorithm)}`;
    tupleCounts.set(key, (tupleCounts.get(key) ?? 0) + 1);
  }
  for (const publication of publications) {
    if (publication.scheme === undefined || publication.hashAlgorithm === undefined) continue;
    const key = `${String(publication.scheme)}|${String(publication.hashAlgorithm)}`;
    if ((tupleCounts.get(key) ?? 0) > 1)
      publication.reason = 'The apex ZONEMD RRset repeats this scheme and hash tuple.';
  }

  let excludedOutOfZoneRecords = 0;
  let excludedApexRecords = 0;
  let duplicatesOmitted = 0;
  let canonicalOctets = 0;
  const records: CanonicalRecord[] = [];
  const duplicateIndex = new Map<string, CanonicalRecord>();
  const issues: string[] = [];

  for (const record of document.records) {
    const owner = ownerValues.get(record);
    if (owner === undefined)
      return reportUnavailable('An internal owner binding was unavailable.', origin);
    if (!masterNameIsAtOrBelow(owner, originValue)) {
      excludedOutOfZoneRecords += 1;
      continue;
    }
    const isApex = masterNameEquals(owner, originValue);
    if (isApex && (isZonemdRecord(record) || coversZonemd(record, origin))) {
      excludedApexRecords += 1;
      continue;
    }
    if (record.className.toUpperCase() !== 'IN')
      return reportUnavailable(
        `Line ${String(record.line)} uses a class outside the supported IN zone profile.`,
        origin,
      );
    if (record.ttl === undefined)
      return reportUnavailable(
        `Line ${String(record.line)} has no explicit or inherited TTL.`,
        origin,
      );
    const code = typeCode(record.type);
    if (code === null)
      return reportUnavailable(
        `Line ${String(record.line)} uses ${record.type}, whose numeric type code is unavailable. Use RFC 3597 TYPE#### syntax for unknown types.`,
        origin,
      );
    const encoded = encodeRdata(record, record.origin ?? origin);
    if (!encoded.ok)
      return reportUnavailable(`Line ${String(record.line)}: ${encoded.reason}`, origin);
    if (encoded.bytes.length > MAX_RDATA_OCTETS)
      return reportUnavailable(
        `Line ${String(record.line)} exceeds the DNS RDATA limit.`,
        origin,
      );
    const identity = `${owner.absolute.toLowerCase()}|${String(code)}|${bytesKey(encoded.bytes)}`;
    const duplicate = duplicateIndex.get(identity);
    if (duplicate !== undefined) {
      if (duplicate.ttl !== record.ttl)
        return reportUnavailable(
          `Equivalent records at ${owner.absolute} ${record.type} use inconsistent TTLs.`,
          origin,
        );
      duplicatesOmitted += 1;
      continue;
    }
    const wire = join([
      owner.wire,
      uint16(code),
      uint16(1),
      uint32(record.ttl),
      uint16(encoded.bytes.length),
      encoded.bytes,
    ]);
    canonicalOctets += wire.length;
    if (canonicalOctets > MAX_CANONICAL_ZONE_OCTETS)
      return reportUnavailable(
        `Canonical zone input exceeds ${String(MAX_CANONICAL_ZONE_OCTETS)} octets.`,
        origin,
      );
    const canonical = { owner, rdata: encoded.bytes, ttl: record.ttl, typeCode: code, wire };
    duplicateIndex.set(identity, canonical);
    records.push(canonical);
  }

  records.sort(compareRecords);
  const input = join(records.map((record) => record.wire));
  let sha384: string;
  let sha512: string;
  try {
    [sha384, sha512] = await Promise.all([
      calculateDigest('SHA-384', input),
      calculateDigest('SHA-512', input),
    ]);
  } catch {
    return reportUnavailable(
      'Browser cryptography could not calculate the complete-zone digests.',
      origin,
    );
  }
  const calculated = new Map<number, string>([
    [1, sha384],
    [2, sha512],
  ]);
  for (const publication of publications) {
    if (publication.reason !== undefined) {
      issues.push(publication.reason);
      continue;
    }
    if (publication.serial !== serial) {
      publication.reason = 'The published ZONEMD serial does not match the apex SOA serial.';
      issues.push(publication.reason);
      continue;
    }
    if (publication.scheme !== 1) {
      publication.reason = `Scheme ${String(publication.scheme)} is not supported.`;
      issues.push(publication.reason);
      continue;
    }
    const expected =
      publication.hashAlgorithm === undefined
        ? undefined
        : calculated.get(publication.hashAlgorithm);
    if (expected === undefined) {
      publication.reason = `Hash algorithm ${String(publication.hashAlgorithm)} is not supported.`;
      issues.push(publication.reason);
      continue;
    }
    publication.matches = publication.digest === expected;
    if (!publication.matches)
      issues.push(`${publicationName(publication)} does not match the canonical zone.`);
  }

  const values: readonly ZoneDigestValue[] = [
    {
      calculated: sha384,
      hashAlgorithm: 1,
      hashName: 'SHA-384',
      publications: publications
        .filter((publication) => publication.hashAlgorithm === 1)
        .map((publication) => ({ ...publication, hashName: publicationName(publication) })),
    },
    {
      calculated: sha512,
      hashAlgorithm: 2,
      hashName: 'SHA-512',
      publications: publications
        .filter((publication) => publication.hashAlgorithm === 2)
        .map((publication) => ({ ...publication, hashName: publicationName(publication) })),
    },
  ];
  const ttl = soa.ttl;
  if (ttl === undefined)
    return reportUnavailable('The apex SOA has no TTL for suggested ZONEMD records.', origin);
  const suggestedRecords: readonly SuggestedZoneDigestRecord[] = values.map((value) => ({
    digest: value.calculated,
    hashAlgorithm: value.hashAlgorithm,
    hashName: value.hashName,
    text: `${origin} ${String(ttl)} IN ZONEMD ${String(serial)} 1 ${String(value.hashAlgorithm)} ${value.calculated}`,
  }));
  const anyMatch = publications.some((publication) => publication.matches === true);
  const anySupported = publications.some(
    (publication) =>
      publication.reason === undefined ||
      (publication.scheme === 1 &&
        (publication.hashAlgorithm === 1 || publication.hashAlgorithm === 2)),
  );
  const state: ZoneDigestState =
    publications.length === 0
      ? 'generated'
      : anyMatch
        ? 'verified'
        : anySupported
          ? 'mismatch'
          : 'unsupported';
  const explanation =
    state === 'generated'
      ? 'Canonical SHA-384 and SHA-512 digests were generated for the declared complete zone; no apex ZONEMD record was supplied for verification.'
      : state === 'verified'
        ? 'At least one supported apex ZONEMD record matches the canonical complete-zone digest.'
        : state === 'mismatch'
          ? 'No supported apex ZONEMD record matches the canonical complete-zone digest.'
          : 'Apex ZONEMD records are present, but none uses a valid supported scheme and hash combination.';

  return {
    authentication:
      coveringSignatures.length > 0
        ? 'covering-signature-present-but-unvalidated'
        : 'checksum-only',
    digests: values,
    duplicatesOmitted,
    explanation,
    excludedApexRecords,
    excludedOutOfZoneRecords,
    includedRecords: records.length,
    issues: [...new Set(issues)],
    origin,
    serial,
    state,
    suggestedRecords,
  };
}
