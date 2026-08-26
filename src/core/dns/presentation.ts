import type { DnsRecord } from './types';

const UINT16_MAX = 65_535;
const UINT32_MAX = 4_294_967_295;
const BASE32HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

function hex(bytes: Uint8Array): string {
  return [...bytes]
    .map((value) => value.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

function base64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base32hex(bytes: Uint8Array): string {
  let bits = 0;
  let accumulator = 0;
  let result = '';
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += BASE32HEX.charAt((accumulator >>> bits) & 0x1f);
    }
  }
  if (bits > 0) result += BASE32HEX.charAt((accumulator << (5 - bits)) & 0x1f);
  return result;
}

function genericRdata(bytes: Uint8Array): string {
  const encoded = hex(bytes);
  return `\\# ${String(bytes.length)}${encoded === '' ? '' : ` ${encoded}`}`;
}

function escapedOctets(bytes: Uint8Array): string {
  return [...bytes]
    .map((byte) =>
      byte >= 0x20 && byte <= 0x7e && byte !== 0x22 && byte !== 0x5c
        ? String.fromCharCode(byte)
        : `\\${String(byte).padStart(3, '0')}`,
    )
    .join('');
}

function quotedOctets(bytes: Uint8Array): string {
  return `"${escapedOctets(bytes)}"`;
}

function escapedLabelOctets(bytes: Uint8Array): string {
  return [...bytes]
    .map((byte) =>
      (byte >= 0x30 && byte <= 0x39) ||
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      byte === 0x2a ||
      byte === 0x2d ||
      byte === 0x5f
        ? String.fromCharCode(byte)
        : `\\${String(byte).padStart(3, '0')}`,
    )
    .join('');
}

function objectValue(value: unknown): Readonly<Record<string, unknown>> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Readonly<Record<string, unknown>>)
    : null;
}

function integerValue(
  value: Readonly<Record<string, unknown>>,
  key: string,
  maximum: number,
): number | null {
  const candidate = value[key];
  return typeof candidate === 'number' &&
    Number.isSafeInteger(candidate) &&
    candidate >= 0 &&
    candidate <= maximum
    ? candidate
    : null;
}

function stringValue(value: Readonly<Record<string, unknown>>, key: string): string | null {
  const candidate = value[key];
  return typeof candidate === 'string' ? candidate : null;
}

function masterName(value: string): string | null {
  if (value === '.') return value;
  const withoutRoot = value.endsWith('.') ? value.slice(0, -1) : value;
  if (withoutRoot === '') return null;
  const labels = withoutRoot.split('.');
  let wireOctets = 1;
  for (const label of labels) {
    const units = label.match(/[A-Za-z0-9_*-]|\\[0-9]{3}/gu);
    if (units?.join('') !== label) return null;
    if (units.length > 63) return null;
    if (units.some((unit) => unit.startsWith('\\') && Number(unit.slice(1)) > 255)) return null;
    wireOctets += units.length + 1;
  }
  if (wireOctets > 255) return null;
  return `${withoutRoot}.`;
}

function wireName(bytes: Uint8Array): string | null {
  const labels: string[] = [];
  let offset = 0;
  let wireLength = 1;
  for (;;) {
    const length = bytes[offset];
    if (length === undefined || length > 63 || (length & 0xc0) !== 0) return null;
    offset += 1;
    if (length === 0) return offset === bytes.length ? `${labels.join('.')}.` : null;
    if (offset + length > bytes.length) return null;
    wireLength += length + 1;
    if (wireLength > 255) return null;
    labels.push(escapedLabelOctets(bytes.slice(offset, offset + length)));
    offset += length;
  }
}

function safeOwner(record: DnsRecord): string {
  if (record.canonicalOwnerWire !== undefined) {
    const wireValue = wireName(record.canonicalOwnerWire);
    if (wireValue !== null) return wireValue;
  }
  const name = masterName(record.owner);
  if (name !== null) return name;
  return `${escapedLabelOctets(new TextEncoder().encode(record.owner))}.`;
}

function txtRdata(record: DnsRecord): string | null {
  const chunks: Uint8Array[] = [];
  if (record.rawRdata.length > 0) {
    let offset = 0;
    while (offset < record.rawRdata.length) {
      const length = record.rawRdata[offset];
      if (length === undefined || offset + 1 + length > record.rawRdata.length) return null;
      chunks.push(record.rawRdata.slice(offset + 1, offset + 1 + length));
      offset += 1 + length;
    }
  } else if (Array.isArray(record.data)) {
    for (const part of record.data) {
      if (!(part instanceof Uint8Array) || part.length > 255) return null;
      chunks.push(part);
    }
  } else if (record.data instanceof Uint8Array && record.data.length <= 255) {
    chunks.push(record.data);
  } else return null;
  return chunks.length === 0 ? null : chunks.map(quotedOctets).join(' ');
}

function caaRdata(raw: Uint8Array): string | null {
  const flags = raw[0];
  const tagLength = raw[1];
  if (flags === undefined || tagLength === undefined || 2 + tagLength > raw.length) return null;
  return `${String(flags)} ${quotedOctets(raw.slice(2, 2 + tagLength))} ${quotedOctets(raw.slice(2 + tagLength))}`;
}

function addressRdata(record: DnsRecord): string | null {
  if (record.type === 'A' && record.rawRdata.length === 4)
    return [...record.rawRdata].join('.');
  if (record.type === 'AAAA' && record.rawRdata.length === 16) {
    const groups: string[] = [];
    for (let offset = 0; offset < record.rawRdata.length; offset += 2) {
      const high = record.rawRdata[offset];
      const low = record.rawRdata[offset + 1];
      if (high === undefined || low === undefined) return null;
      groups.push(((high << 8) | low).toString(16));
    }
    return groups.join(':');
  }
  if (record.rawRdata.length > 0) return null;
  if (typeof record.data !== 'string') return null;
  if (record.type === 'A') {
    const parts = record.data.split('.');
    return parts.length === 4 &&
      parts.every((part) => /^(?:0|[1-9][0-9]{0,2})$/u.test(part) && Number(part) <= 255)
      ? record.data
      : null;
  }
  return /^[0-9A-Fa-f:.]+$/u.test(record.data) ? record.data : null;
}

function nameRdata(data: unknown): string | null {
  return typeof data === 'string' ? masterName(data) : null;
}

function mxRdata(data: unknown): string | null {
  const value = objectValue(data);
  if (value === null) return null;
  const preference = integerValue(value, 'preference', UINT16_MAX);
  const exchange = stringValue(value, 'exchange');
  const name = exchange === null ? null : masterName(exchange);
  return preference === null || name === null ? null : `${String(preference)} ${name}`;
}

function srvRdata(data: unknown): string | null {
  const value = objectValue(data);
  if (value === null) return null;
  const priority = integerValue(value, 'priority', UINT16_MAX);
  const weight = integerValue(value, 'weight', UINT16_MAX);
  const port = integerValue(value, 'port', UINT16_MAX);
  const target = stringValue(value, 'target');
  const name = target === null ? null : masterName(target);
  return priority === null || weight === null || port === null || name === null
    ? null
    : `${String(priority)} ${String(weight)} ${String(port)} ${name}`;
}

function soaRdata(data: unknown): string | null {
  const value = objectValue(data);
  if (value === null) return null;
  const mnameValue = stringValue(value, 'mname');
  const rnameValue = stringValue(value, 'rname');
  const mname = mnameValue === null ? null : masterName(mnameValue);
  const rname = rnameValue === null ? null : masterName(rnameValue);
  const numbers = ['serial', 'refresh', 'retry', 'expire', 'minimum'].map((key) =>
    integerValue(value, key, UINT32_MAX),
  );
  return mname === null || rname === null || numbers.some((number) => number === null)
    ? null
    : `${mname} ${rname} ${numbers.join(' ')}`;
}

function dsRdata(record: DnsRecord): string | null {
  if (record.rawRdata.length >= 4) {
    const high = record.rawRdata[0];
    const low = record.rawRdata[1];
    const algorithm = record.rawRdata[2];
    const digestType = record.rawRdata[3];
    if (
      high === undefined ||
      low === undefined ||
      algorithm === undefined ||
      digestType === undefined
    )
      return null;
    return `${String((high << 8) | low)} ${String(algorithm)} ${String(digestType)} ${hex(record.rawRdata.slice(4))}`;
  }
  const { data } = record;
  const value = objectValue(data);
  if (value === null) return null;
  const keyTag = integerValue(value, 'keyTag', UINT16_MAX);
  const algorithm = integerValue(value, 'algorithm', 255);
  const digestType = integerValue(value, 'digestType', 255);
  const digest = value['digest'];
  return keyTag === null ||
    algorithm === null ||
    digestType === null ||
    !(digest instanceof Uint8Array)
    ? null
    : `${String(keyTag)} ${String(algorithm)} ${String(digestType)} ${hex(digest)}`;
}

function dnskeyRdata(record: DnsRecord): string | null {
  if (record.rawRdata.length >= 4) {
    const high = record.rawRdata[0];
    const low = record.rawRdata[1];
    const protocol = record.rawRdata[2];
    const algorithm = record.rawRdata[3];
    if (
      high === undefined ||
      low === undefined ||
      protocol === undefined ||
      algorithm === undefined
    )
      return null;
    return `${String((high << 8) | low)} ${String(protocol)} ${String(algorithm)} ${base64(record.rawRdata.slice(4))}`;
  }
  const { data } = record;
  const value = objectValue(data);
  if (value === null) return null;
  const flags = integerValue(value, 'flags', UINT16_MAX);
  const algorithm = integerValue(value, 'algorithm', 255);
  const key = stringValue(value, 'key');
  return flags === null ||
    algorithm === null ||
    key === null ||
    !/^[A-Za-z0-9+/]+={0,2}$/u.test(key)
    ? null
    : `${String(flags)} 3 ${String(algorithm)} ${key}`;
}

function rrsigRdata(data: unknown): string | null {
  const value = objectValue(data);
  if (value === null) return null;
  const typeCovered = stringValue(value, 'typeCovered');
  const algorithm = integerValue(value, 'algorithm', 255);
  const labels = integerValue(value, 'labels', 255);
  const originalTtl = integerValue(value, 'originalTTL', UINT32_MAX);
  const expiration = integerValue(value, 'expiration', UINT32_MAX);
  const inception = integerValue(value, 'inception', UINT32_MAX);
  const keyTag = integerValue(value, 'keyTag', UINT16_MAX);
  const signerValue = stringValue(value, 'signersName');
  const signer = signerValue === null ? null : masterName(signerValue);
  const signature = value['signature'];
  return typeCovered === null ||
    !/^[A-Z0-9]+$/u.test(typeCovered) ||
    algorithm === null ||
    labels === null ||
    originalTtl === null ||
    expiration === null ||
    inception === null ||
    keyTag === null ||
    signer === null ||
    !(signature instanceof Uint8Array)
    ? null
    : `${typeCovered} ${String(algorithm)} ${String(labels)} ${String(originalTtl)} ${String(expiration)} ${String(inception)} ${String(keyTag)} ${signer} ${base64(signature)}`;
}

function nsecRdata(data: unknown): string | null {
  const value = objectValue(data);
  if (value === null) return null;
  const nextValue = stringValue(value, 'nextDomain');
  const next = nextValue === null ? null : masterName(nextValue);
  const rrtypes = value['rrtypes'];
  return next === null ||
    !Array.isArray(rrtypes) ||
    !rrtypes.every((type) => typeof type === 'string' && /^[A-Z0-9]+$/u.test(type))
    ? null
    : `${next} ${rrtypes.join(' ')}`;
}

function nsec3Rdata(data: unknown): string | null {
  const value = objectValue(data);
  if (value === null) return null;
  const algorithm = integerValue(value, 'algorithm', 255);
  const flags = integerValue(value, 'flags', 255);
  const iterations = integerValue(value, 'iterations', UINT16_MAX);
  const salt = value['salt'];
  const nextDomain = value['nextDomain'];
  const rrtypes = value['rrtypes'];
  return algorithm === null ||
    flags === null ||
    iterations === null ||
    !(salt instanceof Uint8Array) ||
    !(nextDomain instanceof Uint8Array) ||
    !Array.isArray(rrtypes) ||
    !rrtypes.every((type) => typeof type === 'string' && /^[A-Z0-9]+$/u.test(type))
    ? null
    : `${String(algorithm)} ${String(flags)} ${String(iterations)} ${salt.length === 0 ? '-' : hex(salt)} ${base32hex(nextDomain)} ${rrtypes.join(' ')}`;
}

function tlsaRdata(raw: Uint8Array): string | null {
  const usage = raw[0];
  const selector = raw[1];
  const matchingType = raw[2];
  return usage === undefined || selector === undefined || matchingType === undefined
    ? null
    : `${String(usage)} ${String(selector)} ${String(matchingType)} ${hex(raw.slice(3))}`;
}

function zonemdRdata(raw: Uint8Array): string | null {
  if (raw.length < 6) return null;
  const serial =
    (((raw[0] ?? 0) << 24) | ((raw[1] ?? 0) << 16) | ((raw[2] ?? 0) << 8) | (raw[3] ?? 0)) >>>
    0;
  return `${String(serial)} ${String(raw[4])} ${String(raw[5])} ${hex(raw.slice(6))}`;
}

export function recordDataText(record: DnsRecord): string {
  let formatted: string | null = null;
  if (record.type === 'TXT') formatted = txtRdata(record);
  else if (record.type === 'A' || record.type === 'AAAA') formatted = addressRdata(record);
  else if (['CNAME', 'DNAME', 'NS', 'PTR'].includes(record.type))
    formatted = nameRdata(record.data);
  else if (record.type === 'MX') formatted = mxRdata(record.data);
  else if (record.type === 'SRV') formatted = srvRdata(record.data);
  else if (record.type === 'SOA') formatted = soaRdata(record.data);
  else if (record.type === 'CAA') formatted = caaRdata(record.rawRdata);
  else if (record.type === 'DS') formatted = dsRdata(record);
  else if (record.type === 'DNSKEY') formatted = dnskeyRdata(record);
  else if (record.type === 'RRSIG') formatted = rrsigRdata(record.data);
  else if (record.type === 'NSEC') formatted = nsecRdata(record.data);
  else if (record.type === 'NSEC3') formatted = nsec3Rdata(record.data);
  else if (record.type === 'TLSA') formatted = tlsaRdata(record.rawRdata);
  else if (record.type === 'ZONEMD') formatted = zonemdRdata(record.rawRdata);
  return formatted ?? genericRdata(record.rawRdata);
}

export function bindRecord(record: DnsRecord): string {
  const ttl =
    Number.isSafeInteger(record.ttl) && record.ttl >= 0 && record.ttl <= UINT32_MAX
      ? record.ttl
      : 0;
  const className = /^[A-Z0-9]+$/u.test(record.class.toUpperCase())
    ? record.class.toUpperCase()
    : 'CLASS0';
  const type = /^[A-Z0-9]+$/u.test(record.type.toUpperCase())
    ? record.type.toUpperCase()
    : `TYPE${String(record.typeCode)}`;
  return `${safeOwner(record)} ${String(ttl)} ${className} ${type} ${recordDataText(record)}`;
}
