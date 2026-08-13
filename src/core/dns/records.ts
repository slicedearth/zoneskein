import type { DnsRecord } from './types';

const decoder = new TextDecoder('utf-8', { fatal: false });

export interface RecordField {
  readonly label: string;
  readonly value: string;
}

export interface ParsedRecordView {
  readonly fields: readonly RecordField[];
  readonly text: string;
  readonly txtChunks?: readonly { readonly octets: number; readonly text: string }[];
}

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

function field(label: string, value: unknown): RecordField {
  if (value instanceof Uint8Array) return { label, value: hex(value) };
  return { label, value: String(value) };
}

function objectFields(value: object): readonly RecordField[] {
  return Object.entries(value).map(([label, entry]) => field(label, entry));
}

function textFromFields(fields: readonly RecordField[]): string {
  return fields.map(({ value }) => value).join(' ');
}

function txtView(data: unknown, raw: Uint8Array): ParsedRecordView {
  const chunks = Array.isArray(data)
    ? data.flatMap((part) =>
        part instanceof Uint8Array ? [{ octets: part.length, text: decoder.decode(part) }] : [],
      )
    : [];
  if (chunks.length === 0) return { fields: [], text: `\\# ${String(raw.length)} ${hex(raw)}` };
  const text = chunks
    .map(({ text: value }) => `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`)
    .join(' ');
  return {
    fields: [{ label: 'Combined value', value: chunks.map((chunk) => chunk.text).join('') }],
    text,
    txtChunks: chunks,
  };
}

function readUint16(bytes: Uint8Array, offset: number): number | null {
  const high = bytes[offset];
  const low = bytes[offset + 1];
  return high === undefined || low === undefined ? null : (high << 8) | low;
}

function parseUncompressedName(bytes: Uint8Array, initialOffset: number) {
  const labels: string[] = [];
  let offset = initialOffset;
  while (offset < bytes.length) {
    const length = bytes[offset];
    if (length === undefined || length > 63 || (length & 0xc0) !== 0) return null;
    offset += 1;
    if (length === 0)
      return { name: labels.length === 0 ? '.' : `${labels.join('.')}.`, offset };
    if (offset + length > bytes.length) return null;
    labels.push(decoder.decode(bytes.slice(offset, offset + length)));
    offset += length;
  }
  return null;
}

function formatIp(bytes: Uint8Array): string {
  if (bytes.length === 4) return [...bytes].join('.');
  const groups: string[] = [];
  for (let index = 0; index < bytes.length; index += 2) {
    const value = readUint16(bytes, index);
    if (value === null) return hex(bytes);
    groups.push(value.toString(16));
  }
  return groups.join(':');
}

const SVCB_KEYS: Readonly<Record<number, string>> = {
  0: 'mandatory',
  1: 'alpn',
  2: 'no-default-alpn',
  3: 'port',
  4: 'ipv4hint',
  5: 'ech',
  6: 'ipv6hint',
  7: 'dohpath',
  8: 'ohttp',
};

function svcbParameter(key: number, value: Uint8Array): string {
  if (key === 0) {
    const values: string[] = [];
    for (let offset = 0; offset < value.length; offset += 2) {
      const item = readUint16(value, offset);
      if (item !== null) values.push(SVCB_KEYS[item] ?? `key${String(item)}`);
    }
    return values.join(',');
  }
  if (key === 1) {
    const values: string[] = [];
    for (let offset = 0; offset < value.length;) {
      const length = value[offset];
      if (length === undefined || offset + 1 + length > value.length) return hex(value);
      values.push(decoder.decode(value.slice(offset + 1, offset + 1 + length)));
      offset += 1 + length;
    }
    return values.join(',');
  }
  if (key === 2 || key === 8) return '';
  if (key === 3) return String(readUint16(value, 0) ?? hex(value));
  if (key === 4 || key === 6) {
    const length = key === 4 ? 4 : 16;
    const values: string[] = [];
    for (let offset = 0; offset < value.length; offset += length) {
      values.push(formatIp(value.slice(offset, offset + length)));
    }
    return values.join(',');
  }
  if (key === 5) return base64(value);
  if (key === 7) return decoder.decode(value);
  return hex(value);
}

function svcbView(raw: Uint8Array): ParsedRecordView | null {
  const priority = readUint16(raw, 0);
  const target = parseUncompressedName(raw, 2);
  if (priority === null || target === null) return null;
  const fields: RecordField[] = [field('Priority', priority), field('Target', target.name)];
  let offset = target.offset;
  while (offset < raw.length) {
    const key = readUint16(raw, offset);
    const length = readUint16(raw, offset + 2);
    if (key === null || length === null || offset + 4 + length > raw.length) return null;
    const value = raw.slice(offset + 4, offset + 4 + length);
    fields.push(field(SVCB_KEYS[key] ?? `key${String(key)}`, svcbParameter(key, value)));
    offset += 4 + length;
  }
  return { fields, text: textFromFields(fields) };
}

function tlsaView(raw: Uint8Array): ParsedRecordView | null {
  const usage = raw[0];
  const selector = raw[1];
  const matchingType = raw[2];
  if (usage === undefined || selector === undefined || matchingType === undefined) return null;
  const fields = [
    field('Certificate usage', usage),
    field('Selector', selector),
    field('Matching type', matchingType),
    field('Certificate association data', raw.slice(3)),
  ];
  return { fields, text: textFromFields(fields) };
}

export function parseRecordView(record: DnsRecord): ParsedRecordView {
  if (record.type === 'TXT') return txtView(record.data, record.rawRdata);
  if (record.type === 'SVCB' || record.type === 'HTTPS') {
    return (
      svcbView(record.rawRdata) ?? {
        fields: [],
        text: `\\# ${String(record.rawRdata.length)} ${hex(record.rawRdata)}`,
      }
    );
  }
  if (record.type === 'TLSA') {
    return (
      tlsaView(record.rawRdata) ?? {
        fields: [],
        text: `\\# ${String(record.rawRdata.length)} ${hex(record.rawRdata)}`,
      }
    );
  }
  if (typeof record.data === 'string') {
    return { fields: [field('Value', record.data)], text: record.data };
  }
  if (record.data !== null && typeof record.data === 'object') {
    const fields =
      record.data instanceof Uint8Array
        ? [field('RDATA', record.data)]
        : objectFields(record.data);
    return { fields, text: textFromFields(fields) };
  }
  return {
    fields: [],
    text: `\\# ${String(record.rawRdata.length)} ${hex(record.rawRdata)}`,
  };
}

export function recordJson(record: DnsRecord): Record<string, unknown> {
  const view = parseRecordView(record);
  return {
    class: record.class,
    data: view.text,
    fields: Object.fromEntries(view.fields.map(({ label, value }) => [label, value])),
    owner: record.owner,
    section: record.section,
    ttl: record.ttl,
    type: record.type,
  };
}
