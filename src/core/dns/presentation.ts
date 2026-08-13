import type { DnsRecord } from './types';

const decoder = new TextDecoder('utf-8', { fatal: false });

function hex(bytes: Uint8Array): string {
  return [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');
}

function quotedTxt(data: unknown): string | null {
  if (!Array.isArray(data)) return null;
  return data
    .map((part) => {
      if (!(part instanceof Uint8Array)) return null;
      const text = decoder.decode(part).replaceAll('\\', '\\\\').replaceAll('"', '\\"');
      return `"${text}"`;
    })
    .filter((value): value is string => value !== null)
    .join(' ');
}

export function recordDataText(record: DnsRecord): string {
  const { data } = record;
  if (record.type === 'TXT') return quotedTxt(data) ?? hex(record.rawRdata);
  if (typeof data === 'string') return data;
  if (data instanceof Uint8Array) return `\\# ${String(data.length)} ${hex(data)}`;
  if (data !== null && typeof data === 'object') {
    return Object.values(data)
      .map((value) => (value instanceof Uint8Array ? hex(value) : String(value)))
      .join(' ');
  }
  return String(data);
}

export function bindRecord(record: DnsRecord): string {
  return `${record.owner} ${String(record.ttl)} ${record.class} ${record.type} ${recordDataText(record)}`;
}
