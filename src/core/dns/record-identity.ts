import { canonicalMasterName } from '../zone/master-name';
import type { DnsRecord } from './types';

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function name(value: unknown): string | null {
  return typeof value === 'string' ? (canonicalMasterName(value, '.')?.absolute ?? null) : null;
}

/** Use decoder-validated name fields; keep all opaque octets and TXT boundaries exact. */
export function dnsRecordIdentity(record: DnsRecord): string {
  let data: unknown = ['wire', hex(record.rawRdata)];
  const fields =
    record.data !== null && typeof record.data === 'object' && !Array.isArray(record.data)
      ? (record.data as Readonly<Record<string, unknown>>)
      : null;
  if ([2, 5, 12, 39].includes(record.typeCode)) {
    const target = name(record.data);
    if (target !== null) data = ['name', target];
  } else if (fields !== null) {
    const shape =
      record.typeCode === 15
        ? [['preference'], ['exchange']]
        : record.typeCode === 6
          ? [
              ['serial', 'refresh', 'retry', 'expire', 'minimum'],
              ['mname', 'rname'],
            ]
          : record.typeCode === 33
            ? [['priority', 'weight', 'port'], ['target']]
            : record.typeCode === 17
              ? [[], ['mbox', 'txt']]
              : null;
    if (shape !== null) {
      const numbers = (shape[0] ?? []).map((key) => fields[key]);
      const names = (shape[1] ?? []).map((key) => name(fields[key]));
      if (
        numbers.every(
          (value) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0,
        ) &&
        names.every((value) => value !== null)
      )
        data = ['fields', numbers, names];
    }
  }
  return JSON.stringify([
    name(record.owner) ?? record.owner,
    record.class.toUpperCase(),
    record.typeCode,
    data,
  ]);
}
