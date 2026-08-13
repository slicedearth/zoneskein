import type { DnsRecordType } from './types';

const CUSTOM_WIRE_TYPES: Readonly<Record<string, string>> = {
  HTTPS: 'UNKNOWN_65',
  SVCB: 'UNKNOWN_64',
};

const CUSTOM_DISPLAY_TYPES: Readonly<Record<string, DnsRecordType>> = {
  UNKNOWN_64: 'SVCB',
  UNKNOWN_65: 'HTTPS',
};

export function wireRecordType(type: DnsRecordType): string {
  return CUSTOM_WIRE_TYPES[type] ?? type;
}

export function displayRecordType(type: string): string {
  return CUSTOM_DISPLAY_TYPES[type] ?? type.replace('UNKNOWN_', 'TYPE');
}
