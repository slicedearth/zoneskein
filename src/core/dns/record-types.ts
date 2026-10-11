import type { DnsRecordType, GenericDnsRecordType } from './types';
import { toType } from '@dnsquery/dns-packet/types.js';

const CUSTOM_WIRE_TYPES: Readonly<Record<string, string>> = {
  CDNSKEY: 'UNKNOWN_60',
  CDS: 'UNKNOWN_59',
  CSYNC: 'UNKNOWN_62',
  DSYNC: 'UNKNOWN_66',
  HTTPS: 'UNKNOWN_65',
  SVCB: 'UNKNOWN_64',
  ZONEMD: 'UNKNOWN_63',
};

const CUSTOM_DISPLAY_TYPES: Readonly<Record<string, DnsRecordType>> = {
  UNKNOWN_59: 'CDS',
  UNKNOWN_60: 'CDNSKEY',
  UNKNOWN_62: 'CSYNC',
  UNKNOWN_63: 'ZONEMD',
  UNKNOWN_64: 'SVCB',
  UNKNOWN_65: 'HTTPS',
  UNKNOWN_66: 'DSYNC',
};

const PROHIBITED_GENERIC_TYPES = new Set([
  0,
  41, // OPT is an EDNS pseudo-record, not a data question.
  249, // TKEY
  250, // TSIG
  251, // IXFR
  252, // AXFR
  253, // MAILB
  254, // MAILA
  255, // ANY
  65_535,
]);

export function wireRecordType(type: DnsRecordType): string {
  const generic = /^TYPE(0|[1-9]\d{0,4})$/u.exec(type)?.[1];
  if (generic !== undefined) return `UNKNOWN_${generic}`;
  return CUSTOM_WIRE_TYPES[type] ?? type;
}

export function displayRecordType(type: string): string {
  return CUSTOM_DISPLAY_TYPES[type] ?? type.replace('UNKNOWN_', 'TYPE');
}

/** Numeric identity is stable across mnemonic and RFC 3597 display aliases. */
export function dnsRecordTypeCode(type: string): number | null {
  const upper = type.toUpperCase();
  const generic = /^(?:TYPE|UNKNOWN_)(0|[1-9]\d{0,4})$/u.exec(upper)?.[1];
  if (generic !== undefined) return Number(generic) <= 65_535 ? Number(generic) : null;
  try {
    const value = toType(CUSTOM_WIRE_TYPES[upper] ?? upper);
    return value > 0 && value <= 65_535 ? value : null;
  } catch {
    return null;
  }
}

export function parseGenericRecordType(
  value: string,
):
  | { readonly ok: true; readonly type: GenericDnsRecordType; readonly typeCode: number }
  | { readonly error: string; readonly ok: false } {
  const match = /^(?:TYPE)?(0|[1-9]\d{0,4})$/iu.exec(value.trim());
  if (match?.[1] === undefined)
    return {
      error: 'Enter an RR type number from 1 to 65534, optionally prefixed with TYPE.',
      ok: false,
    };
  const typeCode = Number(match[1]);
  if (typeCode < 1 || typeCode > 65_534)
    return { error: 'RR type numbers must be between 1 and 65534.', ok: false };
  if (PROHIBITED_GENERIC_TYPES.has(typeCode))
    return {
      error: `TYPE${String(typeCode)} is a pseudo, transfer, authentication, meta-query, or reserved type and is not available for interactive lookup.`,
      ok: false,
    };
  return { ok: true, type: `TYPE${String(typeCode)}` as GenericDnsRecordType, typeCode };
}
