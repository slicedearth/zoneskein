import {
  AUTHENTIC_DATA,
  CHECKING_DISABLED,
  DNSSEC_OK,
  RECURSION_AVAILABLE,
  RECURSION_DESIRED,
  TRUNCATED_RESPONSE,
  decode,
  encode,
  type Answer,
  type Packet,
} from '@dnsquery/dns-packet';
import { toClass } from '@dnsquery/dns-packet/classes.js';
import { toRcode } from '@dnsquery/dns-packet/rcodes.js';
import { toString as dnsTypeName, toType } from '@dnsquery/dns-packet/types.js';

import type {
  DnsEdns,
  DnsExtendedError,
  DnsMessage,
  DnsQueryOptions,
  DnsQuestion,
  DnsRecord,
  DnsSection,
} from './types';
import { parseCaaWireData } from './caa-wire';
import { displayRecordType, wireRecordType } from './record-types';

export const MAX_DNS_MESSAGE_BYTES = 65_535;
export const DNS_QUERY_PADDING_BLOCK_BYTES = 128;
const MAX_DNS_MESSAGE_NAME_OPERATIONS = MAX_DNS_MESSAGE_BYTES;
const MAX_DNS_NAME_POINTERS = 128;
const MAX_DNS_NAME_OPERATIONS = 256;
const MAX_DNS_NAME_WIRE_OCTETS = 255;
const EXTENDED_ERROR_NAMES: Readonly<Record<number, string>> = {
  0: 'Other',
  1: 'Unsupported DNSKEY Algorithm',
  2: 'Unsupported DS Digest Type',
  3: 'Stale Answer',
  4: 'Forged Answer',
  5: 'DNSSEC Indeterminate',
  6: 'DNSSEC Bogus',
  7: 'Signature Expired',
  8: 'Signature Not Yet Valid',
  9: 'DNSKEY Missing',
  10: 'RRSIGs Missing',
  11: 'No Zone Key Bit Set',
  12: 'NSEC Missing',
  13: 'Cached Error',
  14: 'Not Ready',
  15: 'Blocked',
  16: 'Censored',
  17: 'Filtered',
  18: 'Prohibited',
  19: 'Stale NXDOMAIN Answer',
  20: 'Not Authoritative',
  21: 'Not Supported',
  22: 'No Reachable Authority',
  23: 'Network Error',
  24: 'Invalid Data',
};

interface DecodedOption {
  readonly code?: number | string;
  readonly data?: Uint8Array;
}

type DecodedOptAnswer = Answer & {
  readonly ednsVersion?: number;
  readonly extendedRcode?: number;
  readonly flags?: number;
  readonly udpPayloadSize?: number;
};

function readUint16(bytes: Uint8Array, offset: number): number {
  const high = bytes[offset];
  const low = bytes[offset + 1];
  if (high === undefined || low === undefined) throw new Error('Truncated DNS integer.');
  return (high << 8) | low;
}

interface RawDnsName {
  readonly canonicalWire: Uint8Array;
  readonly endOffset: number;
  readonly text: string;
  readonly usedCompression: boolean;
}

interface RawDnsNameBudget {
  operations: number;
}

interface RawDnsDataBinding {
  readonly kind: 'replace';
  readonly value: unknown;
}

interface RawDnsRecord {
  readonly classCode: number;
  readonly dataBinding?: RawDnsDataBinding;
  readonly owner: RawDnsName;
  readonly rdata: Uint8Array;
  readonly rdataEnd: number;
  readonly rdataStart: number;
  readonly ttl: number;
  readonly typeCode: number;
}

interface RawDnsQuestion {
  readonly classCode: number;
  readonly name: RawDnsName;
  readonly typeCode: number;
}

interface RawDnsLayout {
  readonly flags: number;
  readonly id: number;
  readonly questions: readonly RawDnsQuestion[];
  readonly records: readonly RawDnsRecord[];
}

function asciiLower(byte: number): number {
  return byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte;
}

function escapedDnsOctet(byte: number): string {
  return (byte >= 0x30 && byte <= 0x39) ||
    (byte >= 0x41 && byte <= 0x5a) ||
    (byte >= 0x61 && byte <= 0x7a) ||
    byte === 0x2a ||
    byte === 0x2d ||
    byte === 0x5f
    ? String.fromCharCode(byte)
    : `\\${String(byte).padStart(3, '0')}`;
}

/** Decode one DNS wire name without interpreting label octets as Unicode text. */
function rawDnsName(
  message: Uint8Array,
  initialOffset: number,
  budget: RawDnsNameBudget,
): RawDnsName {
  if (
    !Number.isSafeInteger(initialOffset) ||
    initialOffset < 0 ||
    initialOffset >= message.length
  )
    throw new Error('DNS name starts outside the message.');

  const labels: Uint8Array[] = [];
  const visitedPointers = new Set<number>();
  let offset = initialOffset;
  let endOffset: number | undefined;
  let operations = 0;
  let pointers = 0;
  let wireOctets = 1;

  for (;;) {
    operations += 1;
    budget.operations += 1;
    if (budget.operations > MAX_DNS_MESSAGE_NAME_OPERATIONS)
      throw new Error('DNS message exceeds the aggregate name-decoding work limit.');
    if (operations > MAX_DNS_NAME_OPERATIONS)
      throw new Error('DNS name exceeds the compression-work limit.');
    const length = message[offset];
    if (length === undefined) throw new Error('Truncated DNS name.');

    if ((length & 0xc0) === 0xc0) {
      const low = message[offset + 1];
      if (low === undefined) throw new Error('Truncated DNS compression pointer.');
      const pointer = ((length & 0x3f) << 8) | low;
      if (pointer >= offset)
        throw new Error('DNS compression pointer must refer to prior message data.');
      if (visitedPointers.has(pointer)) throw new Error('DNS compression pointer loop.');
      pointers += 1;
      if (pointers > MAX_DNS_NAME_POINTERS)
        throw new Error('DNS name exceeds the compression-pointer limit.');
      visitedPointers.add(pointer);
      endOffset ??= offset + 2;
      offset = pointer;
      continue;
    }
    if ((length & 0xc0) !== 0) throw new Error('Unsupported DNS label encoding.');
    offset += 1;
    if (length === 0) {
      endOffset ??= offset;
      break;
    }
    if (length > 63 || offset + length > message.length) throw new Error('Malformed DNS name.');
    wireOctets += length + 1;
    if (wireOctets > MAX_DNS_NAME_WIRE_OCTETS) throw new Error('DNS name is too long.');
    labels.push(message.slice(offset, offset + length));
    offset += length;
  }

  const canonicalWire = new Uint8Array(wireOctets);
  let canonicalOffset = 0;
  for (const label of labels) {
    canonicalWire[canonicalOffset] = label.length;
    canonicalOffset += 1;
    for (const byte of label) {
      canonicalWire[canonicalOffset] = asciiLower(byte);
      canonicalOffset += 1;
    }
  }
  canonicalWire[canonicalOffset] = 0;
  return {
    canonicalWire,
    endOffset,
    text:
      labels.length === 0
        ? '.'
        : labels.map((label) => [...label].map(escapedDnsOctet).join('')).join('.'),
    usedCompression: pointers > 0,
  };
}

function rawDnsLayout(message: Uint8Array): RawDnsLayout {
  if (message.length < 12) throw new Error('DNS message is shorter than its header.');

  const id = readUint16(message, 0);
  const flags = readUint16(message, 2);
  const questionCount = readUint16(message, 4);
  const recordCount = readUint16(message, 6) + readUint16(message, 8) + readUint16(message, 10);
  const budget: RawDnsNameBudget = { operations: 0 };
  let offset = 12;

  const questions: RawDnsQuestion[] = [];
  for (let index = 0; index < questionCount; index += 1) {
    const name = rawDnsName(message, offset, budget);
    offset = name.endOffset;
    if (offset + 4 > message.length) throw new Error('Truncated DNS question.');
    questions.push({
      classCode: readUint16(message, offset + 2),
      name,
      typeCode: readUint16(message, offset),
    });
    offset += 4;
  }

  const records: RawDnsRecord[] = [];
  for (let index = 0; index < recordCount; index += 1) {
    const owner = rawDnsName(message, offset, budget);
    offset = owner.endOffset;
    if (offset + 10 > message.length) throw new Error('Truncated DNS resource record.');
    const typeCode = readUint16(message, offset);
    const classCode = readUint16(message, offset + 2);
    const ttl = readUint32(message, offset + 4);
    const length = readUint16(message, offset + 8);
    const start = offset + 10;
    const end = start + length;
    if (end > message.length) throw new Error('DNS resource record exceeds message bounds.');
    const raw = {
      classCode,
      owner,
      rdata: message.slice(start, end),
      rdataEnd: end,
      rdataStart: start,
      ttl,
      typeCode,
    };
    const dataBinding = rawRecordData(raw, message, budget);
    records.push({ ...raw, ...(dataBinding === undefined ? {} : { dataBinding }) });
    offset = end;
  }

  if (offset !== message.length) throw new Error('DNS message contains trailing bytes.');
  return { flags, id, questions, records };
}

function rawRecordName(
  message: Uint8Array,
  raw: RawDnsRecord,
  offset: number,
  requireRdataEnd: boolean,
  budget: RawDnsNameBudget,
): RawDnsName {
  if (offset < raw.rdataStart || offset >= raw.rdataEnd)
    throw new Error('DNS record name starts outside its RDATA.');
  const name = rawDnsName(message, offset, budget);
  if (name.endOffset > raw.rdataEnd || (requireRdataEnd && name.endOffset !== raw.rdataEnd))
    throw new Error('DNS record name exceeds its RDATA.');
  return name;
}

function readUint32(bytes: Uint8Array, offset: number): number {
  const high = readUint16(bytes, offset);
  const low = readUint16(bytes, offset + 2);
  return high * 0x1_0000 + low;
}

function wireTypeText(typeCode: number): string {
  return displayRecordType(dnsTypeName(typeCode));
}

function rawTypeBitmap(bytes: Uint8Array, initialOffset: number): readonly string[] {
  if (initialOffset >= bytes.length) throw new Error('DNS type bitmap is empty.');
  const types: string[] = [];
  let offset = initialOffset;
  let previousWindow = -1;
  while (offset < bytes.length) {
    const window = bytes[offset];
    const length = bytes[offset + 1];
    if (
      window === undefined ||
      length === undefined ||
      window <= previousWindow ||
      length < 1 ||
      length > 32 ||
      offset + 2 + length > bytes.length
    )
      throw new Error('DNS type bitmap is malformed.');
    const last = bytes[offset + 1 + length];
    if (last === 0) throw new Error('DNS type bitmap is not minimally encoded.');
    for (let octet = 0; octet < length; octet += 1) {
      const value = bytes[offset + 2 + octet];
      if (value === undefined) throw new Error('DNS type bitmap is truncated.');
      for (let bit = 0; bit < 8; bit += 1) {
        if ((value & (0x80 >>> bit)) !== 0)
          types.push(wireTypeText(window * 256 + octet * 8 + bit));
      }
    }
    previousWindow = window;
    offset += 2 + length;
  }
  return types;
}

function rawTxtData(raw: RawDnsRecord): readonly Uint8Array[] {
  if (raw.rdata.length === 0) throw new Error('TXT RDATA is empty.');
  const chunks: Uint8Array[] = [];
  let offset = 0;
  while (offset < raw.rdata.length) {
    const length = raw.rdata[offset];
    if (length === undefined || offset + 1 + length > raw.rdata.length)
      throw new Error('TXT RDATA is malformed.');
    chunks.push(raw.rdata.slice(offset + 1, offset + 1 + length));
    offset += 1 + length;
  }
  return chunks;
}

function rawCaaData(raw: RawDnsRecord): unknown {
  const parsed = parseCaaWireData(raw.rdata);
  if (parsed === null) throw new Error('CAA RDATA is malformed.');
  return parsed;
}

function rawOptData(raw: RawDnsRecord): Readonly<Record<string, unknown>> {
  if (raw.owner.canonicalWire.length !== 1 || raw.owner.canonicalWire[0] !== 0)
    throw new Error('OPT owner name is not the DNS root.');
  const options: DecodedOption[] = [];
  let offset = 0;
  while (offset < raw.rdata.length) {
    if (offset + 4 > raw.rdata.length) throw new Error('EDNS option header is truncated.');
    const code = readUint16(raw.rdata, offset);
    const length = readUint16(raw.rdata, offset + 2);
    if (offset + 4 + length > raw.rdata.length)
      throw new Error('EDNS option exceeds its declared RDATA.');
    options.push({ code, data: raw.rdata.slice(offset + 4, offset + 4 + length) });
    offset += 4 + length;
  }
  return {
    dnssecOk: Boolean(raw.ttl & DNSSEC_OK),
    extendedRcode: raw.ttl >>> 24,
    options,
    udpPayloadSize: raw.classCode,
    version: (raw.ttl >>> 16) & 0xff,
  };
}

function validateSvcbData(
  raw: RawDnsRecord,
  message: Uint8Array,
  budget: RawDnsNameBudget,
): void {
  if (raw.rdata.length < 3) throw new Error('SVCB RDATA is truncated.');
  const priority = readUint16(message, raw.rdataStart);
  const target = rawRecordName(message, raw, raw.rdataStart + 2, false, budget);
  if (target.usedCompression) throw new Error('SVCB target name uses prohibited compression.');
  let offset = target.endOffset;
  let previousKey = -1;
  while (offset < raw.rdataEnd) {
    if (offset + 4 > raw.rdataEnd) throw new Error('SVCB parameter header is truncated.');
    const key = readUint16(message, offset);
    const length = readUint16(message, offset + 2);
    if (key <= previousKey || offset + 4 + length > raw.rdataEnd)
      throw new Error('SVCB parameters are malformed or out of order.');
    previousKey = key;
    offset += 4 + length;
  }
  if (priority === 0 && offset !== target.endOffset)
    throw new Error('SVCB AliasMode contains prohibited parameters.');
}

function rawRecordData(
  raw: RawDnsRecord,
  message: Uint8Array,
  budget: RawDnsNameBudget,
): RawDnsDataBinding | undefined {
  const { typeCode } = raw;
  if (typeCode === 1) {
    if (raw.rdata.length !== 4) throw new Error('A RDATA must contain exactly four octets.');
    return { kind: 'replace', value: [...raw.rdata].join('.') };
  }
  if (typeCode === 28) {
    if (raw.rdata.length !== 16)
      throw new Error('AAAA RDATA must contain exactly sixteen octets.');
    const groups = Array.from({ length: 8 }, (_, index) =>
      readUint16(raw.rdata, index * 2).toString(16),
    );
    return { kind: 'replace', value: groups.join(':') };
  }
  if (typeCode === 16) return { kind: 'replace', value: rawTxtData(raw) };
  if (typeCode === 257) return { kind: 'replace', value: rawCaaData(raw) };
  if (typeCode === 2 || typeCode === 5 || typeCode === 12 || typeCode === 39) {
    return {
      kind: 'replace',
      value: rawRecordName(message, raw, raw.rdataStart, true, budget).text,
    };
  }
  if (typeCode === 15) {
    if (raw.rdata.length < 3) throw new Error('MX RDATA is truncated.');
    return {
      kind: 'replace',
      value: {
        preference: readUint16(message, raw.rdataStart),
        exchange: rawRecordName(message, raw, raw.rdataStart + 2, true, budget).text,
      },
    };
  }
  if (typeCode === 33) {
    if (raw.rdata.length < 7) throw new Error('SRV RDATA is truncated.');
    const target = rawRecordName(message, raw, raw.rdataStart + 6, true, budget);
    if (target.usedCompression) throw new Error('SRV target name uses prohibited compression.');
    return {
      kind: 'replace',
      value: {
        priority: readUint16(message, raw.rdataStart),
        weight: readUint16(message, raw.rdataStart + 2),
        port: readUint16(message, raw.rdataStart + 4),
        target: target.text,
      },
    };
  }
  if (typeCode === 6) {
    const mname = rawRecordName(message, raw, raw.rdataStart, false, budget);
    const rname = rawRecordName(message, raw, mname.endOffset, false, budget);
    if (rname.endOffset + 20 !== raw.rdataEnd)
      throw new Error('SOA RDATA has an invalid length.');
    return {
      kind: 'replace',
      value: {
        mname: mname.text,
        rname: rname.text,
        serial: readUint32(message, rname.endOffset),
        refresh: readUint32(message, rname.endOffset + 4),
        retry: readUint32(message, rname.endOffset + 8),
        expire: readUint32(message, rname.endOffset + 12),
        minimum: readUint32(message, rname.endOffset + 16),
      },
    };
  }
  if (typeCode === 17) {
    const mbox = rawRecordName(message, raw, raw.rdataStart, false, budget);
    const txt = rawRecordName(message, raw, mbox.endOffset, true, budget);
    return { kind: 'replace', value: { mbox: mbox.text, txt: txt.text } };
  }
  if (typeCode === 46) {
    if (raw.rdata.length < 19) throw new Error('RRSIG RDATA is truncated.');
    const signerName = rawRecordName(message, raw, raw.rdataStart + 18, false, budget);
    if (signerName.usedCompression)
      throw new Error('RRSIG signer name uses prohibited compression.');
    if (signerName.endOffset >= raw.rdataEnd)
      throw new Error('RRSIG RDATA has no signature octets.');
    return {
      kind: 'replace',
      value: {
        algorithm: raw.rdata[2],
        expiration: readUint32(message, raw.rdataStart + 8),
        inception: readUint32(message, raw.rdataStart + 12),
        keyTag: readUint16(message, raw.rdataStart + 16),
        labels: raw.rdata[3],
        originalTTL: readUint32(message, raw.rdataStart + 4),
        signature: message.slice(signerName.endOffset, raw.rdataEnd),
        signersName: signerName.text,
        typeCovered: wireTypeText(readUint16(message, raw.rdataStart)),
      },
    };
  }
  if (typeCode === 47) {
    const nextDomain = rawRecordName(message, raw, raw.rdataStart, false, budget);
    if (nextDomain.usedCompression)
      throw new Error('NSEC next-domain name uses prohibited compression.');
    const bitmapOffset = nextDomain.endOffset - raw.rdataStart;
    return {
      kind: 'replace',
      value: { nextDomain: nextDomain.text, rrtypes: rawTypeBitmap(raw.rdata, bitmapOffset) },
    };
  }
  if (typeCode === 50) {
    if (raw.rdata.length < 7) throw new Error('NSEC3 RDATA is truncated.');
    const saltLength = raw.rdata[4];
    if (saltLength === undefined || 5 + saltLength >= raw.rdata.length)
      throw new Error('NSEC3 salt exceeds its RDATA.');
    const hashLengthOffset = 5 + saltLength;
    const hashLength = raw.rdata[hashLengthOffset];
    if (
      hashLength === undefined ||
      hashLength < 1 ||
      hashLengthOffset + 1 + hashLength >= raw.rdata.length
    )
      throw new Error('NSEC3 next-owner hash exceeds its RDATA.');
    const bitmapOffset = hashLengthOffset + 1 + hashLength;
    return {
      kind: 'replace',
      value: {
        algorithm: raw.rdata[0],
        flags: raw.rdata[1],
        iterations: readUint16(raw.rdata, 2),
        nextDomain: raw.rdata.slice(hashLengthOffset + 1, bitmapOffset),
        rrtypes: rawTypeBitmap(raw.rdata, bitmapOffset),
        salt: raw.rdata.slice(5, hashLengthOffset),
      },
    };
  }
  if (typeCode === 41) return { kind: 'replace', value: rawOptData(raw) };
  if (typeCode === 43 && raw.rdata.length < 5) throw new Error('DS RDATA is truncated.');
  if (typeCode === 44 && raw.rdata.length < 3) throw new Error('SSHFP RDATA is truncated.');
  if (typeCode === 48 && raw.rdata.length < 5) throw new Error('DNSKEY RDATA is truncated.');
  if (typeCode === 51) {
    const saltLength = raw.rdata[4];
    if (saltLength === undefined || raw.rdata.length !== 5 + saltLength)
      throw new Error('NSEC3PARAM RDATA is malformed.');
  }
  if (typeCode === 52 && raw.rdata.length < 4) throw new Error('TLSA RDATA is truncated.');
  if (typeCode === 63 && raw.rdata.length < 7) throw new Error('ZONEMD RDATA is truncated.');
  if (typeCode === 64 || typeCode === 65) validateSvcbData(raw, message, budget);
  return undefined;
}

function boundRecordData(answer: Answer, raw: RawDnsRecord): unknown {
  if (raw.dataBinding === undefined) return answer.data;
  return raw.dataBinding.value;
}

function decodedClassCode(value: string | undefined): number {
  const name = value ?? 'IN';
  const standard = toClass(name);
  if (standard !== 0) return standard;
  const unknown = /^UNKNOWN_(\d+)$/u.exec(name.toUpperCase())?.[1];
  if (unknown === undefined) return 0;
  const parsed = Number(unknown);
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= 0xffff ? parsed : 0;
}

function validateDecodedRecord(answer: Answer, raw: RawDnsRecord): void {
  if (toType(answer.type) !== raw.typeCode)
    throw new Error('Decoded DNS record type conflicts with its wire framing.');
  if (raw.typeCode === 41) {
    const opt = answer as DecodedOptAnswer;
    if (
      opt.udpPayloadSize !== raw.classCode ||
      (opt.extendedRcode ?? 0) !== raw.ttl >>> 24 ||
      (opt.ednsVersion ?? 0) !== ((raw.ttl >>> 16) & 0xff) ||
      (opt.flags ?? 0) !== (raw.ttl & 0xffff)
    )
      throw new Error('Decoded OPT metadata conflicts with its wire framing.');
    return;
  }
  if (decodedClassCode(answer.class) !== raw.classCode)
    throw new Error('Decoded DNS record class conflicts with its wire framing.');
  if ((answer.ttl ?? 0) !== raw.ttl)
    throw new Error('Decoded DNS record TTL conflicts with its wire framing.');
}

function toRecord(answer: Answer, raw: RawDnsRecord, section: DnsSection): DnsRecord {
  validateDecodedRecord(answer, raw);
  const opt = raw.typeCode === 41;
  return {
    canonicalOwnerWire: raw.owner.canonicalWire.slice(),
    class: opt ? `CLASS${String(raw.classCode)}` : (answer.class ?? 'IN'),
    data: boundRecordData(answer, raw),
    owner: raw.owner.text,
    rawRdata: raw.rdata,
    section,
    ttl: opt ? 0 : raw.ttl,
    type: wireTypeText(raw.typeCode),
    typeCode: raw.typeCode,
  };
}

function optionCode(option: DecodedOption): number | undefined {
  if (typeof option.code === 'number') return option.code;
  if (option.code === 'OPTION_15') return 15;
  const match = /^OPTION_(\d+)$/u.exec(option.code ?? '');
  return match?.[1] === undefined ? undefined : Number(match[1]);
}

function extendedError(option: DecodedOption): DnsExtendedError | undefined {
  if (optionCode(option) !== 15 || option.data === undefined || option.data.length < 2)
    return undefined;
  const code = readUint16(option.data, 0);
  const decoded = new TextDecoder().decode(option.data.slice(2));
  return {
    code,
    name: EXTENDED_ERROR_NAMES[code] ?? 'Unassigned extended DNS error',
    ...(decoded === '' ? {} : { text: decoded }),
  };
}

function ednsMetadata(additionals: readonly DnsRecord[]): DnsEdns | undefined {
  const opt = additionals.find((record) => record.type === 'OPT');
  if (opt === undefined) return undefined;
  const value =
    opt.data !== null && typeof opt.data === 'object' && !Array.isArray(opt.data)
      ? (opt.data as Readonly<Record<string, unknown>>)
      : undefined;
  if (value === undefined) throw new Error('OPT metadata is not a bounded object.');
  const options = Array.isArray(value['options'])
    ? value['options'].filter(
        (option): option is DecodedOption =>
          option !== null && typeof option === 'object' && !Array.isArray(option),
      )
    : [];
  const extendedErrors = options.flatMap((option) => {
    const error = extendedError(option);
    return error === undefined ? [] : [error];
  });
  return {
    dnssecOk: value['dnssecOk'] === true,
    extendedErrors,
    extendedResponseCode:
      typeof value['extendedRcode'] === 'number' ? value['extendedRcode'] : 0,
    udpPayloadSize: typeof value['udpPayloadSize'] === 'number' ? value['udpPayloadSize'] : 0,
    version: typeof value['version'] === 'number' ? value['version'] : 0,
  };
}

function negativeCacheTtl(
  responseCode: string,
  answers: readonly DnsRecord[],
  authorities: readonly DnsRecord[],
): number | undefined {
  if (responseCode !== 'NXDOMAIN' && (responseCode !== 'NOERROR' || answers.length > 0))
    return undefined;
  const soa = authorities.find((record) => record.type === 'SOA');
  if (soa === undefined || soa.data === null || typeof soa.data !== 'object') return undefined;
  const minimum = (soa.data as Record<string, unknown>)['minimum'];
  if (typeof minimum !== 'number' || !Number.isInteger(minimum) || minimum < 0)
    return undefined;
  return Math.min(soa.ttl, minimum);
}

export function encodeDnsQuery(question: DnsQuestion, options: DnsQueryOptions): Uint8Array {
  const flags = RECURSION_DESIRED | (options.checkingDisabled ? CHECKING_DISABLED : 0);
  const clientSubnet = {
    code: 'CLIENT_SUBNET',
    family: 1,
    ip: '0.0.0.0',
    scopePrefixLength: 0,
    sourcePrefixLength: 0,
  };
  const packet = (ednsOptions: readonly unknown[]): Packet => ({
    additionals: [
      {
        class: 'IN',
        name: '.',
        type: 'OPT',
        flags: options.dnssecOk ? DNSSEC_OK : 0,
        options: ednsOptions,
        udpPayloadSize: 1232,
      } as unknown as Answer,
    ],
    flags,
    id: 0,
    questions: [
      { class: 'IN', name: question.name.absolute, type: wireRecordType(question.type) },
    ],
    type: 'query',
  });

  const unpadded = encode(packet([clientSubnet]));
  // RFC 8467 counts the mandatory four-octet option header in the padded message length.
  const optionHeaderBytes = 4;
  const paddingLength =
    (DNS_QUERY_PADDING_BLOCK_BYTES -
      ((unpadded.length + optionHeaderBytes) % DNS_QUERY_PADDING_BLOCK_BYTES)) %
    DNS_QUERY_PADDING_BLOCK_BYTES;
  return encode(packet([clientSubnet, { code: 'PADDING', length: paddingLength }]));
}

export function decodeDnsMessage(bytes: Uint8Array): DnsMessage {
  if (bytes.length < 12) throw new Error('DNS message is shorter than its header.');
  if (bytes.length > MAX_DNS_MESSAGE_BYTES) {
    throw new Error('DNS response has an invalid message length.');
  }

  const rawLayout = rawDnsLayout(bytes);
  const packet = decode(bytes);
  if (
    (rawLayout.flags & 0x8000) === 0 ||
    packet.type !== 'response' ||
    packet.flag_qr !== true
  ) {
    throw new Error('Resolver returned a DNS query instead of a response.');
  }
  if ((packet.id ?? 0) !== rawLayout.id)
    throw new Error('Decoded DNS message ID conflicts with its wire header.');
  const headerResponseCode = packet.rcode ?? 'UNKNOWN';
  if (toRcode(headerResponseCode) !== (rawLayout.flags & 0x0f))
    throw new Error('Decoded DNS response code conflicts with its wire header.');
  let rawIndex = 0;

  const mapSection = (answers: readonly Answer[] | undefined, section: DnsSection) =>
    (answers ?? []).map((answer) => {
      const raw = rawLayout.records[rawIndex];
      rawIndex += 1;
      if (raw === undefined) throw new Error('DNS record data was not found.');
      return toRecord(answer, raw, section);
    });

  const answers = mapSection(packet.answers, 'answer');
  const authorities = mapSection(packet.authorities, 'authority');
  const additionals = mapSection(packet.additionals, 'additional');
  if (rawIndex !== rawLayout.records.length)
    throw new Error('Decoded DNS record count conflicts with its wire header.');
  const edns = ednsMetadata(additionals);
  const responseCode =
    edns !== undefined && edns.extendedResponseCode !== 0
      ? `EXTENDED_RCODE_${String((edns.extendedResponseCode << 4) | toRcode(headerResponseCode))}`
      : headerResponseCode;
  const negativeTtl = negativeCacheTtl(responseCode, answers, authorities);
  return {
    additionals,
    answers,
    authorities,
    ...(edns === undefined ? {} : { edns }),
    flags: {
      authoritativeAnswer: Boolean(rawLayout.flags & 0x0400),
      authenticatedData: Boolean(rawLayout.flags & AUTHENTIC_DATA),
      checkingDisabled: Boolean(rawLayout.flags & CHECKING_DISABLED),
      recursionAvailable: Boolean(rawLayout.flags & RECURSION_AVAILABLE),
      recursionDesired: Boolean(rawLayout.flags & RECURSION_DESIRED),
      truncated: Boolean(rawLayout.flags & TRUNCATED_RESPONSE),
    },
    id: rawLayout.id,
    messageBytes: bytes.length,
    ...(negativeTtl === undefined ? {} : { negativeCacheTtl: negativeTtl }),
    questions: (() => {
      const decodedQuestions = packet.questions ?? [];
      if (decodedQuestions.length !== rawLayout.questions.length)
        throw new Error('Decoded DNS question count conflicts with its wire header.');
      return decodedQuestions.map((question, index) => {
        const raw = rawLayout.questions[index];
        if (raw === undefined) throw new Error('DNS question data was not found.');
        if (
          toType(question.type) !== raw.typeCode ||
          decodedClassCode(question.class) !== raw.classCode
        )
          throw new Error('Decoded DNS question conflicts with its wire framing.');
        return {
          canonicalNameWire: raw.name.canonicalWire.slice(),
          class: question.class ?? 'IN',
          name: raw.name.text,
          type: wireTypeText(raw.typeCode),
        };
      });
    })(),
    raw: bytes.slice(),
    responseCode,
  };
}
