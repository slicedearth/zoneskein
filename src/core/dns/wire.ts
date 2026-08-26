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
import { toType } from '@dnsquery/dns-packet/types.js';
import { toRcode } from '@dnsquery/dns-packet/rcodes.js';

import type {
  DnsEdns,
  DnsExtendedError,
  DnsMessage,
  DnsQueryOptions,
  DnsQuestion,
  DnsRecord,
  DnsSection,
} from './types';
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
  readonly flag_do?: boolean;
  readonly flags?: number;
  readonly options?: readonly DecodedOption[];
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
}

interface RawDnsNameBudget {
  operations: number;
}

type RawDnsDataBinding =
  | { readonly kind: 'merge'; readonly value: Readonly<Record<string, unknown>> }
  | { readonly kind: 'replace'; readonly value: unknown };

interface RawDnsRecord {
  readonly dataBinding?: RawDnsDataBinding;
  readonly owner: RawDnsName;
  readonly rdata: Uint8Array;
  readonly rdataEnd: number;
  readonly rdataStart: number;
}

interface RawDnsLayout {
  readonly questions: readonly RawDnsName[];
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
  };
}

function rawDnsLayout(message: Uint8Array): RawDnsLayout {
  if (message.length < 12) throw new Error('DNS message is shorter than its header.');

  const questionCount = readUint16(message, 4);
  const recordCount = readUint16(message, 6) + readUint16(message, 8) + readUint16(message, 10);
  const budget: RawDnsNameBudget = { operations: 0 };
  let offset = 12;

  const questions: RawDnsName[] = [];
  for (let index = 0; index < questionCount; index += 1) {
    const name = rawDnsName(message, offset, budget);
    questions.push(name);
    offset = name.endOffset;
    if (offset + 4 > message.length) throw new Error('Truncated DNS question.');
    offset += 4;
  }

  const records: RawDnsRecord[] = [];
  for (let index = 0; index < recordCount; index += 1) {
    const owner = rawDnsName(message, offset, budget);
    offset = owner.endOffset;
    if (offset + 10 > message.length) throw new Error('Truncated DNS resource record.');
    const typeCode = readUint16(message, offset);
    const length = readUint16(message, offset + 8);
    const start = offset + 10;
    const end = start + length;
    if (end > message.length) throw new Error('DNS resource record exceeds message bounds.');
    const raw = {
      owner,
      rdata: message.slice(start, end),
      rdataEnd: end,
      rdataStart: start,
    };
    const dataBinding = rawNameBearingData(typeCode, raw, message, budget);
    records.push({ ...raw, ...(dataBinding === undefined ? {} : { dataBinding }) });
    offset = end;
  }

  if (offset !== message.length) throw new Error('DNS message contains trailing bytes.');
  return { questions, records };
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

function rawNameBearingData(
  typeCode: number,
  raw: RawDnsRecord,
  message: Uint8Array,
  budget: RawDnsNameBudget,
): RawDnsDataBinding | undefined {
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
    return {
      kind: 'replace',
      value: {
        priority: readUint16(message, raw.rdataStart),
        weight: readUint16(message, raw.rdataStart + 2),
        port: readUint16(message, raw.rdataStart + 4),
        target: rawRecordName(message, raw, raw.rdataStart + 6, true, budget).text,
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
    return { kind: 'merge', value: { signersName: signerName.text } };
  }
  if (typeCode === 47) {
    const nextDomain = rawRecordName(message, raw, raw.rdataStart, false, budget);
    return { kind: 'merge', value: { nextDomain: nextDomain.text } };
  }
  return undefined;
}

function boundRecordData(answer: Answer, raw: RawDnsRecord): unknown {
  if (raw.dataBinding === undefined) return answer.data;
  if (raw.dataBinding.kind === 'replace') return raw.dataBinding.value;
  const data: unknown = answer.data;
  if (
    data === null ||
    typeof data !== 'object' ||
    Array.isArray(data) ||
    data instanceof Uint8Array
  )
    throw new Error('DNS record data could not be bound to its wire evidence.');
  return { ...data, ...raw.dataBinding.value };
}

function toRecord(answer: Answer, raw: RawDnsRecord, section: DnsSection): DnsRecord {
  const typeCode = toType(answer.type);
  const opt = answer.type === 'OPT' ? (answer as DecodedOptAnswer) : undefined;
  return {
    canonicalOwnerWire: raw.owner.canonicalWire.slice(),
    class: answer.class ?? 'IN',
    data:
      opt === undefined
        ? boundRecordData(answer, raw)
        : {
            dnssecOk: opt.flag_do ?? Boolean((opt.flags ?? 0) & DNSSEC_OK),
            extendedRcode: opt.extendedRcode ?? 0,
            options: opt.options ?? [],
            udpPayloadSize: opt.udpPayloadSize ?? 0,
            version: opt.ednsVersion ?? 0,
          },
    owner: raw.owner.text,
    rawRdata: raw.rdata,
    section,
    ttl: answer.ttl ?? 0,
    type: typeCode === 0 ? answer.type : displayRecordType(answer.type),
    typeCode,
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

function ednsMetadata(additionals: readonly Answer[] | undefined): DnsEdns | undefined {
  const opt = additionals?.find((answer) => answer.type === 'OPT') as
    DecodedOptAnswer | undefined;
  if (opt === undefined) return undefined;
  const extendedErrors = (opt.options ?? []).flatMap((option) => {
    const error = extendedError(option);
    return error === undefined ? [] : [error];
  });
  return {
    dnssecOk: opt.flag_do ?? Boolean((opt.flags ?? 0) & DNSSEC_OK),
    extendedErrors,
    extendedResponseCode: opt.extendedRcode ?? 0,
    udpPayloadSize: opt.udpPayloadSize ?? 0,
    version: opt.ednsVersion ?? 0,
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
  if (packet.type !== 'response' && packet.flag_qr !== true) {
    throw new Error('Resolver returned a DNS query instead of a response.');
  }
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
  const flags = packet.flags ?? 0;
  const headerResponseCode = packet.rcode ?? 'UNKNOWN';
  const edns = ednsMetadata(packet.additionals);
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
      authoritativeAnswer: packet.flag_aa ?? false,
      authenticatedData: packet.flag_ad ?? Boolean(flags & AUTHENTIC_DATA),
      checkingDisabled: packet.flag_cd ?? Boolean(flags & CHECKING_DISABLED),
      recursionAvailable: packet.flag_ra ?? Boolean(flags & RECURSION_AVAILABLE),
      recursionDesired: packet.flag_rd ?? Boolean(flags & RECURSION_DESIRED),
      truncated: packet.flag_tc ?? Boolean(flags & TRUNCATED_RESPONSE),
    },
    id: packet.id ?? 0,
    messageBytes: bytes.length,
    ...(negativeTtl === undefined ? {} : { negativeCacheTtl: negativeTtl }),
    questions: (packet.questions ?? []).map((question, index) => {
      const rawName = rawLayout.questions[index];
      if (rawName === undefined) throw new Error('DNS question name was not found.');
      return {
        canonicalNameWire: rawName.canonicalWire.slice(),
        class: question.class ?? 'IN',
        name: rawName.text,
        type: displayRecordType(question.type),
      };
    }),
    raw: bytes.slice(),
    responseCode,
  };
}
