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

import type { DnsMessage, DnsQueryOptions, DnsQuestion, DnsRecord, DnsSection } from './types';
import { displayRecordType, wireRecordType } from './record-types';

const MAX_DNS_MESSAGE_BYTES = 65_535;

function readUint16(bytes: Uint8Array, offset: number): number {
  const high = bytes[offset];
  const low = bytes[offset + 1];
  if (high === undefined || low === undefined) throw new Error('Truncated DNS integer.');
  return (high << 8) | low;
}

function skipName(bytes: Uint8Array, initialOffset: number): number {
  let offset = initialOffset;
  let labels = 0;

  while (offset < bytes.length) {
    const length = bytes[offset];
    if (length === undefined) throw new Error('Truncated DNS name.');
    if ((length & 0xc0) === 0xc0) {
      if (offset + 1 >= bytes.length) throw new Error('Truncated DNS compression pointer.');
      return offset + 2;
    }
    if ((length & 0xc0) !== 0) throw new Error('Unsupported DNS label encoding.');
    offset += 1;
    if (length === 0) return offset;
    if (length > 63 || offset + length > bytes.length) throw new Error('Malformed DNS name.');
    offset += length;
    labels += 1;
    if (labels > 127) throw new Error('DNS name contains too many labels.');
  }

  throw new Error('Truncated DNS name.');
}

function rawRecordData(message: Uint8Array): readonly Uint8Array[] {
  if (message.length < 12) throw new Error('DNS message is shorter than its header.');

  const questionCount = readUint16(message, 4);
  const recordCount = readUint16(message, 6) + readUint16(message, 8) + readUint16(message, 10);
  let offset = 12;

  for (let index = 0; index < questionCount; index += 1) {
    offset = skipName(message, offset);
    if (offset + 4 > message.length) throw new Error('Truncated DNS question.');
    offset += 4;
  }

  const values: Uint8Array[] = [];
  for (let index = 0; index < recordCount; index += 1) {
    offset = skipName(message, offset);
    if (offset + 10 > message.length) throw new Error('Truncated DNS resource record.');
    const length = readUint16(message, offset + 8);
    const start = offset + 10;
    const end = start + length;
    if (end > message.length) throw new Error('DNS resource record exceeds message bounds.');
    values.push(message.slice(start, end));
    offset = end;
  }

  if (offset !== message.length) throw new Error('DNS message contains trailing bytes.');
  return values;
}

function toRecord(answer: Answer, rawRdata: Uint8Array, section: DnsSection): DnsRecord {
  const typeCode = toType(answer.type);
  return {
    class: answer.class ?? 'IN',
    data: answer.data,
    owner: answer.name,
    rawRdata,
    section,
    ttl: answer.ttl ?? 0,
    type: typeCode === 0 ? answer.type : displayRecordType(answer.type),
    typeCode,
  };
}

export function encodeDnsQuery(question: DnsQuestion, options: DnsQueryOptions): Uint8Array {
  const flags = RECURSION_DESIRED | (options.checkingDisabled ? CHECKING_DISABLED : 0);
  const additionals: Answer[] = options.dnssecOk
    ? [
        {
          class: 'IN',
          name: '.',
          type: 'OPT',
          flags: DNSSEC_OK,
          options: [
            {
              code: 'CLIENT_SUBNET',
              family: 1,
              ip: '0.0.0.0',
              scopePrefixLength: 0,
              sourcePrefixLength: 0,
            },
          ],
          udpPayloadSize: 1232,
        } as unknown as Answer,
      ]
    : [];

  const packet: Packet = {
    additionals,
    flags,
    id: 0,
    questions: [
      { class: 'IN', name: question.name.absolute, type: wireRecordType(question.type) },
    ],
    type: 'query',
  };
  return encode(packet);
}

export function decodeDnsMessage(bytes: Uint8Array): DnsMessage {
  if (bytes.length < 12) throw new Error('DNS message is shorter than its header.');
  if (bytes.length > MAX_DNS_MESSAGE_BYTES) {
    throw new Error('DNS response has an invalid message length.');
  }

  const packet = decode(bytes);
  if (packet.type !== 'response' && packet.flag_qr !== true) {
    throw new Error('Resolver returned a DNS query instead of a response.');
  }
  const rawData = rawRecordData(bytes);
  let rawIndex = 0;

  const mapSection = (answers: readonly Answer[] | undefined, section: DnsSection) =>
    (answers ?? []).map((answer) => {
      const raw = rawData[rawIndex];
      rawIndex += 1;
      if (raw === undefined) throw new Error('DNS record data was not found.');
      return toRecord(answer, raw, section);
    });

  const flags = packet.flags ?? 0;
  return {
    additionals: mapSection(packet.additionals, 'additional'),
    answers: mapSection(packet.answers, 'answer'),
    authorities: mapSection(packet.authorities, 'authority'),
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
    questions: (packet.questions ?? []).map((question) => ({
      name: question.name,
      type: displayRecordType(question.type),
    })),
    raw: bytes.slice(),
    responseCode: packet.rcode ?? 'UNKNOWN',
  };
}
