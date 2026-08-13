import { toString as dnsTypeName, toType } from '@dnsquery/dns-packet/types.js';

import type { DnsRecord, DnsResponse, DnsSection } from '../dns/types';

interface WireName {
  readonly canonical: Uint8Array;
  readonly nextOffset: number;
  readonly safeText: string | null;
  readonly usedCompression: boolean;
}

interface WireParseWork {
  operations: number;
}

interface WireQuestion {
  readonly classCode: number;
  readonly name: WireName;
  readonly typeCode: number;
}

interface WireRecord {
  readonly classCode: number;
  readonly owner: WireName;
  readonly rdataEnd: number;
  readonly rdataOffset: number;
  readonly section: DnsSection;
  readonly ttl: number;
  readonly typeCode: number;
}

interface ParsedWireResponse {
  readonly additionals: readonly WireRecord[];
  readonly answers: readonly WireRecord[];
  readonly authorities: readonly WireRecord[];
  readonly flags: number;
  readonly id: number;
  readonly questions: readonly WireQuestion[];
  readonly work: WireParseWork;
}

const MAX_PACKET_NAME_OPERATIONS = 32_768;
const MAX_PACKET_RECORDS = 512;
const STANDARD_RESPONSE_CODES: Readonly<Record<string, number>> = {
  FORMERR: 1,
  NOERROR: 0,
  NOTAUTH: 9,
  NOTIMP: 4,
  NOTZONE: 10,
  NXDOMAIN: 3,
  NXRRSET: 8,
  RCODE_11: 11,
  RCODE_12: 12,
  RCODE_13: 13,
  RCODE_14: 14,
  RCODE_15: 15,
  REFUSED: 5,
  SERVFAIL: 2,
  YXDOMAIN: 6,
  YXRRSET: 7,
};
const parsedResponses = new WeakMap<DnsResponse, ParsedWireResponse | null>();
const canonicalRdata = new WeakMap<DnsRecord, Uint8Array>();

function readUint16(bytes: Uint8Array, offset: number): number | null {
  const high = bytes[offset];
  const low = bytes[offset + 1];
  return high === undefined || low === undefined ? null : (high << 8) | low;
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
    : (first * 0x1000000 + (second << 16) + (third << 8) + fourth) >>> 0;
}

function join(parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function foldLabel(label: Uint8Array): Uint8Array {
  return label.map((byte) => (byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte));
}

function safeLabel(label: Uint8Array): string | null {
  let text = '';
  for (const byte of label) {
    const safe =
      (byte >= 0x30 && byte <= 0x39) ||
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      byte === 0x2a ||
      byte === 0x2d ||
      byte === 0x5f;
    if (!safe) return null;
    text += String.fromCharCode(byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte);
  }
  return text;
}

function readName(
  message: Uint8Array,
  initialOffset: number,
  work: WireParseWork,
): WireName | null {
  const labels: Uint8Array[] = [];
  const visited = new Set<number>();
  let cursor = initialOffset;
  let nextOffset: number | undefined;
  let usedCompression = false;
  let wireLength = 1;

  for (let operation = 0; operation < 256; operation += 1) {
    work.operations += 1;
    if (work.operations > MAX_PACKET_NAME_OPERATIONS) return null;
    if (visited.has(cursor) || cursor >= message.length) return null;
    visited.add(cursor);
    const length = message[cursor];
    if (length === undefined) return null;
    if ((length & 0xc0) === 0xc0) {
      const second = message[cursor + 1];
      if (second === undefined) return null;
      const target = ((length & 0x3f) << 8) | second;
      if (target >= cursor) return null;
      nextOffset ??= cursor + 2;
      usedCompression = true;
      cursor = target;
      continue;
    }
    if ((length & 0xc0) !== 0 || length > 63) return null;
    cursor += 1;
    if (length === 0) {
      nextOffset ??= cursor;
      const canonical = join([
        ...labels.map((label) => new Uint8Array([label.length, ...foldLabel(label)])),
        new Uint8Array([0]),
      ]);
      const safeLabels = labels.map(safeLabel);
      return {
        canonical,
        nextOffset,
        safeText: safeLabels.some((label) => label === null)
          ? null
          : safeLabels.length === 0
            ? '.'
            : `${(safeLabels as string[]).join('.')}.`,
        usedCompression,
      };
    }
    if (cursor + length > message.length || wireLength + length + 1 > 255) return null;
    const label = message.slice(cursor, cursor + length);
    labels.push(label);
    wireLength += length + 1;
    cursor += length;
  }
  return null;
}

function parseRecord(
  message: Uint8Array,
  offset: number,
  section: DnsSection,
  work: WireParseWork,
): { readonly nextOffset: number; readonly record: WireRecord } | null {
  const owner = readName(message, offset, work);
  if (owner === null || owner.nextOffset + 10 > message.length) return null;
  const typeCode = readUint16(message, owner.nextOffset);
  const classCode = readUint16(message, owner.nextOffset + 2);
  const ttl = readUint32(message, owner.nextOffset + 4);
  const rdataLength = readUint16(message, owner.nextOffset + 8);
  if (typeCode === null || classCode === null || ttl === null || rdataLength === null)
    return null;
  const rdataOffset = owner.nextOffset + 10;
  const rdataEnd = rdataOffset + rdataLength;
  if (rdataEnd > message.length) return null;
  return {
    nextOffset: rdataEnd,
    record: { classCode, owner, rdataEnd, rdataOffset, section, ttl, typeCode },
  };
}

function parseResponse(response: DnsResponse): ParsedWireResponse | null {
  const cached = parsedResponses.get(response);
  if (cached !== undefined) return cached;
  const message = response.message.raw;
  const work: WireParseWork = { operations: 0 };
  if (message.length === 0) {
    const fallback: ParsedWireResponse = {
      additionals: [],
      answers: [],
      authorities: [],
      flags: 0x8000,
      id: 0,
      questions: [],
      work,
    };
    parsedResponses.set(response, fallback);
    return fallback;
  }
  if (message.length < 12) {
    parsedResponses.set(response, null);
    return null;
  }
  const questionCount = readUint16(message, 4);
  const answerCount = readUint16(message, 6);
  const authorityCount = readUint16(message, 8);
  const additionalCount = readUint16(message, 10);
  const id = readUint16(message, 0);
  const flags = readUint16(message, 2);
  if (
    id === null ||
    flags === null ||
    questionCount === null ||
    answerCount === null ||
    authorityCount === null ||
    additionalCount === null
  ) {
    parsedResponses.set(response, null);
    return null;
  }
  if (answerCount + authorityCount + additionalCount > MAX_PACKET_RECORDS) {
    parsedResponses.set(response, null);
    return null;
  }
  let offset = 12;
  const questions: WireQuestion[] = [];
  for (let index = 0; index < questionCount; index += 1) {
    const name = readName(message, offset, work);
    if (name === null || name.nextOffset + 4 > message.length) {
      parsedResponses.set(response, null);
      return null;
    }
    const typeCode = readUint16(message, name.nextOffset);
    const classCode = readUint16(message, name.nextOffset + 2);
    if (typeCode === null || classCode === null) {
      parsedResponses.set(response, null);
      return null;
    }
    questions.push({ classCode, name, typeCode });
    offset = name.nextOffset + 4;
  }
  const sections: [DnsSection, number, WireRecord[]][] = [
    ['answer', answerCount, []],
    ['authority', authorityCount, []],
    ['additional', additionalCount, []],
  ];
  for (const [section, count, records] of sections) {
    for (let index = 0; index < count; index += 1) {
      const parsed = parseRecord(message, offset, section, work);
      if (parsed === null) {
        parsedResponses.set(response, null);
        return null;
      }
      records.push(parsed.record);
      offset = parsed.nextOffset;
    }
  }
  if (offset !== message.length) {
    parsedResponses.set(response, null);
    return null;
  }
  const parsed: ParsedWireResponse = {
    additionals: sections[2]?.[2] ?? [],
    answers: sections[0]?.[2] ?? [],
    authorities: sections[1]?.[2] ?? [],
    flags,
    id,
    questions,
    work,
  };
  parsedResponses.set(response, parsed);
  return parsed;
}

function safeExpectedName(name: string): Uint8Array | null {
  const value = name.endsWith('.') ? name.slice(0, -1) : name;
  if (value === '') return new Uint8Array([0]);
  const labels = value.split('.');
  const encoded: Uint8Array[] = [];
  let wireLength = 1;
  for (const label of labels) {
    if (label === '') return null;
    const bytes = new TextEncoder().encode(label);
    if (bytes.length > 63 || safeLabel(bytes) === null || wireLength + bytes.length + 1 > 255)
      return null;
    encoded.push(new Uint8Array([bytes.length, ...foldLabel(bytes)]));
    wireLength += bytes.length + 1;
  }
  return join([...encoded, new Uint8Array([0])]);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => right[index] === byte);
}

function responseCodeValue(value: string): number | null {
  const standard = STANDARD_RESPONSE_CODES[value];
  if (standard !== undefined) return standard;
  const extended = /^EXTENDED_RCODE_(\d+)$/u.exec(value)?.[1];
  if (extended === undefined) return null;
  const number = Number(extended);
  return Number.isInteger(number) && number >= 0 && number <= 0xfff ? number : null;
}

function wireResponseCodeMatches(parsed: ParsedWireResponse, decoded: string): boolean {
  const options = parsed.additionals.filter((record) => record.typeCode === 41);
  if (options.length > 1) return false;
  const option = options[0];
  if (option !== undefined && !bytesEqual(option.owner.canonical, new Uint8Array([0])))
    return false;
  const extended = option === undefined ? 0 : (option.ttl >>> 24) & 0xff;
  return responseCodeValue(decoded) === ((extended << 4) | (parsed.flags & 0x0f));
}

function typeCode(type: string): number {
  if (type === 'SVCB') return 64;
  if (type === 'HTTPS') return 65;
  return toType(type);
}

function typeText(code: number): string {
  if (code === 64) return 'SVCB';
  if (code === 65) return 'HTTPS';
  return dnsTypeName(code).replace('UNKNOWN_', 'TYPE');
}

function rawSlice(message: Uint8Array, record: WireRecord): Uint8Array {
  return message.slice(record.rdataOffset, record.rdataEnd);
}

function canonicalNameRdata(
  message: Uint8Array,
  offset: number,
  end: number,
  work: WireParseWork,
): Uint8Array | null {
  const name = readName(message, offset, work);
  return name?.nextOffset !== end ? null : name.canonical;
}

function canonicalApplicationRdata(
  message: Uint8Array,
  record: WireRecord,
  work: WireParseWork,
): Uint8Array | null {
  const raw = rawSlice(message, record);
  if (
    record.typeCode === 1 ||
    record.typeCode === 16 ||
    record.typeCode === 28 ||
    record.typeCode === 43 ||
    record.typeCode === 44 ||
    record.typeCode === 48 ||
    record.typeCode === 50 ||
    record.typeCode === 52 ||
    record.typeCode === 257
  )
    return raw;
  if ([2, 5, 12, 39].includes(record.typeCode))
    return canonicalNameRdata(message, record.rdataOffset, record.rdataEnd, work);
  if (record.typeCode === 15) {
    if (record.rdataOffset + 2 > record.rdataEnd) return null;
    const name = readName(message, record.rdataOffset + 2, work);
    return name?.nextOffset !== record.rdataEnd
      ? null
      : join([message.slice(record.rdataOffset, record.rdataOffset + 2), name.canonical]);
  }
  if (record.typeCode === 6) {
    const mname = readName(message, record.rdataOffset, work);
    if (mname === null) return null;
    const rname = readName(message, mname.nextOffset, work);
    return rname === null || rname.nextOffset + 20 !== record.rdataEnd
      ? null
      : join([
          mname.canonical,
          rname.canonical,
          message.slice(rname.nextOffset, record.rdataEnd),
        ]);
  }
  if (record.typeCode === 33) {
    if (record.rdataOffset + 6 > record.rdataEnd) return null;
    const name = readName(message, record.rdataOffset + 6, work);
    return name?.usedCompression === true || name?.nextOffset !== record.rdataEnd
      ? null
      : join([message.slice(record.rdataOffset, record.rdataOffset + 6), name.canonical]);
  }
  if (record.typeCode === 64 || record.typeCode === 65) {
    if (record.rdataOffset + 2 > record.rdataEnd) return null;
    const name = readName(message, record.rdataOffset + 2, work);
    if (name === null || name.usedCompression || name.nextOffset > record.rdataEnd) return null;
    return join([
      message.slice(record.rdataOffset, record.rdataOffset + 2),
      name.canonical,
      message.slice(name.nextOffset, record.rdataEnd),
    ]);
  }
  if (record.typeCode === 47) return raw;
  return null;
}

function rrsigData(
  message: Uint8Array,
  record: WireRecord,
  work: WireParseWork,
): Record<string, unknown> | null {
  if (record.typeCode !== 46 || record.rdataOffset + 19 > record.rdataEnd) return null;
  const covered = readUint16(message, record.rdataOffset);
  const originalTTL = readUint32(message, record.rdataOffset + 4);
  const expiration = readUint32(message, record.rdataOffset + 8);
  const inception = readUint32(message, record.rdataOffset + 12);
  const keyTag = readUint16(message, record.rdataOffset + 16);
  const signer = readName(message, record.rdataOffset + 18, work);
  if (
    covered === null ||
    originalTTL === null ||
    expiration === null ||
    inception === null ||
    keyTag === null ||
    signer?.safeText === null ||
    signer === null ||
    signer.usedCompression ||
    signer.nextOffset >= record.rdataEnd
  )
    return null;
  const algorithm = message[record.rdataOffset + 2];
  const labels = message[record.rdataOffset + 3];
  if (algorithm === undefined || labels === undefined) return null;
  return {
    algorithm,
    expiration,
    inception,
    keyTag,
    labels,
    originalTTL,
    signature: message.slice(signer.nextOffset, record.rdataEnd),
    signersName: signer.safeText,
    typeCovered: typeText(covered),
  };
}

function sectionData(
  response: DnsResponse,
  section: DnsSection,
): { readonly records: readonly DnsRecord[]; readonly wire: readonly WireRecord[] } | null {
  const parsed = parseResponse(response);
  if (parsed === null) return null;
  if (response.message.raw.length === 0) {
    const records =
      section === 'answer'
        ? response.message.answers
        : section === 'authority'
          ? response.message.authorities
          : response.message.additionals;
    return { records, wire: [] };
  }
  const records =
    section === 'answer'
      ? response.message.answers
      : section === 'authority'
        ? response.message.authorities
        : response.message.additionals;
  const wire =
    section === 'answer'
      ? parsed.answers
      : section === 'authority'
        ? parsed.authorities
        : parsed.additionals;
  return records.length === wire.length ? { records, wire } : null;
}

function cloneBoundRecord(
  response: DnsResponse,
  source: DnsRecord,
  wire: WireRecord,
  requireCanonicalRdata = false,
): DnsRecord | null {
  const parsed = parseResponse(response);
  if (parsed === null) return null;
  if (
    wire.classCode !== 1 ||
    source.class.toUpperCase() !== 'IN' ||
    wire.owner.safeText === null ||
    source.typeCode !== wire.typeCode ||
    source.rawRdata.length !== wire.rdataEnd - wire.rdataOffset ||
    !source.rawRdata.every(
      (byte, index) => response.message.raw[wire.rdataOffset + index] === byte,
    )
  )
    return null;
  if (wire.typeCode === 46) {
    const data = rrsigData(response.message.raw, wire, parsed.work);
    return data === null
      ? null
      : {
          ...source,
          class: 'IN',
          data,
          owner: wire.owner.safeText,
          section: wire.section,
          ttl: wire.ttl,
          type: 'RRSIG',
          typeCode: wire.typeCode,
        };
  }
  const clone = {
    ...source,
    class: 'IN',
    owner: wire.owner.safeText,
    section: wire.section,
    ttl: wire.ttl,
    type: typeText(wire.typeCode),
    typeCode: wire.typeCode,
  };
  const rdata = canonicalApplicationRdata(response.message.raw, wire, parsed.work);
  if (rdata === null && requireCanonicalRdata) return null;
  if (rdata !== null) canonicalRdata.set(clone, rdata);
  return clone;
}

export function boundCanonicalRdata(record: DnsRecord): Uint8Array | undefined {
  return canonicalRdata.get(record);
}

export function wireQuestionMatches(
  response: DnsResponse,
  expectedName: string,
  expectedType: string,
): boolean {
  if (response.message.raw.length === 0) return true;
  const parsed = parseResponse(response);
  const expected = safeExpectedName(expectedName);
  const question = parsed?.questions[0];
  return (
    parsed !== null &&
    parsed.id === 0 &&
    (parsed.flags & 0x8000) !== 0 &&
    (parsed.flags & 0x7800) === 0 &&
    (parsed.flags & 0x0200) === 0 &&
    wireResponseCodeMatches(parsed, response.message.responseCode) &&
    expected !== null &&
    parsed.questions.length === 1 &&
    question?.classCode === 1 &&
    !question.name.usedCompression &&
    question.typeCode === typeCode(expectedType) &&
    bytesEqual(question.name.canonical, expected)
  );
}

export function boundRrset(
  response: DnsResponse,
  section: Extract<DnsSection, 'answer' | 'authority'>,
  owner: string,
  type: string,
): readonly DnsRecord[] | null {
  const data = sectionData(response, section);
  if (data === null) return null;
  if (response.message.raw.length === 0)
    return data.records.filter((record) => {
      const covered =
        record.data !== null && typeof record.data === 'object'
          ? (record.data as Record<string, unknown>)['typeCovered']
          : undefined;
      return (
        record.class.toUpperCase() === 'IN' &&
        record.owner.toLowerCase() === owner.toLowerCase() &&
        (record.type === type || (record.type === 'RRSIG' && covered === type))
      );
    });
  const expectedOwner = safeExpectedName(owner);
  if (expectedOwner === null) return null;
  const expectedType = typeCode(type);
  const values: DnsRecord[] = [];
  for (let index = 0; index < data.records.length; index += 1) {
    const source = data.records[index];
    const wire = data.wire[index];
    if (source === undefined || wire?.classCode !== 1) continue;
    const covered =
      wire.typeCode === 46 ? readUint16(response.message.raw, wire.rdataOffset) : null;
    if (
      !bytesEqual(wire.owner.canonical, expectedOwner) ||
      (wire.typeCode !== expectedType && !(wire.typeCode === 46 && covered === expectedType))
    )
      continue;
    const clone = cloneBoundRecord(response, source, wire, true);
    if (clone === null) {
      // RRSIG records are not members of the covered RRset. RFC 6840 says
      // unusable extra signatures must not invalidate another valid RRSIG.
      if (wire.typeCode === 46) continue;
      return null;
    }
    values.push(clone);
  }
  return values;
}

export function boundDenialRecords(response: DnsResponse): readonly DnsRecord[] | null {
  const data = sectionData(response, 'authority');
  if (data === null || response.message.raw.length === 0) return data?.records ?? null;
  const values: DnsRecord[] = [];
  for (let index = 0; index < data.records.length; index += 1) {
    const source = data.records[index];
    const wire = data.wire[index];
    if (source === undefined || wire === undefined) return null;
    const clone = cloneBoundRecord(response, source, wire);
    if (clone === null) {
      if (wire.typeCode === 46) continue;
      return null;
    }
    values.push(clone);
  }
  return values;
}
