import { describe, expect, it } from 'vitest';

import { parseRecordView, recordJson } from './records';
import type { DnsRecord } from './types';

describe('DNS record field views', () => {
  it('labels complete-zone digest fields from bounded wire RDATA', () => {
    const digest = new Uint8Array(48).fill(0xaa);
    const record: DnsRecord = {
      class: 'IN',
      data: new Uint8Array(),
      owner: 'example.',
      rawRdata: Uint8Array.from([0, 0, 0, 1, 1, 1, ...digest]),
      section: 'answer',
      ttl: 300,
      type: 'ZONEMD',
      typeCode: 63,
    };

    expect(parseRecordView(record)).toEqual({
      fields: [
        { label: 'SOA serial', value: '1' },
        { label: 'Scheme', value: '1' },
        { label: 'Hash algorithm', value: '1' },
        { label: 'Digest', value: 'AA'.repeat(48) },
      ],
      text: `1 1 1 ${'AA'.repeat(48)}`,
    });
  });

  it('fails closed to generic RDATA for a truncated digest record', () => {
    const record: DnsRecord = {
      class: 'IN',
      data: null,
      owner: 'example.',
      rawRdata: Uint8Array.from([0, 0, 0]),
      section: 'answer',
      ttl: 300,
      type: 'ZONEMD',
      typeCode: 63,
    };

    expect(parseRecordView(record).text).toBe('\\# 3 000000');
  });

  it('keeps valid international TXT readable while exposing controls and raw bytes', () => {
    const chunk = Uint8Array.from(new TextEncoder().encode('München\u202e\n'));
    const rawRdata = Uint8Array.from([chunk.length, ...chunk]);
    const record: DnsRecord = {
      class: 'IN',
      data: [chunk],
      owner: 'example.',
      rawRdata,
      section: 'answer',
      ttl: 300,
      type: 'TXT',
      typeCode: 16,
    };
    const view = parseRecordView(record);

    expect(view.text).toBe('"München\\u{202E}\\n"');
    expect(view.fields).toEqual([
      { label: 'Combined value', value: 'München\\u{202E}\\n' },
      {
        label: 'Raw character-strings (Base64)',
        value: view.txtChunks?.[0]?.rawBase64,
      },
    ]);
    expect(recordJson(record)).toMatchObject({
      data: '"München\\u{202E}\\n"',
      rawRdata: {
        encoding: 'base64',
        octets: rawRdata.length,
      },
    });
  });

  it('keeps byte-distinct malformed TXT evidence distinguishable', () => {
    const view = (byte: number) =>
      parseRecordView({
        class: 'IN',
        data: [Uint8Array.from([0x66, byte])],
        owner: 'example.',
        rawRdata: Uint8Array.from([2, 0x66, byte]),
        section: 'answer',
        ttl: 300,
        type: 'TXT',
        typeCode: 16,
      });

    expect(view(0x80).text).toBe('"\\x66\\x80"');
    expect(view(0x81).text).toBe('"\\x66\\x81"');
    expect(view(0x80).txtChunks?.[0]?.rawBase64).not.toBe(view(0x81).txtChunks?.[0]?.rawBase64);
    expect(view(0x80).txtChunks?.[0]?.text).toBeUndefined();
  });

  it('escapes SVCB target and parameter octets without replacement decoding', () => {
    const alpn = new TextEncoder().encode('h2\u202e');
    const rawRdata = Uint8Array.from([
      0,
      1,
      2,
      0x78,
      0x2e,
      0,
      0,
      1,
      0,
      alpn.length + 1,
      alpn.length,
      ...alpn,
    ]);
    const view = parseRecordView({
      class: 'IN',
      data: null,
      owner: 'example.',
      rawRdata,
      section: 'answer',
      ttl: 300,
      type: 'SVCB',
      typeCode: 64,
    });

    expect(view.fields).toEqual(
      expect.arrayContaining([
        { label: 'Target', value: 'x\\046.' },
        { label: 'alpn', value: 'h2\\u{202E}' },
      ]),
    );
    expect(view.text).toContain('h2\\u{202E}');
  });
});
