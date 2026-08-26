import { describe, expect, it } from 'vitest';

import { parseZoneSnippet } from '../zone/parser';
import { bindRecord, recordDataText } from './presentation';
import type { DnsRecord } from './types';

function record(
  type: string,
  data: unknown,
  rawRdata = new Uint8Array(),
  owner = 'owner.example',
): DnsRecord {
  return {
    class: 'IN',
    data,
    owner,
    rawRdata,
    section: 'answer',
    ttl: 300,
    type,
    typeCode: 65,
  };
}

describe('DNS master-file presentation', () => {
  it('escapes every unsafe TXT octet without replacement or line injection', () => {
    const bytes = Uint8Array.from([0x61, 0x0a, 0x22, 0x5c, 0x3b, 0xff]);
    const output = bindRecord(
      record('TXT', [bytes], Uint8Array.from([bytes.length, ...bytes])),
    );

    expect(output).toBe('owner.example. 300 IN TXT "a\\010\\034\\092;\\255"');
    expect(output).not.toContain('\n');
    expect(output).not.toContain('\ufffd');
    const parsed = parseZoneSnippet(output);
    expect(parsed.diagnostics).toEqual([]);
    expect(parsed.records[0]?.rdata[0]?.value).toBe('a\n"\\;\u00ff');
  });

  it('formats structured name records with absolute targets', () => {
    expect(recordDataText(record('MX', { exchange: 'mail.example', preference: 10 }))).toBe(
      '10 mail.example.',
    );
    expect(
      recordDataText(
        record('SRV', { port: 443, priority: 1, target: 'service.example', weight: 2 }),
      ),
    ).toBe('1 2 443 service.example.');
    expect(
      recordDataText(
        record('SOA', {
          expire: 86_400,
          minimum: 300,
          mname: 'ns.example',
          refresh: 3_600,
          retry: 600,
          rname: 'hostmaster.example',
          serial: 1,
        }),
      ),
    ).toBe('ns.example. hostmaster.example. 1 3600 600 86400 300');
  });

  it('formats CAA wire octets safely and round-trips quoted data', () => {
    const raw = Uint8Array.from([
      128,
      5,
      ...new TextEncoder().encode('issue'),
      0x61,
      0x3b,
      0x22,
      0x0a,
      0xff,
    ]);
    const output = bindRecord(record('CAA', {}, raw));

    expect(output).toBe('owner.example. 300 IN CAA 128 "issue" "a;\\034\\010\\255"');
    expect(output).not.toContain('\n');
    const parsed = parseZoneSnippet(output);
    expect(parsed.diagnostics).toEqual([]);
    expect(parsed.records[0]?.rdata.map((token) => token.value)).toEqual([
      '128',
      'issue',
      'a;"\n\u00ff',
    ]);
  });

  it('uses canonical owner wire bytes instead of a potentially misleading display value', () => {
    const output = bindRecord({
      ...record('A', '192.0.2.1', Uint8Array.from([192, 0, 2, 1]), 'a.b.example'),
      canonicalOwnerWire: Uint8Array.from([
        3,
        0x61,
        0x2e,
        0x62,
        7,
        ...new TextEncoder().encode('example'),
        0,
      ]),
    });

    expect(output).toBe('a\\046b.example. 300 IN A 192.0.2.1');
    expect(parseZoneSnippet(output).records[0]?.owner).toBe('a\\046b.example.');
  });

  it('uses RFC 3597 generic RDATA for unsupported or malformed decoded values', () => {
    const unsupported = bindRecord(
      record('HTTPS', { unsafe: '\n; injected' }, Uint8Array.from([0, 1, 0])),
    );
    const malformedTxt = bindRecord(record('TXT', [], Uint8Array.from([5, 0x61, 0x62])));

    expect(unsupported).toBe('owner.example. 300 IN HTTPS \\# 3 000100');
    expect(malformedTxt).toBe('owner.example. 300 IN TXT \\# 3 056162');
    expect(unsupported).not.toContain('injected');
    expect(parseZoneSnippet(unsupported).records[0]?.rdata.map((token) => token.value)).toEqual(
      ['#', '3', '000100'],
    );
  });

  it('preserves DNSKEY protocol and key bytes from wire evidence', () => {
    const raw = Uint8Array.from([1, 1, 4, 15, 0, 255, 1]);
    expect(recordDataText(record('DNSKEY', {}, raw))).toBe('257 4 15 AP8B');
  });

  it('formats complete-zone digest wire evidence without relying on dependency decoding', () => {
    const raw = Uint8Array.from([
      0x78,
      0x48,
      0xb9,
      0x1c,
      1,
      1,
      ...new Uint8Array(48).fill(0xaa),
    ]);
    const value = recordDataText(record('ZONEMD', {}, raw));

    expect(value).toBe(`2018031900 1 1 ${'AA'.repeat(48)}`);
    expect(parseZoneSnippet(`example. 300 IN ZONEMD ${value}`).diagnostics).toEqual([]);
  });
});
