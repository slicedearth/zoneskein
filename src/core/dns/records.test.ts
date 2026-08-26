import { describe, expect, it } from 'vitest';

import { parseRecordView } from './records';
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
});
