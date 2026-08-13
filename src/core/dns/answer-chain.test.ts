import { describe, expect, it } from 'vitest';

import type { DnsRecord } from './types';
import { reachableAnswerRecords } from './answer-chain';

function record(type: string, owner: string, data: unknown, className = 'IN'): DnsRecord {
  return {
    class: className,
    data,
    owner,
    rawRdata: new Uint8Array(),
    section: 'answer',
    ttl: 300,
    type,
    typeCode: type === 'TXT' ? 16 : 5,
  };
}

describe('reachable answer RR binding', () => {
  it('keeps direct and CNAME-reachable records while excluding appended siblings', () => {
    const direct = reachableAnswerRecords(
      'mail.example.com',
      [
        record('CNAME', 'mail.example.com.', 'edge.example.net.'),
        record('TXT', 'edge.example.net.', 'v=policy'),
        record('TXT', 'sibling.example.net.', 'v=hostile'),
        record('TXT', 'edge.example.net.', 'v=wrong-class', 'CH'),
      ],
      'TXT',
    );

    expect(direct.records.map((item) => item.data)).toEqual(['v=policy']);
    expect(direct.aliases).toHaveLength(1);
    expect(direct.ignoredRecords).toBe(1);
  });

  it('does not let an unrelated CNAME make its target reachable', () => {
    const view = reachableAnswerRecords(
      'mail.example.com',
      [
        record('CNAME', 'sibling.example.com.', 'hostile.example.net.'),
        record('TXT', 'hostile.example.net.', 'v=hostile'),
      ],
      'TXT',
    );

    expect(view.records).toEqual([]);
    expect(view.aliases).toEqual([]);
  });

  it('does not let unrelated aliases exhaust the reachable-chain safety limit', () => {
    const unrelatedAliases = Array.from({ length: 128 }, (_, index) =>
      record(
        'CNAME',
        `unrelated-${String(index)}.example.com.`,
        `target-${String(index)}.example.net.`,
      ),
    );
    const view = reachableAnswerRecords(
      'mail.example.com',
      [
        ...unrelatedAliases,
        record('CNAME', 'mail.example.com.', 'edge.example.net.'),
        record('TXT', 'edge.example.net.', 'v=policy'),
      ],
      'TXT',
    );

    expect(view.error).toBeUndefined();
    expect(view.records.map((item) => item.data)).toEqual(['v=policy']);
    expect(view.aliases).toHaveLength(1);
  });

  it('applies the alias limit only to the chain being followed', () => {
    const chain = Array.from({ length: 65 }, (_, index) =>
      record(
        'CNAME',
        index === 0 ? 'mail.example.com.' : `hop-${String(index)}.example.net.`,
        `hop-${String(index + 1)}.example.net.`,
      ),
    );
    const view = reachableAnswerRecords(
      'mail.example.com',
      [...chain, record('TXT', 'hop-65.example.net.', 'v=policy')],
      'TXT',
    );

    expect(view.error).toMatch(/64-alias safety limit/iu);
    expect(view.records).toEqual([]);
    expect(view.aliases).toHaveLength(64);
  });

  it('does not reinterpret a URL-shaped response owner as the queried DNS name', () => {
    const view = reachableAnswerRecords(
      'mail.example.com',
      [record('TXT', 'https://mail.example.com/', 'v=hostile')],
      'TXT',
    );

    expect(view.records).toEqual([]);
  });

  it('binds data reached through a DNAME rewrite', () => {
    const view = reachableAnswerRecords(
      'mail.branch.example.com',
      [
        record('DNAME', 'branch.example.com.', 'service.example.net.'),
        record('TXT', 'mail.service.example.net.', 'v=policy'),
      ],
      'TXT',
    );

    expect(view.records.map((item) => item.data)).toEqual(['v=policy']);
    expect(view.aliases[0]?.type).toBe('DNAME');
  });

  it('rejects CNAME plus requested-type data at the same owner', () => {
    const view = reachableAnswerRecords(
      'mail.example.com',
      [
        record('CNAME', 'mail.example.com.', 'edge.example.net.'),
        record('TXT', 'mail.example.com.', 'v=contradiction'),
        record('TXT', 'edge.example.net.', 'v=policy'),
      ],
      'TXT',
    );

    expect(view.error).toMatch(/both CNAME and requested-type/iu);
    expect(view.records).toEqual([]);
  });

  it('rejects competing CNAME targets at the question owner', () => {
    const view = reachableAnswerRecords(
      'mail.example.com',
      [
        record('CNAME', 'mail.example.com.', 'one.example.net.'),
        record('CNAME', 'mail.example.com.', 'two.example.net.'),
        record('TXT', 'one.example.net.', 'v=one'),
      ],
      'TXT',
    );

    expect(view.error).toMatch(/ambiguous CNAME/iu);
    expect(view.records).toEqual([]);
  });
});
