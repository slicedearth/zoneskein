import { describe, expect, it } from 'vitest';

import type { DnsRecord } from '../dns/types';
import { bindDkimKeyAnswer } from './key-answer';

function record(owner: string, type: string, data: unknown, ttl = 300): DnsRecord {
  return {
    class: 'IN',
    data,
    owner,
    rawRdata: new Uint8Array(),
    section: 'answer',
    ttl,
    type,
    typeCode: type === 'TXT' ? 16 : 5,
  };
}

function txt(owner: string, value: string, ttl = 300): DnsRecord {
  return record(
    owner,
    'TXT',
    [Uint8Array.from(value, (character) => character.charCodeAt(0))],
    ttl,
  );
}

describe('DKIM key answer binding', () => {
  it('ignores an appended sibling TXT record', () => {
    expect(
      bindDkimKeyAnswer(
        [txt('attacker.invalid.', 'v=DKIM1; p=AAAA')],
        'key._domainkey.example.test',
      ),
    ).toEqual({ values: [] });
  });

  it('follows one CNAME chain and carries its effective TTL', () => {
    expect(
      bindDkimKeyAnswer(
        [
          record('key._domainkey.example.test.', 'CNAME', 'hosted.example.', 90),
          txt('hosted.example.', 'v=DKIM1; p=AAAA', 60),
          txt('sibling.invalid.', 'v=DKIM1; p=BBBB', 10),
        ],
        'key._domainkey.example.test',
      ),
    ).toEqual({ ttl: 60, values: ['v=DKIM1; p=AAAA'] });
  });

  it('rejects ambiguous CNAME answers', () => {
    const result = bindDkimKeyAnswer(
      [
        record('key._domainkey.example.test.', 'CNAME', 'one.example.'),
        record('key._domainkey.example.test.', 'CNAME', 'two.example.'),
      ],
      'key._domainkey.example.test',
    );
    expect(result.values).toEqual([]);
    expect(result.error).toMatch(/ambiguous/iu);
  });

  it('rejects one invalid target alongside an otherwise usable CNAME', () => {
    const result = bindDkimKeyAnswer(
      [
        record('key._domainkey.example.test.', 'CNAME', 'hosted.example.'),
        record('key._domainkey.example.test.', 'CNAME', 'https://hosted.example'),
        txt('hosted.example.', 'v=DKIM1; p=AAAA'),
      ],
      'key._domainkey.example.test',
    );

    expect(result.values).toEqual([]);
    expect(result.error).toMatch(/invalid or ambiguous/iu);
  });

  it('ignores many unrelated aliases while following the selector chain', () => {
    const unrelated = Array.from({ length: 200 }, (_, index) =>
      record(`unrelated-${String(index)}.example.`, 'CNAME', 'elsewhere.example.'),
    );

    expect(
      bindDkimKeyAnswer(
        [
          ...unrelated,
          record('key._domainkey.example.test.', 'CNAME', 'hosted.example.', 90),
          txt('hosted.example.', 'v=DKIM1; p=AAAA', 60),
        ],
        'key._domainkey.example.test',
      ),
    ).toEqual({ ttl: 60, values: ['v=DKIM1; p=AAAA'] });
  });

  it('fails closed when the reachable CNAME chain exceeds its work limit', () => {
    const aliases = Array.from({ length: 65 }, (_, index) =>
      record(
        index === 0 ? 'key._domainkey.example.test.' : `alias-${String(index - 1)}.example.`,
        'CNAME',
        `alias-${String(index)}.example.`,
      ),
    );
    const result = bindDkimKeyAnswer(
      [...aliases, txt('alias-64.example.', 'v=DKIM1; p=AAAA')],
      'key._domainkey.example.test',
    );

    expect(result.values).toEqual([]);
    expect(result.error).toMatch(/64-alias safety limit/iu);
  });

  it('uses RRset semantics for byte-identical duplicate key records', () => {
    expect(
      bindDkimKeyAnswer(
        [
          txt('key._domainkey.example.test.', 'v=DKIM1; p=AAAA', 300),
          txt('key._domainkey.example.test.', 'v=DKIM1; p=AAAA', 60),
        ],
        'key._domainkey.example.test',
      ),
    ).toEqual({ ttl: 60, values: ['v=DKIM1; p=AAAA'] });
  });
});
