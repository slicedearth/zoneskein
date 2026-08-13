import { describe, expect, it } from 'vitest';

import type { DnsRecord } from '../dns/types';
import { compareDsToDnskeys, dnskeyDigest, hex } from './digest';
import { dnskeyKeyTag, parseDnskey } from './records';
import type { DsInfo } from './types';

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value.replaceAll(/\s/gu, ''));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

describe('DNSSEC key tags and DS digests', () => {
  const publicKey = decodeBase64(`
    AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/
    2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvx
    egXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9Xzc
    nOf+EPbtG9DMBmADjFDc2w/rljwvFw==
  `);
  const rdata = new Uint8Array(4 + publicKey.length);
  rdata.set([1, 0, 3, 5]);
  rdata.set(publicKey, 4);

  it('matches the RFC 4034 key-tag example', () => {
    expect(dnskeyKeyTag(rdata)).toBe(60_485);
  });

  it('matches the RFC 4509 SHA-256 DS example', async () => {
    const digest = await dnskeyDigest('dskey.example.com.', rdata, 2);
    expect(hex(digest)).toBe(
      'D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A',
    );
  });

  it('calculates SHA-384 candidates and compares multiple DNSKEY records conservatively', async () => {
    const owner = 'dskey.example.com.';
    const matchingRecord: DnsRecord = {
      class: 'IN',
      data: {},
      owner,
      rawRdata: rdata,
      section: 'answer',
      ttl: 3600,
      type: 'DNSKEY',
      typeCode: 48,
    };
    const otherRdata = rdata.slice();
    otherRdata[otherRdata.length - 1] = (otherRdata.at(-1) ?? 0) ^ 1;
    const otherRecord: DnsRecord = { ...matchingRecord, rawRdata: otherRdata };
    const matchingKey = parseDnskey(matchingRecord);
    const otherKey = parseDnskey(otherRecord);
    if (matchingKey === null || otherKey === null) throw new Error('DNSKEY fixture failed.');

    const digest = await dnskeyDigest(owner, rdata, 4);
    const dsRecord: DnsRecord = {
      class: 'IN',
      data: {},
      owner,
      rawRdata: new Uint8Array(),
      section: 'answer',
      ttl: 3600,
      type: 'DS',
      typeCode: 43,
    };
    const published: DsInfo = {
      algorithm: matchingKey.algorithm,
      digest,
      digestType: 4,
      keyTag: matchingKey.keyTag,
      record: dsRecord,
    };

    expect(digest).toHaveLength(48);
    await expect(
      compareDsToDnskeys(owner, [published], [otherKey, matchingKey]),
    ).resolves.toEqual([expect.objectContaining({ dnskey: matchingKey, matches: true })]);

    await expect(
      compareDsToDnskeys(
        owner,
        [{ ...published, digest: new Uint8Array(digest.length) }],
        [matchingKey],
      ),
    ).resolves.toEqual([expect.objectContaining({ matches: false })]);
  });
});
