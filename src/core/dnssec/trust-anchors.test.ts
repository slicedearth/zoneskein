import { describe, expect, it } from 'vitest';

import type { DnsRecord } from '../dns/types';
import { parseDnskey } from './records';
import { matchRootTrustAnchors, ROOT_TRUST_ANCHORS } from './trust-anchors';

function base64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

describe('IANA root trust anchors', () => {
  it('matches the published KSK-2017 DNSKEY by tag, algorithm, and complete digest', async () => {
    const publicKey = base64(
      'AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=',
    );
    const rawRdata = new Uint8Array(4 + publicKey.length);
    rawRdata.set([1, 1, 3, 8]);
    rawRdata.set(publicKey, 4);
    const record: DnsRecord = {
      class: 'IN',
      data: {},
      owner: '.',
      rawRdata,
      section: 'answer',
      ttl: 3600,
      type: 'DNSKEY',
      typeCode: 48,
    };
    const key = parseDnskey(record);
    if (key === null) throw new Error('Root DNSKEY fixture did not parse.');

    expect(key.keyTag).toBe(20326);
    const matches = await matchRootTrustAnchors([key], Date.parse('2026-08-13T00:00:00Z'));
    expect(matches).toHaveLength(1);
    expect(matches[0]?.anchor).toMatchObject({ id: 'Klajeyz', keyTag: 20326 });
    expect(matches[0]?.key).toBe(key);
    expect(ROOT_TRUST_ANCHORS.map((anchor) => anchor.keyTag)).toEqual([20326, 38696]);
  });
});
