import { describe, expect, it } from 'vitest';

import { dnskeyDigest, hex } from './digest';
import { dnskeyKeyTag } from './records';

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
});
