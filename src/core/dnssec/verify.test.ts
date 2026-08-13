import { describe, expect, it } from 'vitest';

import type { DnsRecord } from '../dns/types';
import { dnskeyKeyTag, parseRrsig } from './records';
import { dnskeyRrsetSignedData, verifyDnskeyRrset } from './verify';

function base64UrlBytes(value: string): Uint8Array {
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function buffer(bytes: Uint8Array): ArrayBuffer {
  const value = new ArrayBuffer(bytes.length);
  new Uint8Array(value).set(bytes);
  return value;
}

describe('local DNSKEY RRset signature verification', () => {
  it('verifies an RSA/SHA-256 DNSKEY signature', async () => {
    const generated = await crypto.subtle.generateKey(
      {
        hash: 'SHA-256',
        modulusLength: 1024,
        name: 'RSASSA-PKCS1-v1_5',
        publicExponent: new Uint8Array([1, 0, 1]),
      },
      true,
      ['sign', 'verify'],
    );
    if (!('privateKey' in generated)) throw new Error('RSA key pair was not generated.');
    const jwk = await crypto.subtle.exportKey('jwk', generated.publicKey);
    if (jwk.n === undefined || jwk.e === undefined) throw new Error('RSA JWK is incomplete.');
    const exponent = base64UrlBytes(jwk.e);
    const modulus = base64UrlBytes(jwk.n);
    const publicKey = new Uint8Array(1 + exponent.length + modulus.length);
    publicKey[0] = exponent.length;
    publicKey.set(exponent, 1);
    publicKey.set(modulus, 1 + exponent.length);
    const rdata = new Uint8Array(4 + publicKey.length);
    rdata.set([1, 1, 3, 8]);
    rdata.set(publicKey, 4);
    const keyTag = dnskeyKeyTag(rdata);
    const dnskey: DnsRecord = {
      class: 'IN',
      data: {},
      owner: 'example.test.',
      rawRdata: rdata,
      section: 'answer',
      ttl: 3600,
      type: 'DNSKEY',
      typeCode: 48,
    };
    const signatureData = {
      algorithm: 8,
      expiration: 2_000_000_000,
      inception: 1_000_000_000,
      keyTag,
      labels: 2,
      originalTTL: 3600,
      signature: new Uint8Array(),
      signersName: 'example.test.',
      typeCovered: 'DNSKEY',
    };
    const unsignedRrsig: DnsRecord = {
      class: 'IN',
      data: signatureData,
      owner: 'example.test.',
      rawRdata: new Uint8Array(),
      section: 'answer',
      ttl: 3600,
      type: 'RRSIG',
      typeCode: 46,
    };
    const parsed = parseRrsig(unsignedRrsig, 1_500_000_000);
    if (parsed === null) throw new Error('RRSIG fixture did not parse.');
    const signedData = dnskeyRrsetSignedData([dnskey, unsignedRrsig], parsed);
    const signature = new Uint8Array(
      await crypto.subtle.sign('RSASSA-PKCS1-v1_5', generated.privateKey, buffer(signedData)),
    );
    const rrsig: DnsRecord = {
      ...unsignedRrsig,
      data: { ...signatureData, signature },
    };

    await expect(verifyDnskeyRrset([dnskey, rrsig], 1_500_000_000)).resolves.toEqual([
      expect.objectContaining({ keyTag, status: 'verified' }),
    ]);
  });
});
