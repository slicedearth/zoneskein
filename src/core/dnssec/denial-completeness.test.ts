import { toType } from '@dnsquery/dns-packet/types.js';
import { beforeAll, describe, expect, it } from 'vitest';

import type { DnsRecord, DnsRecordType, DnsResponse } from '../dns/types';
import { validateApplicationRrset } from './application';
import { validateDsDenial } from './denial';
import { parseDnskey, parseRrsig } from './records';
import type { DnskeyInfo } from './types';
import { canonicalName, rrsetSignedData } from './verify';

const NOW = 1_800_000_000;
const OWNER = 'www.example.';
const ZONE = 'example.';
const BASE32HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

interface TestSigner {
  readonly info: DnskeyInfo;
  readonly privateKey: CryptoKey;
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const output = new ArrayBuffer(bytes.length);
  new Uint8Array(output).set(bytes);
  return output;
}

function base64UrlBytes(value: string): Uint8Array {
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function typeBitmap(...types: readonly number[]): Uint8Array {
  const windows = new Map<number, number[]>();
  for (const type of types) {
    const window = Math.floor(type / 256);
    const values = windows.get(window) ?? [];
    values.push(type % 256);
    windows.set(window, values);
  }

  const blocks: Uint8Array[] = [];
  for (const [window, values] of [...windows].sort(([left], [right]) => left - right)) {
    const length = Math.floor(Math.max(...values) / 8) + 1;
    const bitmap = new Uint8Array(length);
    for (const value of values) {
      const index = Math.floor(value / 8);
      bitmap[index] = (bitmap[index] ?? 0) | (1 << (7 - (value % 8)));
    }
    blocks.push(new Uint8Array([window, length, ...bitmap]));
  }
  return concat(...blocks);
}

function base32hex(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32HEX[(value >>> (bits - 5)) & 31] ?? '';
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32HEX[(value << (5 - bits)) & 31] ?? '';
  return output;
}

async function sha1(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-1', asArrayBuffer(bytes)));
}

async function nsec3Hash(
  name: string,
  salt: Uint8Array = new Uint8Array(),
  iterations = 0,
): Promise<Uint8Array> {
  let hash = await sha1(concat(canonicalName(name), salt));
  for (let iteration = 0; iteration < iterations; iteration += 1)
    hash = await sha1(concat(hash, salt));
  return hash;
}

function shifted(bytes: Uint8Array, difference: 1 | -1): Uint8Array {
  const output = bytes.slice();
  for (let index = output.length - 1; index >= 0; index -= 1) {
    const byte = output[index];
    if (byte === undefined) throw new Error('Hash fixture is incomplete.');
    if (difference === 1) {
      output[index] = (byte + 1) & 0xff;
      if (byte !== 0xff) return output;
    } else {
      output[index] = (byte - 1) & 0xff;
      if (byte !== 0) return output;
    }
  }
  throw new Error('Hash fixture cannot be shifted without wrapping.');
}

function record(
  type: string,
  owner: string,
  rawRdata: Uint8Array,
  section: 'answer' | 'authority',
  data: unknown = {},
): DnsRecord {
  const typeCodes: Readonly<Record<string, number>> = {
    A: 1,
    DNSKEY: 48,
    NSEC: 47,
    NSEC3: 50,
    RRSIG: 46,
  };
  return {
    class: 'IN',
    data,
    owner,
    rawRdata,
    section,
    ttl: 300,
    type,
    typeCode: typeCodes[type] ?? toType(type),
  };
}

function nsecRecord(owner: string, nextName: string, ...types: readonly number[]): DnsRecord {
  return record(
    'NSEC',
    owner,
    concat(canonicalName(nextName), typeBitmap(...types)),
    'authority',
  );
}

function compactNsecRecord(owner: string): DnsRecord {
  const immediateSuccessor = concat(new Uint8Array([1, 0]), canonicalName(owner));
  return record(
    'NSEC',
    owner,
    concat(immediateSuccessor, typeBitmap(toType('RRSIG'), toType('NSEC'), 128)),
    'authority',
  );
}

function nsec3Record(
  ownerHash: Uint8Array,
  nextHash: Uint8Array,
  flags: 0 | 1,
  ...types: readonly number[]
): DnsRecord {
  return nsec3RecordWithParameters(ownerHash, nextHash, flags, new Uint8Array(), 0, ...types);
}

function nsec3RecordWithParameters(
  ownerHash: Uint8Array,
  nextHash: Uint8Array,
  flags: 0 | 1,
  salt: Uint8Array,
  iterations: number,
  ...types: readonly number[]
): DnsRecord {
  return record(
    'NSEC3',
    `${base32hex(ownerHash)}.${ZONE}`,
    new Uint8Array([
      1,
      flags,
      iterations >>> 8,
      iterations & 0xff,
      salt.length,
      ...salt,
      nextHash.length,
      ...nextHash,
      ...typeBitmap(...types),
    ]),
    'authority',
  );
}

async function matchingNsec3(
  name: string,
  flags: 0 | 1,
  ...types: readonly number[]
): Promise<DnsRecord> {
  const hash = await nsec3Hash(name);
  return nsec3Record(hash, shifted(hash, 1), flags, ...types);
}

async function matchingNsec3WithParameters(
  name: string,
  flags: 0 | 1,
  salt: Uint8Array,
  iterations: number,
  ...types: readonly number[]
): Promise<DnsRecord> {
  const hash = await nsec3Hash(name, salt, iterations);
  return nsec3RecordWithParameters(hash, shifted(hash, 1), flags, salt, iterations, ...types);
}

async function coveringNsec3(
  name: string,
  flags: 0 | 1,
  ...types: readonly number[]
): Promise<DnsRecord> {
  const hash = await nsec3Hash(name);
  return nsec3Record(shifted(hash, -1), shifted(hash, 1), flags, ...types);
}

async function testSigner(zone = ZONE): Promise<TestSigner> {
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
  const dnskey = record(
    'DNSKEY',
    zone,
    concat(new Uint8Array([1, 1, 3, 8, exponent.length]), exponent, modulus),
    'answer',
  );
  const info = parseDnskey(dnskey);
  if (info === null) throw new Error('Generated DNSKEY did not parse.');
  return { info, privateKey: generated.privateKey };
}

async function signRecord(
  rr: DnsRecord,
  signer: TestSigner,
  labels = rr.owner.replace(/\.$/u, '').split('.').filter(Boolean).length,
  expiration = NOW + 3600,
): Promise<DnsRecord> {
  if (rr.section === 'additional')
    throw new Error('DNSSEC test fixtures may only sign answer or authority records.');
  const data = {
    algorithm: signer.info.algorithm,
    expiration,
    inception: NOW - 3600,
    keyTag: signer.info.keyTag,
    labels,
    originalTTL: rr.ttl,
    signature: new Uint8Array(),
    signersName: signer.info.record.owner,
    typeCovered: rr.type,
  };
  const unsigned = record('RRSIG', rr.owner, new Uint8Array(), rr.section, data);
  const parsed = parseRrsig(unsigned, NOW);
  if (parsed === null) throw new Error('Generated RRSIG did not parse.');
  const signedData = rrsetSignedData([rr, unsigned], parsed);
  if (signedData === null) throw new Error(`${rr.type} fixture could not be canonicalised.`);
  const signature = new Uint8Array(
    await crypto.subtle.sign('RSASSA-PKCS1-v1_5', signer.privateKey, asArrayBuffer(signedData)),
  );
  return { ...unsigned, data: { ...data, signature } };
}

async function signedAuthorities(
  proofs: readonly DnsRecord[],
  signer: TestSigner,
): Promise<readonly DnsRecord[]> {
  const authorities: DnsRecord[] = [];
  for (const proof of proofs) authorities.push(proof, await signRecord(proof, signer));
  return authorities;
}

function response(
  owner: string,
  answers: readonly DnsRecord[],
  authorities: readonly DnsRecord[],
  responseCode: 'NOERROR' | 'NXDOMAIN',
  type: DnsRecordType = 'A',
): DnsResponse {
  return {
    cache: 'miss',
    message: {
      additionals: [],
      answers,
      authorities,
      flags: {
        authenticatedData: false,
        authoritativeAnswer: false,
        checkingDisabled: true,
        recursionAvailable: true,
        recursionDesired: true,
        truncated: false,
      },
      id: 0,
      messageBytes: 256,
      questions: [{ class: 'IN', name: owner, type }],
      raw: new Uint8Array(),
      responseCode,
    },
    queryTimeMs: 1,
    question: {
      name: {
        absolute: owner,
        ascii: owner.slice(0, -1),
        display: owner.slice(0, -1),
        hadRootDot: true,
        unicode: false,
      },
      type,
    },
    receivedAt: new Date(NOW * 1000).toISOString(),
    resolver: {
      endpoint: 'https://resolver.invalid/dns-query',
      httpMethod: 'POST',
      id: 'google',
      label: 'Fixture resolver',
      privacyUrl: 'https://resolver.invalid/privacy',
    },
  };
}

describe('standards-complete authenticated application denial', () => {
  let signer: TestSigner;

  beforeAll(async () => {
    signer = await testSigner();
  });

  describe('authenticated NODATA', () => {
    it('accepts an exact-owner NSEC bitmap that omits both A and CNAME', async () => {
      const proof = nsecRecord(
        OWNER,
        'zzz.example.',
        toType('TXT'),
        toType('RRSIG'),
        toType('NSEC'),
      );
      const result = await validateApplicationRrset(
        response(OWNER, [], await signedAuthorities([proof], signer), 'NOERROR'),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure' });
      expect(result.explanation).toMatch(/NODATA/u);
    });

    it.each([
      ['queried A type', toType('A')],
      ['CNAME type', toType('CNAME')],
    ])('rejects an exact-owner NSEC bitmap containing the %s', async (_, contradiction) => {
      const proof = nsecRecord(
        OWNER,
        'zzz.example.',
        contradiction,
        toType('RRSIG'),
        toType('NSEC'),
      );
      const result = await validateApplicationRrset(
        response(OWNER, [], await signedAuthorities([proof], signer), 'NOERROR'),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'bogus' });
    });

    it('rejects an NSEC proof when its received RRset has an unsigned extra member', async () => {
      const proof = nsecRecord(
        OWNER,
        'zzz.example.',
        toType('TXT'),
        toType('RRSIG'),
        toType('NSEC'),
      );
      const injected = nsecRecord(
        OWNER,
        'yyy.example.',
        toType('TXT'),
        toType('RRSIG'),
        toType('NSEC'),
      );
      const result = await validateApplicationRrset(
        response(OWNER, [], [proof, await signRecord(proof, signer), injected], 'NOERROR'),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'bogus', verificationGroups: [] });
    });

    it('accepts an exact-match NSEC3 proof even when its Opt-Out flag is set', async () => {
      const proof = await matchingNsec3(OWNER, 1, toType('TXT'), toType('RRSIG'));
      const result = await validateApplicationRrset(
        response(OWNER, [], await signedAuthorities([proof], signer), 'NOERROR'),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure' });
      expect(result.explanation).toMatch(/NODATA/u);
    });

    it.each([
      ['queried A type', toType('A')],
      ['CNAME type', toType('CNAME')],
    ])('rejects an exact-match NSEC3 bitmap containing the %s', async (_, contradiction) => {
      const proof = await matchingNsec3(OWNER, 0, contradiction, toType('RRSIG'));
      const result = await validateApplicationRrset(
        response(OWNER, [], await signedAuthorities([proof], signer), 'NOERROR'),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'bogus' });
    });

    it('rejects an NSEC3 proof when its received RRset has an unsigned extra member', async () => {
      const ownerHash = await nsec3Hash(OWNER);
      const proof = nsec3Record(
        ownerHash,
        shifted(ownerHash, 1),
        0,
        toType('TXT'),
        toType('RRSIG'),
      );
      const injected = nsec3Record(
        ownerHash,
        shifted(ownerHash, -1),
        0,
        toType('TXT'),
        toType('RRSIG'),
      );
      const result = await validateApplicationRrset(
        response(OWNER, [], [proof, await signRecord(proof, signer), injected], 'NOERROR'),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'bogus', verificationGroups: [] });
    });

    it('does not treat an Opt-Out covering interval as proof that a non-DS type is absent', async () => {
      const closestEncloser = await matchingNsec3(
        ZONE,
        0,
        toType('SOA'),
        toType('NS'),
        toType('RRSIG'),
      );
      const covering = await coveringNsec3(OWNER, 1);
      const result = await validateApplicationRrset(
        response(
          OWNER,
          [],
          await signedAuthorities([closestEncloser, covering], signer),
          'NOERROR',
        ),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result.state).not.toBe('secure');
    });

    it('accepts an NSEC wildcard NODATA proof with closer-match exclusion', async () => {
      const wildcard = nsecRecord(
        '*.example.',
        'aaa.example.',
        toType('TXT'),
        toType('RRSIG'),
        toType('NSEC'),
      );
      const closerMatch = nsecRecord(
        'aaa.example.',
        'zzz.example.',
        toType('RRSIG'),
        toType('NSEC'),
      );
      const result = await validateApplicationRrset(
        response(
          OWNER,
          [],
          await signedAuthorities([wildcard, closerMatch], signer),
          'NOERROR',
        ),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure' });
      expect(result.explanation).toMatch(/wildcard.*NODATA/iu);
    });

    it('does not use QNAME-only NSEC coverage to authenticate wildcard NODATA from a shorter encloser', async () => {
      const name = 'www.bar.example.';
      const wildcard = nsecRecord(
        '*.example.',
        'aaa.example.',
        toType('TXT'),
        toType('RRSIG'),
        toType('NSEC'),
      );
      const qnameOnly = nsecRecord(
        'v.bar.example.',
        'x.bar.example.',
        toType('RRSIG'),
        toType('NSEC'),
      );
      const result = await validateApplicationRrset(
        response(name, [], await signedAuthorities([wildcard, qnameOnly], signer), 'NOERROR'),
        name,
        'A',
        [signer.info],
        NOW,
      );

      expect(result.state).not.toBe('secure');
      expect(result.explanation).toMatch(/complete|next.closer|NODATA/iu);
    });

    it('accepts an NSEC3 wildcard NODATA proof with a complete closest-encloser proof', async () => {
      const closestEncloser = await matchingNsec3(
        ZONE,
        0,
        toType('SOA'),
        toType('NS'),
        toType('RRSIG'),
      );
      const nextCloser = await coveringNsec3(OWNER, 0);
      const wildcard = await matchingNsec3('*.example.', 0, toType('TXT'), toType('RRSIG'));
      const result = await validateApplicationRrset(
        response(
          OWNER,
          [],
          await signedAuthorities([closestEncloser, nextCloser, wildcard], signer),
          'NOERROR',
        ),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure' });
      expect(result.explanation).toMatch(/wildcard.*NODATA/iu);
    });
  });

  describe('authenticated name errors', () => {
    it('accepts an NSEC interval that covers both QNAME and the closest-encloser wildcard', async () => {
      const proof = nsecRecord(
        ZONE,
        'zzz.example.',
        toType('SOA'),
        toType('NS'),
        toType('RRSIG'),
        toType('NSEC'),
      );
      const result = await validateApplicationRrset(
        response(OWNER, [], await signedAuthorities([proof], signer), 'NXDOMAIN'),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure' });
      expect(result.explanation).toMatch(/NXDOMAIN|name error|does not exist/iu);
    });

    it('does not authenticate an NSEC name error without wildcard exclusion', async () => {
      const proof = nsecRecord('aaa.example.', 'zzz.example.', toType('RRSIG'), toType('NSEC'));
      const result = await validateApplicationRrset(
        response(OWNER, [], await signedAuthorities([proof], signer), 'NXDOMAIN'),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result.state).not.toBe('secure');
    });

    it('does not combine QNAME-only NSEC coverage with wildcard denial at a shorter encloser', async () => {
      const name = 'www.bar.example.';
      const qnameOnly = nsecRecord(
        'v.bar.example.',
        'x.bar.example.',
        toType('RRSIG'),
        toType('NSEC'),
      );
      const wrongWildcard = nsecRecord(
        ZONE,
        'aaa.example.',
        toType('SOA'),
        toType('NS'),
        toType('RRSIG'),
        toType('NSEC'),
      );
      const result = await validateApplicationRrset(
        response(
          name,
          [],
          await signedAuthorities([qnameOnly, wrongWildcard], signer),
          'NXDOMAIN',
        ),
        name,
        'A',
        [signer.info],
        NOW,
      );

      expect(result.state).not.toBe('secure');
      expect(result.explanation).toMatch(/closest.encloser|next.closer|name.error/iu);
    });

    it('accepts the NSEC3 closest-encloser, next-closer, and wildcard proof set', async () => {
      const name = 'ghost.deep.example.';
      const closestEncloser = await matchingNsec3(
        ZONE,
        0,
        toType('SOA'),
        toType('NS'),
        toType('RRSIG'),
      );
      const nextCloser = await coveringNsec3('deep.example.', 0);
      const wildcard = await coveringNsec3('*.example.', 0);
      const result = await validateApplicationRrset(
        response(
          name,
          [],
          await signedAuthorities([closestEncloser, nextCloser, wildcard], signer),
          'NXDOMAIN',
        ),
        name,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure' });
      expect(result.explanation).toMatch(/NXDOMAIN|name error|does not exist/iu);
    });

    it('does not authenticate an NSEC3 name error when the next closer is Opt-Out', async () => {
      const name = 'ghost.deep.example.';
      const closestEncloser = await matchingNsec3(
        ZONE,
        0,
        toType('SOA'),
        toType('NS'),
        toType('RRSIG'),
      );
      const nextCloser = await coveringNsec3('deep.example.', 1);
      const wildcard = await coveringNsec3('*.example.', 0);
      const result = await validateApplicationRrset(
        response(
          name,
          [],
          await signedAuthorities([closestEncloser, nextCloser, wildcard], signer),
          'NXDOMAIN',
        ),
        name,
        'A',
        [signer.info],
        NOW,
      );

      expect(result.state).not.toBe('secure');
    });

    it('does not accept a shorter match when a longer matching ancestor lacks next-closer proof', async () => {
      const name = 'ghost.deep.example.';
      const closestEncloser = await matchingNsec3(
        ZONE,
        0,
        toType('SOA'),
        toType('NS'),
        toType('RRSIG'),
      );
      const unprovenLongerAncestor = await matchingNsec3('deep.example.', 0, toType('RRSIG'));
      const wildcard = await coveringNsec3('*.example.', 0);
      const result = await validateApplicationRrset(
        response(
          name,
          [],
          await signedAuthorities([closestEncloser, unprovenLongerAncestor, wildcard], signer),
          'NXDOMAIN',
        ),
        name,
        'A',
        [signer.info],
        NOW,
      );

      expect(result.state).not.toBe('secure');
    });
  });

  describe('authenticated wildcard answers', () => {
    it('accepts a wildcard-expanded RRset with an authenticated NSEC next-closer proof', async () => {
      const address = record('A', OWNER, new Uint8Array([192, 0, 2, 1]), 'answer', '192.0.2.1');
      const answer = [address, await signRecord(address, signer, 1)];
      const proof = nsecRecord('aaa.example.', 'zzz.example.', toType('RRSIG'), toType('NSEC'));
      const result = await validateApplicationRrset(
        response(OWNER, answer, await signedAuthorities([proof], signer), 'NOERROR'),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure', wildcardExpanded: true });
    });

    it('does not use QNAME-only NSEC coverage to validate a wildcard answer from a shorter encloser', async () => {
      const name = 'www.bar.example.';
      const address = record('A', name, new Uint8Array([192, 0, 2, 1]), 'answer', '192.0.2.1');
      const answer = [address, await signRecord(address, signer, 1)];
      const qnameOnly = nsecRecord(
        'v.bar.example.',
        'x.bar.example.',
        toType('RRSIG'),
        toType('NSEC'),
      );
      const result = await validateApplicationRrset(
        response(name, answer, await signedAuthorities([qnameOnly], signer), 'NOERROR'),
        name,
        'A',
        [signer.info],
        NOW,
      );

      expect(result.state).not.toBe('secure');
      expect(result.explanation).toMatch(/closer.match|next.closer/iu);
    });

    it('does not accept an NSEC3 wildcard answer without an exact closest-encloser match', async () => {
      const address = record('A', OWNER, new Uint8Array([192, 0, 2, 1]), 'answer', '192.0.2.1');
      const answer = [address, await signRecord(address, signer, 1)];
      const proof = await coveringNsec3(OWNER, 0);
      const result = await validateApplicationRrset(
        response(OWNER, answer, await signedAuthorities([proof], signer), 'NOERROR'),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'incomplete', wildcardExpanded: true });
      expect(result.verificationGroups).toEqual([]);
    });

    it('does not combine an NSEC3 closest-encloser match with next-closer parameters from another chain', async () => {
      const address = record('A', OWNER, new Uint8Array([192, 0, 2, 1]), 'answer', '192.0.2.1');
      const answer = [address, await signRecord(address, signer, 1)];
      const closestEncloser = await matchingNsec3WithParameters(
        ZONE,
        0,
        new Uint8Array(),
        1,
        toType('SOA'),
        toType('NS'),
        toType('RRSIG'),
      );
      const nextCloser = await coveringNsec3(OWNER, 0);
      const result = await validateApplicationRrset(
        response(
          OWNER,
          answer,
          await signedAuthorities([closestEncloser, nextCloser], signer),
          'NOERROR',
        ),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'incomplete', wildcardExpanded: true });
      expect(result.verificationGroups).toEqual([]);
    });

    it('accepts an NSEC3 wildcard answer with matching closest-encloser and next-closer proofs', async () => {
      const address = record('A', OWNER, new Uint8Array([192, 0, 2, 1]), 'answer', '192.0.2.1');
      const answer = [address, await signRecord(address, signer, 1)];
      const closestEncloser = await matchingNsec3(
        ZONE,
        0,
        toType('SOA'),
        toType('NS'),
        toType('RRSIG'),
      );
      const nextCloser = await coveringNsec3(OWNER, 0);
      const result = await validateApplicationRrset(
        response(
          OWNER,
          answer,
          await signedAuthorities([closestEncloser, nextCloser], signer),
          'NOERROR',
        ),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure', wildcardExpanded: true });
      expect(result.verificationGroups).toHaveLength(3);
    });
  });

  describe('RFC 9824 compact denial', () => {
    it('accepts an exact-owner NSEC NXNAME proof carried in a NOERROR response', async () => {
      const proof = compactNsecRecord(OWNER);
      const result = await validateApplicationRrset(
        response(OWNER, [], await signedAuthorities([proof], signer), 'NOERROR'),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure' });
      expect(result.explanation).toMatch(/compact|NXNAME|does not exist/iu);
    });

    it('accepts an exact-match NSEC3 NXNAME proof carried in a NOERROR response', async () => {
      const proof = await matchingNsec3(OWNER, 0, 128);
      const result = await validateApplicationRrset(
        response(OWNER, [], await signedAuthorities([proof], signer), 'NOERROR'),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure' });
      expect(result.explanation).toMatch(/compact|NXNAME|does not exist/iu);
    });
  });

  describe('supporting verification groups', () => {
    it('retains each required NSEC3 name-error RRset as a separate verification group', async () => {
      const name = 'ghost.deep.example.';
      const closestEncloser = await matchingNsec3(
        ZONE,
        0,
        toType('SOA'),
        toType('NS'),
        toType('RRSIG'),
      );
      const nextCloser = await coveringNsec3('deep.example.', 0);
      const wildcard = await coveringNsec3('*.example.', 0);
      const expirations = [NOW + 300, NOW + 600, NOW + 900] as const;
      const proofs = [closestEncloser, nextCloser, wildcard] as const;
      const authorities: DnsRecord[] = [];
      for (const [index, proof] of proofs.entries())
        authorities.push(proof, await signRecord(proof, signer, undefined, expirations[index]));

      const result = await validateApplicationRrset(
        response(name, [], authorities, 'NXDOMAIN'),
        name,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure' });
      expect(
        result.verificationGroups.map((group) =>
          group.flatMap((verification) =>
            verification.status === 'verified' && verification.expiration !== undefined
              ? [verification.expiration]
              : [],
          ),
        ),
      ).toEqual(expirations.map((expiration) => [expiration]));
      expect(
        Math.min(
          ...result.verificationGroups.map((group) =>
            Math.max(...group.flatMap((verification) => verification.expiration ?? [])),
          ),
        ),
      ).toBe(NOW + 300);
      expect(
        Math.max(
          ...result.verifications.flatMap((verification) => verification.expiration ?? []),
        ),
      ).toBe(NOW + 900);
      expect(JSON.parse(JSON.stringify(result.verificationGroups))).toHaveLength(3);
    });

    it('keeps the positive wildcard RRset separate from its denial RRset', async () => {
      const address = record('A', OWNER, new Uint8Array([192, 0, 2, 1]), 'answer', '192.0.2.1');
      const answer = [address, await signRecord(address, signer, 1, NOW + 300)];
      const proof = nsecRecord('aaa.example.', 'zzz.example.', toType('RRSIG'), toType('NSEC'));
      const authorities = [proof, await signRecord(proof, signer, undefined, NOW + 900)];
      const result = await validateApplicationRrset(
        response(OWNER, answer, authorities, 'NOERROR'),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure', wildcardExpanded: true });
      expect(
        result.verificationGroups.map((group) =>
          group.flatMap((verification) => verification.expiration ?? []),
        ),
      ).toEqual([[NOW + 300], [NOW + 900]]);
    });

    it('binds the wildcard positive group to the signature label count proved by denial', async () => {
      const name = 'www.bar.example.';
      const address = record('A', name, new Uint8Array([192, 0, 2, 1]), 'answer', '192.0.2.1');
      const provedSignature = await signRecord(address, signer, 1, NOW + 300);
      const unprovedSignature = await signRecord(address, signer, 2, NOW + 900);
      const proof = compactNsecRecord('bar.example.');
      const authorities = [proof, await signRecord(proof, signer, undefined, NOW + 1200)];
      const result = await validateApplicationRrset(
        response(name, [address, provedSignature, unprovedSignature], authorities, 'NOERROR'),
        name,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure', wildcardExpanded: true });
      expect(
        result.verificationGroups[0]?.flatMap((verification) =>
          verification.expiration === undefined ? [] : [verification.expiration],
        ),
      ).toEqual([NOW + 300]);
      expect(result.verifications).toContainEqual(
        expect.objectContaining({ expiration: NOW + 900, status: 'verified' }),
      );
    });

    it('correlates a valid wildcard signature after a malformed leading RRSIG', async () => {
      const address = record('A', OWNER, new Uint8Array([192, 0, 2, 1]), 'answer', '192.0.2.1');
      const malformed = record('RRSIG', OWNER, new Uint8Array(), 'answer', {
        typeCovered: 'A',
      });
      const signature = await signRecord(address, signer, 1, NOW + 450);
      const proof = nsecRecord('aaa.example.', 'zzz.example.', toType('RRSIG'), toType('NSEC'));
      const result = await validateApplicationRrset(
        response(
          OWNER,
          [address, malformed, signature],
          await signedAuthorities([proof], signer),
          'NOERROR',
        ),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure', wildcardExpanded: true });
      expect(result.verificationGroups[0]).toContainEqual(
        expect.objectContaining({ expiration: NOW + 450, status: 'verified' }),
      );
    });

    it('retains an exact positive RRset as one verification group', async () => {
      const address = record('A', OWNER, new Uint8Array([192, 0, 2, 1]), 'answer', '192.0.2.1');
      const answer = [address, await signRecord(address, signer, 2, NOW + 450)];
      const result = await validateApplicationRrset(
        response(OWNER, answer, [], 'NOERROR'),
        OWNER,
        'A',
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({ state: 'secure', wildcardExpanded: false });
      expect(result.verificationGroups).toHaveLength(1);
      expect(result.verificationGroups[0]).toContainEqual(
        expect.objectContaining({ expiration: NOW + 450, status: 'verified' }),
      );
    });
  });

  describe('received denial RRset boundaries', () => {
    it('keeps parent and child-side NSEC RRsets separate at a shared delegation owner', async () => {
      const owner = 'child.example.';
      const childSigner = await testSigner(owner);
      const parentProof = nsecRecord(
        owner,
        'zzz.example.',
        toType('NS'),
        toType('RRSIG'),
        toType('NSEC'),
      );
      const childProof = nsecRecord(
        owner,
        'host.child.example.',
        toType('SOA'),
        toType('NS'),
        toType('RRSIG'),
        toType('NSEC'),
      );
      const result = await validateDsDenial(
        owner,
        [
          parentProof,
          await signRecord(parentProof, signer),
          childProof,
          await signRecord(childProof, childSigner),
        ],
        [signer.info],
        NOW,
      );

      expect(result).toMatchObject({
        proofType: 'NSEC',
        state: 'insecure',
        verifications: [expect.objectContaining({ status: 'verified' })],
      });
    });
  });
});
