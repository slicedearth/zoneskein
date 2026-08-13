import { beforeAll, describe, expect, it } from 'vitest';

import type { DnsRecord } from '../dns/types';
import { validateDsDenial } from './denial';
import { parseDnskey, parseRrsig } from './records';
import type { DnskeyInfo } from './types';
import { canonicalName, rrsetSignedData } from './verify';
import { DnssecWorkBudget } from './work-budget';

const NOW = 1_800_000_000;
const TARGET = 'unsigned.example.';
const ZONE = 'example.';
const BASE32HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

interface TestSigner {
  readonly dnskey: DnsRecord;
  readonly info: DnskeyInfo;
  readonly privateKey: CryptoKey;
}

interface Nsec3Options {
  readonly bitmap?: Uint8Array;
  readonly flags?: number;
  readonly hashAlgorithm?: number;
  readonly iterations?: number;
  readonly nextHash?: Uint8Array;
  readonly originalName?: string;
  readonly ownerHash?: Uint8Array;
  readonly salt?: Uint8Array;
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
  salt: Uint8Array,
  iterations: number,
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

function proofRecord(type: 'NSEC' | 'NSEC3', owner: string, rawRdata: Uint8Array): DnsRecord {
  return {
    class: 'IN',
    data: {},
    owner,
    rawRdata,
    section: 'authority',
    ttl: 3600,
    type,
    typeCode: type === 'NSEC' ? 47 : 50,
  };
}

function nsecRecord(
  bitmap: Uint8Array = typeBitmap(2),
  owner = TARGET,
  nextName = 'zzz.example.',
): DnsRecord {
  return proofRecord('NSEC', owner, concat(canonicalName(nextName), bitmap));
}

async function nsec3Record(options: Nsec3Options = {}): Promise<DnsRecord> {
  const salt = options.salt ?? new Uint8Array();
  const iterations = options.iterations ?? 0;
  const targetHash = await nsec3Hash(options.originalName ?? TARGET, salt, iterations);
  const ownerHash = options.ownerHash ?? targetHash;
  const nextHash = options.nextHash ?? new Uint8Array(targetHash.length);
  const bitmap = options.bitmap ?? typeBitmap(2);
  const rawRdata = new Uint8Array([
    options.hashAlgorithm ?? 1,
    options.flags ?? 0,
    iterations >>> 8,
    iterations & 0xff,
    salt.length,
    ...salt,
    nextHash.length,
    ...nextHash,
    ...bitmap,
  ]);
  return proofRecord('NSEC3', `${base32hex(ownerHash)}.${ZONE}`, rawRdata);
}

async function testSigner(): Promise<TestSigner> {
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

  const rawRdata = new Uint8Array(4 + publicKey.length);
  rawRdata.set([1, 1, 3, 8]);
  rawRdata.set(publicKey, 4);
  const dnskey: DnsRecord = {
    class: 'IN',
    data: {},
    owner: ZONE,
    rawRdata,
    section: 'answer',
    ttl: 3600,
    type: 'DNSKEY',
    typeCode: 48,
  };
  const info = parseDnskey(dnskey);
  if (info === null) throw new Error('Generated DNSKEY did not parse.');
  return { dnskey, info, privateKey: generated.privateKey };
}

async function signProof(proof: DnsRecord, signer: TestSigner): Promise<DnsRecord> {
  const labels = proof.owner.replace(/\.$/u, '').split('.').filter(Boolean).length;
  const data = {
    algorithm: signer.info.algorithm,
    expiration: NOW + 3600,
    inception: NOW - 3600,
    keyTag: signer.info.keyTag,
    labels,
    originalTTL: proof.ttl,
    signature: new Uint8Array(),
    signersName: signer.dnskey.owner,
    typeCovered: proof.type,
  };
  const unsigned: DnsRecord = {
    class: 'IN',
    data,
    owner: proof.owner,
    rawRdata: new Uint8Array(),
    section: 'authority',
    ttl: proof.ttl,
    type: 'RRSIG',
    typeCode: 46,
  };
  const parsed = parseRrsig(unsigned, NOW);
  if (parsed === null) throw new Error('Generated RRSIG did not parse.');
  const signedData = rrsetSignedData([proof, unsigned], parsed);
  if (signedData === null) throw new Error(`${proof.type} fixture could not be canonicalised.`);
  const signature = new Uint8Array(
    await crypto.subtle.sign('RSASSA-PKCS1-v1_5', signer.privateKey, asArrayBuffer(signedData)),
  );
  return { ...unsigned, data: { ...data, signature } };
}

async function validate(proof: DnsRecord, signer: TestSigner) {
  return validateProofs([proof], signer);
}

async function validateProofs(proofs: readonly DnsRecord[], signer: TestSigner) {
  const authorities: DnsRecord[] = [];
  for (const proof of proofs) authorities.push(proof, await signProof(proof, signer));
  return validateDsDenial(TARGET, authorities, [signer.info], NOW);
}

async function closestProvableEncloser(options: Nsec3Options = {}): Promise<DnsRecord> {
  return nsec3Record({
    ...options,
    bitmap: options.bitmap ?? typeBitmap(2, 6, 46),
    originalName: ZONE,
  });
}

function corruptSignature(record: DnsRecord): DnsRecord {
  if (
    record.data === null ||
    typeof record.data !== 'object' ||
    !('signature' in record.data) ||
    !(record.data.signature instanceof Uint8Array)
  )
    throw new Error('RRSIG fixture does not contain signature bytes.');
  const signature = record.data.signature.slice();
  signature[0] = (signature[0] ?? 0) ^ 0x80;
  return { ...record, data: { ...record.data, signature } };
}

describe('authenticated DS denial validation', () => {
  let signer: TestSigner;

  beforeAll(async () => {
    signer = await testSigner();
  });

  describe('NSEC proofs', () => {
    it('accepts a signed exact-owner delegation bitmap without DS or SOA', async () => {
      await expect(validate(nsecRecord(typeBitmap(2, 46, 47)), signer)).resolves.toMatchObject({
        proofType: 'NSEC',
        state: 'insecure',
        verifications: [expect.objectContaining({ status: 'verified' })],
      });
    });

    it('rejects an exact-owner denial bitmap that says a DS RRset exists', async () => {
      await expect(
        validate(nsecRecord(typeBitmap(2, 43, 46, 47)), signer),
      ).resolves.toMatchObject({ state: 'bogus' });
    });

    it.each([
      ['an SOA bit', typeBitmap(2, 6, 46, 47)],
      ['no NS bit', typeBitmap(46, 47)],
    ])(
      'does not treat an exact-owner bitmap with %s as an insecure delegation',
      async (_, bitmap) => {
        await expect(validate(nsecRecord(bitmap), signer)).resolves.toMatchObject({
          proofType: 'NSEC',
          state: 'not-delegated',
        });
      },
    );

    it('does not use a non-matching NSEC owner as an exact DS denial proof', async () => {
      await expect(
        validate(nsecRecord(typeBitmap(2), 'neighbour.example.'), signer),
      ).resolves.toMatchObject({ state: 'incomplete' });
    });

    it('recognises a signed NSEC interval proving an empty non-terminal', async () => {
      const proof = nsecRecord(
        typeBitmap(2, 46, 47),
        'before.example.',
        'child.unsigned.example.',
      );
      await expect(validate(proof, signer)).resolves.toMatchObject({
        proofType: 'NSEC',
        state: 'not-delegated',
      });
    });

    it('uses raw label octets when an NSEC next name proves an empty non-terminal', async () => {
      const proof = proofRecord(
        'NSEC',
        'before.example.',
        concat(new Uint8Array([1, 0xff]), canonicalName(TARGET), typeBitmap(2, 46, 47)),
      );
      await expect(validate(proof, signer)).resolves.toMatchObject({
        proofType: 'NSEC',
        state: 'not-delegated',
      });
    });

    it('does not accept an out-of-zone signed NSEC as an empty non-terminal proof', async () => {
      const proof = nsecRecord(typeBitmap(2, 46, 47), 'aaa.', 'child.unsigned.example.');
      await expect(validate(proof, signer)).resolves.toMatchObject({ state: 'bogus' });
    });

    it('stops at an authenticated DNAME alias boundary', async () => {
      await expect(validate(nsecRecord(typeBitmap(39, 46, 47)), signer)).resolves.toMatchObject(
        {
          proofType: 'NSEC',
          state: 'alias-boundary',
        },
      );
    });

    it('does not reuse an NSEC interval below a DNAME owner', async () => {
      const proof = nsecRecord(
        typeBitmap(6, 39, 46, 47),
        'example.',
        'child.unsigned.example.',
      );
      await expect(validate(proof, signer)).resolves.toMatchObject({ state: 'incomplete' });
    });

    it('does not confuse a covering NSEC name-error interval with an empty non-terminal', async () => {
      const proof = nsecRecord(typeBitmap(2, 46, 47), 'before.example.', 'zzz.example.');
      await expect(validate(proof, signer)).resolves.toMatchObject({ state: 'incomplete' });
    });

    it.each([
      ['a zero-length window', new Uint8Array([0, 0])],
      ['a trailing zero octet', new Uint8Array([0, 2, 0x20, 0])],
      ['out-of-order windows', new Uint8Array([1, 1, 0x80, 0, 1, 0x20])],
      ['a repeated window', new Uint8Array([0, 1, 0x20, 0, 1, 0x20])],
    ])('rejects a signed bitmap containing %s', async (_, bitmap) => {
      await expect(validate(nsecRecord(bitmap), signer)).resolves.toMatchObject({
        state: 'bogus',
      });
    });

    it('rejects proof RDATA changed after it was signed', async () => {
      const original = nsecRecord(typeBitmap(2, 46, 47));
      const signature = await signProof(original, signer);
      const changedBytes = original.rawRdata.slice();
      changedBytes[changedBytes.length - 1] = (changedBytes.at(-1) ?? 0) ^ 0x01;
      const changed = { ...original, rawRdata: changedBytes };

      await expect(
        validateDsDenial(TARGET, [changed, signature], [signer.info], NOW),
      ).resolves.toMatchObject({
        state: 'bogus',
        verifications: [expect.objectContaining({ status: 'invalid' })],
      });
    });

    it('rejects a corrupted signature over otherwise valid proof RDATA', async () => {
      const proof = nsecRecord(typeBitmap(2, 46, 47));
      const signature = corruptSignature(await signProof(proof, signer));

      await expect(
        validateDsDenial(TARGET, [proof, signature], [signer.info], NOW),
      ).resolves.toMatchObject({
        state: 'bogus',
        verifications: [expect.objectContaining({ status: 'invalid' })],
      });
    });
  });

  describe('NSEC3 proofs', () => {
    it('accepts a signed exact-match delegation proof with salt and iterations', async () => {
      const proof = await nsec3Record({
        bitmap: typeBitmap(2, 46),
        iterations: 2,
        salt: new Uint8Array([0x01, 0x23, 0x45, 0x67]),
      });

      await expect(validate(proof, signer)).resolves.toMatchObject({
        proofType: 'NSEC3',
        state: 'insecure',
        verifications: [expect.objectContaining({ status: 'verified' })],
      });
    });

    it('rejects an exact-match denial bitmap that says a DS RRset exists', async () => {
      const proof = await nsec3Record({ bitmap: typeBitmap(2, 43, 46) });
      await expect(validate(proof, signer)).resolves.toMatchObject({ state: 'bogus' });
    });

    it('reports indeterminate existence for an opt-out interval paired with its closest provable encloser', async () => {
      const targetHash = await nsec3Hash(TARGET, new Uint8Array(), 0);
      const proof = await nsec3Record({
        bitmap: typeBitmap(46),
        flags: 1,
        nextHash: shifted(targetHash, 1),
        ownerHash: shifted(targetHash, -1),
      });
      const closest = await closestProvableEncloser();

      await expect(validateProofs([proof, closest], signer)).resolves.toMatchObject({
        proofType: 'NSEC3',
        state: 'opt-out',
      });
    });

    it('does not accept a lone opt-out interval without a closest provable encloser', async () => {
      const targetHash = await nsec3Hash(TARGET, new Uint8Array(), 0);
      const proof = await nsec3Record({
        bitmap: typeBitmap(46),
        flags: 1,
        nextHash: shifted(targetHash, 1),
        ownerHash: shifted(targetHash, -1),
      });

      await expect(validate(proof, signer)).resolves.toMatchObject({ state: 'incomplete' });
    });

    it('reports indeterminate existence for a covering opt-out interval across the hash-space origin', async () => {
      const targetHash = await nsec3Hash(TARGET, new Uint8Array(), 0);
      const ownerHash = shifted(targetHash, -1);
      const proof = await nsec3Record({
        bitmap: typeBitmap(46),
        flags: 1,
        nextHash: shifted(ownerHash, -1),
        ownerHash,
      });
      const closest = await closestProvableEncloser();

      await expect(validateProofs([closest, proof], signer)).resolves.toMatchObject({
        proofType: 'NSEC3',
        state: 'opt-out',
      });
    });

    it('does not accept the same covering interval when the opt-out flag is absent', async () => {
      const targetHash = await nsec3Hash(TARGET, new Uint8Array(), 0);
      const proof = await nsec3Record({
        flags: 0,
        nextHash: shifted(targetHash, 1),
        ownerHash: shifted(targetHash, -1),
      });
      const closest = await closestProvableEncloser();

      await expect(validateProofs([proof, closest], signer)).resolves.toMatchObject({
        state: 'incomplete',
      });
    });

    it('excludes the next-hash boundary from an opt-out interval', async () => {
      const targetHash = await nsec3Hash(TARGET, new Uint8Array(), 0);
      const proof = await nsec3Record({
        flags: 1,
        nextHash: targetHash,
        ownerHash: shifted(targetHash, -1),
      });
      const closest = await closestProvableEncloser();

      await expect(validateProofs([proof, closest], signer)).resolves.toMatchObject({
        state: 'incomplete',
      });
    });

    it('handles the owner boundary as an exact match instead of an opt-out interval', async () => {
      const proof = await nsec3Record({ bitmap: typeBitmap(6, 46), flags: 1 });
      await expect(validate(proof, signer)).resolves.toMatchObject({
        proofType: 'NSEC3',
        state: 'not-delegated',
      });
    });

    it('requires the closest provable encloser to use the covering record parameters', async () => {
      const targetHash = await nsec3Hash(TARGET, new Uint8Array(), 0);
      const proof = await nsec3Record({
        bitmap: typeBitmap(46),
        flags: 1,
        nextHash: shifted(targetHash, 1),
        ownerHash: shifted(targetHash, -1),
      });
      const closest = await closestProvableEncloser({ salt: new Uint8Array([0xaa]) });

      await expect(validateProofs([proof, closest], signer)).resolves.toMatchObject({
        state: 'incomplete',
      });
    });

    it.each([
      ['an unknown hash algorithm', { hashAlgorithm: 2 }],
      ['an excessive iteration count', { iterations: 501 }],
    ] satisfies readonly [string, Nsec3Options][])(
      'reports %s as unsupported',
      async (_, options) => {
        const proof = await nsec3Record(options);
        await expect(validate(proof, signer)).resolves.toMatchObject({ state: 'unsupported' });
      },
    );

    it.each([
      ['a zero-length bitmap window', new Uint8Array([0, 0])],
      ['a non-minimal bitmap window', new Uint8Array([0, 2, 0x20, 0])],
      ['out-of-order bitmap windows', new Uint8Array([1, 1, 0x80, 0, 1, 0x20])],
    ])('rejects a signed NSEC3 proof containing %s', async (_, bitmap) => {
      const proof = await nsec3Record({ bitmap });
      await expect(validate(proof, signer)).resolves.toMatchObject({ state: 'bogus' });
    });

    it('rejects a SHA-1 NSEC3 record whose next hash is not 20 octets', async () => {
      const proof = await nsec3Record({ nextHash: new Uint8Array(19) });
      await expect(validate(proof, signer)).resolves.toMatchObject({ state: 'bogus' });
    });

    it('rejects an opt-out proof whose owner hash has the wrong length', async () => {
      const proof = await nsec3Record({
        flags: 1,
        nextHash: new Uint8Array(20).fill(0xff),
        ownerHash: new Uint8Array(19),
      });
      await expect(validate(proof, signer)).resolves.toMatchObject({ state: 'bogus' });
    });

    it('rejects an opt-out proof whose owner hash is not base32hex', async () => {
      const initial = await nsec3Record({
        flags: 1,
        nextHash: new Uint8Array(20).fill(0xff),
        ownerHash: new Uint8Array(20),
      });
      const proof = { ...initial, owner: `!.${ZONE}` };
      await expect(validate(proof, signer)).resolves.toMatchObject({ state: 'bogus' });
    });

    it('rejects an exact hash owner outside the trusted signer zone', async () => {
      const initial = await nsec3Record();
      const ownerHash = initial.owner.split('.')[0];
      if (ownerHash === undefined) throw new Error('NSEC3 owner fixture is incomplete.');
      const proof = { ...initial, owner: `${ownerHash}.other.` };
      await expect(validate(proof, signer)).resolves.toMatchObject({ state: 'bogus' });
    });

    it('rejects reserved NSEC3 flag bits', async () => {
      const proof = await nsec3Record({ flags: 0x80 });
      await expect(validate(proof, signer)).resolves.toMatchObject({ state: 'bogus' });
    });

    it('rejects an opt-out next hash changed after the proof was signed', async () => {
      const targetHash = await nsec3Hash(TARGET, new Uint8Array(), 0);
      const original = await nsec3Record({
        flags: 1,
        nextHash: shifted(targetHash, 1),
        ownerHash: shifted(targetHash, -1),
      });
      const signature = await signProof(original, signer);
      const changedBytes = original.rawRdata.slice();
      changedBytes[6] = (changedBytes[6] ?? 0) ^ 0x01;
      const changed = { ...original, rawRdata: changedBytes };

      await expect(
        validateDsDenial(TARGET, [changed, signature], [signer.info], NOW),
      ).resolves.toMatchObject({
        state: 'bogus',
        verifications: [expect.objectContaining({ status: 'invalid' })],
      });
    });

    it('shares the NSEC3 hashing budget across validation operations', async () => {
      const proof = await nsec3Record();
      const authorities = [proof, await signProof(proof, signer)];
      const budget = new DnssecWorkBudget({ limits: { nsec3HashRounds: 1 } });

      await expect(
        validateDsDenial(TARGET, authorities, [signer.info], NOW, budget),
      ).resolves.toMatchObject({ state: 'insecure' });
      await expect(
        validateDsDenial(TARGET, authorities, [signer.info], NOW, budget),
      ).resolves.toMatchObject({ state: 'incomplete' });
    });
  });
});
