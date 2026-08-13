import { beforeAll, describe, expect, it } from 'vitest';

import type { DnsRecord, DnsResponse } from '../dns/types';
import { DNSSEC_APPLICATION_TYPES, validateApplicationRrset } from './application';
import { parseDnskey } from './records';
import type { DnskeyInfo } from './types';
import { canonicalName, canonicalRdata } from './verify';

const NOW = 1_800_000_000;
const OWNER = 'www.example.';
const ZONE = 'example.';

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

function uint16(value: number): Uint8Array {
  return new Uint8Array([value >>> 8, value & 0xff]);
}

function uint32(value: number): Uint8Array {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function join(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function record(type: string, data: unknown, rawRdata: Uint8Array, owner = OWNER): DnsRecord {
  return {
    class: 'IN',
    data,
    owner,
    rawRdata,
    section: 'answer',
    ttl: 300,
    type,
    typeCode: type === 'A' ? 1 : 0,
  };
}

function response(
  answers: readonly DnsRecord[],
  responseCode = 'NOERROR',
  decodedOwner = OWNER,
  type: 'A' | 'CNAME' = 'A',
): DnsResponse {
  return {
    cache: 'miss',
    message: {
      additionals: [],
      answers,
      authorities: [],
      flags: {
        authenticatedData: false,
        authoritativeAnswer: false,
        checkingDisabled: true,
        recursionAvailable: true,
        recursionDesired: true,
        truncated: false,
      },
      id: 0,
      messageBytes: 128,
      questions: [{ class: 'IN', name: decodedOwner, type }],
      raw: new Uint8Array(),
      responseCode,
    },
    queryTimeMs: 1,
    question: {
      name: {
        absolute: OWNER,
        ascii: OWNER.slice(0, -1),
        display: OWNER.slice(0, -1),
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
  const publicKey = join(new Uint8Array([exponent.length]), exponent, modulus);
  const dnskey = record('DNSKEY', {}, join(new Uint8Array([1, 1, 3, 8]), publicKey), ZONE);
  const info = parseDnskey(dnskey);
  if (info === null) throw new Error('Generated DNSKEY did not parse.');
  return { info, privateKey: generated.privateKey };
}

function independentSignedData(rr: DnsRecord, signer: DnskeyInfo, labels: number): Uint8Array {
  const originalOwner = labels === 1 ? '*.example.' : rr.owner.toLowerCase();
  const prefix = join(
    uint16(1),
    new Uint8Array([8, labels]),
    uint32(300),
    uint32(NOW + 3600),
    uint32(NOW - 3600),
    uint16(signer.keyTag),
    canonicalName(ZONE),
  );
  return join(
    prefix,
    canonicalName(originalOwner),
    uint16(1),
    uint16(1),
    uint32(300),
    uint16(rr.rawRdata.length),
    rr.rawRdata,
  );
}

async function signedAnswer(
  rr: DnsRecord,
  signer: TestSigner,
  labels = 2,
): Promise<readonly DnsRecord[]> {
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      signer.privateKey,
      asArrayBuffer(independentSignedData(rr, signer.info, labels)),
    ),
  );
  const rrsig = record(
    'RRSIG',
    {
      algorithm: 8,
      expiration: NOW + 3600,
      inception: NOW - 3600,
      keyTag: signer.info.keyTag,
      labels,
      originalTTL: 300,
      signature,
      signersName: ZONE,
      typeCovered: 'A',
    },
    new Uint8Array(),
  );
  return [rr, rrsig];
}

describe('positive application RRset validation', () => {
  let signer: TestSigner;

  beforeAll(async () => {
    signer = await testSigner();
  });

  it('validates an exact positive RRset signed by authenticated zone keys', async () => {
    const address = record('A', '192.0.2.1', new Uint8Array([192, 0, 2, 1]));
    const result = await validateApplicationRrset(
      response(await signedAnswer(address, signer)),
      OWNER,
      'A',
      [signer.info],
      NOW,
    );

    expect(result).toMatchObject({ state: 'secure', type: 'A', wildcardExpanded: false });
    expect(result.verifications).toContainEqual(
      expect.objectContaining({ status: 'verified' }),
    );
  });

  it('rejects application RDATA changed after independent signing', async () => {
    const original = record('A', '192.0.2.1', new Uint8Array([192, 0, 2, 1]));
    const [, signature] = await signedAnswer(original, signer);
    const changed = record('A', '192.0.2.2', new Uint8Array([192, 0, 2, 2]));
    if (signature === undefined) throw new Error('Fixture signature is missing.');

    await expect(
      validateApplicationRrset(response([changed, signature]), OWNER, 'A', [signer.info], NOW),
    ).resolves.toMatchObject({ state: 'bogus' });
  });

  it('keeps a cryptographically valid wildcard expansion incomplete without denial proofs', async () => {
    const address = record('A', '192.0.2.1', new Uint8Array([192, 0, 2, 1]));
    const result = await validateApplicationRrset(
      response(await signedAnswer(address, signer, 1)),
      OWNER,
      'A',
      [signer.info],
      NOW,
    );

    expect(result).toMatchObject({ state: 'incomplete', wildcardExpanded: true });
    expect(result.verifications).toContainEqual(
      expect.objectContaining({ status: 'verified' }),
    );
  });

  it('does not authenticate mismatched, negative, NODATA, or alias answers', async () => {
    const cname = record('CNAME', 'target.example.', canonicalName('target.example.'));
    const cases = [
      response([], 'NXDOMAIN'),
      response([]),
      response([cname]),
      response([], 'NOERROR', 'other.example.'),
    ];
    for (const fixture of cases) {
      await expect(
        validateApplicationRrset(fixture, OWNER, 'A', [signer.info], NOW),
      ).resolves.toMatchObject({ state: 'incomplete' });
    }
  });

  it('does not let an injected invalid wildcard signature downgrade a valid exact signature', async () => {
    const address = record('A', '192.0.2.1', new Uint8Array([192, 0, 2, 1]));
    const [rr, exactSignature] = await signedAnswer(address, signer);
    const [, wildcardSignature] = await signedAnswer(address, signer, 1);
    if (rr === undefined || exactSignature === undefined || wildcardSignature === undefined)
      throw new Error('Signature fixture is incomplete.');
    const data = wildcardSignature.data as Record<string, unknown>;
    const signature = data['signature'];
    if (!(signature instanceof Uint8Array)) throw new Error('Wildcard signature is missing.');
    const corrupt = signature.slice();
    corrupt[0] = (corrupt[0] ?? 0) ^ 0x80;

    await expect(
      validateApplicationRrset(
        response([
          rr,
          { ...wildcardSignature, data: { ...data, signature: corrupt } },
          exactSignature,
        ]),
        OWNER,
        'A',
        [signer.info],
        NOW,
      ),
    ).resolves.toMatchObject({ state: 'secure', wildcardExpanded: false });
  });

  it('keeps an unsigned CNAME synthesised from DNAME incomplete instead of bogus', async () => {
    const dname = record(
      'DNAME',
      'redirect.example.',
      canonicalName('redirect.example.'),
      ZONE,
    );
    const cname = record(
      'CNAME',
      'www.redirect.example.',
      canonicalName('www.redirect.example.'),
    );

    await expect(
      validateApplicationRrset(
        response([dname, cname], 'NOERROR', OWNER, 'CNAME'),
        OWNER,
        'CNAME',
        [signer.info],
        NOW,
      ),
    ).resolves.toMatchObject({ state: 'incomplete' });
  });
});

describe('application RDATA canonicalisation', () => {
  it('canonicalises every application type advertised by the validator', () => {
    const target = canonicalName('Target.Example.');
    const soa = {
      expire: 5,
      minimum: 6,
      mname: 'NS.Example.',
      refresh: 3,
      retry: 4,
      rname: 'Hostmaster.Example.',
      serial: 2,
    };
    const fixtures: Readonly<Record<(typeof DNSSEC_APPLICATION_TYPES)[number], DnsRecord>> = {
      A: record('A', '192.0.2.1', new Uint8Array([192, 0, 2, 1])),
      AAAA: record('AAAA', '2001:db8::1', new Uint8Array(16).fill(1)),
      CAA: record(
        'CAA',
        { flags: 0, tag: 'issue', value: 'ca.example' },
        new Uint8Array([0, 5, 105, 115, 115, 117, 101, 99, 97]),
      ),
      CNAME: record('CNAME', 'Target.Example.', target),
      HTTPS: record('HTTPS', {}, join(uint16(1), target)),
      MX: record('MX', { exchange: 'Target.Example.', preference: 10 }, new Uint8Array()),
      NS: record('NS', 'Target.Example.', target),
      PTR: record('PTR', 'Target.Example.', target),
      SOA: record('SOA', soa, new Uint8Array()),
      SRV: record(
        'SRV',
        { port: 443, priority: 1, target: 'Target.Example.', weight: 2 },
        new Uint8Array(),
      ),
      SVCB: record('SVCB', {}, join(uint16(1), target)),
      TLSA: record('TLSA', {}, new Uint8Array([3, 1, 1, 0xaa])),
      TXT: record('TXT', [new Uint8Array([97, 98, 99])], new Uint8Array([3, 97, 98, 99])),
    };

    expect(Object.keys(fixtures).sort()).toEqual([...DNSSEC_APPLICATION_TYPES].sort());
    for (const fixture of Object.values(fixtures))
      expect(canonicalRdata(fixture)).not.toBeNull();
  });

  it('canonicalises every supported name-bearing application RDATA shape', () => {
    expect(canonicalRdata(record('CNAME', 'TaRGeT.Example.', new Uint8Array()))).toEqual(
      canonicalName('target.example.'),
    );
    expect(
      canonicalRdata(
        record('MX', { exchange: 'Mail.Example.', preference: 10 }, new Uint8Array()),
      ),
    ).toEqual(join(uint16(10), canonicalName('mail.example.')));
    expect(
      canonicalRdata(
        record(
          'SOA',
          {
            expire: 5,
            minimum: 6,
            mname: 'NS.Example.',
            refresh: 3,
            retry: 4,
            rname: 'Hostmaster.Example.',
            serial: 2,
          },
          new Uint8Array(),
        ),
      ),
    ).toEqual(
      join(
        canonicalName('ns.example.'),
        canonicalName('hostmaster.example.'),
        uint32(2),
        uint32(3),
        uint32(4),
        uint32(5),
        uint32(6),
      ),
    );
    expect(
      canonicalRdata(
        record(
          'SRV',
          { port: 443, priority: 1, target: 'Service.Example.', weight: 2 },
          new Uint8Array(),
        ),
      ),
    ).toEqual(join(uint16(1), uint16(2), uint16(443), canonicalName('service.example.')));

    const target = canonicalName('WWW.Example.');
    const svcb = join(uint16(1), target, new Uint8Array([0, 3, 0, 2, 1, 187]));
    expect(canonicalRdata(record('HTTPS', svcb, svcb))).toEqual(
      join(uint16(1), canonicalName('www.example.'), new Uint8Array([0, 3, 0, 2, 1, 187])),
    );
  });

  it('retains valid opaque application RDATA and rejects malformed encodings', () => {
    const address = new Uint8Array([192, 0, 2, 1]);
    expect(canonicalRdata(record('A', '192.0.2.1', address))).toEqual(address);
    expect(canonicalRdata(record('TXT', [], new Uint8Array([3, 97, 98])))).toBeNull();
    expect(canonicalRdata(record('SVCB', {}, new Uint8Array([0, 1, 0xc0, 0])))).toBeNull();
    expect(canonicalRdata(record('TYPE1234', {}, new Uint8Array([1])))).toBeNull();
  });
});
