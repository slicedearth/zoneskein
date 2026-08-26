import { describe, expect, it } from 'vitest';

import { decodeDnsMessage } from '../dns/wire';
import type { DnsRecord, DnsRecordType, DnsResponse, ValidatedDnsName } from '../dns/types';
import { resolverById } from '../doh/resolvers';
import { validateApplicationRrset } from './application';
import { parseDnskey } from './records';
import type { DnskeyInfo } from './types';
import { canonicalName, canonicalRdata } from './verify';
import { boundDenialRecords, boundRrset, wireQuestionMatches } from './wire-evidence';

const NOW = 1_800_000_000;

interface TestSigner {
  readonly info: DnskeyInfo;
  readonly privateKey: CryptoKey;
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

function wireName(...labels: readonly string[]): Uint8Array {
  const encoder = new TextEncoder();
  return join(
    ...labels.map((label) => {
      const bytes = encoder.encode(label);
      return new Uint8Array([bytes.length, ...bytes]);
    }),
    new Uint8Array([0]),
  );
}

function pointer(offset: number): Uint8Array {
  return new Uint8Array([0xc0 | (offset >>> 8), offset & 0xff]);
}

function resourceRecord(
  owner: Uint8Array,
  type: number,
  rdata: Uint8Array,
  classCode = 1,
): Uint8Array {
  return join(owner, uint16(type), uint16(classCode), uint32(300), uint16(rdata.length), rdata);
}

function dnsResponseWire(
  questionName: Uint8Array,
  questionType: number,
  answers: readonly Uint8Array[],
): Uint8Array {
  return join(
    uint16(0),
    uint16(0x8180),
    uint16(1),
    uint16(answers.length),
    uint16(0),
    uint16(0),
    questionName,
    uint16(questionType),
    uint16(1),
    ...answers,
  );
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

function validatedName(value: string): ValidatedDnsName {
  return {
    absolute: value,
    ascii: value.slice(0, -1),
    display: value.slice(0, -1),
    hadRootDot: true,
    unicode: false,
  };
}

function response(raw: Uint8Array, type: DnsRecordType = 'MX'): DnsResponse {
  return {
    cache: 'miss',
    message: decodeDnsMessage(raw),
    queryTimeMs: 1,
    question: { name: validatedName('mail.example.'), type },
    receivedAt: new Date(NOW * 1000).toISOString(),
    resolver: resolverById('cloudflare'),
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
  const rawRdata = join(new Uint8Array([1, 1, 3, 8]), publicKey);
  const dnskey: DnsRecord = {
    class: 'IN',
    data: {},
    owner: 'example.',
    rawRdata,
    section: 'answer',
    ttl: 300,
    type: 'DNSKEY',
    typeCode: 48,
  };
  const info = parseDnskey(dnskey);
  if (info === null) throw new Error('Generated DNSKEY did not parse.');
  return { info, privateKey: generated.privateKey };
}

function independentMxSignedData(signer: DnskeyInfo): Uint8Array {
  const canonicalRdata = join(uint16(10), canonicalName('target.example.'));
  return join(
    uint16(15),
    new Uint8Array([8, 2]),
    uint32(300),
    uint32(NOW + 3600),
    uint32(NOW - 3600),
    uint16(signer.keyTag),
    canonicalName('example.'),
    canonicalName('mail.example.'),
    uint16(15),
    uint16(1),
    uint32(300),
    uint16(canonicalRdata.length),
    canonicalRdata,
  );
}

async function mxWireResponse(
  signer: TestSigner,
  signerName = wireName('ExAmPlE'),
  extraSignerNames: readonly Uint8Array[] = [],
): Promise<DnsResponse> {
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      signer.privateKey,
      asArrayBuffer(independentMxSignedData(signer.info)),
    ),
  );
  const question = wireName('MaIl', 'ExAmPlE');
  const exampleLabelOffset = 12 + 1 + 4;
  const mxRdata = join(
    uint16(10),
    new Uint8Array([6, ...new TextEncoder().encode('TaRgEt')]),
    pointer(exampleLabelOffset),
  );
  const rrsigRdata = (name: Uint8Array) =>
    join(
      uint16(15),
      new Uint8Array([8, 2]),
      uint32(300),
      uint32(NOW + 3600),
      uint32(NOW - 3600),
      uint16(signer.info.keyTag),
      name,
      signature,
    );
  return response(
    dnsResponseWire(question, 15, [
      resourceRecord(pointer(12), 15, mxRdata),
      resourceRecord(pointer(12), 46, rrsigRdata(signerName)),
      ...extraSignerNames.map((name) => resourceRecord(pointer(12), 46, rrsigRdata(name))),
    ]),
  );
}

describe('lossless DNSSEC wire evidence binding', () => {
  it('does not let a bound CAA record bypass structural validation', () => {
    const question = wireName('mail', 'example');
    const caa = new Uint8Array([0, 5, ...new TextEncoder().encode('issueca.example')]);
    const decoded = response(
      dnsResponseWire(question, 257, [resourceRecord(pointer(12), 257, caa)]),
      'CAA',
    );
    const fixture: DnsResponse = {
      ...decoded,
      message: {
        ...decoded.message,
        answers: decoded.message.answers.map((record) => ({
          ...record,
          data: { flags: 0, issuerCritical: false, tag: 'issue', value: 'attacker.test' },
        })),
      },
    };
    const bound = boundRrset(fixture, 'answer', 'mail.example.', 'CAA')?.[0];
    if (bound === undefined) throw new Error('CAA fixture was not bound.');

    expect(canonicalRdata(bound)).toEqual(caa);
    expect(bound.data).toEqual({
      flags: 0,
      issuerCritical: false,
      tag: 'issue',
      value: 'ca.example',
    });
    bound.rawRdata[1] = 15;
    expect(canonicalRdata(bound)).toBeNull();
  });

  it('verifies independently signed mixed-case MX RDATA containing compression', async () => {
    const signer = await testSigner();
    const fixture = await mxWireResponse(signer);

    const result = await validateApplicationRrset(
      fixture,
      'mail.example.',
      'MX',
      [signer.info],
      NOW,
    );

    expect(result).toMatchObject({ state: 'secure', type: 'MX' });
    expect(result.verifications).toContainEqual(
      expect.objectContaining({ status: 'verified' }),
    );
  });

  it('does not use lossy decoded name-bearing RDATA as signature input', async () => {
    const signer = await testSigner();
    const fixture = await mxWireResponse(signer);
    const answers = fixture.message.answers.map((record) =>
      record.type === 'MX'
        ? {
            ...record,
            data: { exchange: 'substituted.invalid.', preference: 10 },
            section: 'authority' as const,
            ttl: 999,
          }
        : record,
    );
    const changed: DnsResponse = {
      ...fixture,
      message: { ...fixture.message, answers },
    };

    const result = await validateApplicationRrset(
      changed,
      'mail.example.',
      'MX',
      [signer.info],
      NOW,
    );

    expect(result).toMatchObject({ state: 'secure' });
    expect(result.records[0]).toMatchObject({ section: 'answer', ttl: 300, type: 'MX' });
  });

  it('ignores an unusable extra signature after another RRSIG validates', async () => {
    const signer = await testSigner();
    const fixture = await mxWireResponse(signer, wireName('ExAmPlE'), [wireName('example.')]);

    await expect(
      validateApplicationRrset(fixture, 'mail.example.', 'MX', [signer.info], NOW),
    ).resolves.toMatchObject({ state: 'secure' });
  });

  it('rejects a decoded-question collision made from a dot inside one wire label', () => {
    const collidingQuestion = wireName('mail.example');
    const fixture = response(dnsResponseWire(collidingQuestion, 15, []));

    expect(fixture.message.questions[0]?.name).toBe('mail\\046example');
    expect(wireQuestionMatches(fixture, 'mail.example.', 'MX')).toBe(false);
  });

  it('treats an unusable signer name as a bogus absent signature', async () => {
    const signer = await testSigner();
    const fixture = await mxWireResponse(signer, wireName('example.'));

    const rrsigData = fixture.message.answers.find((record) => record.type === 'RRSIG')
      ?.data as { signersName?: string } | undefined;
    expect(rrsigData?.signersName).toBe('example\\046');
    await expect(
      validateApplicationRrset(fixture, 'mail.example.', 'MX', [signer.info], NOW),
    ).resolves.toMatchObject({ state: 'bogus' });
  });

  it('rejects an SRV target that uses prohibited DNS compression', () => {
    const question = wireName('mail', 'example');
    const exampleLabelOffset = 12 + 1 + 4;
    const srvRdata = join(uint16(1), uint16(2), uint16(443), pointer(exampleLabelOffset));
    expect(() =>
      response(
        dnsResponseWire(question, 33, [resourceRecord(pointer(12), 33, srvRdata)]),
        'SRV',
      ),
    ).toThrow(/prohibited compression/iu);
  });

  it('binds the zero identifier and response flags to the original DNS header', () => {
    const raw = dnsResponseWire(wireName('mail', 'example'), 15, []);
    raw[1] = 1;
    const decoded = decodeDnsMessage(raw);
    const fixture: DnsResponse = {
      ...response(raw),
      message: { ...decoded, id: 0 },
    };

    expect(wireQuestionMatches(fixture, 'mail.example.', 'MX')).toBe(false);

    const wrongCodeRaw = dnsResponseWire(wireName('mail', 'example'), 15, []);
    wrongCodeRaw[3] = (wrongCodeRaw[3] ?? 0) | 3;
    const wrongCodeDecoded = decodeDnsMessage(wrongCodeRaw);
    const wrongCode: DnsResponse = {
      ...response(wrongCodeRaw),
      message: { ...wrongCodeDecoded, responseCode: 'NOERROR' },
    };
    expect(wireQuestionMatches(wrongCode, 'mail.example.', 'MX')).toBe(false);
  });

  it('rejects aggregate compression work hidden behind many bounded names', () => {
    const question = wireName('mail', 'example');
    const chainStart = 12 + question.length + 4 + 12;
    const chain = join(
      ...Array.from({ length: 120 }, (_, index) =>
        pointer(index === 0 ? 12 : chainStart + (index - 1) * 2),
      ),
    );
    const finalPointer = pointer(chainStart + chain.length - 2);
    const answers = [
      resourceRecord(pointer(12), 65_280, chain),
      ...Array.from({ length: 280 }, () =>
        resourceRecord(finalPointer, 65_280, new Uint8Array()),
      ),
    ];
    const base = response(dnsResponseWire(question, 15, []));
    const raw = dnsResponseWire(question, 15, answers);
    const fixture: DnsResponse = {
      ...base,
      message: { ...base.message, messageBytes: raw.length, raw },
    };

    expect(wireQuestionMatches(fixture, 'mail.example.', 'MX')).toBe(false);
  });

  it('rejects forward compression pointers before canonical reconstruction', () => {
    const question = join(new Uint8Array([0xc0, 0x20]), uint16(15), uint16(1));
    const raw = join(
      uint16(0),
      uint16(0x8180),
      uint16(1),
      uint16(0),
      uint16(0),
      uint16(0),
      question,
    );
    const synthetic: DnsResponse = {
      cache: 'miss',
      message: {
        additionals: [],
        answers: [],
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
        messageBytes: raw.length,
        questions: [{ class: 'IN', name: 'mail.example.', type: 'MX' }],
        raw,
        responseCode: 'NOERROR',
      },
      queryTimeMs: 1,
      question: { name: validatedName('mail.example.'), type: 'MX' },
      receivedAt: new Date(NOW * 1000).toISOString(),
      resolver: resolverById('cloudflare'),
    };

    expect(wireQuestionMatches(synthetic, 'mail.example.', 'MX')).toBe(false);
  });

  it('does not relabel a non-IN denial record as IN while binding raw evidence', () => {
    const questionName = wireName('mail', 'example');
    const nsecRdata = join(wireName('next', 'example'), new Uint8Array([0, 1, 0x40]));
    const raw = join(
      uint16(0),
      uint16(0x8180),
      uint16(1),
      uint16(0),
      uint16(1),
      uint16(0),
      questionName,
      uint16(15),
      uint16(1),
      resourceRecord(pointer(12), 47, nsecRdata, 3),
    );
    const source: DnsRecord = {
      class: 'IN',
      data: {},
      owner: 'mail.example.',
      rawRdata: nsecRdata,
      section: 'authority',
      ttl: 300,
      type: 'NSEC',
      typeCode: 47,
    };
    const fixture: DnsResponse = {
      ...response(raw),
      message: {
        ...decodeDnsMessage(raw),
        authorities: [source],
      },
    };

    expect(boundDenialRecords(fixture)).toBeNull();
  });

  it('ignores unusable extra signatures while retaining raw denial records', () => {
    const questionName = wireName('mail', 'example');
    const nsecRdata = join(wireName('next', 'example'), new Uint8Array([0, 1, 0x40]));
    const malformedRrsig = join(
      uint16(47),
      new Uint8Array([8, 2]),
      uint32(300),
      uint32(NOW + 3600),
      uint32(NOW - 3600),
      uint16(1),
      wireName('example.'),
      new Uint8Array([1]),
    );
    const raw = join(
      uint16(0),
      uint16(0x8180),
      uint16(1),
      uint16(0),
      uint16(2),
      uint16(0),
      questionName,
      uint16(43),
      uint16(1),
      resourceRecord(pointer(12), 47, nsecRdata),
      resourceRecord(pointer(12), 46, malformedRrsig),
    );
    const fixture = response(raw, 'DS');

    expect(boundDenialRecords(fixture)).toEqual([
      expect.objectContaining({ owner: 'mail.example.', ttl: 300, type: 'NSEC' }),
    ]);
  });
});
