import { beforeAll, describe, expect, it } from 'vitest';

import type { DnsRecord, DnsRecordType, DnsResponse, ValidatedDnsName } from '../dns/types';
import { resolverById } from '../doh/resolvers';
import { validateDnssecChain, type DnssecChainQuery } from './chain';
import { dnskeyDigest } from './digest';
import { parseDnskey, parseRrsig } from './records';
import type { RootTrustAnchor, RootTrustAnchorMatch } from './trust-anchors';
import type { DnskeyInfo } from './types';
import { canonicalName, rrsetSignedData } from './verify';

const NOW_SECONDS = 1_800_000_000;
const NOW_MILLISECONDS = NOW_SECONDS * 1000;

interface TestKey {
  readonly dnskey: DnsRecord;
  readonly info: DnskeyInfo;
  readonly privateKey: CryptoKey;
}

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

async function testKey(owner: string): Promise<TestKey> {
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
    owner,
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

async function signature(
  owner: string,
  typeCovered: 'A' | 'CNAME' | 'DS' | 'DNSKEY' | 'NSEC' | 'NSEC3',
  records: readonly DnsRecord[],
  signer: TestKey,
  times: { readonly expiration?: number; readonly inception?: number } = {},
): Promise<DnsRecord> {
  const data = {
    algorithm: signer.info.algorithm,
    expiration: times.expiration ?? NOW_SECONDS + 3600,
    inception: times.inception ?? NOW_SECONDS - 3600,
    keyTag: signer.info.keyTag,
    labels: owner === '.' ? 0 : owner.replace(/\.$/u, '').split('.').length,
    originalTTL: records[0]?.ttl ?? 3600,
    signature: new Uint8Array(),
    signersName: signer.dnskey.owner,
    typeCovered,
  };
  const unsigned: DnsRecord = {
    class: 'IN',
    data,
    owner,
    rawRdata: new Uint8Array(),
    section: typeCovered === 'NSEC' || typeCovered === 'NSEC3' ? 'authority' : 'answer',
    ttl: records[0]?.ttl ?? 3600,
    type: 'RRSIG',
    typeCode: 46,
  };
  const parsed = parseRrsig(unsigned, NOW_SECONDS);
  if (parsed === null) throw new Error('Generated RRSIG did not parse.');
  const signedData = rrsetSignedData([...records, unsigned], parsed);
  if (signedData === null) throw new Error(`${typeCovered} RRset could not be canonicalised.`);
  const signed = new Uint8Array(
    await crypto.subtle.sign('RSASSA-PKCS1-v1_5', signer.privateKey, buffer(signedData)),
  );
  return { ...unsigned, data: { ...data, signature: signed } };
}

function dsRecord(owner: string, key: DnskeyInfo, digest: Uint8Array): DnsRecord {
  const rawRdata = new Uint8Array(4 + digest.length);
  rawRdata[0] = key.keyTag >>> 8;
  rawRdata[1] = key.keyTag & 0xff;
  rawRdata[2] = key.algorithm;
  rawRdata[3] = 2;
  rawRdata.set(digest, 4);
  return {
    class: 'IN',
    data: {},
    owner,
    rawRdata,
    section: 'answer',
    ttl: 3600,
    type: 'DS',
    typeCode: 43,
  };
}

function name(value: string): ValidatedDnsName {
  return {
    absolute: value,
    ascii: value === '.' ? '' : value.slice(0, -1),
    display: value,
    hadRootDot: true,
    unicode: false,
  };
}

function response(
  owner: string,
  type: DnsRecordType,
  answers: readonly DnsRecord[],
  authorities: readonly DnsRecord[] = [],
): DnsResponse {
  return {
    cache: 'miss',
    message: {
      additionals: [],
      answers,
      authorities,
      flags: {
        authoritativeAnswer: false,
        authenticatedData: false,
        checkingDisabled: true,
        recursionAvailable: true,
        recursionDesired: true,
        truncated: false,
      },
      id: 0,
      messageBytes: 0,
      questions: [{ class: 'IN', name: owner, type }],
      raw: new Uint8Array(),
      responseCode: 'NOERROR',
    },
    queryTimeMs: 1,
    question: { name: name(owner), type },
    receivedAt: '2027-01-15T08:00:00.000Z',
    resolver: resolverById('cloudflare'),
  };
}

function anchorMatcher(root: TestKey) {
  const anchor: RootTrustAnchor = {
    algorithm: 8,
    digest: new Uint8Array(32),
    digestHex: '00'.repeat(32),
    digestType: 2,
    id: 'fixture-root',
    keyTag: root.info.keyTag,
    validFrom: '2020-01-01T00:00:00Z',
  };
  return (keys: readonly DnskeyInfo[]): Promise<readonly RootTrustAnchorMatch[]> => {
    const key = keys.find(
      (candidate) =>
        candidate.keyTag === root.info.keyTag && candidate.algorithm === root.info.algorithm,
    );
    return Promise.resolve(key === undefined ? [] : [{ anchor, key }]);
  };
}

async function fixtures() {
  const root = await testKey('.');
  const child = await testKey('test.');
  const rootSignature = await signature('.', 'DNSKEY', [root.dnskey], root);
  const digest = await dnskeyDigest('test.', child.dnskey.rawRdata, 2);
  const ds = dsRecord('test.', child.info, digest);
  const dsSignature = await signature('test.', 'DS', [ds], root);
  const childSignature = await signature('test.', 'DNSKEY', [child.dnskey], child);
  return {
    child,
    childResponse: response('test.', 'DNSKEY', [child.dnskey, childSignature]),
    ds,
    dsResponse: response('test.', 'DS', [ds, dsSignature]),
    root,
    rootResponse: response('.', 'DNSKEY', [root.dnskey, rootSignature]),
  };
}

const BASE32HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

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
  return new Uint8Array(await crypto.subtle.digest('SHA-1', buffer(bytes)));
}

type FixtureSet = Awaited<ReturnType<typeof fixtures>>;

interface ChainResponses {
  readonly child?: DnsResponse;
  readonly ds?: DnsResponse;
  readonly root?: DnsResponse;
}

function fixtureQuery(data: FixtureSet, replacements: ChainResponses = {}): DnssecChainQuery {
  return (owner, type) => {
    if (owner === '.' && type === 'DNSKEY')
      return Promise.resolve(replacements.root ?? data.rootResponse);
    if (owner === 'test.' && type === 'DS')
      return Promise.resolve(replacements.ds ?? data.dsResponse);
    if (owner === 'test.' && type === 'DNSKEY')
      return Promise.resolve(replacements.child ?? data.childResponse);
    return Promise.reject(new Error(`Unexpected ${owner} ${type} question.`));
  };
}

function withOwner(source: TestKey, owner: string): TestKey {
  const dnskey = { ...source.dnskey, owner };
  const info = parseDnskey(dnskey);
  if (info === null) throw new Error('Re-owned DNSKEY did not parse.');
  return { dnskey, info, privateKey: source.privateKey };
}

function withDnskeyRdata(source: TestKey, rawRdata: Uint8Array): TestKey {
  const dnskey = { ...source.dnskey, rawRdata };
  const info = parseDnskey(dnskey);
  if (info === null) throw new Error('Modified DNSKEY did not parse.');
  return { dnskey, info, privateKey: source.privateKey };
}

async function validateFixture(
  data: FixtureSet,
  replacements: ChainResponses = {},
  target = 'test.',
) {
  return validateDnssecChain(target, fixtureQuery(data, replacements), {
    matchTrustAnchors: anchorMatcher(data.root),
    now: NOW_MILLISECONDS,
  });
}

describe('independent DNSSEC chain validation', () => {
  it('validates every signed delegation from an injected test anchor', async () => {
    const data = await fixtures();
    const query: DnssecChainQuery = (owner, type) => {
      if (owner === '.' && type === 'DNSKEY') return Promise.resolve(data.rootResponse);
      if (owner === 'test.' && type === 'DS') return Promise.resolve(data.dsResponse);
      if (owner === 'test.' && type === 'DNSKEY') return Promise.resolve(data.childResponse);
      return Promise.reject(new Error(`Unexpected ${owner} ${type} question.`));
    };

    const report = await validateDnssecChain('test.', query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
    });

    expect(report.state).toBe('secure');
    expect(report.steps.map((step) => step.state)).toEqual(['secure', 'secure']);
    expect(report.evidence).toHaveLength(3);
    expect(report.steps[1]?.dsMatches.some((match) => match.matches)).toBe(true);
  });

  it('continues a secure chain into an exact positive application RRset', async () => {
    const data = await fixtures();
    const address: DnsRecord = {
      class: 'IN',
      data: '192.0.2.1',
      owner: 'test.',
      rawRdata: new Uint8Array([192, 0, 2, 1]),
      section: 'answer',
      ttl: 300,
      type: 'A',
      typeCode: 1,
    };
    const addressSignature = await signature('test.', 'A', [address], data.child);
    const addressResponse = response('test.', 'A', [address, addressSignature]);
    const query: DnssecChainQuery = (owner, type) => {
      if (owner === 'test.' && type === 'A') return Promise.resolve(addressResponse);
      return fixtureQuery(data)(owner, type);
    };

    const report = await validateDnssecChain('test.', query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('secure');
    expect(report.application).toMatchObject({ state: 'secure', type: 'A' });
    expect(report.evidence.map((item) => item.type)).toEqual(['DNSKEY', 'DS', 'DNSKEY', 'A']);
  });

  it('uses authenticated containing-zone keys for a positive non-apex RRset', async () => {
    const data = await fixtures();
    const owner = 'host.test.';
    const nsec: DnsRecord = {
      class: 'IN',
      data: {},
      owner,
      rawRdata: new Uint8Array([...canonicalName('zzz.test.'), 0, 1, 0x40]),
      section: 'authority',
      ttl: 300,
      type: 'NSEC',
      typeCode: 47,
    };
    const nsecSignature = await signature(owner, 'NSEC', [nsec], data.child);
    const denial = response(owner, 'DS', [], [nsec, nsecSignature]);
    const address: DnsRecord = {
      class: 'IN',
      data: '192.0.2.2',
      owner,
      rawRdata: new Uint8Array([192, 0, 2, 2]),
      section: 'answer',
      ttl: 300,
      type: 'A',
      typeCode: 1,
    };
    const addressSignature = await signature(owner, 'A', [address], data.child);
    const addressResponse = response(owner, 'A', [address, addressSignature]);
    const query: DnssecChainQuery = (queryOwner, type) => {
      if (queryOwner === owner && type === 'DS') return Promise.resolve(denial);
      if (queryOwner === owner && type === 'A') return Promise.resolve(addressResponse);
      return fixtureQuery(data)(queryOwner, type);
    };

    const report = await validateDnssecChain(owner, query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('secure');
    expect(report.steps.at(-1)?.state).toBe('not-delegated');
    expect(report.application).toMatchObject({ owner, state: 'secure', type: 'A' });
  });

  it('authenticates an exact CNAME returned while probing the target delegation', async () => {
    const data = await fixtures();
    const owner = 'alias.test.';
    const cname: DnsRecord = {
      class: 'IN',
      data: 'target.test.',
      owner,
      rawRdata: canonicalName('target.test.'),
      section: 'answer',
      ttl: 300,
      type: 'CNAME',
      typeCode: 5,
    };
    const cnameSignature = await signature(owner, 'CNAME', [cname], data.child);
    const aliasResponse = response(owner, 'DS', [cname, cnameSignature]);
    const query: DnssecChainQuery = (queryOwner, type) => {
      if (queryOwner === owner && type === 'DS') return Promise.resolve(aliasResponse);
      return fixtureQuery(data)(queryOwner, type);
    };

    const report = await validateDnssecChain(owner, query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'CNAME',
    });

    expect(report.state).toBe('secure');
    expect(report.application).toMatchObject({ owner, state: 'secure', type: 'CNAME' });
    expect(report.evidence.at(-1)?.type).toBe('DS');

    const continued = await validateDnssecChain(owner, query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });
    expect(continued).toMatchObject({ state: 'incomplete' });
    expect(continued.explanation).toMatch(/CNAME alias/iu);
    expect(continued.application).toBeUndefined();
  });

  it('requires every authenticated link to be current at one common validation instant', async () => {
    const data = await fixtures();
    const expiringRootSignature = await signature(
      '.',
      'DNSKEY',
      [data.root.dnskey],
      data.root,
      {
        expiration: NOW_SECONDS + 1,
      },
    );
    const rootResponse = response('.', 'DNSKEY', [data.root.dnskey, expiringRootSignature]);
    let clock = NOW_MILLISECONDS;
    const query: DnssecChainQuery = (owner, type) => {
      if (owner === '.' && type === 'DNSKEY') return Promise.resolve(rootResponse);
      if (owner === 'test.' && type === 'DS') return Promise.resolve(data.dsResponse);
      if (owner === 'test.' && type === 'DNSKEY') {
        clock = (NOW_SECONDS + 2) * 1000;
        return Promise.resolve(data.childResponse);
      }
      return Promise.reject(new Error(`Unexpected ${owner} ${type} question.`));
    };

    const report = await validateDnssecChain('test.', query, {
      clock: () => clock,
      matchTrustAnchors: anchorMatcher(data.root),
    });

    expect(report.state).toBe('incomplete');
    expect(report.explanation).toMatch(/one common validation time/iu);
    expect(report.validatedAt).toBe(new Date(clock).toISOString());
  });

  it('rejects a DS RRset changed after it was signed', async () => {
    const data = await fixtures();
    const changed = { ...data.ds, rawRdata: data.ds.rawRdata.slice() };
    changed.rawRdata[4] = (changed.rawRdata[4] ?? 0) ^ 0xff;
    const tampered = response('test.', 'DS', [
      changed,
      ...data.dsResponse.message.answers.slice(1),
    ]);
    const query: DnssecChainQuery = (owner, type) => {
      if (owner === '.' && type === 'DNSKEY') return Promise.resolve(data.rootResponse);
      if (owner === 'test.' && type === 'DS') return Promise.resolve(tampered);
      return Promise.reject(new Error(`Unexpected ${owner} ${type} question.`));
    };

    const report = await validateDnssecChain('test.', query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
    });
    expect(report.state).toBe('bogus');
    expect(report.steps.at(-1)?.dsVerifications).toEqual([
      expect.objectContaining({ status: 'invalid' }),
    ]);
  });

  it('accepts a locally verified NSEC proof of an insecure delegation', async () => {
    const data = await fixtures();
    const nsec: DnsRecord = {
      class: 'IN',
      data: {},
      owner: 'unsigned.',
      rawRdata: new Uint8Array([...canonicalName('zzz.'), 0, 1, 0x20]),
      section: 'authority',
      ttl: 3600,
      type: 'NSEC',
      typeCode: 47,
    };
    const nsecSignature = await signature('unsigned.', 'NSEC', [nsec], data.root);
    const denial = response('unsigned.', 'DS', [], [nsec, nsecSignature]);
    const query: DnssecChainQuery = (owner, type) => {
      if (owner === '.' && type === 'DNSKEY') return Promise.resolve(data.rootResponse);
      if (owner === 'unsigned.' && type === 'DS') return Promise.resolve(denial);
      return Promise.reject(new Error(`Unexpected ${owner} ${type} question.`));
    };

    const report = await validateDnssecChain('unsigned.', query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
    });
    expect(report.state).toBe('insecure');
    expect(report.steps.at(-1)?.denial).toMatchObject({ proofType: 'NSEC', state: 'insecure' });
  });

  it('accepts a locally verified exact-match NSEC3 delegation proof', async () => {
    const data = await fixtures();
    const hash = await sha1(canonicalName('unsigned.'));
    const owner = `${base32hex(hash)}.`;
    const nsec3: DnsRecord = {
      class: 'IN',
      data: {},
      owner,
      rawRdata: new Uint8Array([
        1,
        0,
        0,
        0,
        0,
        hash.length,
        ...new Uint8Array(hash.length),
        0,
        1,
        0x20,
      ]),
      section: 'authority',
      ttl: 3600,
      type: 'NSEC3',
      typeCode: 50,
    };
    const nsec3Signature = await signature(owner, 'NSEC3', [nsec3], data.root);
    const denial = response('unsigned.', 'DS', [], [nsec3, nsec3Signature]);
    const query: DnssecChainQuery = (queryOwner, type) => {
      if (queryOwner === '.' && type === 'DNSKEY') return Promise.resolve(data.rootResponse);
      if (queryOwner === 'unsigned.' && type === 'DS') return Promise.resolve(denial);
      return Promise.reject(new Error(`Unexpected ${queryOwner} ${type} question.`));
    };

    const report = await validateDnssecChain('unsigned.', query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
    });
    expect(report.state).toBe('insecure');
    expect(report.steps.at(-1)?.denial).toMatchObject({
      proofType: 'NSEC3',
      state: 'insecure',
    });
  });
});

describe('hostile DNSSEC resolver response handling', () => {
  let data: FixtureSet;

  beforeAll(async () => {
    data = await fixtures();
  });

  it('does not use a signed sibling DS RRset to authenticate an unsigned target DS RRset', async () => {
    const siblingDs = { ...data.ds, owner: 'sibling.' };
    const siblingSignature = await signature('sibling.', 'DS', [siblingDs], data.root);
    const contaminated = response('test.', 'DS', [data.ds, siblingDs, siblingSignature]);

    const report = await validateFixture(data, { ds: contaminated });

    expect(report.state).not.toBe('secure');
  });

  it('does not use a signed sibling DNSKEY RRset to authenticate an unsigned child DNSKEY RRset', async () => {
    const siblingKey = { ...data.child.dnskey, owner: 'sibling.test.' };
    const siblingSignature = await signature(
      'sibling.test.',
      'DNSKEY',
      [siblingKey],
      data.child,
    );
    const contaminated = response('test.', 'DNSKEY', [
      data.child.dnskey,
      siblingKey,
      siblingSignature,
    ]);

    const report = await validateFixture(data, { child: contaminated });

    expect(report.state).not.toBe('secure');
  });

  it('does not establish the root anchor from a copied DNSKEY signed at a different owner', async () => {
    const siblingRoot = withOwner(data.root, 'sibling.');
    const siblingSignature = await signature(
      'sibling.',
      'DNSKEY',
      [siblingRoot.dnskey],
      siblingRoot,
    );
    const contaminated = response('.', 'DNSKEY', [siblingRoot.dnskey, siblingSignature]);

    const report = await validateFixture(data, { root: contaminated }, '.');

    expect(report.state).not.toBe('secure');
  });

  it('rejects a signed DS answer belonging to the wrong owner', async () => {
    const foreignDs = { ...data.ds, owner: 'elsewhere.' };
    const foreignSignature = await signature('elsewhere.', 'DS', [foreignDs], data.root);
    const wrongOwner = response('test.', 'DS', [foreignDs, foreignSignature]);

    const report = await validateFixture(data, { ds: wrongOwner });

    expect(report.state).not.toBe('secure');
  });

  it('rejects a signed DS answer in a class other than IN', async () => {
    const wrongClass = { ...data.ds, class: 'CH' };
    const signed = await signature('test.', 'DS', [data.ds], data.root);
    const wrongClassSignature = { ...signed, class: 'CH' };
    const contaminated = response('test.', 'DS', [wrongClass, wrongClassSignature]);

    const report = await validateFixture(data, { ds: contaminated });

    expect(report.state).not.toBe('secure');
  });

  it('rejects a signed child DNSKEY answer in a class other than IN', async () => {
    const wrongClass = { ...data.child.dnskey, class: 'CH' };
    const signed = await signature('test.', 'DNSKEY', [data.child.dnskey], data.child);
    const wrongClassSignature = { ...signed, class: 'CH' };
    const contaminated = response('test.', 'DNSKEY', [wrongClass, wrongClassSignature]);

    const report = await validateFixture(data, { child: contaminated });

    expect(report.state).not.toBe('secure');
  });

  it.each(['decoded question', 'response question'] as const)(
    'rejects a response with a mismatched %s',
    async (mismatch) => {
      const root = {
        ...data.rootResponse,
        ...(mismatch === 'response question'
          ? { question: { name: name('elsewhere.'), type: 'DNSKEY' as const } }
          : {}),
        message: {
          ...data.rootResponse.message,
          ...(mismatch === 'decoded question'
            ? { questions: [{ class: 'IN', name: 'elsewhere.', type: 'DNSKEY' }] }
            : {}),
        },
      };

      const report = await validateFixture(data, { root }, '.');

      expect(report.state).not.toBe('secure');
    },
  );

  it('finds a target RRSIG separated from its RRset by unrelated answer data', async () => {
    const unrelated: DnsRecord = {
      class: 'IN',
      data: 'unrelated',
      owner: 'elsewhere.',
      rawRdata: new Uint8Array([9, 117, 110, 114, 101, 108, 97, 116, 101, 100]),
      section: 'answer',
      ttl: 3600,
      type: 'TXT',
      typeCode: 16,
    };
    const targetSignature = data.dsResponse.message.answers.at(-1);
    if (targetSignature === undefined) throw new Error('DS signature fixture is missing.');
    const interleaved = response('test.', 'DS', [data.ds, unrelated, targetSignature]);

    const report = await validateFixture(data, { ds: interleaved });

    expect(report.state).toBe('secure');
  });

  it('does not use a target RRSIG returned outside the target answer section', async () => {
    const targetSignature = data.dsResponse.message.answers.at(-1);
    if (targetSignature === undefined) throw new Error('DS signature fixture is missing.');
    const separated = response('test.', 'DS', [data.ds], [targetSignature]);

    const report = await validateFixture(data, { ds: separated });

    expect(report.state).toBe('bogus');
  });

  it('rejects a target DS RRset with no target RRSIG', async () => {
    const unsigned = response('test.', 'DS', [data.ds]);

    const report = await validateFixture(data, { ds: unsigned });

    expect(report.state).toBe('bogus');
  });

  it('treats an exact duplicate DS record as one RRset member', async () => {
    const targetSignature = data.dsResponse.message.answers.at(-1);
    if (targetSignature === undefined) throw new Error('DS signature fixture is missing.');
    const duplicated = response('test.', 'DS', [data.ds, data.ds, targetSignature]);

    const report = await validateFixture(data, { ds: duplicated });

    expect(report.state).toBe('secure');
  });

  it('treats an exact duplicate child DNSKEY as one RRset member', async () => {
    const targetSignature = data.childResponse.message.answers.at(-1);
    if (targetSignature === undefined) throw new Error('DNSKEY signature fixture is missing.');
    const duplicated = response('test.', 'DNSKEY', [
      data.child.dnskey,
      data.child.dnskey,
      targetSignature,
    ]);

    const report = await validateFixture(data, { child: duplicated });

    expect(report.state).toBe('secure');
  });

  it.each([
    ['four-octet DS RDATA', new Uint8Array([0, 1, 8, 2])],
    ['one-octet SHA-256 digest', new Uint8Array([0, 1, 8, 2, 0])],
    ['33-octet SHA-256 digest', new Uint8Array([0, 1, 8, 2, ...new Uint8Array(33)])],
  ])('does not authenticate malformed %s', async (_, rawRdata) => {
    const malformed = { ...data.ds, rawRdata };
    const malformedSignature = await signature('test.', 'DS', [malformed], data.root);
    const contaminated = response('test.', 'DS', [malformed, malformedSignature]);

    const report = await validateFixture(data, { ds: contaminated });

    expect(report.state).not.toBe('secure');
  });

  it('does not authenticate a DNSKEY with no public-key material', async () => {
    const malformedKey = {
      ...data.child.dnskey,
      rawRdata: new Uint8Array([1, 1, 3, 8]),
    };

    const report = await validateFixture(data, {
      child: response('test.', 'DNSKEY', [malformedKey]),
    });

    expect(report.state).not.toBe('secure');
  });

  it('does not continue a chain through an empty eligible child keyset', async () => {
    const rawRdata = data.child.dnskey.rawRdata.slice();
    rawRdata[0] = 0;
    rawRdata[1] = 1;
    const nonZoneKey = withDnskeyRdata(data.child, rawRdata);
    const digest = await dnskeyDigest('test.', nonZoneKey.dnskey.rawRdata, 2);
    const ds = dsRecord('test.', nonZoneKey.info, digest);
    const dsSignature = await signature('test.', 'DS', [ds], data.root);
    const keySignature = await signature('test.', 'DNSKEY', [nonZoneKey.dnskey], nonZoneKey);

    const report = await validateFixture(data, {
      child: response('test.', 'DNSKEY', [nonZoneKey.dnskey, keySignature]),
      ds: response('test.', 'DS', [ds, dsSignature]),
    });

    expect(report.state).toBe('bogus');
    expect(report.steps.at(-1)?.dnskeyVerifications).toEqual([
      expect.objectContaining({ status: 'missing-key' }),
    ]);
  });

  it('does not authenticate a response marked as truncated', async () => {
    const truncated = {
      ...data.rootResponse,
      message: {
        ...data.rootResponse.message,
        flags: { ...data.rootResponse.message.flags, truncated: true },
      },
    };

    const report = await validateFixture(data, { root: truncated }, '.');

    expect(report.state).not.toBe('secure');
  });
});
