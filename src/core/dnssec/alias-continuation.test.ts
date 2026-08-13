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
const MAX_ALIAS_HOPS = 64;
const MAX_CHAIN_QUESTIONS = 80;

interface TestKey {
  readonly dnskey: DnsRecord;
  readonly info: DnskeyInfo;
  readonly privateKey: CryptoKey;
}

interface AliasHarness {
  readonly otherDnskey: DnsResponse;
  readonly otherDs: DnsResponse;
  readonly root: TestKey;
  readonly rootDnskey: DnsResponse;
  readonly source: TestKey;
  readonly sourceDnskey: DnsResponse;
  readonly sourceDs: DnsResponse;
  readonly target: TestKey;
}

interface QueryHarness {
  readonly calls: { readonly name: string; readonly type: DnsRecordType }[];
  readonly query: DnssecChainQuery;
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

function join(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function uint16(value: number): Uint8Array {
  return new Uint8Array([value >>> 8, value & 0xff]);
}

function typeCode(type: string): number {
  const values: Readonly<Record<string, number>> = {
    A: 1,
    CNAME: 5,
    DNAME: 39,
    DS: 43,
    RRSIG: 46,
    NSEC: 47,
    DNSKEY: 48,
    SVCB: 64,
    HTTPS: 65,
  };
  const value = values[type];
  if (value === undefined) throw new Error(`The test harness has no type code for ${type}.`);
  return value;
}

function record(
  owner: string,
  type: string,
  rawRdata: Uint8Array,
  data: unknown = {},
  section: 'answer' | 'authority' = 'answer',
): DnsRecord {
  return {
    class: 'IN',
    data,
    owner,
    rawRdata,
    section,
    ttl: 300,
    type,
    typeCode: typeCode(type),
  };
}

function validatedName(value: string): ValidatedDnsName {
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
        authenticatedData: false,
        authoritativeAnswer: false,
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
    question: { name: validatedName(owner), type },
    receivedAt: new Date(NOW_MILLISECONDS).toISOString(),
    resolver: resolverById('cloudflare'),
  };
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
  const publicKey = join(new Uint8Array([exponent.length]), exponent, modulus);
  const dnskey = record(owner, 'DNSKEY', join(new Uint8Array([1, 1, 3, 8]), publicKey));
  const info = parseDnskey(dnskey);
  if (info === null) throw new Error('Generated DNSKEY did not parse.');
  return { dnskey, info, privateKey: generated.privateKey };
}

async function signature(
  owner: string,
  typeCovered: string,
  records: readonly DnsRecord[],
  signer: TestKey,
  options: { readonly labels?: number } = {},
): Promise<DnsRecord> {
  const data = {
    algorithm: signer.info.algorithm,
    expiration: NOW_SECONDS + 3600,
    inception: NOW_SECONDS - 3600,
    keyTag: signer.info.keyTag,
    labels: options.labels ?? (owner === '.' ? 0 : owner.replace(/\.$/u, '').split('.').length),
    originalTTL: records[0]?.ttl ?? 300,
    signature: new Uint8Array(),
    signersName: signer.dnskey.owner,
    typeCovered,
  };
  const section = typeCovered === 'NSEC' ? 'authority' : 'answer';
  const unsigned = record(owner, 'RRSIG', new Uint8Array(), data, section);
  const parsed = parseRrsig(unsigned, NOW_SECONDS);
  if (parsed === null) throw new Error('Generated RRSIG did not parse.');
  const signedData = rrsetSignedData([...records, unsigned], parsed);
  if (signedData === null) throw new Error(`${typeCovered} RRset could not be canonicalised.`);
  const value = new Uint8Array(
    await crypto.subtle.sign('RSASSA-PKCS1-v1_5', signer.privateKey, asArrayBuffer(signedData)),
  );
  return { ...unsigned, data: { ...data, signature: value } };
}

function dsRecord(owner: string, key: DnskeyInfo, digest: Uint8Array): DnsRecord {
  return record(
    owner,
    'DS',
    join(new Uint8Array([key.keyTag >>> 8, key.keyTag & 0xff, key.algorithm, 2]), digest),
  );
}

async function delegation(
  owner: string,
  child: TestKey,
  parent: TestKey,
): Promise<{ readonly dnskey: DnsResponse; readonly ds: DnsResponse }> {
  const digest = await dnskeyDigest(owner, child.dnskey.rawRdata, 2);
  const ds = dsRecord(owner, child.info, digest);
  const dsSignature = await signature(owner, 'DS', [ds], parent);
  const keySignature = await signature(owner, 'DNSKEY', [child.dnskey], child);
  return {
    dnskey: response(owner, 'DNSKEY', [child.dnskey, keySignature]),
    ds: response(owner, 'DS', [ds, dsSignature]),
  };
}

function typeBitmap(...types: readonly number[]): Uint8Array {
  const windows = new Map<number, number[]>();
  for (const type of types) {
    const window = Math.floor(type / 256);
    const octet = Math.floor((type % 256) / 8);
    const bits = windows.get(window) ?? [];
    bits[octet] = (bits[octet] ?? 0) | (0x80 >>> (type % 8));
    windows.set(window, bits);
  }
  return join(
    ...[...windows.entries()]
      .sort(([left], [right]) => left - right)
      .map(([window, bits]) => {
        const length = bits.length;
        return new Uint8Array([
          window,
          length,
          ...Array.from({ length }, (_, i) => bits[i] ?? 0),
        ]);
      }),
  );
}

async function noDelegation(
  owner: string,
  signer: TestKey,
  types: readonly number[] = [1, 46, 47],
): Promise<DnsResponse> {
  const proof = record(
    owner,
    'NSEC',
    join(canonicalName(`z.${owner}`), typeBitmap(...types)),
    {},
    'authority',
  );
  const proofSignature = await signature(owner, 'NSEC', [proof], signer);
  return response(owner, 'DS', [], [proof, proofSignature]);
}

async function wildcardNextCloserDenial(signer: TestKey): Promise<readonly DnsRecord[]> {
  const proof = record(
    'aaa.test.',
    'NSEC',
    join(canonicalName('zzz.test.'), typeBitmap(46, 47)),
    {},
    'authority',
  );
  return [proof, await signature('aaa.test.', 'NSEC', [proof], signer)];
}

function cname(owner: string, target: string): DnsRecord {
  return record(owner, 'CNAME', canonicalName(target), target);
}

function dname(owner: string, target: string): DnsRecord {
  return record(owner, 'DNAME', canonicalName(target), target);
}

function address(owner: string): DnsRecord {
  return record(owner, 'A', new Uint8Array([192, 0, 2, 1]), '192.0.2.1');
}

function serviceBinding(
  owner: string,
  type: 'HTTPS' | 'SVCB',
  priority: number,
  target: string,
): DnsRecord {
  return record(owner, type, join(uint16(priority), canonicalName(target)), {
    priority,
    target,
  });
}

function anchorMatcher(root: TestKey) {
  const anchor: RootTrustAnchor = {
    algorithm: 8,
    digest: new Uint8Array(32),
    digestHex: '00'.repeat(32),
    digestType: 2,
    id: 'alias-harness-root',
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

async function aliasHarness(): Promise<AliasHarness> {
  const root = await testKey('.');
  const source = await testKey('test.');
  const target = await testKey('other.');
  const rootSignature = await signature('.', 'DNSKEY', [root.dnskey], root);
  const sourceDelegation = await delegation('test.', source, root);
  const targetDelegation = await delegation('other.', target, root);
  return {
    otherDnskey: targetDelegation.dnskey,
    otherDs: targetDelegation.ds,
    root,
    rootDnskey: response('.', 'DNSKEY', [root.dnskey, rootSignature]),
    source,
    sourceDnskey: sourceDelegation.dnskey,
    sourceDs: sourceDelegation.ds,
    target,
  };
}

function queryHarness(
  data: AliasHarness,
  responses: ReadonlyMap<string, DnsResponse>,
  fallback?: (name: string, type: DnsRecordType) => DnsResponse | undefined,
): QueryHarness {
  const calls: { name: string; type: DnsRecordType }[] = [];
  const base = new Map<string, DnsResponse>([
    ['.|DNSKEY', data.rootDnskey],
    ['test.|DS', data.sourceDs],
    ['test.|DNSKEY', data.sourceDnskey],
    ['other.|DS', data.otherDs],
    ['other.|DNSKEY', data.otherDnskey],
  ]);
  return {
    calls,
    query: (name, type) => {
      calls.push({ name, type });
      const value = responses.get(`${name}|${type}`) ?? base.get(`${name}|${type}`);
      const selected = value ?? fallback?.(name, type);
      return selected === undefined
        ? Promise.reject(new Error(`Unexpected ${name} ${type} question.`))
        : Promise.resolve(selected);
    },
  };
}

async function signedCnameResponse(
  owner: string,
  target: string,
  signer: TestKey,
  questionType: DnsRecordType = 'DS',
): Promise<DnsResponse> {
  const alias = cname(owner, target);
  const aliasSignature = await signature(owner, 'CNAME', [alias], signer);
  return response(owner, questionType, [alias, aliasSignature]);
}

async function signedAddressResponse(owner: string, signer: TestKey): Promise<DnsResponse> {
  const value = address(owner);
  const valueSignature = await signature(owner, 'A', [value], signer);
  return response(owner, 'A', [value, valueSignature]);
}

describe('first-party DNSSEC alias continuation contract', () => {
  let data: AliasHarness;

  beforeAll(async () => {
    data = await aliasHarness();
  });

  it('authenticates a signed CNAME before continuing into a differently signed zone', async () => {
    const aliases = await signedCnameResponse('alias.test.', 'other.', data.source);
    const final = await signedAddressResponse('other.', data.target);
    const harness = queryHarness(
      data,
      new Map([
        ['alias.test.|DS', aliases],
        ['other.|A', final],
      ]),
    );

    const report = await validateDnssecChain('alias.test.', harness.query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('secure');
    expect(harness.calls).toContainEqual({ name: 'other.', type: 'A' });
    expect(report.evidence.filter((item) => item.name === 'alias.test.')).toHaveLength(1);
    expect(
      harness.calls.filter((item) => item.name === '.' && item.type === 'DNSKEY'),
    ).toHaveLength(1);
  });

  it('does not follow a wildcard-expanded CNAME without authenticated next-closer denial', async () => {
    const alias = cname('alias.test.', 'other.');
    const aliasSignature = await signature('alias.test.', 'CNAME', [alias], data.source, {
      labels: 1,
    });
    const harness = queryHarness(
      data,
      new Map([['alias.test.|DS', response('alias.test.', 'DS', [alias, aliasSignature])]]),
    );

    const report = await validateDnssecChain('alias.test.', harness.query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('incomplete');
    expect(report.explanation).toMatch(/wildcard.*closer|closer.*wildcard/iu);
    expect(report.application).toBeUndefined();
    expect(harness.calls.some((item) => item.name === 'other.')).toBe(false);
  });

  it('continues through a wildcard-expanded CNAME with authenticated next-closer denial', async () => {
    const alias = cname('alias.test.', 'other.');
    const aliasSignature = await signature('alias.test.', 'CNAME', [alias], data.source, {
      labels: 1,
    });
    const aliases = response(
      'alias.test.',
      'DS',
      [alias, aliasSignature],
      await wildcardNextCloserDenial(data.source),
    );
    const final = await signedAddressResponse('other.', data.target);
    const harness = queryHarness(
      data,
      new Map([
        ['alias.test.|DS', aliases],
        ['other.|A', final],
      ]),
    );

    const report = await validateDnssecChain('alias.test.', harness.query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('secure');
    expect(harness.calls).toContainEqual({ name: 'other.', type: 'A' });
  });

  it('rejects a CNAME authenticated by the target zone instead of its owner zone', async () => {
    const aliases = await signedCnameResponse('alias.test.', 'other.', data.target);
    const harness = queryHarness(data, new Map([['alias.test.|DS', aliases]]));

    const report = await validateDnssecChain('alias.test.', harness.query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('bogus');
    expect(harness.calls).not.toContainEqual({ name: 'other.', type: 'A' });
  });

  it('rejects a final RRset authenticated by the CNAME owner zone keys', async () => {
    const aliases = await signedCnameResponse('alias.test.', 'other.', data.source);
    const wronglySignedFinal = await signedAddressResponse('other.', data.source);
    const harness = queryHarness(
      data,
      new Map([
        ['alias.test.|DS', aliases],
        ['other.|A', wronglySignedFinal],
      ]),
    );

    const report = await validateDnssecChain('alias.test.', harness.query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('bogus');
    expect(harness.calls).toContainEqual({ name: 'other.', type: 'A' });
  });

  it('validates DNAME substitution before following its unsigned synthesised CNAME', async () => {
    const boundary = await noDelegation('branch.test.', data.source, [39, 46, 47]);
    const alias = dname('branch.test.', 'other.');
    const aliasSignature = await signature('branch.test.', 'DNAME', [alias], data.source);
    const synthesised = cname('host.branch.test.', 'host.other.');
    const aliasAnswer = response('host.branch.test.', 'DS', [
      alias,
      aliasSignature,
      synthesised,
    ]);
    const finalDenial = await noDelegation('host.other.', data.target);
    const final = await signedAddressResponse('host.other.', data.target);
    const harness = queryHarness(
      data,
      new Map([
        ['branch.test.|DS', boundary],
        ['host.branch.test.|DS', aliasAnswer],
        ['host.other.|DS', finalDenial],
        ['host.other.|A', final],
      ]),
    );

    const report = await validateDnssecChain('host.branch.test.', harness.query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('secure');
    expect(harness.calls).toContainEqual({ name: 'host.other.', type: 'A' });
  });

  it('derives a DNAME substitution when the response omits the synthesised CNAME', async () => {
    const boundary = await noDelegation('branch.test.', data.source, [39, 46, 47]);
    const alias = dname('branch.test.', 'other.');
    const aliasSignature = await signature('branch.test.', 'DNAME', [alias], data.source);
    const aliasAnswer = response('host.branch.test.', 'DS', [alias, aliasSignature]);
    const finalDenial = await noDelegation('host.other.', data.target);
    const final = await signedAddressResponse('host.other.', data.target);
    const harness = queryHarness(
      data,
      new Map([
        ['branch.test.|DS', boundary],
        ['host.branch.test.|DS', aliasAnswer],
        ['host.other.|DS', finalDenial],
        ['host.other.|A', final],
      ]),
    );

    const report = await validateDnssecChain('host.branch.test.', harness.query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('secure');
    expect(harness.calls).toContainEqual({ name: 'host.other.', type: 'A' });
  });

  it('accepts the permitted zero TTL on a correctly synthesised CNAME', async () => {
    const boundary = await noDelegation('branch.test.', data.source, [39, 46, 47]);
    const alias = dname('branch.test.', 'other.');
    const aliasSignature = await signature('branch.test.', 'DNAME', [alias], data.source);
    const synthesised = { ...cname('host.branch.test.', 'host.other.'), ttl: 0 };
    const aliasAnswer = response('host.branch.test.', 'DS', [
      alias,
      aliasSignature,
      synthesised,
    ]);
    const finalDenial = await noDelegation('host.other.', data.target);
    const final = await signedAddressResponse('host.other.', data.target);
    const harness = queryHarness(
      data,
      new Map([
        ['branch.test.|DS', boundary],
        ['host.branch.test.|DS', aliasAnswer],
        ['host.other.|DS', finalDenial],
        ['host.other.|A', final],
      ]),
    );

    const report = await validateDnssecChain('host.branch.test.', harness.query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('secure');
    expect(harness.calls).toContainEqual({ name: 'host.other.', type: 'A' });
  });

  it('marks an altered synthesised CNAME as bogus without querying the forged target', async () => {
    const boundary = await noDelegation('branch.test.', data.source, [39, 46, 47]);
    const alias = dname('branch.test.', 'other.');
    const aliasSignature = await signature('branch.test.', 'DNAME', [alias], data.source);
    const altered = cname('host.branch.test.', 'forged.other.');
    const aliasAnswer = response('host.branch.test.', 'DS', [alias, aliasSignature, altered]);
    const harness = queryHarness(
      data,
      new Map([
        ['branch.test.|DS', boundary],
        ['host.branch.test.|DS', aliasAnswer],
      ]),
    );

    const report = await validateDnssecChain('host.branch.test.', harness.query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('bogus');
    expect(harness.calls.some((call) => call.name === 'forged.other.')).toBe(false);
  });

  it('rejects an unsigned DNAME even when its synthesised CNAME is well formed', async () => {
    const boundary = await noDelegation('branch.test.', data.source, [39, 46, 47]);
    const alias = dname('branch.test.', 'other.');
    const synthesised = cname('host.branch.test.', 'host.other.');
    const aliasAnswer = response('host.branch.test.', 'DS', [alias, synthesised]);
    const harness = queryHarness(
      data,
      new Map([
        ['branch.test.|DS', boundary],
        ['host.branch.test.|DS', aliasAnswer],
      ]),
    );

    const report = await validateDnssecChain('host.branch.test.', harness.query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('bogus');
    expect(harness.calls.some((call) => call.name === 'host.other.')).toBe(false);
  });

  it('does not follow a labels-reduced DNAME without a dedicated wildcard proof model', async () => {
    const boundary = await noDelegation('branch.test.', data.source, [39, 46, 47]);
    const alias = dname('branch.test.', 'other.');
    const aliasSignature = await signature('branch.test.', 'DNAME', [alias], data.source, {
      labels: 1,
    });
    const synthesised = cname('host.branch.test.', 'host.other.');
    const aliasAnswer = response('host.branch.test.', 'DS', [
      alias,
      aliasSignature,
      synthesised,
    ]);
    const harness = queryHarness(
      data,
      new Map([
        ['branch.test.|DS', boundary],
        ['host.branch.test.|DS', aliasAnswer],
      ]),
    );

    const report = await validateDnssecChain('host.branch.test.', harness.query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('incomplete');
    expect(report.explanation).toMatch(/wildcard.*DNAME|DNAME.*wildcard/iu);
    expect(harness.calls.some((call) => call.name === 'host.other.')).toBe(false);
  });

  it.each(['SVCB', 'HTTPS'] as const)(
    'follows a signed %s AliasMode record to a signed ServiceMode RRset of the same type',
    async (type) => {
      const alias = serviceBinding('test.', type, 0, 'other.');
      const aliasSignature = await signature('test.', type, [alias], data.source);
      const service = serviceBinding('other.', type, 1, '.');
      const serviceSignature = await signature('other.', type, [service], data.target);
      const harness = queryHarness(
        data,
        new Map([
          [`test.|${type}`, response('test.', type, [alias, aliasSignature])],
          [`other.|${type}`, response('other.', type, [service, serviceSignature])],
        ]),
      );

      const report = await validateDnssecChain('test.', harness.query, {
        matchTrustAnchors: anchorMatcher(data.root),
        now: NOW_MILLISECONDS,
        rrsetType: type,
      });

      expect(report.state).toBe('secure');
      expect(harness.calls).toContainEqual({ name: 'other.', type });
      expect(report.evidence.at(-1)).toMatchObject({ name: 'other.', type });
    },
  );

  it.each(['SVCB', 'HTTPS'] as const)(
    'does not follow a signed %s ServiceMode TargetName as an alias',
    async (type) => {
      const service = serviceBinding('test.', type, 1, 'other.');
      const serviceSignature = await signature('test.', type, [service], data.source);
      const harness = queryHarness(
        data,
        new Map([[`test.|${type}`, response('test.', type, [service, serviceSignature])]]),
      );

      const report = await validateDnssecChain('test.', harness.query, {
        matchTrustAnchors: anchorMatcher(data.root),
        now: NOW_MILLISECONDS,
        rrsetType: type,
      });

      expect(report.state).toBe('secure');
      expect(harness.calls).not.toContainEqual({ name: 'other.', type });
    },
  );

  it.each(['SVCB', 'HTTPS'] as const)(
    'does not accept a %s AliasMode target RRset signed by the alias owner keys',
    async (type) => {
      const alias = serviceBinding('test.', type, 0, 'other.');
      const aliasSignature = await signature('test.', type, [alias], data.source);
      const service = serviceBinding('other.', type, 1, '.');
      const wrongSignature = await signature('other.', type, [service], data.source);
      const harness = queryHarness(
        data,
        new Map([
          [`test.|${type}`, response('test.', type, [alias, aliasSignature])],
          [`other.|${type}`, response('other.', type, [service, wrongSignature])],
        ]),
      );

      const report = await validateDnssecChain('test.', harness.query, {
        matchTrustAnchors: anchorMatcher(data.root),
        now: NOW_MILLISECONDS,
        rrsetType: type,
      });

      expect(report.state).toBe('bogus');
      expect(harness.calls).toContainEqual({ name: 'other.', type });
    },
  );

  it.each(['SVCB', 'HTTPS'] as const)(
    'keeps divergent signed %s AliasMode targets authenticated but incomplete',
    async (type) => {
      const one = serviceBinding('test.', type, 0, 'one.other.');
      const two = serviceBinding('test.', type, 0, 'two.other.');
      const aliasSignature = await signature('test.', type, [one, two], data.source);
      const harness = queryHarness(
        data,
        new Map([[`test.|${type}`, response('test.', type, [one, two, aliasSignature])]]),
      );

      const report = await validateDnssecChain('test.', harness.query, {
        matchTrustAnchors: anchorMatcher(data.root),
        now: NOW_MILLISECONDS,
        rrsetType: type,
      });

      expect(report.state).toBe('incomplete');
      expect(report.state).not.toBe('bogus');
      expect(report.application).toMatchObject({ state: 'secure', type });
      expect(report.explanation).toMatch(/AliasMode.*target|target.*AliasMode/iu);
      expect(
        harness.calls.some((call) => call.name === 'one.other.' || call.name === 'two.other.'),
      ).toBe(false);
    },
  );

  it('detects a signed CNAME loop without exhausting the aggregate query limit', async () => {
    const first = await signedCnameResponse('first.test.', 'second.test.', data.source);
    const second = await signedCnameResponse('second.test.', 'first.test.', data.source);
    const harness = queryHarness(
      data,
      new Map([
        ['first.test.|DS', first],
        ['second.test.|DS', second],
      ]),
    );

    const report = await validateDnssecChain('first.test.', harness.query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('incomplete');
    expect(report.explanation).toMatch(/alias loop/iu);
    expect(harness.calls.length).toBeLessThan(MAX_CHAIN_QUESTIONS);
  });

  it('stops a long signed CNAME chain at the alias-hop limit before query amplification', async () => {
    const aliases = await Promise.all(
      Array.from({ length: MAX_ALIAS_HOPS + 1 }, async (_, index) => {
        const owner = `hop-${String(index)}.test.`;
        const target = `hop-${String(index + 1)}.test.`;
        const alias = cname(owner, target);
        return {
          alias,
          owner,
          signature: await signature(owner, 'CNAME', [alias], data.source),
        };
      }),
    );
    const byOwner = new Map(aliases.map((item) => [item.owner, item]));
    const harness = queryHarness(data, new Map(), (name, type) => {
      const item = byOwner.get(name);
      return item === undefined || (type !== 'A' && type !== 'DS')
        ? undefined
        : response(name, type, [item.alias, item.signature]);
    });

    const report = await validateDnssecChain('hop-0.test.', harness.query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
      rrsetType: 'A',
    });

    expect(report.state).toBe('incomplete');
    expect(report.explanation).toMatch(/64.*alias|alias.*64/iu);
    expect(harness.calls.length).toBeLessThanOrEqual(MAX_CHAIN_QUESTIONS);
    expect(
      harness.calls.filter((item) => item.name === 'test.' && item.type === 'DS'),
    ).toHaveLength(1);
    expect(
      harness.calls.filter((item) => item.name === 'test.' && item.type === 'DNSKEY'),
    ).toHaveLength(1);
  }, 20_000);

  it('retains the aggregate question ceiling for a deeply nested authenticated path', async () => {
    const nestedZones = Array.from(
      { length: MAX_CHAIN_QUESTIONS + 5 },
      (_, index) => `${'a.'.repeat(index + 1)}test.`,
    );
    const denials = await Promise.all(
      nestedZones.map(
        async (owner) => [owner, await noDelegation(owner, data.source)] as const,
      ),
    );
    const harness = queryHarness(
      data,
      new Map(denials.map(([owner, denial]) => [`${owner}|DS`, denial])),
    );
    const target = nestedZones.at(-1);
    if (target === undefined) throw new Error('Nested target fixture is missing.');

    const report = await validateDnssecChain(target, harness.query, {
      matchTrustAnchors: anchorMatcher(data.root),
      now: NOW_MILLISECONDS,
    });

    expect(report.state).toBe('incomplete');
    expect(harness.calls).toHaveLength(MAX_CHAIN_QUESTIONS);
    expect(report.evidence.at(-1)?.error).toMatch(/80-question bound/iu);
  }, 20_000);
});
