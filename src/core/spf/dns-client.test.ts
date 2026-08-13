import { describe, expect, it } from 'vitest';

import type {
  DnsMessage,
  DnsQuestion,
  DnsRecord,
  DnsResolver,
  DnsResponse,
  ResolverDefinition,
} from '../dns/types';
import { DnsQueryRun } from '../doh/query-run';
import { WireSpfDnsClient } from './dns-client';

const definition: ResolverDefinition = {
  endpoint: 'https://resolver.test/dns-query',
  httpMethod: 'POST',
  id: 'google',
  label: 'Fixture resolver',
  privacyUrl: 'https://resolver.test/privacy',
};

function record(
  data: unknown,
  type = 'PTR',
  ttl = 300,
  recordClass = 'IN',
  owner = '__question__',
): DnsRecord {
  return {
    class: recordClass,
    data,
    owner,
    rawRdata: new Uint8Array(),
    section: 'answer',
    ttl,
    type,
    typeCode: type === 'PTR' ? 12 : type === 'MX' ? 15 : 1,
  };
}

function message(
  question: DnsQuestion,
  answers: readonly DnsRecord[],
  responseCode: string,
): DnsMessage {
  return {
    additionals: [],
    answers,
    authorities: [],
    flags: {
      authoritativeAnswer: false,
      authenticatedData: false,
      checkingDisabled: false,
      recursionAvailable: true,
      recursionDesired: true,
      truncated: false,
    },
    id: 0,
    messageBytes: 120,
    questions: [{ class: 'IN', name: question.name.absolute, type: question.type }],
    raw: new Uint8Array(120),
    responseCode,
  };
}

class FixtureResolver implements DnsResolver {
  readonly definition = definition;
  readonly questions: DnsQuestion[] = [];
  readonly #answers: readonly DnsRecord[];
  readonly #responseCode: string;

  constructor(answers: readonly DnsRecord[], responseCode = 'NOERROR') {
    this.#answers = answers;
    this.#responseCode = responseCode;
  }

  query(question: DnsQuestion): Promise<DnsResponse> {
    this.questions.push(question);
    const answers = this.#answers.map((answer) =>
      answer.owner === '__question__' ? { ...answer, owner: question.name.absolute } : answer,
    );
    return Promise.resolve({
      cache: 'miss',
      message: message(question, answers, this.#responseCode),
      queryTimeMs: 1,
      question,
      receivedAt: '2026-08-13T00:00:00.000Z',
      resolver: definition,
    });
  }
}

describe('wire SPF DNS client', () => {
  it('uses the canonical reverse name and returns PTR presentation values', async () => {
    const resolver = new FixtureResolver([
      record('Mail.Example.Test.', 'PTR', 120),
      record('ignored.example.test.', 'PTR', 30, 'CH'),
      record('192.0.2.1', 'A', 10),
    ]);
    const client = new WireSpfDnsClient(resolver, new DnsQueryRun());

    const result = await client.lookupPtr('192.0.2.3');

    expect(resolver.questions).toHaveLength(1);
    expect(resolver.questions[0]?.name.absolute).toBe('3.2.0.192.in-addr.arpa.');
    expect(resolver.questions[0]?.type).toBe('PTR');
    expect(result).toEqual({
      messageBytes: 120,
      status: 'answer',
      ttl: 120,
      values: ['Mail.Example.Test.'],
    });
  });

  it('bounds PTR presentation values before returning them to an evaluator', async () => {
    const resolver = new FixtureResolver(
      Array.from({ length: 300 }, (_, index) => record(`host-${String(index)}.example.test.`)),
    );
    const client = new WireSpfDnsClient(resolver, new DnsQueryRun());

    const result = await client.lookupPtr('2001:db8::1');

    expect(result.values).toHaveLength(256);
    expect(result.values.at(-1)).toBe('host-255.example.test.');
    expect(resolver.questions[0]?.name.absolute).toMatch(/\.ip6\.arpa\.$/u);
  });

  it('maps negative and transient PTR responses to their SPF lookup statuses', async () => {
    const nxdomain = await new WireSpfDnsClient(
      new FixtureResolver([], 'NXDOMAIN'),
      new DnsQueryRun(),
    ).lookupPtr('192.0.2.3');
    const servfail = await new WireSpfDnsClient(
      new FixtureResolver([], 'SERVFAIL'),
      new DnsQueryRun(),
    ).lookupPtr('192.0.2.3');

    expect(nxdomain).toMatchObject({ status: 'nxdomain', values: [] });
    expect(servfail).toMatchObject({ status: 'servfail', values: [] });
  });

  it('rejects malformed addresses without issuing a DNS question', async () => {
    const resolver = new FixtureResolver([]);
    const client = new WireSpfDnsClient(resolver, new DnsQueryRun());

    const result = await client.lookupPtr('not-an-address');

    expect(result).toMatchObject({ status: 'error', values: [] });
    expect(resolver.questions).toEqual([]);
  });

  it('ignores same-type records that are not bound to the queried owner', async () => {
    const client = new WireSpfDnsClient(
      new FixtureResolver([record('attacker.example.', 'PTR', 300, 'IN', 'sibling.invalid.')]),
      new DnsQueryRun(),
    );

    await expect(client.lookupPtr('192.0.2.3')).resolves.toMatchObject({
      status: 'nodata',
      values: [],
    });
  });

  it('follows the unique CNAME chain and ignores appended sibling TXT records', async () => {
    const txt = (value: string, owner: string, ttl: number): DnsRecord =>
      record(
        [Uint8Array.from(value, (character) => character.charCodeAt(0))],
        'TXT',
        ttl,
        'IN',
        owner,
      );
    const resolver = new FixtureResolver([
      record('policy.example.', 'CNAME', 90),
      txt('v=spf1 -all', 'policy.example.', 60),
      txt('v=spf1 +all', 'sibling.invalid.', 30),
    ]);
    const client = new WireSpfDnsClient(resolver, new DnsQueryRun());

    await expect(client.lookup('example.test', 'TXT')).resolves.toEqual({
      messageBytes: 120,
      status: 'answer',
      ttl: 60,
      values: ['v=spf1 -all'],
    });
  });

  it('rejects ambiguous CNAME chains instead of consuming either target', async () => {
    const client = new WireSpfDnsClient(
      new FixtureResolver([record('one.example.', 'CNAME'), record('two.example.', 'CNAME')]),
      new DnsQueryRun(),
    );

    await expect(client.lookup('example.test', 'TXT')).resolves.toMatchObject({
      status: 'error',
      values: [],
    });
  });

  it('rejects a reachable CNAME RRset that mixes valid and invalid targets', async () => {
    const client = new WireSpfDnsClient(
      new FixtureResolver([
        record('policy.example.', 'CNAME'),
        record('not a DNS name', 'CNAME'),
      ]),
      new DnsQueryRun(),
    );

    await expect(client.lookup('example.test', 'TXT')).resolves.toMatchObject({
      error: 'The DNS answer contains an invalid or ambiguous CNAME chain.',
      status: 'error',
      values: [],
    });
  });

  it('does not charge unrelated aliases against the reachable CNAME hop limit', async () => {
    const txt = Uint8Array.from('v=spf1 -all', (character) => character.charCodeAt(0));
    const unrelated = Array.from({ length: 256 }, (_, index) =>
      record(
        `unrelated-target-${String(index)}.example.`,
        'CNAME',
        300,
        'IN',
        `unrelated-${String(index)}.example.`,
      ),
    );
    const client = new WireSpfDnsClient(
      new FixtureResolver([
        ...unrelated,
        record('policy.example.', 'CNAME', 120),
        record([txt], 'TXT', 60, 'IN', 'policy.example.'),
      ]),
      new DnsQueryRun(),
    );

    await expect(client.lookup('example.test', 'TXT')).resolves.toEqual({
      messageBytes: 120,
      status: 'answer',
      ttl: 60,
      values: ['v=spf1 -all'],
    });
  });

  it('rejects a chain that requires a sixty-fifth reachable CNAME hop', async () => {
    const aliases = Array.from({ length: 65 }, (_, index) =>
      record(
        `alias-${String(index + 1)}.example.`,
        'CNAME',
        300,
        'IN',
        index === 0 ? '__question__' : `alias-${String(index)}.example.`,
      ),
    );
    const client = new WireSpfDnsClient(new FixtureResolver(aliases), new DnsQueryRun());

    await expect(client.lookup('example.test', 'TXT')).resolves.toMatchObject({
      error: 'The DNS answer exceeds 64 reachable CNAME hops.',
      status: 'error',
      values: [],
    });
  });

  it('accepts exactly sixty-four reachable CNAME hops', async () => {
    const txt = Uint8Array.from('v=spf1 -all', (character) => character.charCodeAt(0));
    const aliases = Array.from({ length: 64 }, (_, index) =>
      record(
        `alias-${String(index + 1)}.example.`,
        'CNAME',
        300,
        'IN',
        index === 0 ? '__question__' : `alias-${String(index)}.example.`,
      ),
    );
    const client = new WireSpfDnsClient(
      new FixtureResolver([...aliases, record([txt], 'TXT', 60, 'IN', 'alias-64.example.')]),
      new DnsQueryRun(),
    );

    await expect(client.lookup('example.test', 'TXT')).resolves.toEqual({
      messageBytes: 120,
      status: 'answer',
      ttl: 60,
      values: ['v=spf1 -all'],
    });
  });

  it('uses RRset semantics for byte-identical duplicate policy records', async () => {
    const value = Uint8Array.from('v=spf1 -all', (character) => character.charCodeAt(0));
    const resolver = new FixtureResolver([
      record([value], 'TXT', 120),
      record([value], 'TXT', 60),
    ]);
    const client = new WireSpfDnsClient(resolver, new DnsQueryRun());

    await expect(client.lookup('example.test', 'TXT')).resolves.toEqual({
      messageBytes: 120,
      status: 'answer',
      ttl: 60,
      values: ['v=spf1 -all'],
    });
  });

  it('keeps distinct MX RDATA while deduplicating exact records and exchange lookups', async () => {
    const resolver = new FixtureResolver([
      record({ exchange: 'Mail.Example.Test.', preference: 10 }, 'MX', 120),
      record({ exchange: 'Mail.Example.Test.', preference: 10 }, 'MX', 60),
      record({ exchange: 'mail.example.test', preference: 20 }, 'MX', 90),
    ]);
    const client = new WireSpfDnsClient(resolver, new DnsQueryRun());

    await expect(client.lookup('example.test', 'MX')).resolves.toEqual({
      messageBytes: 120,
      mxRecords: [
        { exchange: 'mail.example.test', preference: 10 },
        { exchange: 'mail.example.test', preference: 20 },
      ],
      status: 'answer',
      ttl: 60,
      values: ['mail.example.test'],
    });
  });
});
