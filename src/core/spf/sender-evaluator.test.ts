import { describe, expect, it } from 'vitest';

import {
  evaluateSpfSender,
  type SpfSenderContext,
  type SpfSenderDnsClient,
} from './sender-evaluator';
import type { SpfLookupResult, SpfLookupType, SpfMxRecord } from './types';

function answer(values: readonly string[], messageBytes = 100): SpfLookupResult {
  return {
    messageBytes,
    status: values.length === 0 ? 'nodata' : 'answer',
    values,
  };
}

function result(status: SpfLookupResult['status'], error?: string): SpfLookupResult {
  return {
    ...(error === undefined ? {} : { error }),
    messageBytes: 80,
    status,
    values: [],
  };
}

function mxAnswer(records: readonly SpfMxRecord[]): SpfLookupResult {
  return {
    messageBytes: 100,
    mxRecords: records,
    status: records.length === 0 ? 'nodata' : 'answer',
    values: [...new Set(records.map((record) => record.exchange))],
  };
}

class FixtureDns implements SpfSenderDnsClient {
  readonly calls: string[] = [];
  readonly #answers: Readonly<Record<string, SpfLookupResult>>;

  constructor(answers: Readonly<Record<string, SpfLookupResult>>) {
    this.#answers = answers;
  }

  lookup(domain: string, type: SpfLookupType): Promise<SpfLookupResult> {
    this.calls.push(`${type}|${domain}`);
    return Promise.resolve(this.#answers[`${type}|${domain}`] ?? answer([]));
  }

  lookupPtr(ip: string): Promise<SpfLookupResult> {
    this.calls.push(`PTR|${ip}`);
    return Promise.resolve(this.#answers[`PTR|${ip}`] ?? answer([]));
  }
}

function context(overrides: Partial<SpfSenderContext> = {}): SpfSenderContext {
  return {
    heloDomain: 'mail.sender.test',
    ip: '192.0.2.3',
    localPart: 'strong-bad',
    mailFromDomain: 'sender.test',
    receiver: 'mx.receiver.test',
    timestamp: new Date('2026-08-13T00:00:00.000Z'),
    ...overrides,
  };
}

describe('sender-context SPF evaluation', () => {
  it('returns none for an absent policy and malformed initial domain', async () => {
    const dns = new FixtureDns({});
    const absent = await evaluateSpfSender(context(), dns);
    const malformed = await evaluateSpfSender(context({ mailFromDomain: 'single-label' }), dns);

    expect(absent.result).toBe('none');
    expect(absent.voidLookups).toBe(0);
    expect(malformed.result).toBe('none');
    expect(dns.calls).toEqual(['TXT|sender.test']);
  });

  it('uses the HELO identity and postmaster local-part for a null reverse path', async () => {
    const dns = new FixtureDns({
      'TXT|mail.sender.test': answer(['v=spf1 +all']),
    });

    const evaluation = await evaluateSpfSender(
      context({ localPart: 'ignored', mailFromDomain: '' }),
      dns,
    );

    expect(evaluation.result).toBe('pass');
    expect(evaluation.identity).toBe('postmaster@mail.sender.test');
    expect(evaluation.identitySource).toBe('helo');
    expect(evaluation.domain).toBe('mail.sender.test');
  });

  it('evaluates a valid MAIL FROM independently of a malformed HELO', async () => {
    const directDns = new FixtureDns({
      'TXT|sender.test': answer(['v=spf1 +all']),
    });
    const macroDns = new FixtureDns({
      'TXT|sender.test': answer(['v=spf1 exists:%{h}.sender.test -all']),
    });

    const direct = await evaluateSpfSender(context({ heloDomain: '[192.0.2.1]' }), directDns);
    const macro = await evaluateSpfSender(context({ heloDomain: '[192.0.2.1]' }), macroDns);

    expect(direct.result).toBe('pass');
    expect(direct.identitySource).toBe('mail-from');
    expect(directDns.calls).toEqual(['TXT|sender.test']);
    expect(macro.result).toBe('permerror');
    expect(macroDns.calls).toEqual(['TXT|sender.test']);
  });

  it('returns none without DNS when a null reverse path has no valid HELO domain', async () => {
    const dns = new FixtureDns({});

    const evaluation = await evaluateSpfSender(
      context({ heloDomain: '[192.0.2.1]', localPart: '', mailFromDomain: '' }),
      dns,
    );

    expect(evaluation.result).toBe('none');
    expect(evaluation.reason).toMatch(/null reverse path/iu);
    expect(dns.calls).toEqual([]);
  });

  it('rejects invalid or overlong direct-call local-parts before DNS', async () => {
    for (const localPart of ['two dots', 'a'.repeat(65)]) {
      const dns = new FixtureDns({});
      const evaluation = await evaluateSpfSender(context({ localPart }), dns);
      expect(evaluation.result).toBe('permerror');
      expect(dns.calls).toEqual([]);
    }
  });

  it('freezes the evidence capture time from the evaluation context', async () => {
    const evaluation = await evaluateSpfSender(
      context(),
      new FixtureDns({ 'TXT|sender.test': answer(['v=spf1 +all']) }),
    );

    expect(evaluation.capturedAt).toBe('2026-08-13T00:00:00.000Z');
  });

  it('honours mechanism order, qualifiers, IPv4 ranges, and IPv6 ranges', async () => {
    const ipv4Dns = new FixtureDns({
      'TXT|sender.test': answer(['v=spf1 ip4:192.0.2.0/24 a:unused.sender.test -all']),
    });
    const ipv6Dns = new FixtureDns({
      'TXT|sender.test': answer(['v=spf1 ip6:2001:db8:abcd::/64 -all']),
    });
    const softfailDns = new FixtureDns({
      'TXT|sender.test': answer(['v=spf1 ~all']),
    });

    const ipv4 = await evaluateSpfSender(context(), ipv4Dns);
    const ipv6 = await evaluateSpfSender(context({ ip: '2001:db8:abcd::42' }), ipv6Dns);
    const softfail = await evaluateSpfSender(context(), softfailDns);

    expect(ipv4.result).toBe('pass');
    expect(ipv4.match?.term).toBe('ip4:192.0.2.0/24');
    expect(ipv4Dns.calls).toEqual(['TXT|sender.test']);
    expect(ipv6.result).toBe('pass');
    expect(softfail.result).toBe('softfail');
  });

  it('uses the client address family and the corresponding dual CIDR length for a', async () => {
    const dns = new FixtureDns({
      'AAAA|edge.sender.test': answer(['2001:db8:1234::99']),
      'TXT|sender.test': answer(['v=spf1 a:edge.sender.test/24//64 -all']),
    });

    const evaluation = await evaluateSpfSender(context({ ip: '2001:db8:1234::42' }), dns);

    expect(evaluation.result).toBe('pass');
    expect(dns.calls).toEqual(['TXT|sender.test', 'AAAA|edge.sender.test']);
  });

  it('returns permerror for malformed A and AAAA address evidence', async () => {
    const fixtures: readonly [string, SpfSenderContext, string][] = [
      ['A', context(), 'not-an-ipv4-address'],
      ['AAAA', context({ ip: '2001:db8::1' }), 'not-an-ipv6-address'],
    ];
    for (const [type, sender, malformed] of fixtures) {
      const dns = new FixtureDns({
        [`${type}|sender.test`]: answer([malformed]),
        'TXT|sender.test': answer(['v=spf1 a -all']),
      });
      const evaluation = await evaluateSpfSender(sender, dns);

      expect(evaluation.result).toBe('permerror');
      expect(evaluation.reason).toMatch(/malformed.*address data/iu);
    }
  });

  it('counts full MX records without repeating a shared exchange lookup', async () => {
    const passDns = new FixtureDns({
      'A|mail.sender.test': answer(['192.0.2.99']),
      'MX|sender.test': mxAnswer([
        { exchange: 'mail.sender.test', preference: 10 },
        { exchange: 'mail.sender.test', preference: 20 },
      ]),
      'TXT|sender.test': answer(['v=spf1 mx/24 -all']),
    });
    const records = Array.from({ length: 11 }, (_, preference) => ({
      exchange: 'mail.sender.test',
      preference,
    }));
    const overDns = new FixtureDns({
      'MX|sender.test': mxAnswer(records),
      'TXT|sender.test': answer(['v=spf1 mx -all']),
    });

    const pass = await evaluateSpfSender(context(), passDns);
    const over = await evaluateSpfSender(context(), overDns);

    expect(pass.result).toBe('pass');
    expect(passDns.calls.filter((call) => call === 'A|mail.sender.test')).toHaveLength(1);
    expect(over.result).toBe('permerror');
    expect(overDns.calls).toEqual(['TXT|sender.test', 'MX|sender.test']);
  });

  it('uses RRset semantics when counting exact duplicate MX records', async () => {
    const duplicate = { exchange: 'mail.sender.test', preference: 10 } as const;
    const dns = new FixtureDns({
      'A|mail.sender.test': answer(['192.0.2.3']),
      'MX|sender.test': {
        ...mxAnswer(Array.from({ length: 11 }, () => duplicate)),
        values: Array.from({ length: 11 }, () => duplicate.exchange),
      },
      'TXT|sender.test': answer(['v=spf1 mx -all']),
    });

    const evaluation = await evaluateSpfSender(context(), dns);

    expect(evaluation.result).toBe('pass');
    expect(dns.calls.filter((call) => call === 'A|mail.sender.test')).toHaveLength(1);
  });

  it('does not apply an implicit address fallback to a null MX', async () => {
    const dns = new FixtureDns({
      'MX|sender.test': answer(['.']),
      'TXT|sender.test': answer(['v=spf1 mx -all']),
    });

    const evaluation = await evaluateSpfSender(context(), dns);

    expect(evaluation.result).toBe('fail');
    expect(dns.calls).toEqual(['TXT|sender.test', 'MX|sender.test']);
  });

  it('matches include only when the child result is pass and preserves redirect policy', async () => {
    const includedFailDns = new FixtureDns({
      'TXT|provider.test': answer(['v=spf1 -all']),
      'TXT|sender.test': answer(['v=spf1 include:provider.test -all']),
    });
    const includedPassDns = new FixtureDns({
      'TXT|provider.test': answer(['v=spf1 ip4:192.0.2.3 -all']),
      'TXT|sender.test': answer(['v=spf1 -include:provider.test +all']),
    });
    const redirectedDns = new FixtureDns({
      'TXT|policy.test': answer(['v=spf1 ?all']),
      'TXT|sender.test': answer(['v=spf1 redirect=policy.test']),
    });

    const includedFail = await evaluateSpfSender(context(), includedFailDns);
    const includedPass = await evaluateSpfSender(context(), includedPassDns);
    const redirected = await evaluateSpfSender(context(), redirectedDns);

    expect(includedFail.result).toBe('fail');
    expect(includedFail.match?.domain).toBe('sender.test');
    expect(includedPass.result).toBe('fail');
    expect(includedPass.match?.term).toBe('-include:provider.test');
    expect(redirected.result).toBe('neutral');
    expect(redirected.match?.domain).toBe('policy.test');
  });

  it('propagates an include policy DNS failure as temperror without consuming a void', async () => {
    const dns = new FixtureDns({
      'TXT|provider.test': result('servfail', 'fixture server failure'),
      'TXT|sender.test': answer(['v=spf1 include:provider.test -all']),
    });

    const evaluation = await evaluateSpfSender(context(), dns);

    expect(evaluation.result).toBe('temperror');
    expect(evaluation.voidLookups).toBe(0);
  });

  it('expands bounded sender macros according to the RFC transformation order', async () => {
    const expected = '3.2.0.192.strong._spf.sender.test';
    const dns = new FixtureDns({
      [`A|${expected}`]: answer(['198.51.100.2']),
      'TXT|sender.test': answer(['v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all']),
    });

    const evaluation = await evaluateSpfSender(context(), dns);

    expect(evaluation.result).toBe('pass');
    expect(dns.calls).toEqual(['TXT|sender.test', `A|${expected}`]);
    expect(evaluation.trace.some((entry) => entry.stage === 'macro')).toBe(true);
  });

  it('expands HELO, sender-domain, address-family, and current-domain macros', async () => {
    const expected = 'mail.sender.test.sender.test.in-addr._spf.sender.test';
    const dns = new FixtureDns({
      [`A|${expected}`]: answer(['203.0.113.9']),
      'TXT|sender.test': answer(['v=spf1 exists:%{h}.%{o}.%{v}._spf.%{d} -all']),
    });

    const evaluation = await evaluateSpfSender(context(), dns);

    expect(evaluation.result).toBe('pass');
    expect(dns.calls).toEqual(['TXT|sender.test', `A|${expected}`]);
  });

  it('resolves the p macro through bounded forward-confirmed reverse DNS', async () => {
    const dns = new FixtureDns({
      'A|mail.sender.test': answer(['192.0.2.3']),
      'PTR|192.0.2.3': answer(['mail.sender.test']),
      'TXT|sender.test': answer(['v=spf1 exists:%{p} -all']),
    });

    const evaluation = await evaluateSpfSender(context(), dns);

    expect(evaluation.result).toBe('pass');
    expect(evaluation.dnsTerms).toBe(2);
    expect(dns.calls).toEqual([
      'TXT|sender.test',
      'PTR|192.0.2.3',
      'A|mail.sender.test',
      'A|mail.sender.test',
    ]);
  });

  it('validates at most ten PTR targets before applying the ptr domain test', async () => {
    const names = Array.from({ length: 12 }, (_, index) => `host-${String(index)}.other.test`);
    names[9] = 'mail.sender.test';
    const fixtures: Record<string, SpfLookupResult> = {
      'PTR|192.0.2.3': answer(names),
      'TXT|sender.test': answer(['v=spf1 ptr:sender.test -all']),
    };
    for (const [index, name] of names.slice(0, 10).entries()) {
      fixtures[`A|${name}`] = answer([
        index === 9 ? '192.0.2.3' : `198.51.100.${String(index + 1)}`,
      ]);
    }
    const dns = new FixtureDns(fixtures);

    const evaluation = await evaluateSpfSender(context(), dns);

    expect(evaluation.result).toBe('pass');
    expect(dns.calls.filter((call) => call.startsWith('A|'))).toHaveLength(10);
    expect(dns.calls).not.toContain('A|host-10.other.test');
  });

  it('enforces the global ten-term limit before issuing an eleventh term lookup', async () => {
    const mechanisms = Array.from(
      { length: 11 },
      (_, index) => `a:host-${String(index)}.sender.test`,
    ).join(' ');
    const fixtures: Record<string, SpfLookupResult> = {
      'TXT|sender.test': answer([`v=spf1 ${mechanisms} -all`]),
    };
    for (let index = 0; index < 10; index += 1) {
      fixtures[`A|host-${String(index)}.sender.test`] = answer([
        `198.51.100.${String(index + 1)}`,
      ]);
    }
    const dns = new FixtureDns(fixtures);

    const evaluation = await evaluateSpfSender(context(), dns);

    expect(evaluation.result).toBe('permerror');
    expect(evaluation.dnsTerms).toBe(11);
    expect(dns.calls).not.toContain('A|host-10.sender.test');
  });

  it('returns permerror on the third void lookup but temperror on SERVFAIL', async () => {
    const voidDns = new FixtureDns({
      'TXT|sender.test': answer([
        'v=spf1 a:one.sender.test a:two.sender.test a:three.sender.test -all',
      ]),
    });
    const failureDns = new FixtureDns({
      'A|one.sender.test': result('servfail', 'fixture server failure'),
      'TXT|sender.test': answer(['v=spf1 a:one.sender.test -all']),
    });

    const voids = await evaluateSpfSender(context(), voidDns);
    const failure = await evaluateSpfSender(context(), failureDns);

    expect(voids.result).toBe('permerror');
    expect(voids.voidLookups).toBe(3);
    expect(failure.result).toBe('temperror');
    expect(failure.voidLookups).toBe(0);
  });

  it('detects dependency cycles before repeating a policy lookup', async () => {
    const dns = new FixtureDns({
      'TXT|loop.test': answer(['v=spf1 include:sender.test -all']),
      'TXT|sender.test': answer(['v=spf1 include:loop.test -all']),
    });

    const evaluation = await evaluateSpfSender(context(), dns);

    expect(evaluation.result).toBe('permerror');
    expect(evaluation.reason).toMatch(/cycle/iu);
    expect(dns.calls.filter((call) => call === 'TXT|sender.test')).toHaveLength(1);
  });

  it('loads and safely expands a publisher explanation only for a final fail', async () => {
    const dns = new FixtureDns({
      'TXT|sender.test': answer(['v=spf1 -all exp=why.%{d}']),
      'TXT|why.sender.test': answer(['Denied %{s} from %{c} at %{r} on %{t}; sender=%{S}']),
    });

    const evaluation = await evaluateSpfSender(context(), dns);

    expect(evaluation.result).toBe('fail');
    expect(evaluation.explanation).toBe(
      'Denied strong-bad@sender.test from 192.0.2.3 at mx.receiver.test on 1786579200; sender=strong-bad%40sender.test',
    );
    expect(evaluation.dnsTerms).toBe(0);
    expect(dns.calls).toEqual(['TXT|sender.test', 'TXT|why.sender.test']);
  });

  it('ignores unknown modifiers, including values with unknown macro syntax', async () => {
    const dns = new FixtureDns({
      'TXT|sender.test': answer(['v=spf1 vendor=%{not-a-valid-macro ip4:192.0.2.3 -all']),
    });

    const evaluation = await evaluateSpfSender(context(), dns);

    expect(evaluation.result).toBe('pass');
    expect(evaluation.match?.term).toBe('ip4:192.0.2.3');
  });

  it('rejects duplicate known modifiers even when their values differ', async () => {
    const records = [
      'v=spf1 redirect=one.test redirect=two.test',
      'v=spf1 -all exp=first.test exp=second.test',
    ];

    for (const record of records) {
      const evaluation = await evaluateSpfSender(
        context(),
        new FixtureDns({ 'TXT|sender.test': answer([record]) }),
      );
      expect(evaluation.result).toBe('permerror');
    }
  });

  it('returns permerror for non-space policy separators after otherwise valid terms', async () => {
    for (const separator of ['\t', '\r', '\n', '\u00a0', '\u2003']) {
      const evaluation = await evaluateSpfSender(
        context(),
        new FixtureDns({
          'TXT|sender.test': answer([`v=spf1 ip4:192.0.2.3${separator}-all`]),
        }),
      );

      expect(evaluation.result).toBe('permerror');
    }
  });

  it('rejects CIDR syntax on ineligible mechanisms and dual CIDR on address literals', async () => {
    const records = [
      'v=spf1 include:provider.test/24 -all',
      'v=spf1 exists:host.test/24 -all',
      'v=spf1 ptr/24 -all',
      'v=spf1 all/24',
      'v=spf1 ip4:192.0.2.0/24//64 -all',
      'v=spf1 ip6:2001:db8::/32//64 -all',
    ];

    for (const record of records) {
      const evaluation = await evaluateSpfSender(
        context(),
        new FixtureDns({ 'TXT|sender.test': answer([record]) }),
      );
      expect(evaluation.result).toBe('permerror');
    }
  });

  it('fails closed on multiple policies, unsupported mechanisms, and malformed unreachable macros', async () => {
    const fixtures: readonly [string, readonly string[]][] = [
      ['multiple policies', ['v=spf1 -all', 'v=spf1 +all']],
      ['unsupported mechanism', ['v=spf1 vendor:argument -all']],
      ['malformed macro', ['v=spf1 -all exists:%{d0}.sender.test']],
    ];

    for (const [, records] of fixtures) {
      const evaluation = await evaluateSpfSender(
        context(),
        new FixtureDns({ 'TXT|sender.test': answer(records) }),
      );
      expect(evaluation.result).toBe('permerror');
    }
  });

  it('preserves bounded DNS trace evidence and honours cancellation', async () => {
    const controller = new AbortController();
    controller.abort();
    const dns = new FixtureDns({
      'TXT|sender.test': answer(['v=spf1 -all']),
    });

    const evaluation = await evaluateSpfSender(context({ signal: controller.signal }), dns);

    expect(evaluation.result).toBe('temperror');
    expect(evaluation.trace.at(-1)?.stage).toBe('result');
    expect(evaluation.trace.every((entry, index) => entry.sequence === index + 1)).toBe(true);
    expect(dns.calls).toEqual([]);
  });
});
