import { describe, expect, it } from 'vitest';

import { analyseSpf } from './evaluator';
import { flattenSpf } from './flatten';
import type { SpfDnsClient, SpfLookupResult, SpfLookupType, SpfMxRecord } from './types';

function answer(values: readonly string[], ttl = 300, messageBytes = 100): SpfLookupResult {
  return {
    messageBytes,
    status: values.length === 0 ? 'nodata' : 'answer',
    ttl,
    values,
  };
}

function lookupFailure(status: 'error' | 'servfail', message: string): SpfLookupResult {
  return { error: message, messageBytes: 80, status, values: [] };
}

function mxAnswer(records: readonly SpfMxRecord[]): SpfLookupResult {
  return {
    messageBytes: 100,
    mxRecords: records,
    status: records.length === 0 ? 'nodata' : 'answer',
    ttl: 300,
    values: [...new Set(records.map((record) => record.exchange))],
  };
}

class FixtureDns implements SpfDnsClient {
  readonly calls: string[] = [];
  readonly #answers: Readonly<Record<string, SpfLookupResult>>;

  constructor(answers: Readonly<Record<string, SpfLookupResult>>) {
    this.#answers = answers;
  }

  lookup(domain: string, type: SpfLookupType): Promise<SpfLookupResult> {
    this.calls.push(`${domain}|${type}`);
    return Promise.resolve(this.#answers[`${domain}|${type}`] ?? answer([]));
  }
}

describe('SPF dependency analysis', () => {
  it('tracks a nested include and redirect path without confusing terms with DNS requests', async () => {
    const dns = new FixtureDns({
      'a.test|A': answer(['192.0.2.1']),
      'a.test|AAAA': answer([]),
      'a.test|TXT': answer(['v=spf1 a -all']),
      'b.test|TXT': answer(['v=spf1 redirect=c.test']),
      'c.test|TXT': answer(['v=spf1 ip6:2001:db8::/32 -all']),
      'root.test|TXT': answer(['v=spf1 include:a.test include:b.test -all']),
    });
    const report = await analyseSpf('root.test', dns);

    expect(report.edges).toEqual([
      { from: 'root.test', kind: 'include', to: 'a.test' },
      { from: 'root.test', kind: 'include', to: 'b.test' },
      { from: 'b.test', kind: 'redirect', to: 'c.test' },
    ]);
    expect(report.maximumLookupTerms).toBe(4);
    expect(report.maximumDepth).toBe(3);
  });

  it('detects cycles and an over-budget worst-case path', async () => {
    const mechanisms = Array.from(
      { length: 11 },
      (_, index) => `a:host-${String(index)}.test`,
    ).join(' ');
    const dns = new FixtureDns({
      'cycle-a.test|TXT': answer(['v=spf1 include:cycle-b.test -all']),
      'cycle-b.test|TXT': answer(['v=spf1 include:cycle-a.test -all']),
      'over.test|TXT': answer([`v=spf1 ${mechanisms} -all`]),
    });
    const cycle = await analyseSpf('cycle-a.test', dns);
    const over = await analyseSpf('over.test', dns);

    expect(cycle.diagnostics.map((item) => item.code)).toContain('include-cycle');
    expect(over.maximumLookupTerms).toBe(11);
    expect(over.diagnostics.map((item) => item.code)).toContain('lookup-limit');
  });

  it('distinguishes two void lookups from a third void lookup', async () => {
    const dns = new FixtureDns({
      'three.test|TXT': answer(['v=spf1 a:one.test a:two.test a:three.test -all']),
      'two.test|TXT': answer(['v=spf1 a:one.test a:two.test -all']),
    });
    const two = await analyseSpf('two.test', dns);
    const three = await analyseSpf('three.test', dns);

    expect(two.maximumVoidLookups).toBe(2);
    expect(two.diagnostics.map((item) => item.code)).toContain('void-warning');
    expect(three.maximumVoidLookups).toBe(3);
    expect(three.diagnostics.map((item) => item.code)).toContain('void-limit');
  });

  it('does not count DNS failures, multiple policies, or unrelated TXT answers as void', async () => {
    const dns = new FixtureDns({
      'error.test|TXT': lookupFailure('servfail', 'fixture server failure'),
      'multiple.test|TXT': answer(['v=spf1 -all', 'v=spf1 +all']),
      'root.test|TXT': answer([
        'v=spf1 include:error.test include:multiple.test include:unrelated.test -all',
      ]),
      'unrelated.test|TXT': answer(['site-verification=fixture']),
    });

    const report = await analyseSpf('root.test', dns);

    expect(report.maximumVoidLookups).toBe(0);
    expect(report.diagnostics.map((item) => item.code)).toEqual(
      expect.arrayContaining(['lookup-failed', 'multiple-spf-policies', 'no-spf-policy']),
    );
  });

  it('reports mechanism DNS failure as temperror evidence without treating it as void', async () => {
    const dns = new FixtureDns({
      'broken.test|A': lookupFailure('servfail', 'fixture server failure'),
      'broken.test|AAAA': answer([]),
      'root.test|TXT': answer(['v=spf1 a:broken.test -all']),
    });

    const report = await analyseSpf('root.test', dns);
    const failure = report.diagnostics.find((item) => item.code === 'lookup-failed');

    expect(report.maximumVoidLookups).toBe(0);
    expect(failure?.message).toMatch(/temperror/iu);
  });

  it('counts full MX records while resolving a shared exchange only once', async () => {
    const mxRecords = Array.from({ length: 11 }, (_, preference) => ({
      exchange: 'mail.root.test',
      preference,
    }));
    const dns = new FixtureDns({
      'mail.root.test|A': answer(['192.0.2.1']),
      'mail.root.test|AAAA': answer(['2001:db8::1']),
      'root.test|MX': mxAnswer(mxRecords),
      'root.test|TXT': answer(['v=spf1 mx -all']),
    });

    const report = await analyseSpf('root.test', dns);

    expect(report.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'mx-target-limit', severity: 'error' }),
    );
    expect(dns.calls.filter((call) => call === 'mail.root.test|A')).toHaveLength(1);
    expect(dns.calls.filter((call) => call === 'mail.root.test|AAAA')).toHaveLength(1);
  });
});

describe('conservative SPF snapshots', () => {
  it('flattens finite pass sets with safe CIDR coalescing and provenance', async () => {
    const dns = new FixtureDns({
      'mail.root.test|A': answer(['198.51.100.8'], 120),
      'mail.root.test|AAAA': answer(['2001:db8::8'], 120),
      'provider.test|TXT': answer(['v=spf1 ip4:192.0.2.0/25 ip4:192.0.2.128/25 -all'], 600),
      'root.test|MX': answer(['mail.root.test'], 300),
      'root.test|TXT': answer(['v=spf1 include:provider.test mx -all'], 300),
    });
    const { snapshot } = await flattenSpf(
      'root.test',
      dns,
      new Date('2026-08-13T00:00:00.000Z'),
    );

    expect(snapshot.safe).toBe(true);
    expect(snapshot.value).toContain('ip4:192.0.2.0/24');
    expect(snapshot.value).toContain('ip4:198.51.100.8');
    expect(snapshot.value).toContain('ip6:2001:db8::8');
    expect(snapshot.value?.endsWith('-all')).toBe(true);
    expect(snapshot.provenance.length).toBeGreaterThanOrEqual(3);
    expect(snapshot.earliestSourceExpiry).toBe('2026-08-13T00:02:00.000Z');
  });

  it('refuses macros and non-pass DNS mechanisms', async () => {
    const macro = await flattenSpf(
      'macro.test',
      new FixtureDns({
        'macro.test|TXT': answer(['v=spf1 exists:%{i}.example -all']),
      }),
    );
    const qualifier = await flattenSpf(
      'qualifier.test',
      new FixtureDns({
        'provider.test|TXT': answer(['v=spf1 ip4:192.0.2.0/24 -all']),
        'qualifier.test|TXT': answer(['v=spf1 -include:provider.test -all']),
      }),
    );

    expect(macro.snapshot.safe).toBe(false);
    expect(macro.snapshot.blockers.join(' ')).toMatch(/macro|sender context/iu);
    expect(qualifier.snapshot.safe).toBe(false);
    expect(qualifier.snapshot.blockers.join(' ')).toMatch(/non-pass qualifier/iu);
  });

  it('chunks long snapshots into 255-octet TXT character-strings', async () => {
    const networks = Array.from(
      { length: 32 },
      (_, index) => `ip4:198.51.${String(index)}.1/32`,
    ).join(' ');
    const { snapshot } = await flattenSpf(
      'long.test',
      new FixtureDns({
        'long.test|TXT': answer([`v=spf1 ${networks} -all`]),
      }),
    );

    expect(snapshot.safe).toBe(true);
    expect(snapshot.chunks.length).toBeGreaterThan(1);
    expect(
      snapshot.chunks.every((chunk) => new TextEncoder().encode(chunk).length <= 255),
    ).toBe(true);
    expect(snapshot.warnings.join(' ')).toMatch(/512 bytes/iu);
  });

  it('refuses multiple policies and incomplete provider lookups', async () => {
    const multiple = await flattenSpf(
      'multiple.test',
      new FixtureDns({
        'multiple.test|TXT': answer(['v=spf1 ip4:192.0.2.1 -all', 'v=spf1 -all']),
      }),
    );
    const failed = await flattenSpf(
      'failed.test',
      new FixtureDns({
        'failed.test|TXT': answer(['v=spf1 include:provider.test -all']),
        'provider.test|TXT': {
          error: 'fixture transport failure',
          messageBytes: 0,
          status: 'error',
          values: [],
        },
      }),
    );

    expect(multiple.snapshot.safe).toBe(false);
    expect(multiple.snapshot.blockers.join(' ')).toMatch(/exactly one|single complete/iu);
    expect(failed.snapshot.safe).toBe(false);
    expect(failed.snapshot.blockers.join(' ')).toMatch(/failed|complete SPF policy/iu);
  });

  it('deduplicates exact pass ranges without broadening separated networks', async () => {
    const { snapshot } = await flattenSpf(
      'dedupe.test',
      new FixtureDns({
        'dedupe.test|TXT': answer([
          'v=spf1 include:one.test include:two.test ip4:192.0.2.192/26 -all',
        ]),
        'one.test|TXT': answer(['v=spf1 ip4:192.0.2.0/25 -all']),
        'two.test|TXT': answer(['v=spf1 ip4:192.0.2.0/25 -all']),
      }),
    );

    expect(snapshot.safe).toBe(true);
    expect(snapshot.networks).toEqual(['192.0.2.0/25', '192.0.2.192/26']);
  });

  it('preserves an IPv6 policy prefix and schedules recheck before a short TTL expires', async () => {
    const now = new Date('2026-08-13T00:00:00.000Z');
    const { snapshot } = await flattenSpf(
      'root.test',
      new FixtureDns({
        'root.test|TXT': answer(['v=spf1 ip6:2001:db8::/32 -all'], 30),
      }),
      now,
    );

    expect(snapshot.safe).toBe(true);
    expect(snapshot.networks).toEqual(['2001:db8::/32']);
    expect(snapshot.earliestSourceExpiry).toBe('2026-08-13T00:00:30.000Z');
    expect(snapshot.recommendedRecheck).toBe('2026-08-13T00:00:15.000Z');
    expect(new Date(snapshot.recommendedRecheck ?? 0).getTime()).toBeLessThanOrEqual(
      new Date(snapshot.earliestSourceExpiry ?? 0).getTime(),
    );
  });

  it('expires included networks at the earliest policy TTL on their dependency path', async () => {
    const now = new Date('2026-08-13T00:00:00.000Z');
    const { snapshot } = await flattenSpf(
      'root.test',
      new FixtureDns({
        'provider.test|TXT': answer(['v=spf1 ip4:192.0.2.0/24 -all'], 600),
        'root.test|TXT': answer(['v=spf1 include:provider.test -all'], 30),
      }),
      now,
    );

    expect(snapshot.safe).toBe(true);
    expect(snapshot.provenance[0]?.sourceTtl).toBe(30);
    expect(snapshot.earliestSourceExpiry).toBe('2026-08-13T00:00:30.000Z');
  });

  it('keeps expiry unknown when any required dependency TTL is unavailable', async () => {
    const dns = new FixtureDns({
      'provider.test|TXT': answer(['v=spf1 ip4:192.0.2.0/24 -all'], 600),
      'root.test|TXT': {
        messageBytes: 100,
        status: 'answer',
        values: ['v=spf1 include:provider.test -all'],
      },
    });
    const { snapshot } = await flattenSpf('root.test', dns);

    expect(snapshot.safe).toBe(true);
    expect(snapshot.provenance[0]?.sourceTtl).toBeUndefined();
    expect(snapshot.earliestSourceExpiry).toBeUndefined();
    expect(snapshot.recommendedRecheck).toBeUndefined();
  });

  it('ignores an unknown modifier without blocking a finite snapshot', async () => {
    const { analysis, snapshot } = await flattenSpf(
      'root.test',
      new FixtureDns({
        'root.test|TXT': answer(['v=spf1 vendor=future-semantics ip4:192.0.2.0/24 -all']),
      }),
    );

    expect(snapshot.safe).toBe(true);
    expect(snapshot.networks).toEqual(['192.0.2.0/24']);
    expect(analysis.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'unknown-modifier', severity: 'warning' }),
    );
  });
});
