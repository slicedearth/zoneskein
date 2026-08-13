import { describe, expect, it } from 'vitest';

import { analyseSpf } from './evaluator';
import { flattenSpf } from './flatten';
import type { SpfDnsClient, SpfLookupResult, SpfLookupType } from './types';

function answer(values: readonly string[], ttl = 300, messageBytes = 100): SpfLookupResult {
  return {
    messageBytes,
    status: values.length === 0 ? 'nodata' : 'answer',
    ttl,
    values,
  };
}

class FixtureDns implements SpfDnsClient {
  readonly #answers: Readonly<Record<string, SpfLookupResult>>;

  constructor(answers: Readonly<Record<string, SpfLookupResult>>) {
    this.#answers = answers;
  }

  lookup(domain: string, type: SpfLookupType): Promise<SpfLookupResult> {
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
});
