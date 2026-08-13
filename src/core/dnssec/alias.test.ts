import { describe, expect, it } from 'vitest';

import type { DnsRecord, DnsRecordType } from '../dns/types';
import {
  ancestorDnameTransition,
  classifyServiceBindingRrset,
  DnssecAliasPath,
  exactCnameTransition,
  MAX_DNSSEC_ALIAS_TRANSITIONS,
  type DnssecAliasTransition,
} from './alias';
import { canonicalName } from './verify';

const TYPE_CODES: Readonly<Record<string, number>> = {
  CNAME: 5,
  DNAME: 39,
  HTTPS: 65,
  SVCB: 64,
};

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

function record(
  type: 'CNAME' | 'DNAME' | 'HTTPS' | 'SVCB',
  owner: string,
  rawRdata: Uint8Array,
  overrides: Partial<DnsRecord> = {},
): DnsRecord {
  return {
    canonicalOwnerWire: canonicalName(owner),
    class: 'IN',
    data: 'untrusted.presentation.invalid.',
    owner,
    rawRdata,
    section: 'answer',
    ttl: 300,
    type,
    typeCode: TYPE_CODES[type] ?? 0,
    ...overrides,
  };
}

function nameRecord(
  type: 'CNAME' | 'DNAME',
  owner: string,
  target: string,
  overrides: Partial<DnsRecord> = {},
): DnsRecord {
  return record(type, owner, canonicalName(target), overrides);
}

function parameter(key: number, value: Uint8Array = new Uint8Array()): Uint8Array {
  return join(uint16(key), uint16(value.length), value);
}

function serviceRecord(
  type: 'HTTPS' | 'SVCB',
  owner: string,
  priority: number,
  target: string,
  parameters: Uint8Array = new Uint8Array(),
  overrides: Partial<DnsRecord> = {},
): DnsRecord {
  return record(
    type,
    owner,
    join(uint16(priority), canonicalName(target), parameters),
    overrides,
  );
}

function transition(
  fromName: string,
  targetName: string,
  fromType: DnsRecordType = 'A',
): DnssecAliasTransition {
  return {
    aliasOwner: fromName,
    aliasType: 'CNAME',
    fromName,
    fromType,
    kind: 'alias',
    targetName,
    targetType: fromType,
  };
}

describe('bounded DNSSEC alias path tracking', () => {
  it('canonicalises the initial name and each transition target', () => {
    const started = DnssecAliasPath.start('Start.Example.', 'A');
    expect(started).toMatchObject({
      ok: true,
      value: { position: { name: 'start.example.', transitions: 0, type: 'A' } },
    });
    if (!started.ok) throw new Error('Alias path did not start.');

    expect(started.value.follow(transition('START.EXAMPLE.', 'Target.Example.'))).toEqual({
      ok: true,
      value: { name: 'target.example.', transitions: 1, type: 'A' },
    });
  });

  it('rejects invalid initial names without creating a path', () => {
    expect(DnssecAliasPath.start('https://example.test/path', 'A')).toMatchObject({
      error: { code: 'invalid-name' },
      ok: false,
    });
  });

  it('rejects a transition that does not start at the current position', () => {
    const started = DnssecAliasPath.start('start.test.', 'A');
    if (!started.ok) throw new Error('Alias path did not start.');

    expect(started.value.follow(transition('elsewhere.test.', 'target.test.'))).toMatchObject({
      error: { code: 'wrong-position' },
      ok: false,
    });
    expect(started.value.position).toMatchObject({ name: 'start.test.', transitions: 0 });
  });

  it('rejects forged alias owners and record-type changes', () => {
    const started = DnssecAliasPath.start('start.test.', 'A');
    if (!started.ok) throw new Error('Alias path did not start.');
    expect(
      started.value.follow({
        ...transition('start.test.', 'target.test.'),
        aliasOwner: 'other.test.',
      }),
    ).toMatchObject({ error: { code: 'invalid-owner' }, ok: false });
    expect(
      started.value.follow({
        ...transition('start.test.', 'target.test.'),
        targetType: 'AAAA',
      }),
    ).toMatchObject({ error: { code: 'invalid-record' }, ok: false });
    expect(started.value.position).toMatchObject({ name: 'start.test.', transitions: 0 });
  });

  it('detects a canonical name-and-type loop before changing path state', () => {
    const started = DnssecAliasPath.start('first.test.', 'A');
    if (!started.ok) throw new Error('Alias path did not start.');
    expect(started.value.follow(transition('first.test.', 'SECOND.TEST.')).ok).toBe(true);

    expect(started.value.follow(transition('second.test.', 'First.Test.'))).toMatchObject({
      error: { code: 'loop' },
      ok: false,
    });
    expect(started.value.position).toMatchObject({ name: 'second.test.', transitions: 1 });
  });

  it('allows exactly 64 transitions and rejects the next one without mutation', () => {
    const started = DnssecAliasPath.start('hop-0.test.', 'A');
    if (!started.ok) throw new Error('Alias path did not start.');
    for (let index = 0; index < MAX_DNSSEC_ALIAS_TRANSITIONS; index += 1) {
      expect(
        started.value.follow(
          transition(`hop-${String(index)}.test.`, `hop-${String(index + 1)}.test.`),
        ).ok,
      ).toBe(true);
    }

    expect(started.value.follow(transition('hop-64.test.', 'hop-65.test.'))).toMatchObject({
      error: { code: 'transition-limit' },
      ok: false,
    });
    expect(started.value.position).toEqual({
      name: 'hop-64.test.',
      transitions: MAX_DNSSEC_ALIAS_TRANSITIONS,
      type: 'A',
    });
  });
});

describe('authenticated exact CNAME transition parsing', () => {
  it('uses canonical wire RDATA instead of lossy presentation data', () => {
    const parsed = exactCnameTransition('Alias.Example.', 'AAAA', [
      nameRecord('CNAME', 'alias.example.', 'Target.Example.'),
    ]);

    expect(parsed).toEqual({
      ok: true,
      value: {
        aliasOwner: 'alias.example.',
        aliasType: 'CNAME',
        fromName: 'alias.example.',
        fromType: 'AAAA',
        kind: 'alias',
        targetName: 'target.example.',
        targetType: 'AAAA',
      },
    });
  });

  it('accepts exact duplicate records but rejects divergent targets', () => {
    const one = nameRecord('CNAME', 'alias.test.', 'one.test.');
    expect(exactCnameTransition('alias.test.', 'A', [one, { ...one }])).toMatchObject({
      ok: true,
      value: { targetName: 'one.test.' },
    });
    expect(
      exactCnameTransition('alias.test.', 'A', [
        one,
        nameRecord('CNAME', 'alias.test.', 'two.test.'),
      ]),
    ).toMatchObject({ error: { code: 'ambiguous-alias' }, ok: false });
  });

  it('rejects empty, wrong-owner, wrong-class, and wrong-type-code RRsets', () => {
    const valid = nameRecord('CNAME', 'alias.test.', 'target.test.');
    const fixtures: readonly [readonly DnsRecord[], string][] = [
      [[], 'invalid-record'],
      [[nameRecord('CNAME', 'other.test.', 'target.test.')], 'invalid-owner'],
      [[{ ...valid, class: 'CH' }], 'invalid-record'],
      [[{ ...valid, typeCode: 39 }], 'invalid-record'],
    ];
    for (const [records, code] of fixtures)
      expect(exactCnameTransition('alias.test.', 'A', records)).toMatchObject({
        error: { code },
        ok: false,
      });
  });

  it('rejects owner wire mismatches and malformed target names', () => {
    const wrongOwnerWire = nameRecord('CNAME', 'alias.test.', 'target.test.', {
      canonicalOwnerWire: canonicalName('other.test.'),
    });
    expect(exactCnameTransition('alias.test.', 'A', [wrongOwnerWire])).toMatchObject({
      error: { code: 'invalid-owner' },
      ok: false,
    });

    for (const rawRdata of [
      new Uint8Array([0xc0, 0x0c]),
      new Uint8Array([3, 97, 98]),
      join(canonicalName('target.test.'), new Uint8Array([0])),
    ])
      expect(
        exactCnameTransition('alias.test.', 'A', [record('CNAME', 'alias.test.', rawRdata)]),
      ).toMatchObject({ error: { code: 'invalid-rdata' }, ok: false });
  });
});

describe('authenticated ancestor DNAME transition parsing', () => {
  it('derives the substituted target without requiring a synthesised CNAME', () => {
    const parsed = ancestorDnameTransition('Host.Branch.Example.', 'A', [
      nameRecord('DNAME', 'branch.example.', 'redirect.example.'),
    ]);

    expect(parsed).toMatchObject({
      ok: true,
      value: {
        aliasOwner: 'branch.example.',
        aliasType: 'DNAME',
        fromName: 'host.branch.example.',
        synthesisedCnamePresent: false,
        targetName: 'host.redirect.example.',
      },
    });
  });

  it.each([0, 300])('accepts a matching synthesised CNAME with the RFC 6672 TTL %s', (ttl) => {
    const parsed = ancestorDnameTransition(
      'host.branch.example.',
      'A',
      [nameRecord('DNAME', 'branch.example.', 'redirect.example.')],
      [nameRecord('CNAME', 'host.branch.example.', 'host.redirect.example.', { ttl })],
    );

    expect(parsed).toMatchObject({
      ok: true,
      value: { synthesisedCnamePresent: true, targetName: 'host.redirect.example.' },
    });
  });

  it.each([
    ['altered target', nameRecord('CNAME', 'host.branch.example.', 'forged.example.')],
    ['wrong owner', nameRecord('CNAME', 'other.branch.example.', 'host.redirect.example.')],
    [
      'wrong TTL',
      nameRecord('CNAME', 'host.branch.example.', 'host.redirect.example.', { ttl: 299 }),
    ],
  ] as const)('rejects a synthesised CNAME with an %s', (_, cname) => {
    expect(
      ancestorDnameTransition(
        'host.branch.example.',
        'A',
        [nameRecord('DNAME', 'branch.example.', 'redirect.example.')],
        [cname],
      ),
    ).toMatchObject({ error: { code: 'invalid-synthesis' }, ok: false });
  });

  it.each([
    ['same owner', 'host.branch.example.'],
    ['sibling owner', 'sibling.example.'],
    ['descendant owner', 'child.host.branch.example.'],
  ] as const)('rejects a DNAME at the %s', (_, owner) => {
    expect(
      ancestorDnameTransition('host.branch.example.', 'A', [
        nameRecord('DNAME', owner, 'redirect.example.'),
      ]),
    ).toMatchObject({ error: { code: 'invalid-owner' }, ok: false });
  });

  it('rejects divergent DNAME owners, targets, and TTLs', () => {
    const valid = nameRecord('DNAME', 'branch.example.', 'redirect.example.');
    const fixtures = [
      [valid, nameRecord('DNAME', 'example.', 'redirect.example.')],
      [valid, nameRecord('DNAME', 'branch.example.', 'other.example.')],
      [valid, { ...valid, ttl: 301 }],
    ];
    for (const records of fixtures)
      expect(ancestorDnameTransition('host.branch.example.', 'A', records)).toMatchObject({
        error: { code: 'ambiguous-alias' },
        ok: false,
      });
  });

  it('rejects a DNAME substitution whose valid parts exceed the complete-name bound', () => {
    const prefix = 'p'.repeat(63);
    const targetLabel = 't'.repeat(63);
    const current = `${prefix}.${prefix}.a.`;
    const target = `${targetLabel}.${targetLabel}.`;

    expect(
      ancestorDnameTransition(current, 'A', [nameRecord('DNAME', 'a.', target)]),
    ).toMatchObject({ error: { code: 'invalid-synthesis' }, ok: false });
  });

  it('rejects an empty RRset and malformed DNAME target RDATA', () => {
    expect(ancestorDnameTransition('host.example.', 'A', [])).toMatchObject({
      error: { code: 'invalid-record' },
      ok: false,
    });
    expect(
      ancestorDnameTransition('host.example.', 'A', [
        record('DNAME', 'example.', new Uint8Array([0xc0, 0x0c])),
      ]),
    ).toMatchObject({ error: { code: 'invalid-rdata' }, ok: false });
  });
});

describe('authenticated SVCB-compatible RRset classification', () => {
  it.each(['SVCB', 'HTTPS'] as const)(
    'classifies %s priority zero as an AliasMode transition of the same type',
    (type) => {
      const result = classifyServiceBindingRrset('service.example.', type, [
        serviceRecord(type, 'service.example.', 0, 'target.example.'),
      ]);

      expect(result).toMatchObject({
        ok: true,
        value: {
          ignoredServiceRecords: 0,
          kind: 'alias',
          transition: {
            aliasType: type,
            fromName: 'service.example.',
            fromType: type,
            targetName: 'target.example.',
            targetType: type,
          },
        },
      });
    },
  );

  it('uses wire priority and target values instead of presentation data', () => {
    const value = serviceRecord('HTTPS', 'service.example.', 0, 'target.example.', undefined, {
      data: { priority: 1, target: 'forged.example.' },
    });

    expect(classifyServiceBindingRrset('service.example.', 'HTTPS', [value])).toMatchObject({
      ok: true,
      value: { kind: 'alias', transition: { targetName: 'target.example.' } },
    });
  });

  it('classifies AliasMode root as unavailable and ServiceMode root as the owner', () => {
    expect(
      classifyServiceBindingRrset('service.example.', 'HTTPS', [
        serviceRecord('HTTPS', 'service.example.', 0, '.'),
      ]),
    ).toMatchObject({ ok: true, value: { kind: 'unavailable' } });

    expect(
      classifyServiceBindingRrset('service.example.', 'HTTPS', [
        serviceRecord('HTTPS', 'service.example.', 1, '.'),
      ]),
    ).toMatchObject({
      ok: true,
      value: {
        kind: 'service',
        records: [{ effectiveTargetName: 'service.example.', targetName: '.' }],
      },
    });
  });

  it('ignores ServiceMode records when one unambiguous AliasMode target exists', () => {
    const result = classifyServiceBindingRrset('service.example.', 'SVCB', [
      serviceRecord('SVCB', 'service.example.', 4, 'service-one.example.'),
      serviceRecord('SVCB', 'service.example.', 0, 'alias.example.'),
      serviceRecord('SVCB', 'service.example.', 8, 'service-two.example.'),
    ]);

    expect(result).toMatchObject({
      ok: true,
      value: {
        ignoredServiceRecords: 2,
        kind: 'alias',
        records: [{ priority: 0, targetName: 'alias.example.' }],
      },
    });
  });

  it('accepts duplicate AliasMode targets as one transition', () => {
    const one = serviceRecord('SVCB', 'service.example.', 0, 'one.example.');
    expect(
      classifyServiceBindingRrset('service.example.', 'SVCB', [one, { ...one }]),
    ).toMatchObject({
      ok: true,
      value: { kind: 'alias', transition: { targetName: 'one.example.' } },
    });
  });

  it.each(['SVCB', 'HTTPS'] as const)(
    'retains divergent %s AliasMode targets as deterministic authenticated choices',
    (type) => {
      const one = serviceRecord(type, 'service.example.', 0, 'one.example.');
      const two = serviceRecord(type, 'service.example.', 0, 'two.example.');

      for (const records of [
        [one, two],
        [two, one],
      ])
        expect(classifyServiceBindingRrset('service.example.', type, records)).toMatchObject({
          ok: true,
          value: {
            ignoredServiceRecords: 0,
            kind: 'alias-choices',
            targetNames: ['one.example.', 'two.example.'],
          },
        });
    },
  );

  it('accepts structurally valid ignored AliasMode parameters', () => {
    const parameters = join(
      parameter(1, new Uint8Array([2, 104, 50])),
      parameter(3, uint16(443)),
    );
    expect(
      classifyServiceBindingRrset('service.example.', 'HTTPS', [
        serviceRecord('HTTPS', 'service.example.', 0, 'target.example.', parameters),
      ]),
    ).toMatchObject({ ok: true, value: { kind: 'alias' } });
  });

  it.each([
    ['truncated priority', new Uint8Array([0])],
    ['compressed target', new Uint8Array([0, 0, 0xc0, 0x0c])],
    [
      'truncated parameter',
      join(uint16(1), canonicalName('.'), new Uint8Array([0, 3, 0, 2, 1])),
    ],
    [
      'duplicate parameter key',
      join(uint16(1), canonicalName('.'), parameter(3), parameter(3)),
    ],
    [
      'descending parameter keys',
      join(uint16(1), canonicalName('.'), parameter(4), parameter(3)),
    ],
  ] as const)('rejects %s wire RDATA', (_, rawRdata) => {
    expect(
      classifyServiceBindingRrset('service.example.', 'SVCB', [
        record('SVCB', 'service.example.', rawRdata),
      ]),
    ).toMatchObject({ error: { code: 'invalid-rdata' }, ok: false });
  });

  it('rejects empty, wrong-owner, wrong-class, and wrong-type RRsets', () => {
    const valid = serviceRecord('SVCB', 'service.example.', 1, '.');
    const fixtures: readonly [readonly DnsRecord[], string][] = [
      [[], 'invalid-record'],
      [[serviceRecord('SVCB', 'other.example.', 1, '.')], 'invalid-owner'],
      [[{ ...valid, class: 'CH' }], 'invalid-record'],
      [[{ ...valid, type: 'HTTPS', typeCode: 65 }], 'invalid-record'],
    ];
    for (const [records, code] of fixtures)
      expect(classifyServiceBindingRrset('service.example.', 'SVCB', records)).toMatchObject({
        error: { code },
        ok: false,
      });
  });

  it('rejects an AliasMode self-reference when the path applies it', () => {
    const classified = classifyServiceBindingRrset('service.example.', 'HTTPS', [
      serviceRecord('HTTPS', 'service.example.', 0, 'service.example.'),
    ]);
    const path = DnssecAliasPath.start('service.example.', 'HTTPS');
    if (!classified.ok || classified.value.kind !== 'alias' || !path.ok)
      throw new Error('Alias fixture did not classify.');

    expect(path.value.follow(classified.value.transition)).toMatchObject({
      error: { code: 'loop' },
      ok: false,
    });
  });
});
