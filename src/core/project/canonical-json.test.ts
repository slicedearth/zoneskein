import { describe, expect, it } from 'vitest';

import { canonicalJson } from './canonical-json';
import { CHANGE_WORKSPACE_LIMITS } from './limits';

function expectFailure(value: unknown, code: string): void {
  const result = canonicalJson(value);
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error.code).toBe(code);
}

describe('canonical project JSON', () => {
  it('sorts every object key while retaining array order', () => {
    expect(canonicalJson({ z: 1, a: { y: true, b: null }, list: [3, 2, 1] })).toEqual({
      ok: true,
      value: '{"a":{"b":null,"y":true},"list":[3,2,1],"z":1}',
    });
  });

  it('accepts null-prototype data and repeated non-cyclic references', () => {
    const child = { value: 'safe' };
    const root = Object.assign(Object.create(null) as Record<string, unknown>, {
      left: child,
      right: child,
    });

    expect(canonicalJson(root)).toEqual({
      ok: true,
      value: '{"left":{"value":"safe"},"right":{"value":"safe"}}',
    });
  });

  it.each([
    ['floating point', 1.5],
    ['negative zero', -0],
    ['unsafe integer', Number.MAX_SAFE_INTEGER + 1],
    ['positive infinity', Number.POSITIVE_INFINITY],
    ['NaN', Number.NaN],
    ['undefined', undefined],
    ['bigint', 1n],
    ['symbol', Symbol('value')],
    ['function', () => undefined],
  ])('rejects %s values', (_label, value) => {
    expectFailure(value, 'unsupported-value');
  });

  it('rejects cycles, sparse arrays, named array properties, symbols, and non-plain objects', () => {
    const cyclic: { self?: unknown } = {};
    cyclic.self = cyclic;
    const sparse = new Array<unknown>(2);
    sparse[1] = 'present';
    const named = [1] as number[] & { note?: string };
    named.note = 'not JSON';
    const pseudoIndex = [1] as number[] & Record<string, unknown>;
    pseudoIndex['4294967295'] = 2;

    expectFailure(cyclic, 'unsupported-value');
    expectFailure(sparse, 'unsupported-value');
    expectFailure(named, 'unsupported-value');
    expectFailure(pseudoIndex, 'unsupported-value');
    expectFailure({ [Symbol('key')]: true }, 'unsupported-value');
    expectFailure(new Date('2026-08-14T00:00:00.000Z'), 'unsupported-value');
  });

  it('rejects accessor properties without invoking them', () => {
    let calls = 0;
    const value = Object.defineProperty({}, 'secret', {
      enumerable: true,
      get() {
        calls += 1;
        return 'leaked';
      },
    });
    const array = Object.defineProperty([1], '0', {
      enumerable: true,
      get() {
        calls += 1;
        return 2;
      },
    });

    expectFailure(value, 'unsupported-value');
    expectFailure(array, 'unsupported-value');
    expect(calls).toBe(0);
  });

  it('rejects unpaired surrogates in values and keys', () => {
    expectFailure('\ud800', 'unsupported-value');
    expectFailure('\udc00', 'unsupported-value');
    expectFailure({ ['bad\ud800']: true }, 'unsupported-value');
    expect(canonicalJson('pair \ud83d\udc99').ok).toBe(true);
  });

  it('enforces string, key, collection, depth, and total-value bounds', () => {
    expectFailure('x'.repeat(CHANGE_WORKSPACE_LIMITS.jsonStringOctets + 1), 'resource-limit');
    expectFailure(
      { ['x'.repeat(CHANGE_WORKSPACE_LIMITS.jsonKeyOctets + 1)]: true },
      'resource-limit',
    );
    expectFailure(
      Array.from({ length: CHANGE_WORKSPACE_LIMITS.collectionItems + 1 }, () => null),
      'resource-limit',
    );

    let nested: unknown = null;
    for (let index = 0; index <= CHANGE_WORKSPACE_LIMITS.jsonDepth; index += 1) {
      nested = [nested];
    }
    expectFailure(nested, 'resource-limit');

    const manyValues = Array.from({ length: 257 }, () =>
      Array.from({ length: 256 }, () => null),
    );
    expectFailure(manyValues, 'resource-limit');

    const escapedOutput = Array.from({ length: 129 }, () => '\u0000'.repeat(8_192));
    expectFailure(escapedOutput, 'resource-limit');
  });
});
