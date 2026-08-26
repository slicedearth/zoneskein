import { describe, expect, it } from 'vitest';

import {
  canonicalMasterName,
  masterNameEquals,
  masterNameIsAtOrBelow,
  type CanonicalMasterName,
} from './master-name';

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function requiredName(value: CanonicalMasterName | null): CanonicalMasterName {
  expect(value).not.toBeNull();
  if (value === null) throw new Error('The fixture master name was not canonical.');
  return value;
}

describe('raw-aware master-file names', () => {
  it('keeps escaped dots inside a label and treats decimal escapes identically', () => {
    const structural = canonicalMasterName('foo.bar.example.');
    const escaped = canonicalMasterName(String.raw`foo\.bar.example.`);
    const decimal = canonicalMasterName(String.raw`foo\046bar.example.`);

    expect(structural?.labels.map((label) => label.length)).toEqual([3, 3, 7]);
    expect(escaped?.labels.map((label) => label.length)).toEqual([7, 7]);
    expect(hex(escaped?.wire ?? new Uint8Array())).toBe('07666f6f2e626172076578616d706c6500');
    expect(masterNameEquals(requiredName(decimal), requiredName(escaped))).toBe(true);
    expect(masterNameEquals(requiredName(structural), requiredName(escaped))).toBe(false);
  });

  it('resolves relative names against the active origin and preserves canonical octets', () => {
    const origin = canonicalMasterName('Example.');
    const relative = canonicalMasterName('Child', origin ?? undefined);
    const escapedUppercase = canonicalMasterName(String.raw`\067hild.example.`);

    expect(origin?.absolute).toBe('example.');
    expect(relative?.absolute).toBe('child.example.');
    expect(escapedUppercase?.absolute).toBe('child.example.');
    expect(masterNameEquals(requiredName(relative), requiredName(escapedUppercase))).toBe(true);
    expect(masterNameIsAtOrBelow(requiredName(relative), requiredName(origin))).toBe(true);
  });

  it('rejects malformed, overlong, or originless relative names', () => {
    expect(canonicalMasterName('relative')).toBeNull();
    expect(canonicalMasterName('two..dots.')).toBeNull();
    expect(canonicalMasterName(`${'a'.repeat(64)}.`)).toBeNull();
    expect(canonicalMasterName('trailing\\')).toBeNull();
  });
});
