import { describe, expect, it } from 'vitest';

import { decodeBase64, decodeEchConfigList, isValidEchConfigList } from './svcb';
import { RFC_9934_ECH_CONFIG } from '../../test/ech-fixture';

function uint16(value: number): readonly number[] {
  return [value >>> 8, value & 0xff];
}
function encode(bytes: readonly number[]): string {
  return btoa(String.fromCharCode(...bytes));
}
const published = [...(decodeBase64(RFC_9934_ECH_CONFIG) ?? [])];
const content = published.slice(6);
function config(body: readonly number[], version = 0xfe0d): readonly number[] {
  return [...uint16(version), ...uint16(body.length), ...body];
}
function list(configs: readonly (readonly number[])[]): string {
  const bytes = configs.flat();
  return encode([...uint16(bytes.length), ...bytes]);
}

describe('ECHConfigList decoding', () => {
  it('decodes the independent public RFC 9934 configuration', () => {
    const report = decodeEchConfigList(RFC_9934_ECH_CONFIG);
    expect(report.status).toBe('valid');
    expect(report.configurations[0]).toMatchObject({
      configId: 231,
      cipherSuites: [{ aeadId: 1, kdfId: 1 }],
      kemId: 32,
      publicKeyOctets: 32,
      publicName: 'example.com',
      supportedVersion: true,
      supportedKem: true,
    });
    expect(isValidEchConfigList(RFC_9934_ECH_CONFIG)).toBe(true);
  });

  it('rejects truncation at every supported-content boundary, including repaired outer lengths', () => {
    for (let end = 0; end < content.length; end += 1) {
      expect(
        decodeEchConfigList(list([config(content.slice(0, end))])).status,
        'content length ' + String(end),
      ).toBe('invalid');
    }
    for (let end = 0; end < published.length; end += 1)
      expect(decodeEchConfigList(encode(published.slice(0, end))).status).toBe('invalid');
  });

  it.each([0, 2, 31, 33])('rejects a %s-byte key for the known X25519 KEM', (length) => {
    const body = [
      ...content.slice(0, 3),
      ...uint16(length),
      ...Array<number>(length).fill(1),
      ...content.slice(37),
    ];
    expect(decodeEchConfigList(list([config(body)])).status).toBe('invalid');
  });

  it('preserves unknown versions and KEMs without claiming supported validation', () => {
    const unknownKem = [...content];
    unknownKem[1] = 0xff;
    unknownKem[2] = 0xff;
    expect(decodeEchConfigList(list([config([], 0xfafa)])).status).toBe('unsupported');
    expect(decodeEchConfigList(list([config(unknownKem)])).status).toBe('unsupported');
    const mixed = decodeEchConfigList(list([config([], 0xfafa), published.slice(2)]));
    expect(mixed.status).toBe('valid');
    expect(mixed.configurations).toHaveLength(2);
    expect(mixed.configurations[1]?.configId).toBe(231);
    expect(
      decodeEchConfigList(list(Array.from({ length: 33 }, () => config([], 0xfafa)))).status,
    ).toBe('invalid');
  });

  it('rejects malformed inner extension vectors and the previous shifted layout', () => {
    expect(decodeEchConfigList('ACL+DQAeACAAAqq7AAQAAQABQA5wdWJsaWMuZXhhbXBsZQAA').status).toBe(
      'invalid',
    );
    const malformed = [...content.slice(0, -2), ...uint16(4), 0, 1, 0, 8];
    expect(decodeEchConfigList(list([config(malformed)])).status).toBe('invalid');
  });
});
