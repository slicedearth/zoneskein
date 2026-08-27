import { describe, expect, it } from 'vitest';

import { decodeEchConfigList } from './svcb';

function uint16(value: number): readonly number[] {
  return [value >>> 8, value & 0xff];
}

function fixture(): string {
  const name = [...new TextEncoder().encode('public.example')];
  const content = [
    ...uint16(0x20),
    ...uint16(2),
    0xaa,
    0xbb,
    ...uint16(4),
    ...uint16(1),
    ...uint16(1),
    64,
    name.length,
    ...name,
    ...uint16(0),
  ];
  const config = [...uint16(0xfe0d), ...uint16(content.length), ...content];
  const list = [...uint16(config.length), ...config];
  return btoa(String.fromCharCode(...list));
}

describe('ECHConfigList decoding', () => {
  it('decodes supported ECH configuration contents', () => {
    const report = decodeEchConfigList(fixture());
    expect(report.status).toBe('valid');
    expect(report.configurations[0]).toMatchObject({
      cipherSuites: [{ aeadId: 1, kdfId: 1 }],
      kemId: 32,
      publicKeyOctets: 2,
      publicName: 'public.example',
      supportedVersion: true,
    });
  });

  it('rejects inconsistent outer lengths', () => {
    expect(decodeEchConfigList('AAEA').status).toBe('invalid');
  });
});
