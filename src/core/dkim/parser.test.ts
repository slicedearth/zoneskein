import { describe, expect, it } from 'vitest';

import { inspectDkimKey, parseDkimKeyRecord, validateDkimSelector } from './parser';

describe('DKIM key record inspection', () => {
  it('parses and imports an Ed25519 key', async () => {
    const key = parseDkimKeyRecord(
      `v=DKIM1; k=ed25519; p=${btoa(String.fromCharCode(...new Uint8Array(32).fill(7)))}`,
    );
    expect(key.valid).toBe(true);
    await expect(inspectDkimKey(key)).resolves.toMatchObject({ bits: 256, status: 'valid' });
  });

  it('identifies revoked and malformed keys', async () => {
    const revoked = parseDkimKeyRecord('v=DKIM1; p=');
    const malformed = parseDkimKeyRecord('v=DKIM2; p=***');
    await expect(inspectDkimKey(revoked)).resolves.toMatchObject({ status: 'revoked' });
    expect(malformed.valid).toBe(false);
  });

  it.each([
    [
      'SubjectPublicKeyInfo',
      'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDmoQmuysYdunKx3ckNWLv8u8OJhpm9xkOFb9FV+FW9IqphwPZLts/+QXeCxiF27UylP8Bw3iwu07lVeKY9HmMlpCfn0hum80G0z30Y+QFyohnDJvSddfa2iVTjsox/tRcvt1opns5WGzfxRb8CxOANGPWCaVDNVuK2EayVaLggJQIDAQAB',
    ],
    [
      'PKCS #1 RSAPublicKey',
      'MIGJAoGBAOahCa7Kxh26crHdyQ1Yu/y7w4mGmb3GQ4Vv0VX4Vb0iqmHA9ku2z/5Bd4LGIXbtTKU/wHDeLC7TuVV4pj0eYyWkJ+fSG6bzQbTPfRj5AXKiGcMm9J119raJVOOyjH+1Fy+3WimezlYbN/FFvwLE4A0Y9YJpUM1W4rYRrJVouCAlAgMBAAE=',
    ],
  ])('imports RSA %s key data from p=', async (_label, publicKey) => {
    await expect(
      inspectDkimKey(parseDkimKeyRecord(`v=DKIM1; k=rsa; p=${publicKey}`)),
    ).resolves.toMatchObject({ bits: 1024, status: 'weak' });
  });

  it('validates selectors locally', () => {
    expect(validateDkimSelector('selector-2026')).toBeNull();
    expect(validateDkimSelector('march2005.reykjavik')).toBeNull();
    expect(validateDkimSelector('bad..selector')).not.toBeNull();
    expect(validateDkimSelector('_private')).not.toBeNull();
    expect(validateDkimSelector('private_key')).not.toBeNull();
    expect(validateDkimSelector(`${'a'.repeat(64)}.selector`)).not.toBeNull();
  });

  it('keeps tag names case-sensitive and enforces the version position and value', () => {
    expect(parseDkimKeyRecord('v=dkim1; p=AAAA').valid).toBe(false);
    expect(parseDkimKeyRecord('p=AAAA; v=DKIM1').valid).toBe(false);
    expect(parseDkimKeyRecord('V=DKIM1; p=AAAA')).toMatchObject({
      tags: { V: 'DKIM1', p: 'AAAA' },
      valid: true,
    });
  });

  it('treats an absent h as all hashes but rejects empty lists and hidden whitespace', () => {
    expect(parseDkimKeyRecord('v=DKIM1; p=AAAA')).toMatchObject({
      hashAlgorithms: ['*'],
      valid: true,
    });
    expect(parseDkimKeyRecord('v=DKIM1; h=; p=AAAA').valid).toBe(false);
    expect(parseDkimKeyRecord('v=D KIM1; p=AAAA').valid).toBe(false);
    expect(parseDkimKeyRecord('v=DKIM1; k=r sa; p=AAAA').valid).toBe(false);
    expect(parseDkimKeyRecord('v=DKIM1; h=sha256 : future; p=AAAA')).toMatchObject({
      hashAlgorithms: ['sha256', 'future'],
      valid: true,
    });
  });

  it('accepts the wildcard within a service-type list', () => {
    expect(parseDkimKeyRecord('v=DKIM1; s=email : *; p=AAAA')).toMatchObject({
      services: ['email', '*'],
      valid: true,
    });
  });

  it.each([
    ['t= y', ['y'], true],
    ['t= s', ['s'], false],
    ['t= y : s', ['y', 's'], true],
  ] as const)('normalises selector flags from %s', (tag, selectorFlags, testing) => {
    expect(parseDkimKeyRecord(`v=DKIM1; p=AAAA; ${tag}`)).toMatchObject({
      selectorFlags: [...selectorFlags],
      testing,
      valid: true,
    });
  });
});
