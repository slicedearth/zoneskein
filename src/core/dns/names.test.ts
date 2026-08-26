import { describe, expect, it } from 'vitest';

import { validateDnsName } from './names';

describe('DNS name validation', () => {
  it('normalises root dots and IDNA names', () => {
    expect(validateDnsName('.')).toMatchObject({
      ok: true,
      value: { absolute: '.', ascii: '', display: '.', hadRootDot: true },
    });
    expect(validateDnsName('Example.COM.')).toMatchObject({
      ok: true,
      value: { absolute: 'example.com.', ascii: 'example.com', hadRootDot: true },
    });
    expect(validateDnsName('bücher.example')).toMatchObject({
      ok: true,
      value: { absolute: 'xn--bcher-kva.example.', unicode: true },
    });
  });

  it.each([
    ['https://example.com/', 'url-components'],
    ['https://user@example.com', 'url-components'],
    ['https://example.com/path', 'url-components'],
    ['example.com?ignored', 'invalid-hostname'],
    ['example.com#ignored', 'invalid-hostname'],
    ['example%2ecom', 'invalid-hostname'],
    ['example.com:443', 'invalid-hostname'],
    ['*.example.com', 'wildcard'],
    ['a..example', 'invalid-label'],
    [`${'a'.repeat(64)}.example`, 'label-too-long'],
    [`${`${'a'.repeat(63)}.`.repeat(4)}example`, 'name-too-long'],
  ])('rejects %s with %s', (input, code) => {
    expect(validateDnsName(input)).toMatchObject({ ok: false, error: { code } });
  });
});
