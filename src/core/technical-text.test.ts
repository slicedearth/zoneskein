import { marked } from 'marked';
import { describe, expect, it } from 'vitest';

import {
  escapeTechnicalText,
  hasUnpairedSurrogate,
  hasUnsafeTechnicalText,
  markdownTableLiteral,
  projectTechnicalBytes,
  projectedTechnicalText,
  stringifyTechnicalEvidence,
  utf8Base64Evidence,
} from './technical-text';

describe('technical evidence text', () => {
  it('visibly and injectively escapes control, direction, ignorable, and replacement characters', () => {
    const controls =
      '\u0000\t\n\r\u007f\u0085\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u2028\u2029\u200b\u2060\ufeff\ufffd';
    const escaped = escapeTechnicalText('literal \\u{202E} ' + controls);

    expect(hasUnsafeTechnicalText(controls)).toBe(true);
    expect(hasUnsafeTechnicalText('Café 🌏')).toBe(false);
    expect(escaped).toContain('literal \\\\u{202E}');
    expect(escaped).toContain('\\u{202E}');
    expect(escaped).toContain('\\u{2066}');
    expect(escaped).toContain('\\u{200B}');
    expect(escaped).toContain('\\u{FFFD}');
    for (const control of controls) expect(escaped).not.toContain(control);
  });

  it('keeps international UTF-8 readable and makes invalid byte sequences distinguishable', () => {
    const readable = projectTechnicalBytes(new TextEncoder().encode('München 🌏'));
    const firstInvalid = projectTechnicalBytes(Uint8Array.from([0x66, 0x80]));
    const secondInvalid = projectTechnicalBytes(Uint8Array.from([0x66, 0x81]));

    expect(readable).toMatchObject({ display: 'München 🌏', encoding: 'utf-8' });
    expect(firstInvalid).toMatchObject({ display: '\\x66\\x80', encoding: 'binary' });
    expect(secondInvalid.display).toBe('\\x66\\x81');
    expect(firstInvalid.rawBase64).not.toBe(secondInvalid.rawBase64);
  });

  it('keeps hostile CommonMark and GFM constructs as literal rendered text', () => {
    const tick = String.fromCharCode(96);
    const payloads = [
      '![pixel](https://attacker.invalid/pixel)',
      '[deceptive](https://attacker.invalid)',
      '<https://attacker.invalid>',
      '<img src=x onerror=alert(1)>',
      '**emphasis** and ' + tick + 'code' + tick,
      '# heading\n> quote\n- list',
      'bare@example.invalid and https://attacker.invalid',
      'pipe | backslash \\ and ' + tick.repeat(3) + ' fence',
    ];
    const document = [
      '| Evidence |',
      '| --- |',
      ...payloads.map((payload) => '| ' + markdownTableLiteral(payload) + ' |'),
    ].join('\n');
    const html = marked.parse(document, { async: false, gfm: true });
    if (typeof html !== 'string')
      throw new Error('Synchronous Markdown parsing returned a promise.');
    const rendered = window.document.createElement('div');
    rendered.innerHTML = html;

    expect(html).not.toMatch(/<(?:a|img|blockquote|h[1-6]|pre)\b/iu);
    expect(html).not.toContain('<em>');
    expect(html).not.toContain('<strong>');
    expect(rendered.querySelectorAll('td > code')).toHaveLength(payloads.length);
    expect(rendered.textContent).toContain('![pixel](https://attacker.invalid/pixel)');
    expect(rendered.textContent).toContain('<img src=x onerror=alert(1)>');
  });

  it('serialises controls visibly and byte arrays with explicit provenance', () => {
    const parsed = JSON.parse(
      stringifyTechnicalEvidence({
        bytes: Uint8Array.from([0x66, 0x80]),
        literal: '\\u{202E}',
        projected: projectedTechnicalText('actual \\u{202E}'),
        unsafe: '\u202e',
      }),
    ) as Record<string, unknown>;

    expect(parsed).toEqual({
      bytes: { encoding: 'base64', octets: 2, value: 'ZoA=' },
      literal: '\\\\u{202E}',
      projected: 'actual \\u{202E}',
      unsafe: '\\u{202E}',
    });
    expect(parsed['literal']).not.toBe(parsed['unsafe']);
    expect(() => projectedTechnicalText(String.fromCodePoint(0x202e))).toThrow(
      /must not contain unsafe/iu,
    );
  });

  it('retains canonical UTF-8 text octets as explicit Base64 evidence', () => {
    const source = 'München \u202e';
    const evidence = utf8Base64Evidence(source);
    const bytes = Uint8Array.from(atob(evidence.value), (character) => character.charCodeAt(0));

    expect(evidence).toMatchObject({ encoding: 'base64', octets: bytes.length });
    expect(new TextDecoder().decode(bytes)).toBe(source);
    expect(hasUnpairedSurrogate('paired \ud83c\udf0f')).toBe(false);
    expect(hasUnpairedSurrogate(String.fromCharCode(0xd800))).toBe(true);
    expect(() => utf8Base64Evidence(String.fromCharCode(0xd800))).toThrow(
      /unpaired UTF-16 surrogate/iu,
    );
  });
});
