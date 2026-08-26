import { describe, expect, it } from 'vitest';

import { parseMailFromIdentity, parseSenderClientIp, parseSenderDomain } from './sender-input';

describe('MAIL FROM sender input', () => {
  it('accepts bare and bracketed mailboxes', () => {
    expect(parseMailFromIdentity('sender@Example.COM')).toEqual({
      ok: true,
      value: { domain: 'example.com', localPart: 'sender', nullReversePath: false },
    });
    expect(parseMailFromIdentity('<sender@example.com>')).toEqual({
      ok: true,
      value: { domain: 'example.com', localPart: 'sender', nullReversePath: false },
    });
    expect(parseMailFromIdentity('<"sender name@team"@example.com>')).toEqual({
      ok: true,
      value: {
        domain: 'example.com',
        localPart: '"sender name@team"',
        nullReversePath: false,
      },
    });
  });

  it('maps empty input and <> to the null reverse path', () => {
    expect(parseMailFromIdentity('')).toEqual({
      ok: true,
      value: { domain: '', localPart: '', nullReversePath: true },
    });
    expect(parseMailFromIdentity('<>')).toEqual({
      ok: true,
      value: { domain: '', localPart: '', nullReversePath: true },
    });
  });

  it('rejects malformed mailbox boundaries and domains', () => {
    expect(parseMailFromIdentity('<sender@example.com')).toMatchObject({ ok: false });
    expect(parseMailFromIdentity('sender@localhost')).toMatchObject({ ok: false });
    expect(parseMailFromIdentity('@example.com')).toMatchObject({ ok: false });
    expect(parseMailFromIdentity('two@@example.com')).toMatchObject({ ok: false });
    expect(parseMailFromIdentity('two dots@example.com')).toMatchObject({ ok: false });
    expect(parseMailFromIdentity('.leading@example.com')).toMatchObject({ ok: false });
    expect(parseMailFromIdentity('trailing.@example.com')).toMatchObject({ ok: false });
    expect(parseMailFromIdentity('"unterminated@example.com')).toMatchObject({ ok: false });
  });

  it('enforces the RFC 5321 64-octet local-part limit', () => {
    expect(parseMailFromIdentity(`${'a'.repeat(64)}@example.com`)).toMatchObject({ ok: true });
    const overlong = parseMailFromIdentity(`${'a'.repeat(65)}@example.com`);
    expect(overlong.ok).toBe(false);
    if (overlong.ok) throw new Error('Expected an overlong local-part rejection.');
    expect(overlong.error).toMatch(/64 octets/iu);
  });

  it('normalises valid sender fields and rejects invalid fields locally', () => {
    expect(parseSenderClientIp(' 2001:db8::1 ')).toMatchObject({
      ok: true,
      value: '2001:db8::1',
    });
    expect(parseSenderClientIp('not-an-address')).toMatchObject({ ok: false });
    expect(parseSenderClientIp('127.1')).toMatchObject({ ok: false });
    expect(parseSenderClientIp('010.0.0.1')).toMatchObject({ ok: false });
    expect(parseSenderClientIp('fe80::1%eth0')).toMatchObject({ ok: false });
    expect(parseSenderDomain('Mail.Example.COM', 'HELO/EHLO')).toEqual({
      ok: true,
      value: 'mail.example.com',
    });
    expect(parseSenderDomain('localhost', 'receiver')).toMatchObject({ ok: false });
  });
});
