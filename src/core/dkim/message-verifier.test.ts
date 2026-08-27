import { describe, expect, it, vi } from 'vitest';

import {
  canonicaliseDkimBody,
  canonicaliseDkimHeader,
  dkimBodyHash,
  parseDkimMessage,
  parseDkimSignature,
  verifyDkimMessage,
} from './message-verifier';

const RFC_8463_MESSAGE = `DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=brisbane; t=1528637909; h=from : to :
 subject : date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus
 Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game.  Are you hungry yet?

Joe.
`;

const RFC_8463_KEY = 'v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=';

const FIXED_RSA_MESSAGE = `DKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=fixed; h=from:subject; bh=CpQrkuJerbSLbJb+3wem7Ybf6UdzqoOp6epFKC3N3qY=; b=5DtLabjQDiCWJaEa8aIKqsBqtUznIzdMv1DToJn35vKlXiVELM5jATNqRGXyyVvEwIN52ZNQ3Z7k9iSsTbFHn9ZacEbgyM2uN57BFfbXjDr/gC1NJLWNxgc788qrFeD5wDwLrKM2Q2+UADJrwOfzfxw14Qw+oPfZ7kNgBaXWBa4=
From: vector@example.test
Subject: fixed RSA vector

fixed vector body
`;

const FIXED_RSA_SPKI =
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDmoQmuysYdunKx3ckNWLv8u8OJhpm9xkOFb9FV+FW9IqphwPZLts/+QXeCxiF27UylP8Bw3iwu07lVeKY9HmMlpCfn0hum80G0z30Y+QFyohnDJvSddfa2iVTjsox/tRcvt1opns5WGzfxRb8CxOANGPWCaVDNVuK2EayVaLggJQIDAQAB';
const FIXED_RSA_PKCS1 =
  'MIGJAoGBAOahCa7Kxh26crHdyQ1Yu/y7w4mGmb3GQ4Vv0VX4Vb0iqmHA9ku2z/5Bd4LGIXbtTKU/wHDeLC7TuVV4pj0eYyWkJ+fSG6bzQbTPfRj5AXKiGcMm9J119raJVOOyjH+1Fy+3WimezlYbN/FFvwLE4A0Y9YJpUM1W4rYRrJVouCAlAgMBAAE=';

function encoded(bytes: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

describe('DKIM message verification', () => {
  it('normalises message line endings and implements both canonicalisation modes', () => {
    const message = parseDkimMessage('X-Test:\t one\n\t two  \n\n body \t\n\n');
    expect(message.headers).toHaveLength(1);
    const header = message.headers[0];
    if (header === undefined) throw new Error('Expected the fixture header.');
    expect(canonicaliseDkimHeader(header, 'relaxed')).toBe('x-test:one two\r\n');
    expect(canonicaliseDkimBody(message.body, 'relaxed')).toBe(' body\r\n');
    expect(canonicaliseDkimBody('', 'simple')).toBe('\r\n');
    expect(canonicaliseDkimBody('', 'relaxed')).toBe('');
    expect(
      canonicaliseDkimHeader({ name: 'X', raw: 'X:\u00a0', value: '\u00a0' }, 'relaxed'),
    ).toBe('x:\u00a0\r\n');
  });

  it('matches the RFC 6376 SHA-256 fixtures for an empty body', async () => {
    await expect(dkimBodyHash('', 'simple')).resolves.toBe(
      'frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=',
    );
    await expect(dkimBodyHash('', 'relaxed')).resolves.toBe(
      '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=',
    );
    await expect(dkimBodyHash('\r\n\r\n', 'relaxed')).resolves.toBe(
      '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=',
    );
  });

  it('preserves uploaded message octets and reports reconstructed line endings', () => {
    const uploaded = parseDkimMessage(
      new Uint8Array([0x46, 0x72, 0x6f, 0x6d, 0x3a, 0x20, 0xff, 0x0d, 0x0a, 0x0d, 0x0a, 0xff]),
    );
    const pasted = parseDkimMessage('From: tést@example.test\n\nbody');

    expect(uploaded).toMatchObject({ lineEndingsNormalised: false, sourceOctets: 12 });
    expect(uploaded.headers[0]?.value.charCodeAt(1)).toBe(0xff);
    expect(pasted.sourceOctets).toBe(
      new TextEncoder().encode('From: tést@example.test\n\nbody').length,
    );
    expect(pasted.lineEndingsNormalised).toBe(true);
  });

  it('verifies the independently published RFC 8463 message with a key omitting h', async () => {
    const results = await verifyDkimMessage(
      RFC_8463_MESSAGE,
      (name) =>
        Promise.resolve({
          records: name === 'brisbane._domainkey.football.example.com' ? [RFC_8463_KEY] : [],
          temporary: false,
        }),
      new Date('2018-06-10T14:58:29.000Z'),
    );
    expect(results).toEqual([
      expect.objectContaining({
        bodyHashMatches: true,
        domain: 'football.example.com',
        selector: 'brisbane',
        status: 'pass',
      }),
    ]);
  });

  it.each(['t= y', 't= y : s'])(
    'recognises a whitespace-padded testing flag in %s',
    async (tag) => {
      const results = await verifyDkimMessage(
        RFC_8463_MESSAGE,
        () => Promise.resolve({ records: [`${RFC_8463_KEY}; ${tag}`], temporary: false }),
        new Date('2018-06-10T14:58:29.000Z'),
      );

      expect(results[0]?.status).toBe('pass');
      expect(results[0]?.keyTesting).toBe(true);
    },
  );

  it.each([
    ['t= s', false],
    ['t= y : s', true],
  ])('enforces a whitespace-padded strict AUID flag in %s', async (tag, testing) => {
    const bodyHash = await dkimBodyHash('body', 'simple');
    const message = `DKIM-Signature: v=1; a=ed25519-sha256; d=example.test; s=key; i=@sub.example.test; h=from; bh=${bodyHash}; b=AAAA\r\nFrom: sender@example.test\r\n\r\nbody`;
    const results = await verifyDkimMessage(message, () =>
      Promise.resolve({ records: [`${RFC_8463_KEY}; ${tag}`], temporary: false }),
    );

    expect(results[0]?.status).toBe('permerror');
    expect(results[0]?.reason).toMatch(/strict AUID domain/iu);
    expect(results[0]?.keyTesting === true).toBe(testing);
  });

  it.each([
    ['SubjectPublicKeyInfo', FIXED_RSA_SPKI],
    ['PKCS #1 RSAPublicKey', FIXED_RSA_PKCS1],
  ])('verifies a fixed independent RSA-SHA256 vector with %s p= data', async (_label, key) => {
    const results = await verifyDkimMessage(FIXED_RSA_MESSAGE, () =>
      Promise.resolve({ records: [`v=DKIM1; k=rsa; p=${key}`], temporary: false }),
    );

    expect(results).toEqual([
      expect.objectContaining({ bodyHashMatches: true, keyBits: 1024, status: 'pass' }),
    ]);
  });

  it('fails a tampered body before the DNS key can be accepted', async () => {
    let queried = false;
    const results = await verifyDkimMessage(
      RFC_8463_MESSAGE.replace('We lost the game.', 'We won the game.'),
      () => {
        queried = true;
        return Promise.resolve({ records: [RFC_8463_KEY], temporary: false });
      },
    );
    expect(results[0]).toMatchObject({ bodyHashMatches: false, status: 'fail' });
    expect(queried).toBe(false);
  });

  it('distinguishes malformed, unsupported, and temporary outcomes', async () => {
    const missingHeader = parseDkimMessage('DKIM-Signature: v=1; a=rsa-sha256\r\n\r\nbody')
      .headers[0];
    if (missingHeader === undefined) throw new Error('Expected the fixture signature.');
    const missing = parseDkimSignature(missingHeader);
    expect(missing.valid).toBe(false);

    const bodyHash = await dkimBodyHash('body', 'simple');
    const unsupported = `DKIM-Signature: v=1; a=future-sha256; d=example.test; s=key; h=from; bh=${bodyHash}; b=AAAA\r\nFrom: a@example.test\r\n\r\nbody`;
    await expect(
      verifyDkimMessage(unsupported, () => Promise.resolve({ records: [], temporary: false })),
    ).resolves.toEqual([expect.objectContaining({ status: 'unsupported' })]);

    const temporary = unsupported.replace('future-sha256', 'ed25519-sha256');
    await expect(
      verifyDkimMessage(temporary, () =>
        Promise.resolve({
          error: 'DNS timed out.',
          records: [],
          temporary: true,
        }),
      ),
    ).resolves.toEqual([expect.objectContaining({ status: 'temperror' })]);
  });

  it('requires From to be signed and rejects timestamps too far in the future', async () => {
    const bodyHash = await dkimBodyHash('body', 'simple');
    const unsignedFrom = `DKIM-Signature: v=1; a=ed25519-sha256; d=example.test; s=key; h=subject; bh=${bodyHash}; b=AAAA\r\nFrom: a@example.test\r\nSubject: test\r\n\r\nbody`;
    const future = `DKIM-Signature: v=1; a=ed25519-sha256; d=example.test; s=key; t=2000000000; h=from; bh=${bodyHash}; b=AAAA\r\nFrom: a@example.test\r\n\r\nbody`;

    const unsignedResult = await verifyDkimMessage(unsignedFrom, () =>
      Promise.resolve({ records: [RFC_8463_KEY], temporary: false }),
    );
    const futureResult = await verifyDkimMessage(
      future,
      () => Promise.resolve({ records: [RFC_8463_KEY], temporary: false }),
      new Date('2026-08-13T00:00:00.000Z'),
    );

    expect(unsignedResult[0]?.status).toBe('permerror');
    expect(unsignedResult[0]?.reason).toMatch(/sign the From/iu);
    expect(futureResult[0]?.status).toBe('fail');
    expect(futureResult[0]?.reason).toMatch(/future/iu);
  });

  it('rejects malformed Base64, malformed AUIDs, and case-mismatched required tags', () => {
    const base = parseDkimMessage(
      'DKIM-Signature: v=1; a=ed25519-sha256; d=example.test; s=key; h=from; bh=***; b=AAAA\r\nFrom: a@example.test\r\n\r\nbody',
    ).headers[0];
    const malformedIdentity = parseDkimMessage(
      'DKIM-Signature: v=1; a=ed25519-sha256; d=example.test; s=key; i=a@b@example.test; h=from; bh=AAAA; b=AAAA\r\nFrom: a@example.test\r\n\r\nbody',
    ).headers[0];
    const uppercaseVersion = parseDkimMessage(
      'DKIM-Signature: V=1; a=ed25519-sha256; d=example.test; s=key; h=from; bh=AAAA; b=AAAA\r\nFrom: a@example.test\r\n\r\nbody',
    ).headers[0];
    if (base === undefined || malformedIdentity === undefined || uppercaseVersion === undefined)
      throw new Error('Expected signature fixtures.');

    expect(parseDkimSignature(base).diagnostics).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: 'signature-body-hash-base64' })]),
    );
    expect(parseDkimSignature(malformedIdentity).diagnostics).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: 'signature-identity' })]),
    );
    expect(parseDkimSignature(uppercaseVersion).valid).toBe(false);
  });

  it('accepts encoded and quoted AUID local-parts but rejects malformed encoding', () => {
    const encodedIdentity = parseDkimMessage(
      'DKIM-Signature: v=1; a=ed25519-sha256; d=example.test; s=key; i==22a=40b=3B=20c=22@sub.example.test; h=from; bh=AAAA; b=AAAA\r\nFrom: a@example.test\r\n\r\nbody',
    ).headers[0];
    const lowerCaseHex = parseDkimMessage(
      'DKIM-Signature: v=1; a=ed25519-sha256; d=example.test; s=key; i=user=3b@example.test; h=from; bh=AAAA; b=AAAA\r\nFrom: a@example.test\r\n\r\nbody',
    ).headers[0];
    if (encodedIdentity === undefined || lowerCaseHex === undefined)
      throw new Error('Expected AUID fixtures.');

    expect(parseDkimSignature(encodedIdentity)).toMatchObject({
      identity: '"a@b; c"@sub.example.test',
      valid: true,
    });
    expect(parseDkimSignature(lowerCaseHex).diagnostics).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: 'signature-identity' })]),
    );
  });

  it('reports unknown canonicalisation as unsupported and rejects ambiguous From fields', async () => {
    const bodyHash = await dkimBodyHash('body', 'simple');
    const unknownCanonicalisation = `DKIM-Signature: v=1; a=ed25519-sha256; c=future/simple; d=example.test; s=key; h=from; bh=${bodyHash}; b=AAAA\r\nFrom: a@example.test\r\n\r\nbody`;
    const duplicateFrom = `DKIM-Signature: v=1; a=ed25519-sha256; d=example.test; s=key; h=from; bh=${bodyHash}; b=AAAA\r\nFrom: first@example.test\r\nFrom: second@example.test\r\n\r\nbody`;
    const lookup = () => Promise.resolve({ records: [RFC_8463_KEY], temporary: false });

    await expect(verifyDkimMessage(unknownCanonicalisation, lookup)).resolves.toEqual([
      expect.objectContaining({ status: 'unsupported' }),
    ]);
    const duplicateResult = await verifyDkimMessage(duplicateFrom, lookup);
    expect(duplicateResult[0]?.status).toBe('permerror');
    expect(duplicateResult[0]?.reason).toMatch(/multiple From/iu);
  });

  it('can sign a pre-existing DKIM-Signature field without selecting itself twice', async () => {
    const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ]);
    if (!('privateKey' in keyPair)) throw new Error('Expected an Ed25519 key pair.');
    const bodyHash = await dkimBodyHash('body', 'simple');
    const current = `DKIM-Signature: v=1; a=ed25519-sha256; d=example.test; s=counter; h=dkim-signature:from; bh=${bodyHash}; b=`;
    const previous = 'DKIM-Signature: v=1; a=unsupported-sha256';
    const from = 'From: sender@example.test';
    const headerInput = `${previous}\r\n${from}\r\n${current}`;
    const headerDigest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(headerInput),
    );
    const signature = await crypto.subtle.sign('Ed25519', keyPair.privateKey, headerDigest);
    const publicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const message = `${current}${encoded(signature)}\r\n${previous}\r\n${from}\r\n\r\nbody`;

    const results = await verifyDkimMessage(message, () =>
      Promise.resolve({
        records: [`v=DKIM1; k=ed25519; p=${encoded(publicKey)}`],
        temporary: false,
      }),
    );

    expect(results[0]).toMatchObject({ status: 'pass' });
  });

  it('verifies when b is the first signature tag', async () => {
    const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ]);
    if (!('privateKey' in keyPair)) throw new Error('Expected an Ed25519 key pair.');
    const bodyHash = await dkimBodyHash('body', 'simple');
    const unsigned = `DKIM-Signature: b=; v=1; a=ed25519-sha256; d=example.test; s=first; h=from; bh=${bodyHash}`;
    const from = 'From: sender@example.test';
    const headerDigest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(`${from}\r\n${unsigned}`),
    );
    const signature = await crypto.subtle.sign('Ed25519', keyPair.privateKey, headerDigest);
    const publicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const message = `${unsigned.replace('b=', `b=${encoded(signature)}`)}\r\n${from}\r\n\r\nbody`;

    const results = await verifyDkimMessage(message, () =>
      Promise.resolve({
        records: [`v=DKIM1; k=ed25519; p=${encoded(publicKey)}`],
        temporary: false,
      }),
    );

    expect(results[0]).toMatchObject({ status: 'pass' });
  });

  it('blanks only the case-sensitive b tag when an unknown B tag precedes it', async () => {
    const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ]);
    if (!('privateKey' in keyPair)) throw new Error('Expected an Ed25519 key pair.');
    const bodyHash = await dkimBodyHash('body', 'simple');
    const unsigned = `DKIM-Signature: B=QUJD; v=1; a=ed25519-sha256; d=example.test; s=case; h=from; bh=${bodyHash}; b=`;
    const from = 'From: sender@example.test';
    const headerDigest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(`${from}\r\n${unsigned}`),
    );
    const signature = await crypto.subtle.sign('Ed25519', keyPair.privateKey, headerDigest);
    const publicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const message = `${unsigned}${encoded(signature)}\r\n${from}\r\n\r\nbody`;

    const results = await verifyDkimMessage(message, () =>
      Promise.resolve({
        records: [`v=DKIM1; k=ed25519; p=${encoded(publicKey)}`],
        temporary: false,
      }),
    );

    expect(results[0]).toMatchObject({ status: 'pass' });
  });

  it('handles bounded folded whitespace before the b tag in linear work', async () => {
    const bodyHash = await dkimBodyHash('body', 'simple');
    const foldedWhitespace = '\r\n\t\t'.repeat(4_000);
    const message = `DKIM-Signature: v=1; a=ed25519-sha256; d=example.test; s=folded; h=from; bh=${bodyHash};${foldedWhitespace}b=AAAA\r\nFrom: sender@example.test\r\n\r\nbody`;
    const lookup = vi.fn(() =>
      Promise.resolve({ error: 'No key is published.', records: [], temporary: false }),
    );

    const results = await verifyDkimMessage(message, lookup);

    expect(lookup).toHaveBeenCalledOnce();
    expect(lookup).toHaveBeenCalledWith('folded._domainkey.example.test');
    expect(results[0]).toMatchObject({ reason: 'No key is published.', status: 'permerror' });
  });

  it('rejects non-LDH selectors and AUID domains before DNS', async () => {
    const bodyHash = await dkimBodyHash('body', 'simple');
    const invalidSelector = `DKIM-Signature: v=1; a=ed25519-sha256; d=example.test; s=_private; h=from; bh=${bodyHash}; b=AAAA\r\nFrom: a@example.test\r\n\r\nbody`;
    const invalidIdentity = invalidSelector.replace(
      's=_private',
      's=key; i=@sub_domain.example.test',
    );
    const lookup = vi.fn(() => Promise.resolve({ records: [RFC_8463_KEY], temporary: false }));

    await expect(verifyDkimMessage(invalidSelector, lookup)).resolves.toEqual([
      expect.objectContaining({ status: 'permerror' }),
    ]);
    await expect(verifyDkimMessage(invalidIdentity, lookup)).resolves.toEqual([
      expect.objectContaining({ status: 'permerror' }),
    ]);
    expect(lookup).not.toHaveBeenCalled();
  });

  it('stops local verification when its run is aborted', async () => {
    const controller = new AbortController();
    const lookup = () => {
      controller.abort();
      return Promise.resolve({ records: [RFC_8463_KEY], temporary: false });
    };

    await expect(
      verifyDkimMessage(
        RFC_8463_MESSAGE,
        lookup,
        new Date('2018-06-10T14:58:29.000Z'),
        controller.signal,
      ),
    ).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('reuses one bounded DNS key lookup for repeated selector signatures', async () => {
    const signature = RFC_8463_MESSAGE.slice(0, RFC_8463_MESSAGE.indexOf('\nFrom:'));
    const duplicated = RFC_8463_MESSAGE.replace(signature, `${signature}\n${signature}`);
    let lookups = 0;

    const results = await verifyDkimMessage(
      duplicated,
      () => {
        lookups += 1;
        return Promise.resolve({ records: [RFC_8463_KEY], temporary: false });
      },
      new Date('2018-06-10T14:58:29.000Z'),
    );

    expect(results).toHaveLength(2);
    expect(results.every((result) => result.status === 'pass')).toBe(true);
    expect(lookups).toBe(1);
  });

  it('bounds message and signature work', async () => {
    expect(() => parseDkimMessage('x'.repeat(1_048_577))).toThrow(/safety limit/iu);
    const message = `${Array.from({ length: 21 }, () => 'DKIM-Signature: v=1').join('\r\n')}\r\n\r\nbody`;
    await expect(
      verifyDkimMessage(message, () => Promise.resolve({ records: [], temporary: false })),
    ).rejects.toThrow(/signature work limit/iu);
  });
});
