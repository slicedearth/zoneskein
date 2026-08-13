import { describe, expect, it } from 'vitest';

import { authorRecord, chunkTxtValue, type RecordAuthoringDraft } from './authoring';
import { lintZoneSnippet } from './lint';

function draft(
  type: RecordAuthoringDraft['type'],
  fields: Readonly<Record<string, string>>,
): RecordAuthoringDraft {
  return { fields, owner: 'service.example.', ttl: '1h', type };
}

describe('DNS record authoring', () => {
  it.each([
    ['A', { address: '192.0.2.1' }, '192.0.2.1'],
    ['AAAA', { address: '2001:db8::1' }, '2001:db8:0:0:0:0:0:1'],
    ['MX', { preference: '10', target: 'mail.example.' }, '10 mail.example.'],
    [
      'SRV',
      { port: '443', priority: '10', target: 'edge.example.', weight: '5' },
      '10 5 443 edge.example.',
    ],
    ['CAA', { flags: '0', tag: 'issue', value: 'ca.example' }, '0 issue "ca.example"'],
    [
      'TLSA',
      { associationData: 'AA'.repeat(32), matchingType: '1', selector: '1', usage: '3' },
      `3 1 1 ${'AA'.repeat(32)}`,
    ],
    [
      'SSHFP',
      { algorithm: '4', fingerprint: 'BB'.repeat(32), fingerprintType: '2' },
      `4 2 ${'BB'.repeat(32)}`,
    ],
    [
      'URI',
      { priority: '10', target: 'https://example.test/path', weight: '1' },
      '10 1 "https://example.test/path"',
    ],
    [
      'DNSKEY',
      { algorithm: '13', flags: '257', protocol: '3', publicKey: 'AAAA' },
      '257 3 13 AAAA',
    ],
    [
      'DS',
      { algorithm: '13', digest: 'CC'.repeat(32), digestType: '2', keyTag: '12345' },
      `12345 13 2 ${'CC'.repeat(32)}`,
    ],
    [
      'NAPTR',
      {
        flags: 's',
        order: '100',
        preference: '10',
        regexp: '',
        replacement: '_sip._tcp.example.',
        service: 'SIP+D2T',
      },
      '100 10 "s" "SIP+D2T" "" _sip._tcp.example.',
    ],
  ] as const)('builds and round-trips %s records', (type, fields, expected) => {
    const result = authorRecord(draft(type, fields));
    expect(result).toMatchObject({ rdata: expected, valid: true });
    expect(lintZoneSnippet(result.bind ?? '').diagnostics).not.toEqual(
      expect.arrayContaining([expect.objectContaining({ severity: 'error' })]),
    );
  });

  it('splits TXT data by decoded UTF-8 octets and escapes presentation text', () => {
    const value = `${'é'.repeat(127)}a${'b'.repeat(255)}`;
    expect(chunkTxtValue(value).map((chunk) => new TextEncoder().encode(chunk).length)).toEqual(
      [255, 255],
    );
    const result = authorRecord(draft('TXT', { value: 'say "hello" \\ safely' }));
    expect(result.bind).toContain('"say \\"hello\\" \\\\ safely"');
    expect(result.valid).toBe(true);
    expect(lintZoneSnippet(result.bind ?? '').records[0]?.rdata[0]?.value).toBe(
      'say "hello" \\ safely',
    );
  });

  it('uses decimal master-file escapes for control characters', () => {
    const value = 'first\u0000\r\nsecond\u007f';
    const result = authorRecord(draft('TXT', { value }));
    expect(result.bind).toContain('"first\\000\\013\\010second\\127"');
    expect(result.valid).toBe(true);
    const parsed = lintZoneSnippet(result.bind ?? '');
    expect(parsed.records[0]?.rdata[0]?.value).toBe(value);
    expect(parsed.diagnostics.some((diagnostic) => diagnostic.rule.startsWith('escape-'))).toBe(
      false,
    );
  });

  it('validates SVCB aliases, duplicate parameters, mandatory keys, and address hints', () => {
    const invalid = authorRecord(
      draft('HTTPS', {
        parameters: 'mandatory=alpn,port\nalpn=h2,h3\nport=443\nipv4hint=2001:db8::1\nalpn=h2',
        priority: '0',
        target: 'edge.example.',
      }),
    );
    expect(invalid.valid).toBe(false);
    expect(invalid.diagnostics.map((item) => item.code)).toEqual(
      expect.arrayContaining([
        'svcb-key-duplicate',
        'svcb-hint-invalid',
        'svcb-alias-parameters',
      ]),
    );
  });

  it('rejects reserved numeric SvcParam keys and malformed ECH configuration data', () => {
    const invalid = authorRecord(
      draft('SVCB', {
        parameters: 'key65535=value\nech=not_base64',
        priority: '1',
        target: 'edge.example.',
      }),
    );
    expect(invalid.valid).toBe(false);
    expect(invalid.diagnostics.map((item) => item.code)).toEqual(
      expect.arrayContaining(['svcb-key-range', 'svcb-ech-invalid']),
    );
  });

  it('canonicalises SvcParam keys, ordering, and mandatory references', () => {
    const result = authorRecord(
      draft('HTTPS', {
        parameters: 'port=443\nkey1=h2,h3\nmandatory=port,key1\nech=AAT+DQAA',
        priority: '1',
        target: '.',
      }),
    );

    expect(result).toMatchObject({
      rdata: '1 . mandatory="alpn,port" alpn="h2,h3" port="443" ech="AAT+DQAA"',
      valid: true,
    });
    expect(lintZoneSnippet(result.bind ?? '').diagnostics).not.toEqual(
      expect.arrayContaining([expect.objectContaining({ severity: 'error' })]),
    );
  });

  it('rejects numeric aliases of duplicate keys and incomplete ALPN controls', () => {
    const result = authorRecord(
      draft('SVCB', {
        parameters: 'alpn=h2\nkey1=h3\nno-default-alpn',
        priority: '1',
        target: 'service.example.',
      }),
    );

    expect(result.valid).toBe(false);
    expect(result.diagnostics.map((item) => item.code)).toContain('svcb-key-duplicate');

    const noAlpn = authorRecord(
      draft('SVCB', {
        parameters: 'no-default-alpn',
        priority: '1',
        target: 'service.example.',
      }),
    );
    expect(noAlpn.diagnostics.map((item) => item.code)).toContain(
      'svcb-no-default-without-alpn',
    );
  });

  it('requires AliasMode records to use a non-root target without parameters', () => {
    const result = authorRecord(draft('HTTPS', { parameters: '', priority: '0', target: '.' }));
    expect(result.valid).toBe(false);
    expect(result.diagnostics.map((item) => item.code)).toContain('svcb-alias-root-target');
  });

  it('rejects malformed security-sensitive record fields', () => {
    expect(
      authorRecord(
        draft('DS', { algorithm: '13', digest: 'AA', digestType: '2', keyTag: '123' }),
      ),
    ).toMatchObject({ valid: false });
    expect(
      authorRecord(
        draft('DNSKEY', { algorithm: '13', flags: '257', protocol: '2', publicKey: 'AAAA' }),
      ).diagnostics,
    ).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: 'dnskey-protocol-invalid' })]),
    );
  });
});
