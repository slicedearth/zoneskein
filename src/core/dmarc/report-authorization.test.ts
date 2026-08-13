import { describe, expect, it } from 'vitest';

import {
  dmarcReportAuthorizationName,
  dmarcReportDestinationHost,
  evaluateDmarcReportAuthorization,
} from './report-authorization';

function alphabeticTag(index: number): string {
  const first = String.fromCharCode(97 + Math.floor(index / 26));
  const second = String.fromCharCode(97 + (index % 26));
  return `x${first}${second}`;
}

describe('DMARC external report authorisation', () => {
  it('accepts a basic-valid v=DMARC1 record with optional trailing tags and semicolon', () => {
    const result = evaluateDmarcReportAuthorization('mailto:dmarc@reports.example.net', [
      'unrelated TXT',
      'v=DMARC1; xprovider=ignored;',
    ]);

    expect(result).toEqual(
      expect.objectContaining({
        authorized: true,
        destinationHost: 'reports.example.net',
        selectedUris: ['mailto:dmarc@reports.example.net'],
        status: 'authorized',
        validRecords: 1,
      }),
    );
  });

  it('accepts multiple basic-valid records when they do not conflict', () => {
    const result = evaluateDmarcReportAuthorization('mailto:dmarc@example.net', [
      'v=DMARC1',
      'V=DMARC1; x=one',
    ]);

    expect(result.authorized).toBe(true);
    expect(result.validRecords).toBe(2);
  });

  it('applies a bounded same-host rua override', () => {
    const result = evaluateDmarcReportAuthorization('mailto:old@reports.example.net', [
      'v=DMARC1; rua=mailto:new@reports.example.net, mailto:backup@reports.example.net',
    ]);

    expect(result.authorized).toBe(true);
    expect(result.overrideUris).toEqual([
      'mailto:new@reports.example.net',
      'mailto:backup@reports.example.net',
    ]);
    expect(result.selectedUris).toEqual(result.overrideUris);
  });

  it('uses ruf for failure-report overrides and ignores a cross-kind rua tag', () => {
    const result = evaluateDmarcReportAuthorization(
      'mailto:old@reports.example.net',
      ['v=DMARC1; rua=mailto:ignored@attacker.example; ruf=mailto:new@reports.example.net'],
      'ruf',
    );

    expect(result.authorized).toBe(true);
    expect(result.selectedUris).toEqual(['mailto:new@reports.example.net']);
    expect(result.reason).toMatch(/same-host ruf override/iu);
  });

  it('ignores a cross-kind ruf tag during aggregate authorisation', () => {
    const result = evaluateDmarcReportAuthorization(
      'mailto:old@reports.example.net',
      ['v=DMARC1; ruf=mailto:ignored@attacker.example'],
      'rua',
    );

    expect(result.authorized).toBe(true);
    expect(result.selectedUris).toEqual(['mailto:old@reports.example.net']);
  });

  it('fails closed on a cross-host same-kind ruf override', () => {
    const result = evaluateDmarcReportAuthorization(
      'mailto:old@reports.example.net',
      ['v=DMARC1; ruf=mailto:redirect@attacker.example'],
      'ruf',
    );

    expect(result.status).toBe('unauthorized');
    expect(result.reason).toMatch(/cross-host ruf/iu);
  });

  it('fails closed on malformed, cross-host, or conflicting overrides', () => {
    const malformed = evaluateDmarcReportAuthorization('mailto:old@reports.example.net', [
      'v=DMARC1; rua=not a URI',
    ]);
    const crossHost = evaluateDmarcReportAuthorization('mailto:old@reports.example.net', [
      'v=DMARC1; rua=mailto:redirect@attacker.example',
    ]);
    const conflicting = evaluateDmarcReportAuthorization('mailto:old@reports.example.net', [
      'v=DMARC1; rua=mailto:first@reports.example.net',
      'v=DMARC1; rua=mailto:second@reports.example.net',
    ]);

    expect(malformed.status).toBe('unauthorized');
    expect(crossHost.status).toBe('unauthorized');
    expect(conflicting.status).toBe('unauthorized');
    expect(crossHost.reason).toMatch(/cross-host/iu);
  });

  it('requires v=DMARC1 to be the first exact version tag', () => {
    for (const record of [
      'x=one; v=DMARC1',
      'v=dmarc1',
      'v=DMARC1;; x=one',
      'v=DMARC1; v=DMARC1',
      'v=DMARC1; x-provider=one',
      'v=DMARC1; x1=one',
    ]) {
      expect(
        evaluateDmarcReportAuthorization('mailto:dmarc@example.net', [record]).status,
      ).toBe('unauthorized');
    }
  });

  it('bounds record count, record length, tag count, and override URI count', () => {
    const tooManyRecords = evaluateDmarcReportAuthorization(
      'mailto:dmarc@example.net',
      Array.from({ length: 33 }, () => 'v=DMARC1'),
    );
    const tooLong = evaluateDmarcReportAuthorization('mailto:dmarc@example.net', [
      `v=DMARC1; x=${'a'.repeat(8_193)}`,
    ]);
    const tooManyTags = evaluateDmarcReportAuthorization('mailto:dmarc@example.net', [
      `v=DMARC1;${Array.from({ length: 64 }, (_, index) => `${alphabeticTag(index)}=a`).join(';')}`,
    ]);
    const tooManyUris = evaluateDmarcReportAuthorization('mailto:dmarc@example.net', [
      `v=DMARC1; rua=${Array.from({ length: 11 }, (_, index) => `mailto:r${String(index)}@example.net`).join(',')}`,
    ]);

    expect(tooManyRecords.status).toBe('indeterminate');
    expect(tooLong.status).toBe('indeterminate');
    expect(tooManyTags.status).toBe('unauthorized');
    expect(tooManyUris.status).toBe('unauthorized');
  });

  it('extracts A-label hosts and constructs a DNS-bounded authorisation name', () => {
    expect(dmarcReportDestinationHost('mailto:reports@bücher.example!10m')).toBe(
      'xn--bcher-kva.example',
    );
    expect(
      dmarcReportAuthorizationName('mail.example.com', 'mailto:dmarc@reports.example.net'),
    ).toBe('mail.example.com._report._dmarc.reports.example.net');
    expect(
      dmarcReportAuthorizationName(
        `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.example`,
        `mailto:dmarc@${'d'.repeat(63)}.reports.example.net`,
      ),
    ).toBeNull();
  });
});
