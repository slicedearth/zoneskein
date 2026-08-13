import { describe, expect, it } from 'vitest';

import { DnsQueryRun } from '../doh/query-run';
import { queryPolicyRecords } from './policy-query';
import type { DnsMessage, DnsRecord, DnsResolver, DnsResponse } from './types';

function record(owner: string, value: string): DnsRecord {
  return {
    class: 'IN',
    data: [Uint8Array.from(value, (character) => character.charCodeAt(0))],
    owner,
    rawRdata: new Uint8Array(),
    section: 'answer',
    ttl: 300,
    type: 'TXT',
    typeCode: 16,
  };
}

class FixtureResolver implements DnsResolver {
  readonly definition = {
    endpoint: 'https://resolver.invalid/dns-query',
    httpMethod: 'GET' as const,
    id: 'google' as const,
    label: 'Fixture resolver',
    privacyUrl: 'https://resolver.invalid/privacy',
  };

  readonly #answers: readonly DnsRecord[];
  readonly #responseCode: string;

  constructor(answers: readonly DnsRecord[], responseCode = 'NOERROR') {
    this.#answers = answers;
    this.#responseCode = responseCode;
  }

  query(question: Parameters<DnsResolver['query']>[0]): Promise<DnsResponse> {
    const message: DnsMessage = {
      additionals: [],
      answers: this.#answers,
      authorities: [],
      flags: {
        authenticatedData: false,
        authoritativeAnswer: false,
        checkingDisabled: false,
        recursionAvailable: true,
        recursionDesired: true,
        truncated: false,
      },
      id: 0,
      messageBytes: 100,
      questions: [{ class: 'IN', name: question.name.absolute, type: question.type }],
      raw: new Uint8Array(),
      responseCode: this.#responseCode,
    };
    return Promise.resolve({
      cache: 'miss',
      message,
      queryTimeMs: 1,
      question,
      receivedAt: '2026-08-13T00:00:00.000Z',
      resolver: this.definition,
    });
  }
}

describe('policy query RR binding', () => {
  it('does not select an unrelated TXT RR appended to the answer', async () => {
    const result = await queryPolicyRecords(
      new FixtureResolver([
        record('mail.example.com.', 'v=DMARC1; p=reject'),
        record('sibling.example.com.', 'v=DMARC1; p=none'),
      ]),
      new DnsQueryRun(),
      'mail.example.com',
      'TXT',
    );

    expect(result.records).toHaveLength(1);
    expect(result.values).toEqual(['v=DMARC1; p=reject']);
  });

  it('does not expose contradictory positive records from NXDOMAIN', async () => {
    const result = await queryPolicyRecords(
      new FixtureResolver([record('mail.example.com.', 'v=DMARC1; p=reject')], 'NXDOMAIN'),
      new DnsQueryRun(),
      'mail.example.com',
      'TXT',
    );

    expect(result.records).toEqual([]);
    expect(result.values).toEqual([]);
    expect(result.responseCode).toBe('NXDOMAIN');
  });

  it('surfaces an ambiguous alias answer instead of selecting policy data', async () => {
    const result = await queryPolicyRecords(
      new FixtureResolver([
        {
          ...record('mail.example.com.', 'unused'),
          data: 'one.example.net.',
          type: 'CNAME',
          typeCode: 5,
        },
        {
          ...record('mail.example.com.', 'unused'),
          data: 'two.example.net.',
          type: 'CNAME',
          typeCode: 5,
        },
        record('one.example.net.', 'v=DMARC1; p=reject'),
      ]),
      new DnsQueryRun(),
      'mail.example.com',
      'TXT',
    );

    expect(result.error).toMatch(/ambiguous CNAME/iu);
    expect(result.values).toEqual([]);
  });
});
