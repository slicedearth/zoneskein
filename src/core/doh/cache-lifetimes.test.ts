import { describe, expect, it } from 'vitest';

import { validateDnsName } from '../dns/names';
import type { DnsRecord, DnsResponse, DnsSection } from '../dns/types';
import { DnsMemoryCache } from './cache';
import { resolverById } from './resolvers';

const RECEIVED_AT = '2027-01-15T08:00:00.000Z';
const RECEIVED_MILLISECONDS = Date.parse(RECEIVED_AT);
const RECEIVED_SECONDS = Math.floor(RECEIVED_MILLISECONDS / 1000);

function record(type: string, ttl: number, section: DnsSection, data: unknown = {}): DnsRecord {
  return {
    class: 'IN',
    data,
    owner: 'example.com.',
    rawRdata: new Uint8Array(),
    section,
    ttl,
    type,
    typeCode: 0,
  };
}

interface ResponseOptions {
  readonly answers?: readonly DnsRecord[];
  readonly authorities?: readonly DnsRecord[];
  readonly negativeCacheTtl?: number;
  readonly receivedAt?: string;
}

function response(options: ResponseOptions): DnsResponse {
  const parsed = validateDnsName('example.com');
  if (!parsed.ok) throw new Error(parsed.error.message);
  return {
    cache: 'miss',
    message: {
      additionals: [],
      answers: options.answers ?? [],
      authorities: options.authorities ?? [],
      flags: {
        authenticatedData: false,
        authoritativeAnswer: false,
        checkingDisabled: false,
        recursionAvailable: true,
        recursionDesired: true,
        truncated: false,
      },
      id: 0,
      messageBytes: 0,
      ...(options.negativeCacheTtl === undefined
        ? {}
        : { negativeCacheTtl: options.negativeCacheTtl }),
      questions: [{ class: 'IN', name: 'example.com.', type: 'A' }],
      raw: new Uint8Array(),
      responseCode: options.negativeCacheTtl === undefined ? 'NOERROR' : 'NXDOMAIN',
    },
    queryTimeMs: 1,
    question: { name: parsed.value, type: 'A' },
    receivedAt: options.receivedAt ?? RECEIVED_AT,
    resolver: resolverById('google'),
  };
}

function expectLifetime(
  value: DnsResponse,
  lifetimeSeconds: number,
  now = RECEIVED_MILLISECONDS,
) {
  let clock = now;
  const cache = new DnsMemoryCache(() => clock);
  cache.set('fixture', value);
  if (lifetimeSeconds <= 0) {
    expect(cache.get('fixture')).toBeNull();
    return;
  }
  expect(cache.get('fixture')).toBe(value);
  clock = now + lifetimeSeconds * 1000 - 1;
  expect(cache.get('fixture')).toBe(value);
  clock += 1;
  expect(cache.get('fixture')).toBeNull();
}

describe('DNS cache lifetime caps', () => {
  it('uses the shortest answer TTL', () => {
    expectLifetime(
      response({
        answers: [record('A', 30, 'answer'), record('A', 11, 'answer')],
      }),
      11,
    );
  });

  it('also caps a complete response by its shortest authority TTL', () => {
    expectLifetime(
      response({
        answers: [record('A', 60, 'answer')],
        authorities: [record('NS', 13, 'authority')],
      }),
      13,
    );
  });

  it.each([
    ['NSEC', 7],
    ['NSEC3', 8],
    ['RRSIG', 9],
  ])('caps a denial response by its %s TTL', (type, ttl) => {
    expectLifetime(response({ authorities: [record(type, ttl, 'authority')] }), ttl);
  });

  it('caps an RRset by the RRSIG Original TTL', () => {
    expectLifetime(
      response({
        answers: [
          record('A', 60, 'answer'),
          record('RRSIG', 60, 'answer', {
            expiration: RECEIVED_SECONDS + 120,
            originalTTL: 6,
          }),
        ],
      }),
      6,
    );
  });

  it('caps an RRset at an upcoming RRSIG expiration', () => {
    expectLifetime(
      response({
        answers: [
          record('A', 60, 'answer'),
          record('RRSIG', 60, 'answer', {
            expiration: RECEIVED_SECONDS + 5,
            originalTTL: 60,
          }),
        ],
      }),
      5,
    );
  });

  it('does not cache an RRset whose RRSIG had already expired when received', () => {
    expectLifetime(
      response({
        answers: [
          record('A', 60, 'answer'),
          record('RRSIG', 60, 'answer', {
            expiration: RECEIVED_SECONDS - 1,
            originalTTL: 60,
          }),
        ],
      }),
      0,
    );
  });

  it('caps a negative response by its derived negative TTL', () => {
    expectLifetime(
      response({
        authorities: [record('SOA', 60, 'authority')],
        negativeCacheTtl: 4,
      }),
      4,
    );
  });

  it('subtracts response age from the remaining record TTL', () => {
    const receivedAt = new Date(RECEIVED_MILLISECONDS - 10_000).toISOString();
    expectLifetime(response({ answers: [record('A', 60, 'answer')], receivedAt }), 50);
  });
});
