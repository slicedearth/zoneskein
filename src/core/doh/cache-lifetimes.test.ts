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
  readonly authenticatedData?: boolean;
  readonly authorities?: readonly DnsRecord[];
  readonly extendedError?: boolean;
  readonly negativeCacheTtl?: number;
  readonly receivedAt?: string;
  readonly responseCode?: string;
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
        authenticatedData: options.authenticatedData ?? false,
        authoritativeAnswer: false,
        checkingDisabled: false,
        recursionAvailable: true,
        recursionDesired: true,
        truncated: false,
      },
      id: 0,
      messageBytes: 0,
      ...(options.extendedError === true
        ? {
            edns: {
              dnssecOk: true,
              extendedErrors: [{ code: 6, name: 'DNSSEC Bogus' }],
              extendedResponseCode: 0,
              udpPayloadSize: 1232,
              version: 0,
            },
          }
        : {}),
      ...(options.negativeCacheTtl === undefined
        ? {}
        : { negativeCacheTtl: options.negativeCacheTtl }),
      questions: [{ class: 'IN', name: 'example.com.', type: 'A' }],
      raw: new Uint8Array(),
      responseCode:
        options.responseCode ??
        (options.negativeCacheTtl === undefined ? 'NOERROR' : 'NXDOMAIN'),
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
  const initial = cache.get('fixture');
  expect(initial !== null && 'response' in initial ? initial.response : null).toBe(value);
  clock = now + lifetimeSeconds * 1000 - 1;
  const beforeExpiry = cache.get('fixture');
  expect(
    beforeExpiry !== null && 'response' in beforeExpiry ? beforeExpiry.response : null,
  ).toBe(value);
  clock += 1;
  expect(cache.get('fixture')).toBeNull();
}

function expectClassification(value: DnsResponse, classification: string) {
  const cache = new DnsMemoryCache(() => RECEIVED_MILLISECONDS);
  cache.set('fixture', value);
  expect(cache.get('fixture')).toMatchObject({ classification });
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

  it('does not let unrelated authority TTLs shorten a positive answer', () => {
    expectLifetime(
      response({
        answers: [record('A', 60, 'answer')],
        authorities: [record('NS', 13, 'authority')],
      }),
      60,
    );
  });

  it('caps a resolver-authenticated negative by its signed denial evidence', () => {
    const value = response({
      authenticatedData: true,
      authorities: [
        record('SOA', 60, 'authority'),
        record('NSEC', 7, 'authority'),
        record('RRSIG', 9, 'authority', {
          expiration: RECEIVED_SECONDS + 30,
          originalTTL: 11,
        }),
      ],
      negativeCacheTtl: 60,
    });
    expectClassification(value, 'resolver-ad-negative');
    expectLifetime(value, 7);
  });

  it('uses only the derived RFC 2308 TTL for an ordinary negative', () => {
    const value = response({
      authorities: [record('SOA', 60, 'authority'), record('NS', 2, 'authority')],
      negativeCacheTtl: 9,
    });
    expectClassification(value, 'ordinary-negative');
    expectLifetime(value, 9);
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

  it.each(['SERVFAIL', 'REFUSED', 'FORMERR'])(
    'uses short failure caching for %s without inheriting authority TTLs',
    (responseCode) => {
      const value = response({
        authorities: [record('SOA', 86_400, 'authority')],
        responseCode,
      });
      expectClassification(value, 'resolution-failure');
      expectLifetime(value, 5);
    },
  );

  it('does not let Extended DNS Error evidence override a useful NOERROR answer', () => {
    const value = response({
      answers: [record('A', 86_400, 'answer')],
      extendedError: true,
    });
    expectClassification(value, 'positive');
    expectLifetime(value, 86_400);
  });
});
