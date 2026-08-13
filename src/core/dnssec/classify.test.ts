import { encode } from '@dnsquery/dns-packet';
import { describe, expect, it } from 'vitest';

import { validateDnsName } from '../dns/names';
import type { DnsRecord, DnsResponse } from '../dns/types';
import { decodeDnsMessage } from '../dns/wire';
import { resolverById } from '../doh/resolvers';
import { classifyDnssecEvidence } from './classify';

function response(
  responseCode: 'NOERROR' | 'SERVFAIL',
  authenticatedData: boolean,
): DnsResponse {
  const name = validateDnsName('example.com');
  if (!name.ok) throw new Error(name.error.message);
  const message = decodeDnsMessage(
    encode({
      answers: [],
      flags: 0x8180 | (authenticatedData ? 0x20 : 0),
      id: 0,
      questions: [{ class: 'IN', name: 'example.com.', type: 'DNSKEY' }],
      rcode: responseCode,
      type: 'response',
    }),
  );
  return {
    cache: 'miss',
    message: { ...message, responseCode },
    queryTimeMs: 2,
    question: { name: name.value, type: 'DNSKEY' },
    receivedAt: '2026-08-13T00:00:00.000Z',
    resolver: resolverById('google'),
  };
}

function record(type: 'DNSKEY' | 'NSEC', section: 'answer' | 'authority'): DnsRecord {
  return {
    class: 'IN',
    data: {},
    owner: 'example.com.',
    rawRdata: new Uint8Array(),
    section,
    ttl: 300,
    type,
    typeCode: type === 'DNSKEY' ? 48 : 47,
  };
}

function withDnskeyAnswer(value: DnsResponse): DnsResponse {
  return {
    ...value,
    message: { ...value.message, answers: [record('DNSKEY', 'answer')] },
  };
}

function withAuthenticatedNsec(value: DnsResponse): DnsResponse {
  return {
    ...value,
    message: { ...value.message, authorities: [record('NSEC', 'authority')] },
  };
}

describe('DNSSEC evidence classification', () => {
  it('does not equate an absent AD flag with an unsigned delegation', () => {
    expect(
      classifyDnssecEvidence({
        checkingDnskey: response('NOERROR', false),
        dsMatches: [],
        publishedDsCount: 0,
        signatures: [],
        validatingDnskey: response('NOERROR', false),
      }),
    ).toMatchObject({ code: 'indeterminate' });
  });

  it('reports resolver validation without overstating local trust', () => {
    expect(
      classifyDnssecEvidence({
        dsMatches: [],
        publishedDsCount: 0,
        signatures: [],
        validatingDnskey: response('NOERROR', true),
      }),
    ).toMatchObject({ code: 'resolver-validated' });
  });

  it('reports the validating SERVFAIL and checking-disabled data pattern as likely bogus', () => {
    expect(
      classifyDnssecEvidence({
        checkingDnskey: withDnskeyAnswer(response('NOERROR', false)),
        dsMatches: [],
        publishedDsCount: 1,
        signatures: [],
        validatingDnskey: response('SERVFAIL', false),
      }),
    ).toMatchObject({ code: 'likely-bogus', tone: 'error' });
  });

  it('requires authenticated denial evidence before calling a delegation unsigned', () => {
    expect(
      classifyDnssecEvidence({
        dsMatches: [],
        publishedDsCount: 0,
        signatures: [],
        validatingDs: withAuthenticatedNsec(response('NOERROR', true)),
        validatingDnskey: response('NOERROR', false),
      }),
    ).toMatchObject({ code: 'unsigned' });
  });
});
