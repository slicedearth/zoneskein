import { describe, expect, it } from 'vitest';

import type { DnsResponse, ResolverId } from '../dns/types';
import { compareDnsGraphObservations } from './resolver-comparison';

function response(
  id: ResolverId,
  rawRdata: readonly number[],
  options: {
    readonly ad?: boolean;
    readonly authority?: readonly number[];
    readonly code?: string;
    readonly ede?: number;
    readonly ttl?: number;
  } = {},
): DnsResponse {
  return {
    cache: 'miss',
    message: {
      additionals: [],
      answers:
        rawRdata.length === 0
          ? []
          : [
              {
                class: 'IN',
                data: '192.0.2.1',
                owner: 'example.com',
                rawRdata: Uint8Array.from(rawRdata),
                section: 'answer',
                ttl: options.ttl ?? 300,
                type: 'A',
                typeCode: 1,
              },
            ],
      authorities:
        options.authority === undefined
          ? []
          : [
              {
                class: 'IN',
                data: Uint8Array.from(options.authority),
                owner: 'example.com',
                rawRdata: Uint8Array.from(options.authority),
                section: 'authority',
                ttl: options.ttl ?? 300,
                type: 'NSEC',
                typeCode: 47,
              },
            ],
      ...(options.ede === undefined
        ? {}
        : {
            edns: {
              dnssecOk: true,
              extendedErrors: [{ code: options.ede, name: 'Resolver detail' }],
              extendedResponseCode: 0,
              udpPayloadSize: 1232,
              version: 0,
            },
          }),
      flags: {
        authenticatedData: options.ad ?? false,
        authoritativeAnswer: false,
        checkingDisabled: false,
        recursionAvailable: true,
        recursionDesired: true,
        truncated: false,
      },
      id: 1,
      messageBytes: 64,
      questions: [],
      raw: new Uint8Array(),
      responseCode: options.code ?? 'NOERROR',
    },
    queryTimeMs: 2,
    question: {
      name: {
        absolute: 'example.com.',
        ascii: 'example.com',
        display: 'example.com',
        hadRootDot: false,
        unicode: false,
      },
      type: 'A',
    },
    receivedAt: '2026-08-27T00:00:00.000Z',
    resolver: {
      endpoint: `https://${id}.example/dns-query`,
      httpMethod: 'POST',
      id,
      label: id,
      privacyUrl: `https://${id}.example/privacy`,
    },
  };
}

function observation(value: DnsResponse) {
  return {
    questionName: 'example.com.',
    questionType: 'A',
    response: value,
  } as const;
}

describe('resolver comparison', () => {
  it('separates TTL-only cache-age differences from answer-data differences', () => {
    const result = compareDnsGraphObservations([
      observation(response('cloudflare', [192, 0, 2, 1], { ttl: 300 })),
      observation(response('google', [192, 0, 2, 1], { ttl: 240 })),
      observation(response('quad9', [192, 0, 2, 1], { ttl: 180 })),
    ]);

    expect(result[0]?.state).toBe('disagreement');
    expect(result[0]?.differences.map((item) => item.kind)).toEqual(['ttl']);
  });

  it('retains response, data, DNSSEC-signal, and EDE disagreement separately', () => {
    const result = compareDnsGraphObservations([
      observation(response('cloudflare', [192, 0, 2, 1], { ad: true, ede: 6 })),
      observation(response('google', [], { code: 'SERVFAIL' })),
    ]);

    expect(result[0]?.differences.map((item) => item.kind)).toEqual([
      'response-code',
      'answer-data',
      'dnssec-signal',
      'extended-error',
    ]);
  });

  it('does not turn a failed resolver request into apparent agreement', () => {
    const result = compareDnsGraphObservations([
      observation(response('cloudflare', [192, 0, 2, 1])),
      {
        error: 'Timed out.',
        questionName: 'example.com.',
        questionType: 'A',
        resolverLabel: 'Other resolver',
      },
    ]);

    expect(result[0]?.state).toBe('incomplete');
    expect(result[0]?.observations[1]).toMatchObject({ error: 'Timed out.' });
  });

  it('retains divergent negative authority evidence when answer sections are empty', () => {
    const result = compareDnsGraphObservations([
      observation(response('cloudflare', [], { authority: [1, 2, 3] })),
      observation(response('google', [], { authority: [1, 2, 4] })),
    ]);

    expect(result[0]?.state).toBe('disagreement');
    expect(result[0]?.differences.map((item) => item.kind)).toEqual(['authority-data']);
  });
});
