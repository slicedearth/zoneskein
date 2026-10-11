import { describe, expect, it } from 'vitest';

import { compressionFixture } from '../../test/dns-compression-fixture';
import type { DnsRecord, DnsResponse } from '../dns/types';
import { buildDnsEvidenceBundle } from './dns-graph';

function response(records: readonly DnsRecord[]): DnsResponse {
  return {
    cache: 'miss',
    message: {
      additionals: [],
      answers: records,
      authorities: [],
      flags: {
        authenticatedData: false,
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
      responseCode: 'NOERROR',
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
      type: 'MX',
    },
    receivedAt: '2026-08-27T00:00:00.000Z',
    resolver: {
      endpoint: 'https://resolver.example/dns-query',
      httpMethod: 'POST',
      id: 'cloudflare',
      label: 'Cloudflare 1.1.1.1',
      privacyUrl: 'https://resolver.example/privacy',
    },
  };
}

describe('buildDnsEvidenceBundle', () => {
  it('retains case-sensitive and delimiter-bearing TXT bytes without presentation collisions', () => {
    const chunks = [['Token'], ['token'], ['a|b'], ['a', 'b'], ['ab'], ['', 'ab'], ['ab', '']];
    const records: DnsRecord[] = chunks.map((parts) => ({
      class: 'IN',
      data: parts.map((part) => Uint8Array.from(new TextEncoder().encode(part))),
      owner: 'example.com',
      rawRdata: Uint8Array.from(
        parts.flatMap((part) => [part.length, ...new TextEncoder().encode(part)]),
      ),
      section: 'answer',
      ttl: 300,
      type: 'TXT',
      typeCode: 16,
    }));
    const build = (values: readonly DnsRecord[]) =>
      buildDnsEvidenceBundle(
        'example.com',
        [{ questionName: 'example.com.', questionType: 'TXT', response: response(values) }],
        '2026-08-27T00:00:01.000Z',
      );
    const bundle = build(records);
    const nodes = bundle.nodes.filter((node) => node.kind === 'record');
    expect(nodes).toHaveLength(7);
    expect(new Set(nodes.map((node) => node.id)).size).toBe(7);
    expect(nodes.some((node) => node.label.includes('Token'))).toBe(true);
    expect(nodes.some((node) => node.label.includes('token'))).toBe(true);
    expect(bundle.links.filter((link) => link.kind === 'publishes')).toHaveLength(7);
    expect(JSON.parse(JSON.stringify(bundle))).toEqual(bundle);
    expect(build([...records].reverse())).toEqual(bundle);
    expect(build([...records, ...records])).toEqual(bundle);
  });

  it('deduplicates only DNS-name case and compression equivalents', () => {
    const records = (['literal', 'question-pointer', 'owner-pointer'] as const).flatMap(
      (layout) => compressionFixture(5, layout).answers,
    );
    const build = (values: readonly DnsRecord[]) =>
      buildDnsEvidenceBundle(
        'example.com',
        [{ questionName: 'example.com.', questionType: 'CNAME', response: response(values) }],
        '2026-08-27T00:00:01.000Z',
      );
    const bundle = build(records);
    expect(bundle.nodes.filter((node) => node.kind === 'record')).toHaveLength(1);
    expect(bundle.nodes.filter((node) => node.kind === 'target')).toHaveLength(1);
    expect(build([...records].reverse())).toEqual(bundle);
  });

  it('retains record dependencies and resolver provenance', () => {
    const record: DnsRecord = {
      class: 'IN',
      data: { exchange: 'mail.example.com', preference: 10 },
      owner: 'example.com',
      rawRdata: new Uint8Array(),
      section: 'answer',
      ttl: 300,
      type: 'MX',
      typeCode: 15,
    };
    const bundle = buildDnsEvidenceBundle(
      'example.com',
      [{ questionName: 'example.com.', questionType: 'MX', response: response([record]) }],
      '2026-08-27T00:00:01.000Z',
    );
    expect(bundle.status).toBe('complete');
    expect(bundle.nodes.some((node) => node.kind === 'resolver')).toBe(true);
    expect(bundle.nodes.some((node) => node.label === 'mail.example.com.')).toBe(true);
    expect(bundle.links.some((link) => link.kind === 'points-to')).toBe(true);
  });

  it('preserves failed questions as explicit uncertainty', () => {
    const bundle = buildDnsEvidenceBundle('example.com', [
      { error: 'Timed out.', questionName: 'example.com.', questionType: 'AAAA' },
    ]);
    expect(bundle.status).toBe('partial');
    expect(bundle.incompleteReasons).toEqual(['AAAA: Timed out.']);
    expect(bundle.nodes.some((node) => node.kind === 'uncertainty')).toBe(true);
  });

  it('marks dense repeated dependencies partial when the relationship bound is reached', () => {
    const dependencies = Array.from(
      { length: 20 },
      (_, index) => `include:spf${String(index)}.example`,
    ).join(' ');
    const records: DnsRecord[] = Array.from({ length: 100 }, (_, index) => ({
      class: 'IN',
      data: [
        Uint8Array.from(
          new TextEncoder().encode(`v=spf1 ${dependencies} marker-${String(index)}`),
        ),
      ],
      owner: `selector${String(index)}.example.com`,
      rawRdata: Uint8Array.from([index]),
      section: 'answer',
      ttl: 300,
      type: 'TXT',
      typeCode: 16,
    }));

    const bundle = buildDnsEvidenceBundle('example.com', [
      { questionName: 'example.com.', questionType: 'TXT', response: response(records) },
    ]);

    expect(bundle.links).toHaveLength(320);
    expect(bundle.incompleteReasons).toContain(
      'The evidence graph reached its bounded relationship limit.',
    );
    expect(bundle.status).toBe('partial');
  });
});
