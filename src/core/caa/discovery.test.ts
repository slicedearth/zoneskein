import { describe, expect, it } from 'vitest';

import type { PolicyQueryResult } from '../dns/policy-query';
import type { DnsRecord } from '../dns/types';
import { discoverCaaPolicy } from './discovery';

function record(type: string, owner: string, data: unknown): DnsRecord {
  return {
    class: 'IN',
    data,
    owner,
    rawRdata: new Uint8Array(),
    section: 'answer',
    ttl: 300,
    type,
    typeCode: type === 'CAA' ? 257 : 5,
  };
}

function result(
  answers: readonly DnsRecord[],
  records: readonly DnsRecord[] = [],
): PolicyQueryResult {
  return {
    answers,
    messageBytes: 100,
    records,
    responseCode: 'NOERROR',
    ttl: 300,
    values: [],
  };
}

describe('CAA recursive discovery', () => {
  it('walks parents of the original name without manually following aliases', async () => {
    const queried: string[] = [];
    const caa = record('CAA', 'example.com.', {
      flags: 0,
      tag: 'issue',
      value: 'ca.example',
    });
    const report = await discoverCaaPolicy(
      ['www.example.com', 'example.com', 'com'],
      (name) => {
        queried.push(name);
        return Promise.resolve(
          name === 'www.example.com'
            ? result([record('CNAME', 'www.example.com.', 'edge.example.net.')])
            : result([caa], [caa]),
        );
      },
    );

    expect(queried).toEqual(['www.example.com', 'example.com']);
    expect(queried).not.toContain('edge.example.net');
    expect(report).toMatchObject({
      aliases: [{ owner: 'www.example.com', target: 'edge.example.net', type: 'CNAME' }],
      foundFor: 'example.com',
      source: 'example.com',
    });
  });

  it('records a recursively resolved alias owner without changing the parent walk', async () => {
    const caa = record('CAA', 'policy.example.net.', {
      flags: 0,
      tag: 'issue',
      value: 'ca.example',
    });
    const report = await discoverCaaPolicy(['www.example.com', 'example.com'], () =>
      Promise.resolve(
        result([record('CNAME', 'www.example.com.', 'policy.example.net.'), caa], [caa]),
      ),
    );

    expect(report).toMatchObject({ foundFor: 'www.example.com', source: 'policy.example.net' });
    expect(report.queried).toEqual(['www.example.com']);
  });

  it('ignores an unrelated CAA RRset appended to the answer section', async () => {
    const sibling = record('CAA', 'sibling.example.', {
      flags: 0,
      tag: 'issue',
      value: 'hostile.example',
    });
    const parent = record('CAA', 'example.com.', {
      flags: 0,
      tag: 'issue',
      value: 'ca.example',
    });
    const report = await discoverCaaPolicy(['www.example.com', 'example.com'], (name) =>
      Promise.resolve(
        name === 'www.example.com' ? result([sibling], [sibling]) : result([parent], [parent]),
      ),
    );

    expect(report).toMatchObject({ foundFor: 'example.com', source: 'example.com' });
    expect(report.records).toEqual([{ flags: 0, tag: 'issue', value: 'ca.example' }]);
  });

  it('rejects contradictory positive CAA data in an NXDOMAIN response', async () => {
    const caa = record('CAA', 'www.example.com.', {
      flags: 0,
      tag: 'issue',
      value: 'ca.example',
    });
    const report = await discoverCaaPolicy(['www.example.com', 'example.com'], () =>
      Promise.resolve({
        ...result([caa], [caa]),
        responseCode: 'NXDOMAIN',
      }),
    );

    expect(report.records).toEqual([]);
    expect(report.queried).toEqual(['www.example.com']);
    expect(report.errors[0]).toContain('positive CAA data with NXDOMAIN');
  });

  it('stops rather than treating a resolver failure as absence', async () => {
    const report = await discoverCaaPolicy(['www.example.com', 'example.com'], () =>
      Promise.resolve({
        answers: [],
        messageBytes: 0,
        records: [],
        responseCode: 'SERVFAIL',
        values: [],
      }),
    );

    expect(report.queried).toEqual(['www.example.com']);
    expect(report.errors[0]).toContain('SERVFAIL');
  });
});
