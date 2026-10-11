import { describe, expect, it } from 'vitest';

import type { DnsMessage, DnsRecord } from '../dns/types';
import { inspectResinfo } from './resinfo';

function message(
  authoritative: boolean,
  values = ['qnamemin', 'exterr=15-17', 'infourl=https://resolver.example/guide'],
): DnsMessage {
  const encoded = values.flatMap((value) => {
    const bytes = [...new TextEncoder().encode(value)];
    return [bytes.length, ...bytes];
  });
  const record: DnsRecord = {
    class: 'IN',
    data: new Uint8Array(encoded),
    owner: 'resolver.example',
    rawRdata: new Uint8Array(encoded),
    section: 'answer',
    ttl: 7200,
    type: 'TYPE261',
    typeCode: 261,
  };
  return {
    additionals: [],
    answers: [record],
    authorities: [],
    flags: {
      authenticatedData: false,
      authoritativeAnswer: authoritative,
      checkingDisabled: false,
      recursionAvailable: true,
      recursionDesired: false,
      truncated: false,
    },
    id: 0,
    messageBytes: 128,
    questions: [],
    raw: new Uint8Array(),
    responseCode: 'NOERROR',
  };
}

describe('RESINFO inspection', () => {
  it('accepts one authoritative syntactically valid self-publication', () => {
    const report = inspectResinfo(message(true));
    expect(report.state).toBe('accepted');
    expect(report.attributes).toHaveLength(3);
  });

  it('discards a non-authoritative response', () => {
    expect(inspectResinfo(message(false)).state).toBe('discarded');
  });

  it('rejects repeated attributes and invalid diagnostic URLs', () => {
    expect(inspectResinfo(message(true, ['qnamemin', 'QNAMEMIN'])).state).toBe('malformed');
    expect(
      inspectResinfo(message(true, ['infourl=https://user@resolver.example/'])).state,
    ).toBe('malformed');
  });
});
