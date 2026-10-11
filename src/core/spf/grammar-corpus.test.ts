import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { analyseSpf } from './evaluator';
import { flattenSpf } from './flatten';
import { parseSpfMechanismSyntax, parseSpfRecord } from './parser';
import { evaluateSpfSender, type SpfSenderDnsClient } from './sender-evaluator';
import type { SpfLookupResult } from './types';

const malformed = [
  'a:',
  'mx:',
  'ptr:',
  'all:',
  'a:/24',
  'a://64',
  'mx:/24',
  'mx://64',
  'all/24',
  'include:',
  'ip4/24',
  'ip6/64',
];
const valid = [
  'a',
  'mx',
  'ptr',
  'a/24',
  'a//64',
  'a:mail.example/24//64',
  'mx/24//64',
  'ip4:192.0.2.1',
  'ip6:2001:db8::1',
];
const now = new Date('2026-10-11T00:00:00Z');

function fixture(policy: string): SpfSenderDnsClient {
  const answer = (values: string[]): SpfLookupResult => ({
    status: 'answer',
    values,
    messageBytes: 100,
    expiresAt: '2026-10-11T01:00:00Z',
  });
  return {
    lookup: (_domain, type) =>
      Promise.resolve(
        type === 'TXT'
          ? answer([policy])
          : type === 'MX'
            ? {
                ...answer(['mail.example']),
                mxRecords: [{ preference: 10, exchange: 'mail.example' }],
              }
            : answer([type === 'A' ? '192.0.2.1' : '2001:db8::1']),
      ),
    lookupPtr: () => Promise.resolve(answer(['mail.example'])),
  };
}

describe('shared SPF grammar corpus', () => {
  it.each(valid)('preserves valid syntax: %s', (term) => {
    expect(parseSpfMechanismSyntax(term)).not.toBeNull();
    expect(
      parseSpfRecord(`v=spf1 ${term} -all`, 'example.test').diagnostics.filter(
        (item) => item.severity === 'error',
      ),
    ).toEqual([]);
  });

  it('keeps all three consumers fail-closed despite successful address and MX evidence', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(...malformed),
        fc.constantFrom('', '+', '-', '~', '?'),
        async (term, qualifier) => {
          const policy = `v=spf1 ${qualifier}${term} -all`;
          expect(parseSpfMechanismSyntax(`${qualifier}${term}`)).toBeNull();
          expect(
            (await analyseSpf('example.test', fixture(policy))).diagnostics.some(
              (item) => item.severity === 'error',
            ),
          ).toBe(true);
          expect((await flattenSpf('example.test', fixture(policy), now)).snapshot.safe).toBe(
            false,
          );
          expect(
            (
              await evaluateSpfSender(
                {
                  ip: '192.0.2.1',
                  heloDomain: 'mail.example',
                  localPart: 'test',
                  mailFromDomain: 'example.test',
                  receiver: 'receiver.example',
                  timestamp: now,
                },
                fixture(policy),
              )
            ).result,
          ).toBe('permerror');
        },
      ),
      { seed: 7112026, numRuns: 60 },
    );
  });
});
