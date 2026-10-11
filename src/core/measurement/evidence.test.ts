import { describe, expect, it } from 'vitest';

import { globalpingEvidenceBundle } from './evidence';
import type { GlobalpingDnsMeasurement } from './globalping';

describe('external measurement evidence', () => {
  it('bounds graph expansion independently of a valid measurement response', () => {
    const answers = Array.from({ length: 256 }, (_, index) => ({
      className: 'IN',
      name: 'example.com.',
      ttl: 300,
      type: 'TXT',
      value: `answer-${String(index)}`,
    }));
    const measurement: GlobalpingDnsMeasurement = {
      completedAt: '2026-08-27T00:00:00.000Z',
      id: 'measurement-1',
      probesCount: 1,
      results: [
        {
          hops: Array.from({ length: 48 }, (_, index) => ({
            answers,
            resolver: `192.0.2.${String(index + 1)}`,
            totalMs: 10,
          })),
          probe: {
            asn: 64_496,
            city: 'Melbourne',
            country: 'Australia',
            network: 'Example network',
          },
          rawOutput: '',
          status: 'finished',
        },
      ],
      target: 'example.com',
    };

    const bundle = globalpingEvidenceBundle(measurement);

    expect(bundle.nodes).toHaveLength(160);
    expect(bundle.links.length).toBeLessThanOrEqual(320);
    expect(bundle.incompleteReasons).toContain(
      'The evidence graph reached its bounded display limit.',
    );
    expect(bundle.status).toBe('partial');
  });
});
