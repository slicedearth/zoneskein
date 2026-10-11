import { describe, expect, it, vi } from 'vitest';

import { decodeChangeWorkspace } from './codec';
import { workspaceExampleFile } from './examples';
import { workspaceValidationReport } from './report';

describe('separate workspace validation report', () => {
  it('binds a report to the exact workspace without changing the project envelope', async () => {
    const file = await workspaceExampleFile('origins');
    const decoded = await decodeChangeWorkspace(new TextEncoder().encode(file));
    if (!decoded.ok) throw new Error(decoded.error.message);
    vi.stubGlobal('__ZONESKEIN_BUILD__', {
      revision: 'a'.repeat(40),
      modified: true,
      sourceSha256: 'b'.repeat(64),
    });
    try {
      const historical: unknown = JSON.parse(
        workspaceValidationReport(
          decoded.value.workspace,
          file,
          {
            state: 'mismatch-accepted',
            claimedDigest: 'c'.repeat(64),
            calculatedDigest: 'd'.repeat(64),
          },
          false,
        ),
      );
      expect(historical).toMatchObject({
        workspaceSchema: 'zoneskein-project-v1',
        build: { revision: 'a'.repeat(40), modified: true },
        validation: {
          analysisSource: 'supplied-or-prior-analysis-not-recomputed',
          authenticity: 'not-established',
          importProvenance: { state: 'mismatch-accepted' },
        },
      });
      expect(
        (
          JSON.parse(
            workspaceValidationReport(
              decoded.value.workspace,
              file,
              { state: 'not-checked' },
              true,
            ),
          ) as { validation: { analysisSource: string } }
        ).validation.analysisSource,
      ).toBe('recomputed-in-this-session');
      expect(Object.keys(JSON.parse(file) as object).sort()).toEqual([
        'format',
        'integrity',
        'workspace',
      ]);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
