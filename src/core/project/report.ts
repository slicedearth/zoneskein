import type { ChangeWorkspace, ChangeWorkspaceIntegrityProvenance } from './types';

/** Separate report: the exact-key zoneskein-project-v1 envelope is unchanged. */
export function workspaceValidationReport(
  workspace: ChangeWorkspace,
  envelopeJson: string,
  integrity: ChangeWorkspaceIntegrityProvenance,
  recomputedInSession: boolean,
): string {
  const envelope = JSON.parse(envelopeJson) as { integrity: { digest: string } };
  return JSON.stringify(
    {
      format: 'zoneskein-workspace-validation-report-v1',
      workspaceSchema: 'zoneskein-project-v1',
      workspaceId: workspace.id,
      workspaceDigest: envelope.integrity.digest,
      build:
        typeof __ZONESKEIN_BUILD__ === 'undefined'
          ? { revision: null, modified: null, sourceSha256: null }
          : __ZONESKEIN_BUILD__,
      validation: {
        schema: 'validated',
        integrity: 'fresh-internal-consistency-digest',
        authenticity: 'not-established',
        analysisSource: recomputedInSession
          ? 'recomputed-in-this-session'
          : 'supplied-or-prior-analysis-not-recomputed',
        analysisStatus: workspace.analysis.status,
        analysedAt: workspace.analysis.analysedAt,
        importProvenance: integrity,
      },
      generatedAt: new Date().toISOString(),
    },
    null,
    2,
  );
}
