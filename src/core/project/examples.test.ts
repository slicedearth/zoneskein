import { describe, expect, it, vi } from 'vitest';

import { decodeChangeWorkspace } from './codec';
import { editChangeWorkspace } from './create';
import { WORKSPACE_EXAMPLES, workspaceExampleFile } from './examples';

describe('synthetic offline examples', () => {
  it.each(WORKSPACE_EXAMPLES)('retains the expected boundary for $id', async ({ id }) => {
    const network = vi
      .spyOn(globalThis, 'fetch')
      .mockRejectedValue(new Error('Unexpected network'));
    try {
      const result = await decodeChangeWorkspace(
        new TextEncoder().encode(await workspaceExampleFile(id)),
      );
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error(result.error.message);
      expect(result.value.integrity.status).toBe(id === 'quarantine' ? 'mismatch' : 'match');
      expect(result.value.workspace.analysis.status).toBe(
        id === 'incomplete' ? 'partial' : 'complete',
      );
      expect(
        editChangeWorkspace(
          result.value.workspace,
          { title: 'Edited example' },
          { now: () => new Date('2026-10-10T16:00:00Z') },
        ).ok,
      ).toBe(true);
      if (id === 'origins')
        expect(
          result.value.workspace.analysis.changes.some(
            (change) => change.type === 'CNAME' && change.category === 'value-changed',
          ),
        ).toBe(true);
      if (id === 'spf')
        expect(result.value.workspace.analysis.changes[0]?.category).toBe('formatting-only');
      expect(network).not.toHaveBeenCalled();
    } finally {
      network.mockRestore();
    }
  });
});
