import { chunkTxtValue } from '../zone/authoring';
import { createChangeLabWorkspace } from './create';
import { encodeChangeWorkspace } from './codec';

export const WORKSPACE_EXAMPLES = [
  {
    id: 'origins',
    title: 'Multi-origin migration',
    expected:
      'One CNAME target changes from old.example.test to new.example.test. Both targets are supplied; no missing-target warning is expected.',
  },
  {
    id: 'spf',
    title: 'Long SPF strings',
    expected:
      'The same synthetic SPF value uses different TXT string boundaries. Expect application-level equivalence, not canonical-wire equality. No DNS is queried.',
  },
  {
    id: 'incomplete',
    title: 'Incomplete resolver evidence',
    expected:
      'Only A records were observed. MX and other types remain unknown; the analysis must remain partial, never a complete migration assessment.',
  },
  {
    id: 'quarantine',
    title: 'Integrity quarantine',
    expected:
      'A deliberately altered synthetic file must remain quarantined until explicitly accepted. A matching digest would still not authenticate its author.',
  },
] as const;
export type WorkspaceExampleId = (typeof WORKSPACE_EXAMPLES)[number]['id'];

export async function workspaceExampleFile(id: WorkspaceExampleId): Promise<string> {
  const base =
    '$ORIGIN example.test.\n$ORIGIN old.example.test.\nwww.example.test. 300 IN CNAME target\ntarget 300 IN A 192.0.2.1';
  const spf = `v=spf1 ${Array.from({ length: 32 }, (_, i) => `ip4:198.51.${String(i)}.1/32`).join(' ')} -all`;
  const txt = (chunks: readonly string[]) =>
    `example.test. 300 IN TXT (${chunks.map((chunk) => JSON.stringify(chunk)).join(' ')})`;
  const example = WORKSPACE_EXAMPLES.find((item) => item.id === id);
  const created = createChangeLabWorkspace(
    {
      title: `Synthetic: ${example?.title ?? id}`,
      origin: 'example.test.',
      currentSource:
        id === 'spf'
          ? txt(chunkTxtValue(spf))
          : id === 'incomplete'
            ? 'www 300 IN A 192.0.2.1'
            : base,
      intendedSource:
        id === 'spf'
          ? txt([spf.slice(0, 200), ...chunkTxtValue(spf.slice(200))])
          : id === 'incomplete'
            ? 'www 300 IN A 192.0.2.2'
            : base.replaceAll('old.example.test.', 'new.example.test.'),
      ...(id === 'incomplete'
        ? {
            currentStatus: 'partial' as const,
            currentIncompleteReasons: [
              'Synthetic resolver observation: A only; MX timed out and other types were not selected.',
            ],
          }
        : {}),
    },
    {
      now: () => new Date('2026-01-01T00:00:00Z'),
      uuid: () => '00000000-0000-4000-8000-000000000011',
    },
  );
  if (!created.ok) throw new Error(created.error.message);
  const encoded = await encodeChangeWorkspace(created.value);
  if (!encoded.ok) throw new Error(encoded.error.message);
  return id === 'quarantine'
    ? encoded.value.replace('Synthetic: Integrity quarantine', 'Synthetic: Altered quarantine')
    : encoded.value;
}
