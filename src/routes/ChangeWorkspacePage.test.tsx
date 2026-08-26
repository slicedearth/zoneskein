import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  CHANGE_WORKSPACE_LIMITS,
  createChangeLabWorkspace,
  editChangeWorkspace,
  encodeChangeWorkspace,
  parseChangeWorkspace,
  type ChangeWorkspace,
} from '../core/project';
import { ChangeWorkspacePage } from './ChangeWorkspacePage';

const encoder = new TextEncoder();
const originalCreateObjectUrl = Object.getOwnPropertyDescriptor(URL, 'createObjectURL');
const originalRevokeObjectUrl = Object.getOwnPropertyDescriptor(URL, 'revokeObjectURL');
const createObjectUrl = vi.fn(() => 'blob:https://zoneskein.test/workspace');
const revokeObjectUrl = vi.fn<(url: string) => void>();

function uuid(index: number): string {
  return `00000000-0000-4000-8000-${index.toString(16).padStart(12, '0')}`;
}

function workspace(title = 'Address rollout'): ChangeWorkspace {
  const created = createChangeLabWorkspace(
    {
      currentSource: 'www 300 IN A 192.0.2.1',
      intendedSource: 'www 300 IN A 192.0.2.2',
      origin: 'example.test.',
      title,
    },
    {
      now: () => new Date('2020-08-14T01:00:00.000Z'),
      uuid: () => uuid(1),
    },
  );
  if (!created.ok) throw new Error(created.error.message);
  return created.value;
}

function workspaceWithEndpoint(): ChangeWorkspace {
  const base = workspace('Imported provenance');
  const parsed = parseChangeWorkspace({
    ...base,
    evidence: {
      incompleteReasons: [],
      runs: [
        {
          completedAt: '2020-08-14T01:03:00.000Z',
          id: uuid(2),
          incompleteReasons: [],
          resolvers: [
            {
              endpoint:
                'https://attacker.example.test/dns-query?next=javascript%3Aalert%281%29',
              id: uuid(3),
              incompleteReasons: [],
              label: 'Imported resolver',
              questions: [
                {
                  authenticatedData: true,
                  className: 'IN',
                  error: null,
                  id: uuid(4),
                  name: 'www.example.test.',
                  observedAt: '2020-08-14T01:02:00.000Z',
                  records: ['www.example.test. 300 IN A 192.0.2.1'],
                  responseCode: 0,
                  status: 'answer',
                  type: 'A',
                },
              ],
              resolverId: 'custom',
              status: 'complete',
            },
          ],
          startedAt: '2020-08-14T01:01:00.000Z',
          status: 'complete',
        },
      ],
      status: 'complete',
    },
  });
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

async function serialised(value: ChangeWorkspace): Promise<string> {
  const encoded = await encodeChangeWorkspace(value);
  if (!encoded.ok) throw new Error(encoded.error.message);
  return encoded.value;
}

function buffer(text: string): ArrayBuffer {
  const bytes = encoder.encode(text);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function localFile(text: string, name = 'workspace.zoneskein.json'): File {
  const bytes = buffer(text);
  return {
    arrayBuffer: vi.fn(() => Promise.resolve(bytes)),
    name,
    size: bytes.byteLength,
  } as unknown as File;
}

function chooseFile(file: File): void {
  fireEvent.change(screen.getByLabelText('Import workspace file'), {
    target: { files: [file] },
  });
}

describe('local Change Workspace', () => {
  beforeEach(() => {
    createObjectUrl.mockClear();
    revokeObjectUrl.mockClear();
    Object.defineProperty(URL, 'createObjectURL', {
      configurable: true,
      value: createObjectUrl,
    });
    Object.defineProperty(URL, 'revokeObjectURL', {
      configurable: true,
      value: revokeObjectUrl,
    });
  });

  afterEach(() => {
    if (originalCreateObjectUrl === undefined)
      delete (URL as { createObjectURL?: unknown }).createObjectURL;
    else Object.defineProperty(URL, 'createObjectURL', originalCreateObjectUrl);
    if (originalRevokeObjectUrl === undefined)
      delete (URL as { revokeObjectURL?: unknown }).revokeObjectURL;
    else Object.defineProperty(URL, 'revokeObjectURL', originalRevokeObjectUrl);
    vi.unstubAllGlobals();
  });

  it('imports a valid strict workspace and reports the accepted active state', async () => {
    const imported = workspace('Validated import');
    const onWorkspaceChange = vi.fn();
    render(
      <ChangeWorkspacePage
        initialWorkspace={workspace('Existing workspace')}
        onWorkspaceChange={onWorkspaceChange}
      />,
    );

    chooseFile(localFile(await serialised(imported)));

    expect(
      await screen.findByText(/Workspace imported after strict schema and digest validation/iu),
    ).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Validated import' })).toBeVisible();
    expect(screen.getByText(/^SHA-256 internally consistent:/u)).toBeVisible();
    expect(screen.getByText(/exported JSON is not encrypted/iu)).toBeVisible();
    expect(screen.getByText(/stored analysis supplied with or captured into/iu)).toBeVisible();
    expect(onWorkspaceChange).toHaveBeenCalledTimes(1);
    expect(onWorkspaceChange).toHaveBeenLastCalledWith(imported);
  });

  it('rejects an oversized file before reading and rejects malformed or hostile schemas', async () => {
    render(<ChangeWorkspacePage initialWorkspace={workspace()} />);
    const read = vi.fn(() => Promise.resolve(new ArrayBuffer(0)));
    chooseFile({
      arrayBuffer: read,
      name: 'oversized.json',
      size: CHANGE_WORKSPACE_LIMITS.fileOctets + 1,
    } as unknown as File);

    expect(screen.getByRole('alert')).toHaveTextContent(/file is too large/iu);
    expect(read).not.toHaveBeenCalled();

    chooseFile(localFile('{"format":"zoneskein-project-v1","__proto__":{}}'));
    expect(await screen.findByRole('alert')).toHaveTextContent(/Object keys must be exactly/iu);

    chooseFile(localFile('{'));
    expect(await screen.findByRole('alert')).toHaveTextContent(/malformed JSON/iu);
    expect(screen.getByRole('heading', { name: 'Address rollout' })).toBeVisible();
  });

  it('quarantines a digest mismatch until explicit acknowledgement and keeps its warning', async () => {
    const onWorkspaceChange = vi.fn<(next: ChangeWorkspace) => void>();
    const object = JSON.parse(await serialised(workspace('Original title'))) as {
      workspace: { title: string };
    };
    object.workspace.title = 'Altered title';
    render(
      <ChangeWorkspacePage
        initialWorkspace={workspace('Active title')}
        onWorkspaceChange={onWorkspaceChange}
      />,
    );

    chooseFile(localFile(JSON.stringify(object)));

    expect(
      await screen.findByRole('heading', { name: 'Digest mismatch quarantine' }),
    ).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Active title' })).toBeVisible();
    expect(onWorkspaceChange).not.toHaveBeenCalled();
    const accept = screen.getByRole('button', { name: 'Accept altered workspace' });
    expect(accept).toBeDisabled();
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: /I understand that this file was altered/iu,
      }),
    );
    fireEvent.click(accept);

    expect(screen.getByRole('heading', { name: 'Altered title' })).toBeVisible();
    expect(screen.getByText(/explicitly accepted after a SHA-256 mismatch/iu)).toBeVisible();
    expect(onWorkspaceChange).toHaveBeenCalledTimes(1);

    fireEvent.change(screen.getByLabelText('Workspace title'), {
      target: { value: 'Locally renamed' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Apply edits' }));
    expect(screen.getByText(/explicitly accepted after a SHA-256 mismatch/iu)).toBeVisible();
  });

  it('renders imported resolver endpoints as inert text and never contacts them', async () => {
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal('fetch', fetchMock);
    render(<ChangeWorkspacePage initialWorkspace={workspace()} />);

    chooseFile(localFile(await serialised(workspaceWithEndpoint())));

    const endpoint = await screen.findByText(
      'https://attacker.example.test/dns-query?next=javascript%3Aalert%281%29',
    );
    expect(endpoint.tagName).toBe('CODE');
    expect(endpoint.closest('a')).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('keeps unavailable states unknown and blocks analysis and Change Lab hand-off', () => {
    const unavailable = editChangeWorkspace(workspace(), {
      current: {
        incompleteReasons: ['The current snapshot was not supplied.'],
        origin: null,
        source: '',
        status: 'unavailable',
      },
      intended: {
        incompleteReasons: ['The proposed snapshot was not supplied.'],
        origin: null,
        source: '',
        status: 'unavailable',
      },
    });
    if (!unavailable.ok) throw new Error(unavailable.error.message);
    const open = vi.fn();
    render(<ChangeWorkspacePage initialWorkspace={unavailable.value} onOpenChangeLab={open} />);

    expect(screen.getByText(/absence is not treated as an empty zone/iu)).toBeVisible();
    expect(screen.getByRole('button', { name: 'Reanalyse' })).toBeDisabled();
    const handoff = screen.getByRole('button', { name: 'Open in Change Lab' });
    expect(handoff).toBeDisabled();
    fireEvent.click(handoff);
    expect(open).not.toHaveBeenCalled();
  });

  it('labels a partial analysis without claiming an overall risk', () => {
    const partial = createChangeLabWorkspace({
      currentIncompleteReasons: ['Only selected record types were observed.'],
      currentSource: 'www 300 IN A 192.0.2.1',
      currentStatus: 'partial',
      intendedSource: 'www 300 IN A 192.0.2.2',
      origin: 'example.test.',
      title: 'Scoped observation',
    });
    if (!partial.ok) throw new Error(partial.error.message);

    render(<ChangeWorkspacePage initialWorkspace={partial.value} />);

    expect(screen.getByText('Overall risk unknown')).toBeVisible();
    expect(screen.getByText(/Only selected record types were observed/iu)).toBeVisible();
  });

  it('invalidates stored analysis when zone text changes and emits the new workspace', () => {
    const onWorkspaceChange = vi.fn<(next: ChangeWorkspace) => void>();
    render(
      <ChangeWorkspacePage
        initialWorkspace={workspace()}
        onWorkspaceChange={onWorkspaceChange}
      />,
    );
    expect(screen.getByText('Analysed changes')).toBeVisible();

    fireEvent.change(screen.getByLabelText('Intended BIND-style zone text'), {
      target: { value: 'www 300 IN A 192.0.2.99' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Apply edits' }));

    expect(screen.getByText(/Stored analysis was invalidated/iu)).toBeVisible();
    expect(screen.getByText('Analysis not run')).toBeVisible();
    expect(screen.queryByText('Analysed changes')).not.toBeInTheDocument();
    expect(onWorkspaceChange).toHaveBeenCalledTimes(1);
    expect(onWorkspaceChange.mock.lastCall?.[0].analysis.status).toBe('not-run');
  });

  it('uses a safe export filename and revokes the object URL immediately', async () => {
    let downloaded = '';
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      downloaded = this.download;
    });
    render(<ChangeWorkspacePage initialWorkspace={workspace('../../Café production')} />);

    fireEvent.click(screen.getByRole('button', { name: 'Export JSON' }));

    expect(await screen.findByText(/Workspace exported as/iu)).toBeVisible();
    expect(downloaded).toBe('zoneskein-cafe-production.zoneskein.json');
    expect(createObjectUrl).toHaveBeenCalledTimes(1);
    expect(revokeObjectUrl).toHaveBeenCalledWith('blob:https://zoneskein.test/workspace');
  });

  it('does not let a late import overwrite a newer local clear', async () => {
    let resolveRead: ((value: ArrayBuffer) => void) | undefined;
    const pendingRead = new Promise<ArrayBuffer>((resolve) => {
      resolveRead = resolve;
    });
    const imported = await serialised(workspace('Late import'));
    const onWorkspaceChange = vi.fn();
    render(
      <ChangeWorkspacePage
        initialWorkspace={workspace('Before clear')}
        onWorkspaceChange={onWorkspaceChange}
      />,
    );
    chooseFile({
      arrayBuffer: vi.fn(() => pendingRead),
      name: 'late.json',
      size: encoder.encode(imported).byteLength,
    } as unknown as File);
    expect(await screen.findByText(/Reading and validating/iu)).toBeVisible();

    fireEvent.click(screen.getByRole('button', { name: 'Clear workspace' }));
    expect(screen.getByRole('heading', { name: 'Untitled change workspace' })).toBeVisible();
    resolveRead?.(buffer(imported));

    await waitFor(() => expect(screen.queryByText(/Reading and validating/iu)).toBeNull());
    expect(screen.getByRole('heading', { name: 'Untitled change workspace' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Late import' })).not.toBeInTheDocument();
    expect(onWorkspaceChange).toHaveBeenCalledTimes(1);
  });

  it('does not download a stale export after the workspace is cleared', async () => {
    let resolveDigest: ((value: ArrayBuffer) => void) | undefined;
    const digest = new Promise<ArrayBuffer>((resolve) => {
      resolveDigest = resolve;
    });
    let digestCompleted = false;
    const subtle = {
      digest: vi.fn(async () => {
        const value = await digest;
        digestCompleted = true;
        return value;
      }),
    };
    vi.stubGlobal('crypto', { randomUUID: () => uuid(8), subtle });
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);
    render(<ChangeWorkspacePage initialWorkspace={workspace('Before clear')} />);

    fireEvent.click(screen.getByRole('button', { name: 'Export JSON' }));
    fireEvent.click(screen.getByRole('button', { name: 'Clear workspace' }));
    resolveDigest?.(new Uint8Array(32).buffer);

    await waitFor(() => expect(digestCompleted).toBe(true));
    expect(click).not.toHaveBeenCalled();
    expect(screen.getByRole('heading', { name: 'Untitled change workspace' })).toBeVisible();
  });
});
