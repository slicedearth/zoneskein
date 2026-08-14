import { fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ChangeWorkspace } from '../core/project';
import { RecordStudioPage } from './RecordStudioPage';

const RECORD_TYPES = [
  'A',
  'AAAA',
  'CAA',
  'CNAME',
  'DNSKEY',
  'DS',
  'HTTPS',
  'MX',
  'NAPTR',
  'NS',
  'PTR',
  'SOA',
  'SRV',
  'SSHFP',
  'SVCB',
  'TLSA',
  'TXT',
  'URI',
];

describe('DNS Record Studio', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('offers every supported authoring type through a labelled selector', () => {
    render(<RecordStudioPage />);

    const selector = screen.getByRole('combobox', { name: 'Record type' });
    expect(selector).toBeVisible();
    expect(
      within(selector)
        .getAllByRole('option')
        .map((option) => option.textContent),
    ).toEqual(RECORD_TYPES);
  });

  it('adds one canonical record, rejects its duplicate, and lints the working set', async () => {
    const user = userEvent.setup();
    render(<RecordStudioPage />);

    await user.type(screen.getByRole('textbox', { name: 'Owner name' }), 'www.example.com.');
    await user.type(screen.getByRole('textbox', { name: 'IPv4 address' }), '192.0.2.10');

    const add = screen.getByRole('button', { name: 'Add valid record' });
    expect(add).toBeEnabled();
    await user.click(add);

    const workingSet = screen.getByRole('region', { name: 'Working set' });
    expect(within(workingSet).getByText('www.example.com. 3600 IN A 192.0.2.10')).toBeVisible();
    expect(within(workingSet).getByText('1 / 256 records')).toBeVisible();

    await user.click(add);
    expect(
      screen.getByText('That canonical BIND record is already in the working set.'),
    ).toBeVisible();
    expect(within(workingSet).getByText('1 / 256 records')).toBeVisible();

    await user.click(within(workingSet).getByRole('button', { name: 'Lint working set' }));
    expect(within(workingSet).getByText('No diagnostics')).toBeVisible();
  });

  it('shows UTF-8-aware TXT chunks before a record is added', async () => {
    const user = userEvent.setup();
    render(<RecordStudioPage />);

    await user.type(screen.getByRole('textbox', { name: 'Owner name' }), 'text.example.com.');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Record type' }), 'TXT');
    fireEvent.change(screen.getByRole('textbox', { name: 'Text value' }), {
      target: { value: 'é'.repeat(128) },
    });

    expect(screen.getByText('2 chunks')).toBeVisible();
    const chunks = screen.getByRole('table', {
      name: 'TXT chunks split at UTF-8 octet boundaries',
    });
    expect(within(chunks).getAllByRole('row')).toHaveLength(3);
    expect(within(chunks).getAllByText('254')).toHaveLength(1);
    expect(within(chunks).getAllByText('2')).toHaveLength(2);
  });

  it('hands a bounded working set to an in-memory workspace without querying DNS', async () => {
    const user = userEvent.setup();
    const fetch = vi.fn();
    const onCreateWorkspace = vi.fn<(workspace: ChangeWorkspace) => void>();
    vi.stubGlobal('fetch', fetch);
    render(<RecordStudioPage onCreateWorkspace={onCreateWorkspace} />);

    await user.type(screen.getByRole('textbox', { name: 'Owner name' }), 'www.example.com.');
    await user.type(screen.getByRole('textbox', { name: 'IPv4 address' }), '192.0.2.10');
    await user.click(screen.getByRole('button', { name: 'Add valid record' }));
    await user.click(screen.getByRole('button', { name: 'Open in Change Workspace' }));

    expect(fetch).not.toHaveBeenCalled();
    expect(onCreateWorkspace).toHaveBeenCalledOnce();
    expect(onCreateWorkspace.mock.calls[0]?.[0]).toMatchObject({
      analysis: { status: 'not-run' },
      current: {
        incompleteReasons: [
          'No current-zone snapshot accompanied this Record Studio hand-off.',
        ],
        origin: null,
        source: '',
        status: 'unavailable',
      },
      evidence: { incompleteReasons: [], runs: [], status: 'none' },
      intended: {
        incompleteReasons: [],
        origin: null,
        source: 'www.example.com. 3600 IN A 192.0.2.10',
        status: 'complete',
      },
    });
  });
});
