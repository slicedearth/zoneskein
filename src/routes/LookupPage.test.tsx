import { encode } from '@dnsquery/dns-packet';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { LookupPage } from './LookupPage';

function answerResponse(): Response {
  const bytes = encode({
    answers: [
      { class: 'IN', data: '192.0.2.25', name: 'lookup-test.example.', ttl: 300, type: 'A' },
    ],
    flags: 0x81a0,
    id: 0,
    questions: [{ class: 'IN', name: 'lookup-test.example.', type: 'A' }],
    type: 'response',
  });
  const body = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(body).set(bytes);
  return new Response(body, {
    headers: { 'Content-Type': 'application/dns-message' },
    status: 200,
  });
}

describe('DNS record explorer', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('rejects unsafe input before any network request', async () => {
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<LookupPage />);

    await user.type(screen.getByLabelText('DNS name'), 'https://example.com/path');
    await user.click(screen.getByRole('button', { name: 'Inspect records' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('DNS name only');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('renders a normalised recursive-resolver response', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(answerResponse());
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<LookupPage />);

    for (const type of ['AAAA', 'MX', 'TXT']) {
      await user.click(screen.getByRole('checkbox', { name: type }));
    }
    await user.type(screen.getByLabelText('DNS name'), 'lookup-test.example');
    await user.click(screen.getByRole('button', { name: 'Inspect records' }));

    expect(await screen.findByText('192.0.2.25')).toBeVisible();
    expect(screen.getByText('Completed 1 DNS questions.')).toBeVisible();
    const [target, init] = fetchMock.mock.calls[0] ?? [];
    if (typeof target !== 'string') throw new Error('Expected a string resolver URL.');
    expect(target).toMatch(/^https:\/\/dns\.google\/dns-query\?dns=/u);
    expect(init).toEqual(expect.objectContaining({ method: 'GET', mode: 'cors' }));
  });
});
