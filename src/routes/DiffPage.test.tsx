import { encode } from '@dnsquery/dns-packet';
import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { DnsQueryError } from '../core/dns/types';
import { WireDnsResolver } from '../core/doh/wire-resolver';
import { DiffPage } from './DiffPage';

function dnsResponse(
  answers: Parameters<typeof encode>[0]['answers'],
  name = 'change.example.',
): Response {
  const bytes = encode({
    answers,
    flags: 0x8180,
    id: 0,
    questions: [{ class: 'IN', name, type: 'A' }],
    type: 'response',
  });
  const body = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(body).set(bytes);
  return new Response(body, {
    headers: { 'Content-Type': 'application/dns-message' },
    status: 200,
  });
}

function selectOnlyA(domain = 'change.example'): void {
  fireEvent.click(screen.getByRole('button', { name: 'Current DNS + proposed' }));
  for (const type of ['AAAA', 'MX', 'TXT', 'CAA']) {
    fireEvent.click(screen.getByRole('checkbox', { name: type }));
  }
  fireEvent.change(screen.getByLabelText('Current DNS name'), {
    target: { value: domain },
  });
}

describe('DNS Change Lab current snapshot binding', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('includes only requested-owner and reachable-alias records', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      dnsResponse([
        {
          class: 'IN',
          data: 'edge.example.',
          name: 'change.example.',
          ttl: 60,
          type: 'CNAME',
        },
        {
          class: 'IN',
          data: '192.0.2.25',
          name: 'edge.example.',
          ttl: 300,
          type: 'A',
        },
        {
          class: 'IN',
          data: '203.0.113.99',
          name: 'sibling.example.',
          ttl: 1,
          type: 'A',
        },
      ]),
    );
    vi.stubGlobal('fetch', fetchMock);
    render(<DiffPage />);
    selectOnlyA();
    fireEvent.change(screen.getByLabelText('Proposed snapshot'), {
      target: {
        value: 'change.example. 60 IN CNAME edge.example.\nedge.example. 300 IN A 192.0.2.25',
      },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));

    expect(await screen.findByText('Comparison found 0 classified changes.')).toBeVisible();
    const snapshot = screen.getByText(
      (_, element) =>
        element !== null &&
        element.tagName === 'PRE' &&
        element.textContent.includes('192.0.2.25'),
    );
    expect(snapshot).toHaveTextContent('change.example. 60 IN CNAME edge.example.');
    expect(snapshot).toHaveTextContent('edge.example. 300 IN A 192.0.2.25');
    expect(snapshot).not.toHaveTextContent('sibling.example');
    expect(snapshot).not.toHaveTextContent('203.0.113.99');
  });

  it('surfaces an ambiguous reachable alias RRset as an incomplete type', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue(
        dnsResponse(
          [
            {
              class: 'IN',
              data: 'one.example.',
              name: 'ambiguous.example.',
              ttl: 60,
              type: 'CNAME',
            },
            {
              class: 'IN',
              data: 'two.example.',
              name: 'ambiguous.example.',
              ttl: 60,
              type: 'CNAME',
            },
            {
              class: 'IN',
              data: '192.0.2.25',
              name: 'one.example.',
              ttl: 300,
              type: 'A',
            },
          ],
          'ambiguous.example.',
        ),
      ),
    );
    render(<DiffPage />);
    selectOnlyA('ambiguous.example');

    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));

    const partial = (await screen.findByText('Partial current view')).closest('article');
    expect(partial).not.toBeNull();
    expect(partial).toHaveTextContent(
      /A: The DNS answer contains an invalid or ambiguous CNAME RRset\./u,
    );
    expect(screen.getByText('No selected records were returned.')).toBeInTheDocument();
  });

  it('uses the run cancellation state instead of matching an error message', async () => {
    vi.spyOn(WireDnsResolver.prototype, 'query').mockImplementation(
      (_question, options) =>
        new Promise((_resolve, reject) => {
          options.signal?.addEventListener(
            'abort',
            () => reject(new DnsQueryError('aborted', 'Request stopped by the operator.')),
            { once: true },
          );
        }),
    );
    render(<DiffPage />);
    selectOnlyA('cancel.example');
    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));

    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }));

    expect(await screen.findByText('The current-DNS query was cancelled.')).toBeVisible();
    expect(screen.queryByText(/Comparison found/u)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();
  });
});
