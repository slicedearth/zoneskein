import { encode } from '@dnsquery/dns-packet';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { marked } from 'marked';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { DNS_RECORD_TYPES } from '../core/dns/types';
import { LookupPage } from './LookupPage';

vi.mock('../core/doh/rate-limit', () => ({
  BrowserRateLimiter: class {
    imposeCooldown(): void {
      // Lookup route tests exercise presentation, not cross-tab resolver pacing.
    }

    wait(): Promise<void> {
      return Promise.resolve();
    }
  },
}));

function answerResponse(name = 'lookup-test.example.'): Response {
  const bytes = encode({
    answers: [{ class: 'IN', data: '192.0.2.25', name, ttl: 300, type: 'A' }],
    flags: 0x81a0,
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

function txtAnswerResponse(value: string, name = 'markdown-lookup.example.'): Response {
  const bytes = encode({
    answers: [{ class: 'IN', data: [value], name, ttl: 300, type: 'TXT' }],
    flags: 0x81a0,
    id: 0,
    questions: [{ class: 'IN', name, type: 'TXT' }],
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
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('selects every forward type and restores the four documented defaults locally', async () => {
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<LookupPage />);

    await user.click(screen.getByRole('checkbox', { name: 'PTR' }));
    expect(screen.getByRole('checkbox', { name: 'PTR' })).toBeChecked();

    await user.click(screen.getByRole('button', { name: 'Select all' }));
    for (const type of DNS_RECORD_TYPES) {
      const checkbox = screen.getByRole('checkbox', { name: type });
      if (type === 'PTR') expect(checkbox).not.toBeChecked();
      else expect(checkbox).toBeChecked();
    }

    await user.click(screen.getByRole('button', { name: 'Reset to defaults' }));
    for (const type of DNS_RECORD_TYPES) {
      const checkbox = screen.getByRole('checkbox', { name: type });
      if (['A', 'AAAA', 'MX', 'TXT'].includes(type)) expect(checkbox).toBeChecked();
      else expect(checkbox).not.toBeChecked();
    }
    expect(
      screen.getByText(
        new RegExp(`all ${String(DNS_RECORD_TYPES.length - 1)} forward record types`, 'iu'),
      ),
    ).toBeVisible();
    expect(screen.getByRole('button', { name: 'Clear query and results' })).toBeVisible();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('explains the Quad9 transport requirement before a query is sent', async () => {
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<LookupPage />);

    await user.selectOptions(screen.getByLabelText('Resolver'), 'quad9');

    expect(screen.getByLabelText('Resolver')).toHaveAccessibleDescription(
      /end-to-end HTTP\/2 or HTTP\/3 DNS-over-HTTPS path/iu,
    );
    expect(screen.getByText(/inspection proxy.*HTTP\/1\.1/iu)).toBeVisible();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('offers one automatic Quad9 choice with its fallback privacy disclosure', async () => {
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<LookupPage />);

    const resolver = screen.getByLabelText('Resolver');
    expect(within(resolver).getAllByRole('option')).toHaveLength(3);
    expect(within(resolver).getByRole('option', { name: 'Quad9' })).toHaveValue('quad9');
    expect(
      within(resolver).queryByRole('option', { name: 'Quad9 (compatibility mode)' }),
    ).not.toBeInTheDocument();

    await user.selectOptions(resolver, 'quad9');
    expect(resolver).toHaveAccessibleDescription(
      /switches once to the same-origin compatibility relay/iu,
    );
    expect(screen.getByText(/lets Netlify observe the DNS question/iu)).toBeVisible();
    expect(fetchMock).not.toHaveBeenCalled();
  });

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
    expect(screen.getByRole('status', { name: 'DNS lookup status' })).toHaveTextContent(
      'Completed 1 DNS questions.',
    );
    expect(
      screen.getByRole('heading', { level: 2, name: 'Lookup results for lookup-test.example' }),
    ).toBeVisible();
    expect(screen.getByLabelText(/Google Public DNS, NOERROR, 1 answer/iu)).toBeVisible();
    expect(
      screen.getByRole('region', { name: /Google Public DNS A answer records table/iu }),
    ).toBeVisible();
    const [target, init] = fetchMock.mock.calls[0] ?? [];
    if (typeof target !== 'string') throw new Error('Expected a string resolver URL.');
    expect(target).toMatch(/^https:\/\/dns\.google\/dns-query\?dns=/u);
    expect(init).toEqual(expect.objectContaining({ method: 'GET', mode: 'cors' }));
  });

  it('cancels and ignores a pending run when a material input changes', async () => {
    let resolveFetch: ((response: Response) => void) | undefined;
    let requestSignal: AbortSignal | undefined;
    const fetchMock = vi.fn<typeof fetch>((_target, init) => {
      requestSignal = init?.signal ?? undefined;
      return new Promise((resolve) => {
        resolveFetch = resolve;
      });
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<LookupPage />);

    for (const type of ['AAAA', 'MX', 'TXT']) {
      fireEvent.click(screen.getByRole('checkbox', { name: type }));
    }
    const name = screen.getByLabelText('DNS name');
    fireEvent.change(name, { target: { value: 'pending-lookup.example' } });
    fireEvent.click(screen.getByRole('button', { name: 'Inspect records' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    expect(screen.getByRole('status', { name: 'DNS lookup status' })).toHaveTextContent(
      'DNS questions are in progress.',
    );

    fireEvent.change(name, { target: { value: 'replacement-lookup.example' } });
    expect(requestSignal?.aborted).toBe(true);
    resolveFetch?.(answerResponse('pending-lookup.example.'));

    await waitFor(() =>
      expect(screen.getByRole('status', { name: 'DNS lookup status' })).toBeEmptyDOMElement(),
    );
    expect(screen.queryByText('192.0.2.25')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('heading', { name: /Lookup results for/iu }),
    ).not.toBeInTheDocument();
  });

  it('keeps comparison failures and immutable provenance in evidence exports', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    const fetchMock = vi.fn<typeof fetch>((target) => {
      if (typeof target !== 'string') throw new Error('Expected a string resolver URL.');
      if (target.startsWith('https://dns.google/')) {
        return Promise.resolve(answerResponse('comparison-lookup.example.'));
      }
      return Promise.reject(new TypeError('Browser transport rejected the request.'));
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<LookupPage />);

    for (const type of ['AAAA', 'MX', 'TXT']) {
      fireEvent.click(screen.getByRole('checkbox', { name: type }));
    }
    fireEvent.change(screen.getByLabelText('DNS name'), {
      target: { value: 'comparison-lookup.example' },
    });
    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Compare Cloudflare, Google and Quad9' }),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Inspect records' }));

    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Lookup results for comparison-lookup.example',
      }),
    ).toBeVisible();
    expect(screen.getByRole('status', { name: 'DNS lookup status' })).toHaveTextContent(
      'partial results',
    );
    const successSummary = screen.getByLabelText(/Google Public DNS, NOERROR, 1 answer/iu);
    expect(successSummary).toBeVisible();
    expect(successSummary.closest('details')).not.toHaveAttribute('open');
    expect(
      screen.queryByRole('region', { name: /Google Public DNS A answer records table/iu }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText('Raw DNS wire message')).not.toBeInTheDocument();
    fireEvent.click(successSummary);
    expect(
      await screen.findByRole('region', {
        name: /Google Public DNS A answer records table/iu,
      }),
    ).toBeVisible();
    expect(screen.getByText('Raw DNS wire message')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Plain answers unavailable' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'BIND answers unavailable' })).toBeDisabled();
    expect(screen.getAllByText('transport-error')).toHaveLength(2);
    expect(screen.getAllByText(/end-to-end HTTP\/2 or HTTP\/3/iu).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole('button', { name: 'Copy JSON evidence' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    const evidence = JSON.parse(String(writeText.mock.calls[0]?.[0])) as {
      readonly observations: readonly {
        readonly error?: { readonly code: string; readonly message: string };
        readonly outcome: string;
        readonly resolver: { readonly endpoint: string; readonly id: string };
      }[];
      readonly run: {
        readonly comparison: boolean;
        readonly recordTypes: readonly string[];
        readonly resolvers: readonly { readonly id: string }[];
        readonly submittedInput: string;
      };
      readonly schemaVersion: number;
    };
    expect(evidence).toMatchObject({
      run: {
        comparison: true,
        recordTypes: ['A'],
        submittedInput: 'comparison-lookup.example',
      },
      schemaVersion: 1,
    });
    expect(evidence.run.resolvers.map((resolver) => resolver.id)).toEqual([
      'cloudflare',
      'google',
      'quad9-relay',
    ]);
    expect(evidence.observations).toHaveLength(3);
    expect(
      evidence.observations.filter((observation) => observation.outcome === 'error'),
    ).toHaveLength(2);
    expect(
      evidence.observations.find((observation) => observation.resolver.id === 'quad9-relay'),
    ).toMatchObject({
      error: { code: 'transport-error' },
      resolver: { endpoint: '/api/doh/quad9' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Copy Markdown evidence' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(2));
    const markdown = String(writeText.mock.calls[1]?.[0]);
    expect(markdown).toContain('comparison-lookup.example');
    expect(markdown).toContain('### Cloudflare 1.1.1.1 — transport-error');
    expect(markdown).toContain('### Quad9 (compatibility mode) — transport-error');
    expect(markdown).toContain('end-to-end HTTP/2 or HTTP/3');
  });

  it('automatically falls back to the relay and exports that immutable provenance', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    const fetchMock = vi.fn<typeof fetch>((target) => {
      if (typeof target !== 'string') throw new Error('Expected a string resolver URL.');
      if (target.startsWith('https://cloudflare-dns.com/')) {
        return Promise.reject(new TypeError('Cloudflare transport unavailable.'));
      }
      if (target.startsWith('https://dns.quad9.net/')) {
        return Promise.reject(new TypeError('Quad9 direct transport unavailable.'));
      }
      return Promise.resolve(answerResponse('relay-comparison.example.'));
    });
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    render(<LookupPage />);

    for (const type of ['AAAA', 'MX', 'TXT']) {
      await user.click(screen.getByRole('checkbox', { name: type }));
    }
    await user.type(screen.getByLabelText('DNS name'), 'relay-comparison.example');
    await user.click(
      screen.getByRole('checkbox', { name: 'Compare Cloudflare, Google and Quad9' }),
    );
    expect(
      screen.getByText(/switches once to the same-origin compatibility relay/iu),
    ).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Inspect records' }));

    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Lookup results for relay-comparison.example',
      }),
    ).toBeVisible();
    expect(fetchMock).toHaveBeenCalledTimes(4);
    const targets = fetchMock.mock.calls.map(([target]) => {
      if (typeof target !== 'string') throw new Error('Expected a string resolver URL.');
      return target;
    });
    expect(targets).toEqual([
      'https://cloudflare-dns.com/dns-query',
      expect.stringMatching(/^https:\/\/dns\.google\/dns-query\?dns=/u),
      expect.stringMatching(/^https:\/\/dns\.quad9\.net\/dns-query\?dns=/u),
      '/api/doh/quad9',
    ]);
    expect(
      screen.getByLabelText(/Quad9 \(compatibility mode\), NOERROR, 1 answer/iu),
    ).toBeVisible();

    await user.click(screen.getByRole('button', { name: 'Copy JSON evidence' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    const evidence = JSON.parse(String(writeText.mock.calls[0]?.[0])) as {
      readonly observations: readonly {
        readonly resolver: {
          readonly endpoint: string;
          readonly id: string;
          readonly transport: {
            readonly intermediary?: { readonly label: string; readonly privacyUrl: string };
            readonly kind: string;
            readonly upstream?: {
              readonly endpoint: string;
              readonly label: string;
              readonly privacyUrl: string;
            };
          };
        };
      }[];
      readonly run: { readonly resolvers: readonly { readonly id: string }[] };
    };
    expect(evidence.run.resolvers.map((resolver) => resolver.id)).toEqual([
      'cloudflare',
      'google',
      'quad9-relay',
    ]);
    expect(evidence.observations).toHaveLength(3);
    expect(
      evidence.observations.find((observation) => observation.resolver.id === 'quad9-relay')
        ?.resolver,
    ).toMatchObject({
      endpoint: '/api/doh/quad9',
      transport: {
        intermediary: {
          label: 'Netlify',
          privacyUrl: 'https://www.netlify.com/privacy/',
        },
        kind: 'relay',
        upstream: {
          endpoint: 'https://dns.quad9.net/dns-query',
          label: 'Quad9',
          privacyUrl: 'https://quad9.net/privacy/policy/',
        },
      },
    });

    await user.click(screen.getByRole('button', { name: 'Copy Markdown evidence' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(2));
    expect(String(writeText.mock.calls[1]?.[0])).toContain(
      '- Quad9 (compatibility mode): Netlify compatibility relay → Quad9 (https://dns.quad9.net/dns-query)',
    );

    await user.click(
      screen.getByRole('checkbox', { name: 'Compare Cloudflare, Google and Quad9' }),
    );
    expect(
      screen.queryByRole('heading', { name: /Lookup results for/iu }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('status', { name: 'DNS lookup status' })).toBeEmptyDOMElement();
  });

  it('reports a compatibility-relay HTTP 429 without another fallback', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError('Quad9 direct transport unavailable.'))
      .mockResolvedValueOnce(
        new Response('', { headers: { 'Retry-After': '9' }, status: 429 }),
      );
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<LookupPage />);

    for (const type of ['AAAA', 'MX', 'TXT']) {
      await user.click(screen.getByRole('checkbox', { name: type }));
    }
    await user.selectOptions(screen.getByLabelText('Resolver'), 'quad9');
    await user.type(screen.getByLabelText('DNS name'), 'relay-limited.example');
    await user.click(screen.getByRole('button', { name: 'Inspect records' }));

    expect(await screen.findByText('rate-limited')).toBeVisible();
    expect(
      screen.getByText(/Automatic compatibility mode also failed: The resolver rate-limited/iu),
    ).toBeVisible();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1]?.[0]).toBe('/api/doh/quad9');
  });

  it('escapes HTML-like DNS text in Markdown evidence', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    vi.stubGlobal(
      'fetch',
      vi
        .fn<typeof fetch>()
        .mockResolvedValue(txtAnswerResponse('<img src=x onerror=alert(1)> & evidence')),
    );
    render(<LookupPage />);

    for (const type of ['A', 'AAAA', 'MX']) {
      fireEvent.click(screen.getByRole('checkbox', { name: type }));
    }
    fireEvent.change(screen.getByLabelText('DNS name'), {
      target: { value: 'markdown-lookup.example' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Inspect records' }));

    expect((await screen.findAllByText(/img src=x/iu)).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole('button', { name: 'Copy Markdown evidence' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    const markdown = String(writeText.mock.calls[0]?.[0]);
    const html = marked.parse(markdown, { async: false, gfm: true });
    if (typeof html !== 'string')
      throw new Error('Synchronous Markdown parsing returned a promise.');
    const rendered = window.document.createElement('div');
    rendered.innerHTML = html;
    expect(rendered.querySelector('img')).toBeNull();
    expect(rendered.querySelector('a')).toBeNull();
    expect(rendered.textContent).toContain('<img src=x onerror=alert(1)> & evidence');
  });

  it('renders hostile TXT controls visibly and retains exact raw RDATA in JSON evidence', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    vi.stubGlobal(
      'fetch',
      vi
        .fn<typeof fetch>()
        .mockResolvedValue(
          txtAnswerResponse('ordinary 🌏 \u202e\u2066hidden\nline', 'control-lookup.example.'),
        ),
    );
    render(<LookupPage />);
    for (const type of ['A', 'AAAA', 'MX']) {
      fireEvent.click(screen.getByRole('checkbox', { name: type }));
    }
    fireEvent.change(screen.getByLabelText('DNS name'), {
      target: { value: 'control-lookup.example' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Inspect records' }));

    const visible = await screen.findAllByText(
      /ordinary 🌏.*\\u\{202E\}.*\\u\{2066\}hidden\\nline/iu,
    );
    expect(visible.some((element) => element.getAttribute('dir') === 'ltr')).toBe(true);
    expect(document.body.textContent).not.toContain('\u202e');

    fireEvent.click(screen.getByRole('button', { name: 'Copy JSON evidence' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    const evidence = JSON.parse(String(writeText.mock.calls[0]?.[0])) as {
      observations: {
        response: {
          answerRecords: {
            data: string;
            rawRdata: { encoding: string; octets: number; value: string };
          }[];
        };
      }[];
      textProjection?: string;
    };
    const record = evidence.observations[0]?.response.answerRecords[0];
    expect(evidence.textProjection).toBe('visible-escapes-v1');
    expect(record?.data).toContain('\\u{202E}\\u{2066}');
    expect(record?.data).not.toContain('\u202e');
    expect(record?.rawRdata.encoding).toBe('base64');
    expect(typeof record?.rawRdata.octets).toBe('number');
    expect(typeof record?.rawRdata.value).toBe('string');
  });

  it('groups comparison observations by record type before resolver', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockRejectedValue(new TypeError('Transport unavailable.')),
    );
    render(<LookupPage />);

    for (const type of ['MX', 'TXT']) {
      fireEvent.click(screen.getByRole('checkbox', { name: type }));
    }
    fireEvent.change(screen.getByLabelText('DNS name'), {
      target: { value: 'type-major-lookup.example' },
    });
    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Compare Cloudflare, Google and Quad9' }),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Inspect records' }));

    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Lookup results for type-major-lookup.example',
      }),
    ).toBeVisible();
    const groups = screen.getAllByRole('heading', { level: 3 });
    expect(groups.map((heading) => heading.textContent)).toEqual(['A records', 'AAAA records']);
    for (const heading of groups) {
      const group = heading.closest('.lookup-result-group');
      if (!(group instanceof HTMLElement)) throw new Error('Expected a lookup result group.');
      expect(within(group).getAllByText('transport-error')).toHaveLength(3);
    }
  });
});
