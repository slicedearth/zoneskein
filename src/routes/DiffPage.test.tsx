import { encode } from '@dnsquery/dns-packet';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { marked } from 'marked';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ChangeWorkspace } from '../core/project';
import { DnsQueryError } from '../core/dns/types';
import { decodeDnsMessage } from '../core/dns/wire';
import { WireDnsResolver } from '../core/doh/wire-resolver';
import { RESOLVERS } from '../core/doh/resolvers';
import { ZONE_ANALYSIS_LIMITS } from '../core/zone/parser';
import { DiffPage } from './DiffPage';

vi.mock('../core/doh/rate-limit', () => ({
  BrowserRateLimiter: class {
    imposeCooldown(): void {
      // Route tests retain the wire resolver but exercise pacing in its dedicated suite.
    }

    wait(): Promise<void> {
      return Promise.resolve();
    }
  },
}));

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
  const labels = domain.replace(/\.$/u, '').split('.');
  fireEvent.change(screen.getByLabelText('Authoritative zone origin'), {
    target: { value: labels.length > 1 ? labels.slice(1).join('.') : domain },
  });
}

describe('DNS Change Lab', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('separates requested-owner state from reachable alias dependencies', async () => {
    const onCreateWorkspace = vi.fn<(workspace: ChangeWorkspace) => void>();
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      dnsResponse([
        {
          class: 'IN',
          data: 'edge.cdn.example.net.',
          name: 'change.example.',
          ttl: 60,
          type: 'CNAME',
        },
        {
          class: 'IN',
          data: '192.0.2.25',
          name: 'edge.cdn.example.net.',
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
    render(<DiffPage onCreateWorkspace={onCreateWorkspace} />);
    selectOnlyA();
    fireEvent.change(screen.getByLabelText('Proposed snapshot'), {
      target: {
        value: 'change.example. 60 IN CNAME edge.cdn.example.net.',
      },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));

    expect(
      await screen.findByText('Comparison found 0 classified changes.', {}, { timeout: 3000 }),
    ).toBeVisible();
    const controlled = screen
      .getByText('Observed controlled-owner snapshot')
      .closest('details');
    expect(controlled).not.toBeNull();
    expect(controlled).toHaveTextContent('change.example. 60 IN CNAME edge.cdn.example.net.');
    expect(controlled).not.toHaveTextContent('192.0.2.25');
    const dependencies = screen
      .getByText('Observed alias dependency evidence')
      .closest('details');
    expect(dependencies).not.toBeNull();
    expect(dependencies).toHaveTextContent('edge.cdn.example.net. 300 IN A 192.0.2.25');
    expect(dependencies).not.toHaveTextContent('sibling.example');
    expect(dependencies).not.toHaveTextContent('203.0.113.99');
    expect(screen.queryByText('zone-apex-cname')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Open in Change Workspace' }));
    const workspace = onCreateWorkspace.mock.calls[0]?.[0];
    expect(workspace).toMatchObject({
      analysis: { status: 'partial' },
      current: {
        incompleteReasons: [
          'Live comparison covers only change.example. for the selected A record types within the declared example. authoritative zone; other owners, unselected types and delegation boundaries remain unknown.',
        ],
        origin: 'example.',
        source: 'change.example. 60 IN CNAME edge.cdn.example.net.',
        status: 'partial',
      },
      evidence: { status: 'complete' },
    });
    const evidenceRecords = workspace?.evidence.runs[0]?.resolvers[0]?.questions[0]?.records;
    expect(evidenceRecords).toEqual([
      'change.example. 60 IN CNAME edge.cdn.example.net.',
      'edge.cdn.example.net. 300 IN A 192.0.2.25',
    ]);
  });

  it('captures the explicit Netlify relay path as inert Change Workspace evidence', async () => {
    const onCreateWorkspace = vi.fn<(workspace: ChangeWorkspace) => void>();
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      dnsResponse(
        [
          {
            class: 'IN',
            data: '192.0.2.45',
            name: 'relay-workspace.example.',
            ttl: 300,
            type: 'A',
          },
        ],
        'relay-workspace.example.',
      ),
    );
    vi.stubGlobal('fetch', fetchMock);
    render(<DiffPage onCreateWorkspace={onCreateWorkspace} />);
    selectOnlyA('relay-workspace.example');
    fireEvent.change(screen.getByLabelText('Resolver'), {
      target: { value: 'quad9-relay' },
    });
    const resolverNote = screen.getByText(/DNS question and connection metadata to Netlify/iu);
    expect(resolverNote).toHaveAttribute('id', 'diff-resolver-note');
    expect(screen.getByLabelText('Resolver')).toHaveAttribute(
      'aria-describedby',
      'diff-resolver-note',
    );
    fireEvent.change(screen.getByLabelText('Proposed snapshot'), {
      target: { value: 'relay-workspace.example. 300 IN A 192.0.2.45' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));

    expect(await screen.findByText('Comparison found 0 classified changes.')).toBeVisible();
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/doh/quad9');
    fireEvent.click(screen.getByRole('button', { name: 'Open in Change Workspace' }));
    expect(onCreateWorkspace.mock.calls[0]?.[0].evidence.runs[0]?.resolvers[0]).toMatchObject({
      endpoint: '/api/doh/quad9',
      label: 'Quad9 (compatibility mode)',
      resolverId: 'quad9-relay',
    });
  });

  it('requires the current name to be inside an explicitly declared zone boundary', () => {
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal('fetch', fetchMock);
    render(<DiffPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Current DNS + proposed' }));
    fireEvent.change(screen.getByLabelText('Current DNS name'), {
      target: { value: 'www.example.com' },
    });
    fireEvent.change(screen.getByLabelText('Authoritative zone origin'), {
      target: { value: 'unrelated.example' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));

    expect(screen.getByRole('alert')).toHaveTextContent(
      'The current DNS name must be the zone origin or a name beneath it.',
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('excludes proposed records at unobserved owners from a live comparison', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue(
        dnsResponse(
          [
            {
              class: 'IN',
              data: '192.0.2.1',
              name: 'scoped.example.',
              ttl: 300,
              type: 'A',
            },
          ],
          'scoped.example.',
        ),
      ),
    );
    render(<DiffPage />);
    selectOnlyA('scoped.example');
    fireEvent.change(screen.getByLabelText('Proposed snapshot'), {
      target: {
        value: 'scoped.example. 300 IN A 192.0.2.1\nother.example. 300 IN A 192.0.2.2',
      },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));

    expect(await screen.findByText('Comparison found 0 classified changes.')).toBeVisible();
    expect(
      screen.getAllByText(/1 proposed record at another owner was excluded/iu).length,
    ).toBeGreaterThan(0);
    expect(screen.queryByText(/192\.0\.2\.2.*added/iu)).not.toBeInTheDocument();
  });

  it('surfaces an ambiguous reachable alias RRset as an incomplete type', async () => {
    const onCreateWorkspace = vi.fn<(workspace: ChangeWorkspace) => void>();
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
    render(<DiffPage onCreateWorkspace={onCreateWorkspace} />);
    selectOnlyA('ambiguous.example');

    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));

    const partial = (await screen.findByText('Partial current view')).closest('article');
    expect(partial).not.toBeNull();
    expect(partial).toHaveTextContent(
      /A: The DNS answer contains an invalid or ambiguous CNAME RRset\./u,
    );
    expect(screen.getByText('No selected records were returned.')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Open in Change Workspace' }));
    expect(onCreateWorkspace).toHaveBeenCalledOnce();
    expect(onCreateWorkspace.mock.calls[0]?.[0]).toMatchObject({
      analysis: {
        status: 'partial',
      },
      current: {
        incompleteReasons: [
          'Live comparison covers only ambiguous.example. for the selected A record types within the declared example. authoritative zone; other owners, unselected types and delegation boundaries remain unknown.',
          'A: The DNS answer contains an invalid or ambiguous CNAME RRset.',
        ],
        status: 'partial',
      },
      evidence: {
        incompleteReasons: ['A: The DNS answer contains an invalid or ambiguous CNAME RRset.'],
        runs: [
          {
            resolvers: [
              {
                endpoint: 'https://dns.google/dns-query',
                questions: [
                  {
                    error: 'A: The DNS answer contains an invalid or ambiguous CNAME RRset.',
                    records: [],
                    responseCode: null,
                    status: 'malformed-response',
                  },
                ],
                resolverId: 'google',
                status: 'partial',
              },
            ],
            status: 'partial',
          },
        ],
        status: 'partial',
      },
    });
  });

  it('omits proposed record types that were not selected for current observation', async () => {
    const onCreateWorkspace = vi.fn<(workspace: ChangeWorkspace) => void>();
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue(dnsResponse([], 'unselected.example.')),
    );
    render(<DiffPage onCreateWorkspace={onCreateWorkspace} />);
    selectOnlyA('unselected.example');
    fireEvent.change(screen.getByLabelText('Proposed snapshot'), {
      target: { value: 'unselected.example. 300 IN MX 10 mail.example.net.' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));

    expect(
      await screen.findByText('Comparison found 0 classified changes.', {}, { timeout: 3000 }),
    ).toBeVisible();
    expect(screen.getByText('current-observation-incomplete')).toBeVisible();
    expect(screen.getByText(/Current MX data could not be observed/iu)).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Open in Change Workspace' }));
    const workspace = onCreateWorkspace.mock.calls[0]?.[0];
    expect(workspace).toMatchObject({
      analysis: {
        changes: [],
        status: 'partial',
      },
      current: { status: 'partial' },
    });
    expect(workspace?.analysis.findings.map((finding) => finding.code)).toEqual(
      expect.arrayContaining(['current-observation-incomplete', 'current-observation-scope']),
    );
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

  it('reports a local resource limit without rendering a partial comparison', () => {
    const oversized = Array.from(
      { length: ZONE_ANALYSIS_LIMITS.records + 1 },
      (_, index) => `record-${String(index)} IN A 192.0.2.1`,
    ).join('\n');
    render(<DiffPage onCreateWorkspace={vi.fn()} />);
    fireEvent.change(screen.getByLabelText('Current or earlier snapshot'), {
      target: { value: oversized },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));

    expect(screen.getByRole('alert')).toHaveTextContent(
      /Comparison incomplete.*record safety/iu,
    );
    expect(
      screen.getByText('Comparison stopped because the required inputs are incomplete.'),
    ).toBeVisible();
    expect(screen.queryByText('Change set')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Open in Change Workspace' }),
    ).not.toBeInTheDocument();
  });

  it.each([
    ['$INCLUDE child.example.zone', 'directive-unsupported'],
    ['www.example. 300 IN', 'record-incomplete'],
  ])('blocks pasted input with %s instead of producing a report', (source, rule) => {
    render(<DiffPage onCreateWorkspace={vi.fn()} />);
    fireEvent.change(screen.getByLabelText('Current or earlier snapshot'), {
      target: { value: source },
    });
    fireEvent.change(screen.getByLabelText('Proposed or later snapshot'), {
      target: { value: 'www.example. 300 IN A 192.0.2.2' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));

    expect(screen.getByRole('alert')).toHaveTextContent(rule);
    expect(screen.getByRole('alert')).toHaveTextContent(/No partial change set or plan/iu);
    expect(screen.queryByText('Change set')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Open in Change Workspace' }),
    ).not.toBeInTheDocument();
  });

  it('blocks malformed proposed input after a live observation', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue(dnsResponse([], 'malformed-live.example.')),
    );
    render(<DiffPage onCreateWorkspace={vi.fn()} />);
    selectOnlyA('malformed-live.example');
    fireEvent.change(screen.getByLabelText('Proposed snapshot'), {
      target: { value: '$INCLUDE unobserved.example.zone' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('directive-unsupported');
    expect(screen.queryByText('Change set')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Open in Change Workspace' }),
    ).not.toBeInTheDocument();
  });

  it('bounds an evidence run around an older cached observation timestamp', async () => {
    const cachedAt = '2020-08-14T01:00:00.000Z';
    const bytes = encode({
      answers: [
        {
          class: 'IN',
          data: '192.0.2.1',
          name: 'cached-evidence.example.',
          ttl: 300,
          type: 'A',
        },
      ],
      flags: 0x8180,
      id: 0,
      questions: [{ class: 'IN', name: 'cached-evidence.example.', type: 'A' }],
      type: 'response',
    });
    const message = decodeDnsMessage(bytes);
    vi.spyOn(WireDnsResolver.prototype, 'query').mockImplementation((question) =>
      Promise.resolve({
        cache: 'hit',
        message,
        queryTimeMs: 0,
        question,
        receivedAt: cachedAt,
        resolver: RESOLVERS.google,
      }),
    );
    const onCreateWorkspace = vi.fn<(workspace: ChangeWorkspace) => void>();
    render(<DiffPage onCreateWorkspace={onCreateWorkspace} />);
    selectOnlyA('cached-evidence.example');
    fireEvent.change(screen.getByLabelText('Proposed snapshot'), {
      target: { value: 'cached-evidence.example. 300 IN A 192.0.2.1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));

    expect(await screen.findByText('Comparison found 0 classified changes.')).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Open in Change Workspace' }));

    expect(onCreateWorkspace).toHaveBeenCalledOnce();
    const run = onCreateWorkspace.mock.calls[0]?.[0].evidence.runs[0];
    expect(run?.startedAt).toBe(cachedAt);
    expect(run?.resolvers[0]?.questions[0]?.observedAt).toBe(cachedAt);
    expect(Date.parse(run?.completedAt ?? '')).toBeGreaterThanOrEqual(Date.parse(cachedAt));
  });

  it('creates a workspace from completed pasted sources without network activity', () => {
    const fetch = vi.fn();
    const onCreateWorkspace = vi.fn<(workspace: ChangeWorkspace) => void>();
    vi.stubGlobal('fetch', fetch);
    render(<DiffPage onCreateWorkspace={onCreateWorkspace} />);
    const current = 'www.example.com. 300 IN A 192.0.2.1';
    const intended = 'www.example.com. 300 IN A 192.0.2.2';
    fireEvent.change(screen.getByLabelText('Current or earlier snapshot'), {
      target: { value: current },
    });
    fireEvent.change(screen.getByLabelText('Proposed or later snapshot'), {
      target: { value: intended },
    });
    fireEvent.change(screen.getByLabelText('Origin for relative names'), {
      target: { value: 'example.com' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));
    fireEvent.click(screen.getByRole('button', { name: 'Open in Change Workspace' }));

    expect(fetch).not.toHaveBeenCalled();
    expect(onCreateWorkspace).toHaveBeenCalledOnce();
    expect(onCreateWorkspace.mock.calls[0]?.[0]).toMatchObject({
      analysis: { changes: [{ category: 'value-changed' }], status: 'complete' },
      current: { origin: 'example.com', source: current, status: 'complete' },
      evidence: { runs: [], status: 'none' },
      intended: { origin: 'example.com', source: intended, status: 'complete' },
    });
  });

  it('loads workspace hand-offs only into pasted mode without selecting a resolver', () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    render(
      <DiffPage
        initialInput={{
          current: 'www.example.com. 300 IN A 192.0.2.1',
          intended: 'www.example.com. 300 IN A 192.0.2.2',
          origin: 'example.com.',
        }}
      />,
    );

    expect(screen.getByRole('button', { name: 'Two pasted snapshots' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    expect(screen.getByLabelText('Current or earlier snapshot')).toHaveValue(
      'www.example.com. 300 IN A 192.0.2.1',
    );
    expect(screen.getByLabelText('Proposed or later snapshot')).toHaveValue(
      'www.example.com. 300 IN A 192.0.2.2',
    );
    expect(screen.getByLabelText('Origin for relative names')).toHaveValue('example.com.');
    expect(screen.getByLabelText('Proposed snapshot origin')).toHaveValue('example.com.');
    expect(screen.queryByLabelText('Resolver')).not.toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('preserves partial semantics and distinct origins without producing a guessed plan', () => {
    const onCreateWorkspace = vi.fn<(workspace: ChangeWorkspace) => void>();
    render(
      <DiffPage
        initialInput={{
          current: 'www 300 IN A 192.0.2.1',
          currentIncompleteReasons: ['Only the selected address RRset was observed.'],
          currentOrigin: 'current.example.',
          currentStatus: 'partial',
          intended: 'www 300 IN A 192.0.2.2',
          intendedOrigin: 'intended.example.',
          intendedStatus: 'complete',
        }}
        onCreateWorkspace={onCreateWorkspace}
      />,
    );

    expect(screen.getByLabelText('Origin for relative names')).toHaveValue('current.example.');
    expect(screen.getByLabelText('Proposed snapshot origin')).toHaveValue('intended.example.');
    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));

    expect(screen.getByRole('alert')).toHaveTextContent(
      /Current zone state is partial.*Only the selected address RRset was observed/iu,
    );
    expect(screen.queryByText('Change set')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Return to Change Workspace' }));

    expect(onCreateWorkspace).toHaveBeenCalledOnce();
    const returnedWorkspace = onCreateWorkspace.mock.calls[0]?.[0];
    expect(returnedWorkspace).toMatchObject({
      analysis: {
        changes: [],
        status: 'partial',
      },
      current: {
        incompleteReasons: ['Only the selected address RRset was observed.'],
        origin: 'current.example.',
        status: 'partial',
      },
      intended: { origin: 'intended.example.', status: 'complete' },
    });
    expect(returnedWorkspace?.analysis.incompleteReasons.join(' ')).toMatch(
      /Current zone state is partial.*Only the selected address RRset was observed/iu,
    );
  });

  it('invalidates a completed pasted comparison after an intended-source edit', () => {
    const onCreateWorkspace = vi.fn<(workspace: ChangeWorkspace) => void>();
    render(<DiffPage onCreateWorkspace={onCreateWorkspace} />);
    fireEvent.change(screen.getByLabelText('Current or earlier snapshot'), {
      target: { value: 'www.example. 300 IN A 192.0.2.1' },
    });
    fireEvent.change(screen.getByLabelText('Proposed or later snapshot'), {
      target: { value: 'www.example. 300 IN A 192.0.2.2' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));
    expect(screen.getByText('Change set')).toBeVisible();

    fireEvent.change(screen.getByLabelText('Proposed or later snapshot'), {
      target: { value: 'www.example. 300 IN A 192.0.2.3' },
    });
    expect(screen.queryByText('Change set')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Open in Change Workspace' }),
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));
    fireEvent.click(screen.getByRole('button', { name: 'Open in Change Workspace' }));
    expect(onCreateWorkspace.mock.calls[0]?.[0].intended.source).toBe(
      'www.example. 300 IN A 192.0.2.3',
    );
  });

  it('prevents a deferred current-DNS result from overwriting a later edit', async () => {
    let resolveFetch: ((response: Response) => void) | undefined;
    const pending = new Promise<Response>((resolve) => {
      resolveFetch = resolve;
    });
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockReturnValue(pending));
    render(<DiffPage onCreateWorkspace={vi.fn()} />);
    selectOnlyA('deferred.example');
    fireEvent.change(screen.getByLabelText('Proposed snapshot'), {
      target: { value: 'deferred.example. 300 IN A 192.0.2.2' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));
    expect(screen.getByRole('button', { name: 'Querying current DNS…' })).toBeDisabled();

    fireEvent.change(screen.getByLabelText('Proposed snapshot'), {
      target: { value: 'deferred.example. 300 IN A 192.0.2.3' },
    });
    await act(async () => {
      resolveFetch?.(
        dnsResponse(
          [
            {
              class: 'IN',
              data: '192.0.2.1',
              name: 'deferred.example.',
              ttl: 300,
              type: 'A',
            },
          ],
          'deferred.example.',
        ),
      );
      await pending;
    });

    await waitFor(() => {
      expect(screen.queryByText(/Comparison found/iu)).not.toBeInTheDocument();
    });
    expect(screen.queryByText('Change set')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Open in Change Workspace' }),
    ).not.toBeInTheDocument();
  });

  it('exports hostile zone values only as literal Markdown evidence', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    const tick = String.fromCharCode(96);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    render(<DiffPage />);
    fireEvent.change(screen.getByLabelText('Current or earlier snapshot'), {
      target: { value: 'example.test. 300 IN TXT "safe"' },
    });
    fireEvent.change(screen.getByLabelText('Proposed or later snapshot'), {
      target: {
        value:
          'example.test. 300 IN TXT "![pixel](https://attacker.invalid/p) <img src=x> **bold** ' +
          tick +
          'code' +
          tick +
          ' | \u202e"',
      },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Compare snapshots' }));
    expect(screen.getByText('Change set')).toBeVisible();

    fireEvent.click(screen.getByRole('button', { name: 'Copy Markdown report' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    const markdown = String(writeText.mock.calls[0]?.[0]);
    const html = marked.parse(markdown, { async: false, gfm: true });
    if (typeof html !== 'string')
      throw new Error('Synchronous Markdown parsing returned a promise.');
    const rendered = window.document.createElement('div');
    rendered.innerHTML = html;

    expect(rendered.querySelector('img')).toBeNull();
    expect(rendered.querySelector('a')).toBeNull();
    expect(rendered.querySelector('blockquote')).toBeNull();
    expect(rendered.textContent).toContain('![pixel](https://attacker.invalid/p)');
    expect(rendered.textContent).toContain('<img src=x>');
    expect(rendered.textContent).toContain('\\u{202E}');
    expect(markdown).not.toContain('\u202e');
  });
});
