import { decode, encode } from '@dnsquery/dns-packet';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { SpfPage } from './SpfPage';
import type { MailAuthenticationEvidence } from '../core/mail/evidence';

afterEach(() => vi.unstubAllGlobals());

function spfAnswer(
  input: RequestInfo | URL,
  init?: RequestInit,
  policy = 'v=spf1 -all',
): Response {
  if (typeof input !== 'string') throw new Error('Expected a string DNS request URL.');
  const encoded = new URL(input, 'http://localhost').searchParams.get('dns');
  let request: Uint8Array;
  if (encoded !== null) {
    const base64 = encoded.replaceAll('-', '+').replaceAll('_', '/');
    request = Uint8Array.from(
      atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')),
      (character) => character.charCodeAt(0),
    );
  } else if (init?.body instanceof ArrayBuffer) request = new Uint8Array(init.body);
  else if (ArrayBuffer.isView(init?.body)) {
    request = new Uint8Array(init.body.buffer, init.body.byteOffset, init.body.byteLength);
  } else throw new Error('Expected a DNS wire query.');
  const question = decode(request).questions?.[0];
  if (question === undefined) throw new Error('Expected one DNS question.');
  const bytes = encode({
    answers: [{ class: 'IN', data: [policy], name: question.name, ttl: 300, type: 'TXT' }],
    flags: 0x8180,
    id: 0,
    questions: [question],
    type: 'response',
  });
  const body = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(body).set(bytes);
  return new Response(body, {
    headers: { 'Content-Type': 'application/dns-message' },
    status: 200,
  });
}

describe('SpfPage', () => {
  it('hands only the domain-level sender result to DMARC', async () => {
    const onUseForDmarc = vi.fn<(evidence: MailAuthenticationEvidence) => void>();
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>((input, init) =>
        Promise.resolve(spfAnswer(input, init, 'v=spf1 ip4:192.0.2.1 -all')),
      ),
    );
    render(<SpfPage onUseForDmarc={onUseForDmarc} />);
    fireEvent.click(screen.getByRole('button', { name: 'Sender evaluation' }));
    fireEvent.change(screen.getByLabelText('SMTP client IP'), {
      target: { value: '192.0.2.1' },
    });
    fireEvent.change(screen.getByLabelText('MAIL FROM address'), {
      target: { value: 'private-user@bounce.example' },
    });
    fireEvent.change(screen.getByLabelText('HELO/EHLO domain'), {
      target: { value: 'mail.example' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Evaluate sender' }));

    expect(
      await screen.findByRole('heading', { name: 'private-user@bounce.example' }),
    ).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Use SPF result in DMARC' }));
    expect(onUseForDmarc).toHaveBeenCalledOnce();
    const evidence = onUseForDmarc.mock.calls[0]?.[0];
    expect(evidence).toMatchObject({
      dkim: [],
      spf: { domain: 'bounce.example', result: 'pass', source: 'spf-sender' },
    });
    expect(JSON.stringify(evidence)).not.toContain('private-user');
    expect(JSON.stringify(evidence)).not.toContain('192.0.2.1');
    expect(screen.getByText(/separate DMARC hand-off contains only/iu)).toBeVisible();
  });

  it('discloses the Netlify intermediary when the Quad9 relay is selected', () => {
    render(<SpfPage />);

    const resolver = screen.getByLabelText('Resolver');
    fireEvent.change(resolver, { target: { value: 'quad9-relay' } });

    const note = screen.getByText(/DNS question and connection metadata to Netlify/iu);
    expect(note).toHaveAttribute('id', 'spf-resolver-note');
    expect(resolver).toHaveAttribute('aria-describedby', 'spf-resolver-note');
  });

  it('uses pressed-button mode semantics and evaluates invalid sender input locally', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<SpfPage />);

    const senderMode = screen.getByRole('button', { name: 'Sender evaluation' });
    expect(senderMode).toHaveAttribute('aria-pressed', 'false');
    expect(screen.queryByRole('tab')).not.toBeInTheDocument();

    fireEvent.click(senderMode);
    expect(senderMode).toHaveAttribute('aria-pressed', 'true');
    fireEvent.change(screen.getByLabelText('SMTP client IP'), {
      target: { value: 'not-an-address' },
    });
    fireEvent.change(screen.getByLabelText('MAIL FROM address'), {
      target: { value: 'sender@example.com' },
    });
    fireEvent.change(screen.getByLabelText('HELO/EHLO domain'), {
      target: { value: 'mail.example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Evaluate sender' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/valid IPv4 or IPv6/iu);
    expect(
      screen.queryByText('permerror', { selector: '.status-badge' }),
    ).not.toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects an invalid receiver before DNS', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<SpfPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Sender evaluation' }));
    fireEvent.change(screen.getByLabelText('SMTP client IP'), {
      target: { value: '192.0.2.1' },
    });
    fireEvent.change(screen.getByLabelText('MAIL FROM address'), {
      target: { value: 'sender@example.com' },
    });
    fireEvent.change(screen.getByLabelText('HELO/EHLO domain'), {
      target: { value: 'mail.example.com' },
    });
    fireEvent.change(screen.getByLabelText('Receiver hostname (optional)'), {
      target: { value: 'localhost' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Evaluate sender' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/receiver domain/iu);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('allows malformed HELO through when a valid non-null MAIL FROM supplies the policy domain', async () => {
    const fetchMock = vi.fn<typeof fetch>((input) => Promise.resolve(spfAnswer(input)));
    vi.stubGlobal('fetch', fetchMock);
    render(<SpfPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Sender evaluation' }));
    fireEvent.change(screen.getByLabelText('SMTP client IP'), {
      target: { value: '192.0.2.1' },
    });
    fireEvent.change(screen.getByLabelText('MAIL FROM address'), {
      target: { value: 'sender@spf-helo-route.test' },
    });
    fireEvent.change(screen.getByLabelText('HELO/EHLO domain'), {
      target: { value: '[192.0.2.1]' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Evaluate sender' }));

    await screen.findByRole('heading', { name: 'sender@spf-helo-route.test' });
    expect(screen.getAllByText('fail', { selector: '.status-badge' })).not.toHaveLength(0);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('rejects malformed HELO locally when the reverse path is null', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<SpfPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Sender evaluation' }));
    fireEvent.change(screen.getByLabelText('SMTP client IP'), {
      target: { value: '192.0.2.1' },
    });
    fireEvent.change(screen.getByLabelText('MAIL FROM address'), { target: { value: '<>' } });
    fireEvent.change(screen.getByLabelText('HELO/EHLO domain'), {
      target: { value: '[192.0.2.1]' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Evaluate sender' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/HELO\/EHLO domain/iu);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('announces completion and exports the selected resolver with sensitive clipboard guidance', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>((input) => Promise.resolve(spfAnswer(input))),
    );
    render(<SpfPage />);

    fireEvent.click(screen.getByRole('button', { name: 'Sender evaluation' }));
    expect(screen.getByText(/only when you are authorised to process it/iu)).toBeVisible();
    expect(screen.getByRole('form', { name: 'SPF inputs' })).toHaveAttribute(
      'aria-describedby',
      'spf-sender-privacy-note',
    );
    fireEvent.change(screen.getByLabelText('SMTP client IP'), {
      target: { value: '192.0.2.1' },
    });
    fireEvent.change(screen.getByLabelText('MAIL FROM address'), {
      target: { value: 'sender@spf-evidence.test' },
    });
    fireEvent.change(screen.getByLabelText('HELO/EHLO domain'), {
      target: { value: 'mail.spf-evidence.test' },
    });
    fireEvent.change(screen.getByLabelText('Resolver'), { target: { value: 'quad9' } });
    fireEvent.click(screen.getByRole('button', { name: 'Evaluate sender' }));

    expect(await screen.findByRole('status', { name: 'SPF run status' })).toHaveTextContent(
      'SPF sender evaluation complete: fail.',
    );
    expect(screen.getByText(/places the supplied mailbox.*clipboard/iu)).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Copy evaluation JSON' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    const evidence = JSON.parse(String(writeText.mock.calls[0]?.[0])) as {
      capturedAt?: string;
      resolver?: { id?: string };
    };
    expect(evidence.capturedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/iu);
    expect(evidence.resolver?.id).toBe('quad9');
  });

  it('retains relay and fixed-upstream provenance in analysis and snapshot exports', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>((input, init) => Promise.resolve(spfAnswer(input, init))),
    );
    render(<SpfPage />);

    fireEvent.change(screen.getByLabelText('Resolver'), {
      target: { value: 'quad9-relay' },
    });
    fireEvent.change(screen.getByLabelText('Domain'), {
      target: { value: 'spf-relay-evidence.test' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Analyse SPF' }));
    expect(
      await screen.findByRole('heading', { level: 2, name: 'spf-relay-evidence.test' }),
    ).toBeVisible();

    fireEvent.click(screen.getByRole('button', { name: 'Copy analysis JSON' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    const analysis = JSON.parse(String(writeText.mock.calls[0]?.[0])) as {
      readonly evidenceSchema?: string;
      readonly resolver?: {
        readonly endpoint?: string;
        readonly id?: string;
        readonly relay?: { readonly operator?: string; readonly upstreamEndpoint?: string };
      };
    };
    expect(analysis).toMatchObject({
      evidenceSchema: 'zoneskein-spf-analysis-v1',
      resolver: {
        endpoint: '/api/doh/quad9',
        id: 'quad9-relay',
        relay: {
          operator: 'Netlify',
          upstreamEndpoint: 'https://dns.quad9.net/dns-query',
        },
      },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Snapshot flattener' }));
    fireEvent.click(screen.getByRole('button', { name: 'Build guarded snapshot' }));
    expect(
      await screen.findByRole('heading', { name: 'Point-in-time SPF snapshot' }),
    ).toBeVisible();

    fireEvent.click(screen.getByRole('button', { name: 'Copy provenance JSON' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(2));
    const snapshot = JSON.parse(String(writeText.mock.calls[1]?.[0])) as {
      readonly evidenceSchema?: string;
      readonly resolver?: {
        readonly id?: string;
        readonly relay?: { readonly operator?: string };
      };
    };
    expect(snapshot).toMatchObject({
      evidenceSchema: 'zoneskein-spf-snapshot-v1',
      resolver: { id: 'quad9-relay', relay: { operator: 'Netlify' } },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Copy Markdown' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(3));
    expect(writeText.mock.calls[2]?.[0]).toContain('Intermediary: Netlify');
    expect(writeText.mock.calls[2]?.[0]).toContain(
      'Fixed upstream: Quad9 (https://dns.quad9.net/dns-query)',
    );
  });

  it('keeps material controls bound to the pending SPF run', async () => {
    let finishRequest: (() => void) | undefined;
    let pendingRequest: Promise<Response> | undefined;
    const fetchMock = vi.fn<typeof fetch>((input) => {
      pendingRequest = new Promise<Response>((resolve) => {
        finishRequest = () => resolve(spfAnswer(input));
      });
      return pendingRequest;
    });
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<SpfPage />);

    const domain = screen.getByLabelText('Domain');
    const resolver = screen.getByLabelText('Resolver');
    await user.type(domain, 'locked-spf.test');
    await user.selectOptions(resolver, 'quad9');
    await user.click(screen.getByRole('button', { name: 'Analyse SPF' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());

    expect(domain).toBeDisabled();
    expect(resolver).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Analysis' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Snapshot flattener' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Sender evaluation' })).toBeDisabled();
    expect(domain).toHaveValue('locked-spf.test');
    expect(resolver).toHaveValue('quad9');
    if (pendingRequest === undefined || finishRequest === undefined) {
      throw new Error('Expected the SPF request to be pending.');
    }

    finishRequest();
    await pendingRequest;
    expect(
      await screen.findByRole('heading', { level: 2, name: 'locked-spf.test' }),
    ).toBeVisible();
    expect(domain).toBeEnabled();
    expect(resolver).toBeEnabled();
  });

  it('does not let a cleared run report a later transport failure', async () => {
    let rejectRequest: ((reason?: unknown) => void) | undefined;
    let pendingRequest: Promise<Response> | undefined;
    const fetchMock = vi.fn<typeof fetch>(() => {
      pendingRequest = new Promise<Response>((_resolve, reject) => {
        rejectRequest = reject;
      });
      return pendingRequest;
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<SpfPage />);

    fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'stale-spf.test' } });
    fireEvent.click(screen.getByRole('button', { name: 'Analyse SPF' }));
    expect(await screen.findByRole('status', { name: 'SPF run status' })).toHaveTextContent(
      /being evaluated/iu,
    );
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    if (pendingRequest === undefined) {
      throw new Error('Expected the DNS request to be pending.');
    }
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    rejectRequest?.(new Error('Old request failed.'));

    await expect(pendingRequest).rejects.toThrow('Old request failed.');
    await waitFor(() =>
      expect(screen.getByRole('status', { name: 'SPF run status' })).toBeEmptyDOMElement(),
    );
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'stale-spf.test' })).not.toBeInTheDocument();
  });

  it('invalidates completed evidence when a material input changes', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>((input) => Promise.resolve(spfAnswer(input))),
    );
    render(<SpfPage />);

    const domain = screen.getByLabelText('Domain');
    fireEvent.change(domain, { target: { value: 'completed-spf.test' } });
    fireEvent.click(screen.getByRole('button', { name: 'Analyse SPF' }));
    expect(
      await screen.findByRole('heading', { level: 2, name: 'completed-spf.test' }),
    ).toBeVisible();

    fireEvent.change(domain, { target: { value: 'changed-spf.test' } });

    expect(
      screen.queryByRole('heading', { level: 2, name: 'completed-spf.test' }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('status', { name: 'SPF run status' })).toBeEmptyDOMElement();
  });

  it('cancels a pending DNS run when the SPF page unmounts', async () => {
    let requestSignal: AbortSignal | undefined;
    const fetchMock = vi.fn<typeof fetch>((_input, init) => {
      requestSignal = init?.signal ?? undefined;
      return new Promise<Response>((_resolve, reject) => {
        requestSignal?.addEventListener(
          'abort',
          () => reject(new DOMException('Aborted', 'AbortError')),
          { once: true },
        );
      });
    });
    vi.stubGlobal('fetch', fetchMock);
    const { unmount } = render(<SpfPage />);

    fireEvent.change(screen.getByLabelText('Domain'), {
      target: { value: 'pending-spf.test' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Analyse SPF' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    expect(requestSignal?.aborted).toBe(false);

    unmount();

    expect(requestSignal?.aborted).toBe(true);
  });
});
