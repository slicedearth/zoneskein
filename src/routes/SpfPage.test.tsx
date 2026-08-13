import { decode, encode } from '@dnsquery/dns-packet';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { SpfPage } from './SpfPage';

afterEach(() => vi.unstubAllGlobals());

function spfAnswer(input: RequestInfo | URL): Response {
  if (typeof input !== 'string') throw new Error('Expected a string DNS request URL.');
  const encoded = new URL(input).searchParams.get('dns');
  if (encoded === null) throw new Error('Expected a DNS wire query.');
  const base64 = encoded.replaceAll('-', '+').replaceAll('_', '/');
  const request = Uint8Array.from(
    atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')),
    (character) => character.charCodeAt(0),
  );
  const question = decode(request).questions?.[0];
  if (question === undefined) throw new Error('Expected one DNS question.');
  const bytes = encode({
    answers: [
      { class: 'IN', data: ['v=spf1 -all'], name: question.name, ttl: 300, type: 'TXT' },
    ],
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
