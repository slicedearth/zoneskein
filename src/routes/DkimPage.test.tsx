import { decode, encode } from '@dnsquery/dns-packet';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { DkimPage } from './DkimPage';
import { dkimBodyHash, MAX_DKIM_MESSAGE_BYTES } from '../core/dkim/message-verifier';
import type { MailAuthenticationEvidence } from '../core/mail/evidence';

const ED25519_KEY = 'v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=';
const FIXED_RSA_MESSAGE = `DKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=fixed; h=from:subject; bh=CpQrkuJerbSLbJb+3wem7Ybf6UdzqoOp6epFKC3N3qY=; b=5DtLabjQDiCWJaEa8aIKqsBqtUznIzdMv1DToJn35vKlXiVELM5jATNqRGXyyVvEwIN52ZNQ3Z7k9iSsTbFHn9ZacEbgyM2uN57BFfbXjDr/gC1NJLWNxgc788qrFeD5wDwLrKM2Q2+UADJrwOfzfxw14Qw+oPfZ7kNgBaXWBa4=
From: vector@example.test
Subject: fixed RSA vector

fixed vector body
`;
const FIXED_RSA_KEY =
  'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDmoQmuysYdunKx3ckNWLv8u8OJhpm9xkOFb9FV+FW9IqphwPZLts/+QXeCxiF27UylP8Bw3iwu07lVeKY9HmMlpCfn0hum80G0z30Y+QFyohnDJvSddfa2iVTjsox/tRcvt1opns5WGzfxRb8CxOANGPWCaVDNVuK2EayVaLggJQIDAQAB';

function requestBytes(input: RequestInfo | URL, init?: RequestInit): Uint8Array {
  if (init?.body instanceof ArrayBuffer) return new Uint8Array(init.body);
  if (typeof input !== 'string') throw new Error('Expected a string DNS request URL.');
  const encoded = new URL(input).searchParams.get('dns');
  if (encoded === null) throw new Error('Expected a DNS wire query.');
  const base64 = encoded.replaceAll('-', '+').replaceAll('_', '/');
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function txtResponse(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  value: string,
): Response {
  const question = decode(requestBytes(input, init)).questions?.[0];
  if (question === undefined) throw new Error('Expected one DNS question.');
  const bytes = encode({
    answers: [{ class: 'IN', data: [value], name: question.name, ttl: 300, type: 'TXT' }],
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

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('DkimPage', () => {
  it('discloses the automatic Quad9 compatibility boundary', () => {
    render(<DkimPage />);

    const resolver = screen.getByLabelText('Resolver');
    fireEvent.change(resolver, { target: { value: 'quad9' } });

    const note = screen.getByText(/compatibility mode lets Netlify observe the DNS question/iu);
    expect(note).toHaveAttribute('id', 'dkim-resolver-note');
    expect(resolver).toHaveAttribute('aria-describedby', 'dkim-resolver-note');
  });

  it('shows the actual Quad9 path used for selector evidence', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError('Direct transport unavailable.'))
      .mockImplementation((input, init) =>
        Promise.resolve(txtResponse(input, init, ED25519_KEY)),
      );
    vi.stubGlobal('fetch', fetchMock);
    render(<DkimPage />);

    fireEvent.change(screen.getByLabelText('Resolver'), { target: { value: 'quad9' } });
    fireEvent.change(screen.getByLabelText('Signing domain'), {
      target: { value: 'example.test' },
    });
    fireEvent.change(screen.getByLabelText('Selector'), { target: { value: 'key' } });
    fireEvent.click(screen.getByRole('button', { name: 'Inspect DKIM key' }));

    expect(
      await screen.findByText('Quad9 (compatibility mode)', { selector: 'dd' }),
    ).toBeVisible();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('rejects non-LDH and overlong complete selector names before DNS', () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<DkimPage />);

    fireEvent.change(screen.getByLabelText('Signing domain'), {
      target: { value: 'example.test' },
    });
    fireEvent.change(screen.getByLabelText('Selector'), { target: { value: '_private' } });
    fireEvent.click(screen.getByRole('button', { name: 'Inspect DKIM key' }));
    expect(screen.getByRole('alert')).toHaveTextContent(/LDH DNS labels/iu);

    const longSelector = `${'a'.repeat(63)}.${'b'.repeat(63)}`;
    const longDomain = `${'c'.repeat(63)}.${'d'.repeat(63)}.test`;
    fireEvent.change(screen.getByLabelText('Signing domain'), {
      target: { value: longDomain },
    });
    fireEvent.change(screen.getByLabelText('Selector'), {
      target: { value: longSelector },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Inspect DKIM key' }));
    expect(screen.getByRole('alert')).toHaveTextContent(
      /complete DKIM selector name.*253 octets/iu,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('verifies an unsigned pasted message locally without persisting or querying it', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<DkimPage />);

    const messageMode = screen.getByRole('button', { name: 'Message verifier' });
    expect(messageMode).toHaveAttribute('aria-pressed', 'false');
    expect(screen.queryByRole('tab')).not.toBeInTheDocument();
    await user.click(messageMode);
    expect(
      screen.getByText(/only when you are authorised to process its contents/iu),
    ).toBeVisible();
    expect(screen.getByRole('form', { name: 'DKIM inputs' })).toHaveAttribute(
      'aria-describedby',
      'dkim-message-privacy-note',
    );
    await user.type(
      screen.getByLabelText('Raw RFC 5322 message'),
      'From: sender@example.com\n\nBody',
    );
    await user.click(screen.getByRole('button', { name: 'Verify message signatures' }));

    expect(await screen.findByText('Unsigned')).toBeVisible();
    expect(screen.getByRole('status', { name: 'DKIM run status' })).toHaveTextContent(
      'DKIM message verification complete: No DKIM signature.',
    );
    expect(screen.getByText(/never saved or placed in a share link/iu)).toBeVisible();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('hands only passing production signing domains to DMARC', async () => {
    const onUseForDmarc = vi.fn<(evidence: MailAuthenticationEvidence) => void>();
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>((input, init) =>
        Promise.resolve(txtResponse(input, init, FIXED_RSA_KEY)),
      ),
    );
    render(<DkimPage onUseForDmarc={onUseForDmarc} />);
    fireEvent.click(screen.getByRole('button', { name: 'Message verifier' }));
    fireEvent.change(screen.getByLabelText('Raw RFC 5322 message'), {
      target: { value: FIXED_RSA_MESSAGE },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verify message signatures' }));

    expect(
      await screen.findByRole('heading', { name: 'Pass after CRLF reconstruction' }),
    ).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Use passing domains in DMARC' }));
    expect(onUseForDmarc).toHaveBeenCalledOnce();
    const evidence = onUseForDmarc.mock.calls[0]?.[0];
    expect(evidence).toMatchObject({
      dkim: [
        {
          domain: 'example.test',
          reconstructed: true,
          source: 'dkim-message',
        },
      ],
    });
    expect(JSON.stringify(evidence)).not.toContain('vector@example.test');
    expect(screen.getByText(/excludes the raw message.*selectors.*content/iu)).toBeVisible();
  });

  it('keeps uploaded filenames and message content out of copied evidence', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    render(<DkimPage />);
    await user.click(screen.getByRole('button', { name: 'Message verifier' }));
    await user.upload(
      screen.getByLabelText('Raw message file (optional)'),
      new File(['From: private@example.test\r\n\r\nPrivate body'], 'Alice Tax Return.eml', {
        type: 'message/rfc822',
      }),
    );
    await user.click(screen.getByRole('button', { name: 'Verify message signatures' }));
    await screen.findByText('Unsigned');
    await user.click(screen.getByRole('button', { name: 'Copy verification JSON' }));

    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    const evidence = String(writeText.mock.calls[0]?.[0]);
    expect(evidence).toContain('"inputKind": "uploaded-eml"');
    expect(evidence).toContain('"capturedAt"');
    expect(evidence).toContain('"id": "google"');
    expect(evidence).not.toContain('Alice Tax Return.eml');
    expect(evidence).not.toContain('private@example.test');
    expect(evidence).not.toContain('Private body');
  });

  it('redacts the AUID local-part from copied verification evidence', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    const fetchMock = vi.fn();
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<DkimPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Message verifier' }));
    fireEvent.change(screen.getByLabelText('Raw RFC 5322 message'), {
      target: {
        value:
          'DKIM-Signature: v=1; a=future-sha256; d=example.test; s=key; i=private-user@example.test; h=from; bh=AAAA; b=AAAA\nFrom: person@example.test\n\nConfidential body',
      },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verify message signatures' }));
    await screen.findByRole('heading', { name: 'Verification incomplete' });
    fireEvent.click(screen.getByRole('button', { name: 'Copy verification JSON' }));

    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    const evidence = String(writeText.mock.calls[0]?.[0]);
    expect(evidence).toContain('redacted@example.test');
    expect(evidence).not.toContain('private-user');
    expect(evidence).not.toContain('person@example.test');
    expect(evidence).not.toContain('Confidential body');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('discards an active verification when the message is edited before DNS completes', async () => {
    const bodyHash = await dkimBodyHash('body', 'simple');
    let rejectRequest: ((reason?: unknown) => void) | undefined;
    let pendingRequest: Promise<Response> | undefined;
    const fetchMock = vi.fn<typeof fetch>(() => {
      pendingRequest = new Promise<Response>((_resolve, reject) => {
        rejectRequest = reject;
      });
      return pendingRequest;
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<DkimPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Message verifier' }));
    fireEvent.change(screen.getByLabelText('Raw RFC 5322 message'), {
      target: {
        value: `DKIM-Signature: v=1; a=ed25519-sha256; d=stale-message.test; s=key; h=from; bh=${bodyHash}; b=AAAA\r\nFrom: old@stale-message.test\r\n\r\nbody`,
      },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verify message signatures' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    if (pendingRequest === undefined) {
      throw new Error('Expected the DNS request to be pending.');
    }

    fireEvent.change(screen.getByLabelText('Raw RFC 5322 message'), {
      target: { value: 'From: replacement@example.test\r\n\r\nReplacement body' },
    });
    rejectRequest?.(new Error('The old selector lookup failed.'));

    await expect(pendingRequest).rejects.toThrow('The old selector lookup failed.');
    await waitFor(() =>
      expect(screen.getByRole('status', { name: 'DKIM run status' })).toBeEmptyDOMElement(),
    );
    expect(screen.getByRole('button', { name: 'Verify message signatures' })).toBeEnabled();
    expect(screen.getByLabelText('Raw RFC 5322 message')).toHaveValue(
      'From: replacement@example.test\n\nReplacement body',
    );
    expect(screen.getByRole('status', { name: 'DKIM run status' })).toBeEmptyDOMElement();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { level: 2 })).not.toBeInTheDocument();
  });

  it('clears the old message before an oversized replacement can fail', async () => {
    const user = userEvent.setup();
    render(<DkimPage />);
    await user.click(screen.getByRole('button', { name: 'Message verifier' }));
    await user.type(
      screen.getByLabelText('Raw RFC 5322 message'),
      'From: old@example.test\n\nOld body',
    );
    const oversized = new File(
      [new Uint8Array(MAX_DKIM_MESSAGE_BYTES + 1)],
      'replacement.eml',
      { type: 'message/rfc822' },
    );
    await user.upload(screen.getByLabelText('Raw message file (optional)'), oversized);

    expect(await screen.findByRole('alert')).toHaveTextContent(/exceeds.*safety limit/iu);
    expect(screen.getByLabelText('Raw RFC 5322 message')).toHaveValue('');
    await user.click(screen.getByRole('button', { name: 'Verify message signatures' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/paste a complete message/iu);
    expect(screen.queryByText('Unsigned')).not.toBeInTheDocument();
  });

  it('makes hostile key text visible while preserving exact record evidence', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    const control = String.fromCodePoint(0x202e);
    const record = `${ED25519_KEY}; n=literal \\u{202E}; x=${control}hidden`;
    const visible = `${ED25519_KEY}; n=literal \\\\u{202E}; x=\\u{202E}hidden`;
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>((input, init) => Promise.resolve(txtResponse(input, init, record))),
    );
    render(<DkimPage />);

    fireEvent.change(screen.getByLabelText('Signing domain'), {
      target: { value: 'control-key.test' },
    });
    fireEvent.change(screen.getByLabelText('Selector'), { target: { value: 'key' } });
    fireEvent.click(screen.getByRole('button', { name: 'Inspect DKIM key' }));

    const result = (await screen.findByText('Published key record')).closest('article');
    if (result === null) throw new Error('Expected a DKIM key result panel.');
    expect(within(result).getByText(visible, { selector: 'pre' })).toBeVisible();
    expect(result.textContent).not.toContain(control);
    expect(document.body.textContent).not.toContain(control);

    fireEvent.click(within(result).getByRole('button', { name: 'Copy safe DKIM record' }));
    fireEvent.click(
      within(result).getByRole('button', { name: 'Copy exact DKIM record as Base64' }),
    );
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(2));

    expect(writeText.mock.calls[0]?.[0]).toBe(visible);
    const exactBase64 = String(writeText.mock.calls[1]?.[0]);
    const exactBytes = Uint8Array.from(atob(exactBase64), (character) =>
      character.charCodeAt(0),
    );
    expect(new TextDecoder().decode(exactBytes)).toBe(record);
  });

  it('does not resurrect a key report after switching modes during Web Crypto inspection', async () => {
    let finishImport: ((key: CryptoKey) => void) | undefined;
    let pendingImport: Promise<CryptoKey> | undefined;
    const importKey = vi.spyOn(crypto.subtle, 'importKey').mockImplementation(() => {
      pendingImport = new Promise<CryptoKey>((resolve) => {
        finishImport = resolve;
      });
      return pendingImport;
    });
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>((input, init) =>
        Promise.resolve(txtResponse(input, init, ED25519_KEY)),
      ),
    );
    render(<DkimPage />);
    fireEvent.change(screen.getByLabelText('Signing domain'), {
      target: { value: 'stale-key.test' },
    });
    fireEvent.change(screen.getByLabelText('Selector'), { target: { value: 'key' } });
    fireEvent.click(screen.getByRole('button', { name: 'Inspect DKIM key' }));
    await waitFor(() => expect(importKey).toHaveBeenCalled());
    if (pendingImport === undefined) {
      throw new Error('Expected Web Crypto key import to be pending.');
    }

    fireEvent.click(screen.getByRole('button', { name: 'Message verifier' }));
    finishImport?.({} as CryptoKey);
    await pendingImport;

    expect(screen.getByRole('button', { name: 'Message verifier' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    expect(screen.getByRole('status', { name: 'DKIM run status' })).toBeEmptyDOMElement();
    expect(
      screen.queryByRole('heading', { name: /stale-key\.test/iu }),
    ).not.toBeInTheDocument();
  });
});
