import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { DNSSEC_APPLICATION_TYPES } from '../core/dnssec/application';
import * as dnssecChain from '../core/dnssec/chain';
import {
  assessRootTrustAnchorMaintenance,
  ROOT_TRUST_ANCHOR_SOURCE,
} from '../core/dnssec/trust-anchors';
import { DnssecPage } from './DnssecPage';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('DnssecPage', () => {
  it('offers chain-only and every bounded exact-positive RRset target', () => {
    render(<DnssecPage />);

    const target = screen.getByLabelText('Validation target');
    expect(target).toHaveValue('chain');
    expect(screen.getAllByRole('option')).toHaveLength(DNSSEC_APPLICATION_TYPES.length + 4);
    expect(screen.getByRole('option', { name: 'Quad9 (automatic)' })).toHaveValue('quad9');
    expect(
      screen.queryByRole('option', { name: 'Quad9 (compatibility mode)' }),
    ).not.toBeInTheDocument();
    const resolver = screen.getByLabelText('Resolver transport');
    fireEvent.change(resolver, { target: { value: 'quad9' } });
    const note = screen.getByText(/compatibility mode lets Netlify observe the DNS question/iu);
    expect(note).toHaveAttribute('id', 'dnssec-resolver-note');
    expect(resolver).toHaveAttribute('aria-describedby', 'dnssec-resolver-note');

    fireEvent.change(target, { target: { value: 'HTTPS' } });
    expect(target).toHaveValue('HTTPS');
    expect(screen.getByRole('button', { name: 'Validate DNSSEC' })).toBeVisible();
  });

  it('rejects an invalid owner locally before making a DNS request', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<DnssecPage />);

    await user.type(screen.getByLabelText('Zone or owner name'), 'bad name');
    await user.selectOptions(screen.getByLabelText('Validation target'), 'A');
    await user.click(screen.getByRole('button', { name: 'Validate DNSSEC' }));

    expect(await screen.findByRole('alert')).toBeVisible();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('locks run inputs while loading and invalidates a run when cleared', async () => {
    const fetchMock = vi.fn<typeof fetch>((_input, init) => {
      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () =>
          reject(new DOMException('The request was aborted.', 'AbortError')),
        );
      });
    });
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<DnssecPage />);

    const owner = screen.getByLabelText('Zone or owner name');
    const target = screen.getByLabelText('Validation target');
    const resolver = screen.getByLabelText('Resolver transport');
    await user.type(owner, 'example.test');
    await user.selectOptions(target, 'A');
    await user.selectOptions(resolver, 'quad9');
    await user.click(screen.getByRole('button', { name: 'Validate DNSSEC' }));

    expect(await screen.findByRole('button', { name: 'Validating…' })).toBeDisabled();
    expect(owner).toBeDisabled();
    expect(target).toBeDisabled();
    expect(resolver).toBeDisabled();

    await user.click(screen.getByRole('button', { name: 'Clear' }));
    expect(owner).toBeEnabled();
    expect(owner).toHaveValue('');
    expect(target).toBeEnabled();
    expect(resolver).toBeEnabled();
    await waitFor(() =>
      expect(screen.queryByRole('heading', { name: 'example.test.' })).not.toBeInTheDocument(),
    );
  });

  it('exports versioned raw evidence and invalidates it when any material input changes', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    const validateSpy = vi.spyOn(dnssecChain, 'validateDnssecChain').mockResolvedValue({
      evidence: [
        {
          decodedQuestion: { class: 'IN', name: 'example.test.', type: 'A' },
          name: 'example.test.',
          rawDnsBase64: 'AA==',
          receivedAt: new Date(1_800_000_000_000).toISOString(),
          resolverEndpoint: 'https://cloudflare-dns.com/dns-query',
          type: 'A',
        },
      ],
      explanation: 'The fixture chain validated locally.',
      evidenceValidUntil: new Date(1_800_003_600_000).toISOString(),
      state: 'secure',
      steps: [],
      target: 'example.test.',
      trustAnchorMaintenance: assessRootTrustAnchorMaintenance(1_800_000_000_000),
      trustAnchorSource: ROOT_TRUST_ANCHOR_SOURCE,
      validatedAt: new Date(1_800_000_000_000).toISOString(),
      validatorVersion: 4,
    });
    render(<DnssecPage />);

    const owner = screen.getByLabelText('Zone or owner name');
    const target = screen.getByLabelText('Validation target');
    const resolver = screen.getByLabelText('Resolver transport');
    const submit = screen.getByRole('button', { name: 'Validate DNSSEC' });
    fireEvent.change(owner, { target: { value: 'example.test' } });
    fireEvent.change(target, { target: { value: 'A' } });
    fireEvent.click(submit);
    expect(await screen.findByRole('heading', { name: 'example.test.' })).toBeVisible();
    const validationCall = validateSpy.mock.calls[0];
    expect(validationCall?.[0]).toBe('example.test.');
    expect(validationCall?.[2]?.resolver?.id).toBe('google');
    fireEvent.click(screen.getByRole('button', { name: 'Copy evidence bundle' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    const evidence = JSON.parse(String(writeText.mock.calls[0]?.[0])) as {
      readonly evidence: readonly { readonly rawDnsBase64?: string }[];
      readonly evidenceValidUntil?: string;
      readonly validatorVersion: number;
    };
    expect(evidence.validatorVersion).toBe(4);
    expect(evidence.evidenceValidUntil).toBe(new Date(1_800_003_600_000).toISOString());
    expect(evidence.evidence[0]?.rawDnsBase64).toBe('AA==');

    fireEvent.change(target, { target: { value: 'HTTPS' } });
    expect(screen.queryByRole('heading', { name: 'example.test.' })).not.toBeInTheDocument();

    fireEvent.click(submit);
    expect(await screen.findByRole('heading', { name: 'example.test.' })).toBeVisible();
    fireEvent.change(resolver, { target: { value: 'quad9' } });
    expect(screen.queryByRole('heading', { name: 'example.test.' })).not.toBeInTheDocument();

    fireEvent.click(submit);
    expect(await screen.findByRole('heading', { name: 'example.test.' })).toBeVisible();
    fireEvent.change(owner, { target: { value: 'example.testx' } });
    expect(screen.queryByRole('heading', { name: 'example.test.' })).not.toBeInTheDocument();
  });
});
