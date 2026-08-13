import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { DNSSEC_APPLICATION_TYPES } from '../core/dnssec/application';
import * as dnssecChain from '../core/dnssec/chain';
import { ROOT_TRUST_ANCHOR_SOURCE } from '../core/dnssec/trust-anchors';
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

  it('invalidates completed evidence when any material run input changes', async () => {
    vi.spyOn(dnssecChain, 'validateDnssecChain').mockResolvedValue({
      evidence: [],
      explanation: 'The fixture chain validated locally.',
      state: 'secure',
      steps: [],
      target: 'example.test.',
      trustAnchorSource: ROOT_TRUST_ANCHOR_SOURCE,
      validatedAt: new Date(1_800_000_000_000).toISOString(),
      validatorVersion: 2,
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
