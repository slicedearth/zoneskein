import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import * as zoneDigest from '../core/zone/zonemd';
import { ZoneLintPage } from './ZoneLintPage';

const COMPLETE_ZONE = `$ORIGIN example.
@ 300 IN SOA ns hostmaster 1 3600 600 86400 300
@ 300 IN NS ns
ns 300 IN A 192.0.2.1`;

describe('ZoneLintPage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('keeps complete-zone calculation explicit and invalidates stale results on editing', async () => {
    const user = userEvent.setup();
    render(<ZoneLintPage />);

    await user.type(screen.getByLabelText('Zone snippet'), COMPLETE_ZONE);
    await user.click(screen.getByRole('button', { name: 'Lint zone input' }));

    expect(await screen.findByText('Not calculated')).toBeVisible();
    expect(screen.queryByText('Generated publication records')).not.toBeInTheDocument();

    await user.click(
      screen.getByRole('checkbox', {
        name: 'Treat this input as a complete standalone zone for ZONEMD calculation',
      }),
    );
    expect(
      screen.getByRole('checkbox', {
        name: 'Treat this input as a complete standalone zone for ZONEMD calculation',
      }),
    ).toBeChecked();
    await user.click(screen.getByRole('button', { name: 'Lint zone input' }));

    const digestPanel = (
      await screen.findByRole('heading', {
        name: 'Complete-zone integrity digest',
      })
    ).closest('article');
    expect(digestPanel).toHaveTextContent('Digests generated');
    expect(screen.getByText('Generated publication records')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Copy SHA-384 ZONEMD record' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Copy SHA-512 ZONEMD record' })).toBeVisible();

    await user.type(screen.getByLabelText('Zone snippet'), '\nwww 300 IN A 192.0.2.2');
    await waitFor(() =>
      expect(screen.queryByText('Generated publication records')).not.toBeInTheDocument(),
    );
  });

  it('reports a published digest mismatch without treating it as authenticated', async () => {
    const user = userEvent.setup();
    render(<ZoneLintPage />);

    await user.type(
      screen.getByLabelText('Zone snippet'),
      `${COMPLETE_ZONE}\n@ 300 IN ZONEMD 1 1 1 ${'00'.repeat(48)}`,
    );
    await user.click(
      screen.getByRole('checkbox', {
        name: 'Treat this input as a complete standalone zone for ZONEMD calculation',
      }),
    );
    await user.click(screen.getByRole('button', { name: 'Lint zone input' }));

    const digestPanel = (
      await screen.findByRole('heading', {
        name: 'Complete-zone integrity digest',
      })
    ).closest('article');
    expect(digestPanel).toHaveTextContent('Digest mismatch');
    expect(screen.getByText(/internal consistency only|not proof of origin/iu)).toBeVisible();
  });

  it('keeps an oversized report visible without offering a snapshot that cannot be saved', async () => {
    const user = userEvent.setup();
    render(<ZoneLintPage />);

    fireEvent.change(screen.getByLabelText('Zone snippet'), {
      target: { value: `;${'x'.repeat(262_143)}` },
    });
    await user.click(screen.getByRole('button', { name: 'Lint zone input' }));

    expect(await screen.findByRole('heading', { name: 'Lint results' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Snapshot too large' })).toBeDisabled();
  });

  it('invalidates conclusions and actions after every material input changes, then relints', async () => {
    const user = userEvent.setup();
    render(<ZoneLintPage />);
    const source = screen.getByLabelText('Zone snippet');
    const origin = screen.getByLabelText('Origin when $ORIGIN is absent');
    const minimum = screen.getByLabelText('Minimum recommended TTL');
    const maximum = screen.getByLabelText('Maximum recommended TTL');
    const submit = screen.getByRole('button', { name: 'Lint zone input' });

    await user.type(source, '@ 300 IN A 192.0.2.1');
    await user.type(origin, 'example.test');

    const relint = async () => {
      await user.click(submit);
      expect(await screen.findByRole('heading', { name: 'Lint results' })).toBeVisible();
      expect(screen.getByRole('button', { name: 'Save snapshot' })).toBeVisible();
    };
    const expectInvalid = () => {
      expect(screen.queryByRole('heading', { name: 'Lint results' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Save snapshot' })).not.toBeInTheDocument();
    };

    await relint();
    await user.type(source, '\nmail 300 IN A 192.0.2.2');
    expectInvalid();

    await relint();
    await user.clear(origin);
    await user.type(origin, 'changed.test');
    expectInvalid();

    await relint();
    await user.clear(minimum);
    await user.type(minimum, '60');
    expectInvalid();

    await relint();
    await user.clear(maximum);
    await user.type(maximum, '900');
    expectInvalid();

    await relint();
    await user.click(
      screen.getByRole('checkbox', {
        name: 'Treat this input as a complete standalone zone for ZONEMD calculation',
      }),
    );
    expectInvalid();
    await relint();
  });

  it('does not restore a superseded result when digest analysis completes late', async () => {
    let finish: ((report: zoneDigest.ZoneDigestReport) => void) | undefined;
    vi.spyOn(zoneDigest, 'analyseZoneDigest').mockImplementation(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    render(<ZoneLintPage />);
    fireEvent.change(screen.getByLabelText('Zone snippet'), {
      target: { value: '@ 300 IN A 192.0.2.1' },
    });
    fireEvent.change(screen.getByLabelText('Origin when $ORIGIN is absent'), {
      target: { value: 'example.test' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Lint zone input' }));
    expect(screen.getByRole('button', { name: 'Analysing…' })).toBeDisabled();

    fireEvent.change(screen.getByLabelText('Zone snippet'), {
      target: { value: '@ 300 IN A 192.0.2.2' },
    });
    finish?.({
      authentication: 'checksum-only',
      digests: [],
      duplicatesOmitted: 0,
      excludedApexRecords: 0,
      excludedOutOfZoneRecords: 0,
      explanation: 'Superseded result.',
      includedRecords: 1,
      issues: [],
      state: 'unavailable',
      suggestedRecords: [],
    });

    await waitFor(() =>
      expect(screen.queryByRole('heading', { name: 'Lint results' })).not.toBeInTheDocument(),
    );
    expect(screen.getByRole('button', { name: 'Lint zone input' })).toBeEnabled();
    expect(screen.queryByText('Superseded result.')).not.toBeInTheDocument();
  });

  it('renders pasted directional controls as explicit isolated evidence', async () => {
    const user = userEvent.setup();
    render(<ZoneLintPage />);

    await user.type(
      screen.getByLabelText('Zone snippet'),
      '@ 300 IN TXT "ordinary 🌏 \u202e hidden"',
    );
    await user.type(screen.getByLabelText('Origin when $ORIGIN is absent'), 'example.test');
    await user.click(screen.getByRole('button', { name: 'Lint zone input' }));

    const value = await screen.findByText(/ordinary 🌏.*\\u\{202E\} hidden/iu);
    expect(value).toHaveAttribute('dir', 'ltr');
    expect(value).toHaveClass('technical-value');
    expect(value).not.toHaveTextContent('\u202e');
  });

  it('rejects zone text that cannot have exact UTF-8 evidence', async () => {
    render(<ZoneLintPage />);
    fireEvent.change(screen.getByLabelText('Zone snippet'), {
      target: { value: '@ 300 IN TXT "' + String.fromCharCode(0xd800) + '"' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Lint zone input' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/unpaired UTF-16 surrogates/iu);
    expect(screen.queryByRole('heading', { name: 'Lint results' })).not.toBeInTheDocument();
  });
});
