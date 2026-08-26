import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { ZoneLintPage } from './ZoneLintPage';

const COMPLETE_ZONE = `$ORIGIN example.
@ 300 IN SOA ns hostmaster 1 3600 600 86400 300
@ 300 IN NS ns
ns 300 IN A 192.0.2.1`;

describe('ZoneLintPage', () => {
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
});
