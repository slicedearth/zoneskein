import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { CaaPage } from './CaaPage';
import { discoverCaaPolicy, type CaaDiscoveryReport } from '../core/caa/discovery';

vi.mock('../core/caa/discovery', () => ({
  discoverCaaPolicy: vi.fn(),
}));

vi.mock('../core/doh/rate-limit', () => ({
  BrowserRateLimiter: class {
    imposeCooldown(): void {
      // Route tests do not exercise cross-tab resolver pacing.
    }

    wait(): Promise<void> {
      return Promise.resolve();
    }
  },
}));

const discoverCaaPolicyMock = vi.mocked(discoverCaaPolicy);

function report(overrides: Partial<CaaDiscoveryReport> = {}): CaaDiscoveryReport {
  return {
    aliases: [],
    errors: [],
    queried: ['example.test'],
    records: [],
    requested: 'example.test',
    ...overrides,
  };
}

function deferredReport() {
  let resolve!: (value: CaaDiscoveryReport) => void;
  const promise = new Promise<CaaDiscoveryReport>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

afterEach(() => discoverCaaPolicyMock.mockReset());

describe('CaaPage', () => {
  it('blocks copying malformed local CAA drafts and associates field errors', async () => {
    const user = userEvent.setup();
    render(<CaaPage />);

    const issuer = screen.getByLabelText('Issuer-domain-name');
    await user.clear(issuer);
    await user.type(issuer, 'not a domain');

    expect(issuer).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByText(/valid issuer-domain-name/iu)).toHaveAttribute(
      'id',
      'caa-issuer-error',
    );
    expect(screen.getByRole('button', { name: 'Copy CAA record' })).toBeDisabled();

    await user.clear(issuer);
    await user.type(issuer, 'ca.example');
    expect(screen.getByRole('button', { name: 'Copy CAA record' })).toBeEnabled();

    const accountUri = screen.getByLabelText('CA account URI (optional)');
    await user.type(accountUri, 'not a uri');
    expect(accountUri).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByRole('button', { name: 'Copy CAA record' })).toBeDisabled();

    await user.clear(accountUri);
    const validationMethods = screen.getByLabelText('Validation methods (optional)');
    await user.type(validationMethods, 'dns 01');
    expect(validationMethods).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByRole('button', { name: 'Copy CAA record' })).toBeDisabled();
  });

  it('reports an exhausted parent-walk budget as partial evidence', async () => {
    const domain = [...Array.from({ length: 80 }, () => 'a'), 'b', 'c', 'test'].join('.');
    discoverCaaPolicyMock.mockImplementation((names) =>
      Promise.resolve(
        report({
          queried: names,
          requested: domain,
        }),
      ),
    );
    const user = userEvent.setup();
    render(<CaaPage />);

    await user.type(screen.getByLabelText('DNS name'), domain);
    await user.click(screen.getByRole('button', { name: 'Inspect CAA' }));

    await waitFor(() =>
      expect(screen.getByRole('status', { name: 'CAA run status' })).toHaveTextContent(
        'CAA inspection complete with partial DNS evidence.',
      ),
    );
    expect(discoverCaaPolicyMock.mock.calls[0]?.[0]).toHaveLength(80);
    expect(screen.getByText(/safety budget was exhausted before b\.c\.test/iu)).toBeVisible();
  });

  it('discloses the automatic Quad9 compatibility boundary', async () => {
    const user = userEvent.setup();
    render(<CaaPage />);

    const resolver = screen.getByLabelText('Resolver');
    await user.selectOptions(resolver, 'quad9');

    const note = screen.getByText(/compatibility mode lets Netlify observe the DNS question/iu);
    expect(note).toHaveAttribute('id', 'caa-resolver-note');
    expect(resolver).toHaveAttribute('aria-describedby', 'caa-resolver-note');
  });

  it('announces loading and completion, and exposes populated results as a keyboard region', async () => {
    const deferred = deferredReport();
    discoverCaaPolicyMock.mockReturnValue(deferred.promise);
    const user = userEvent.setup();
    render(<CaaPage />);

    await user.type(screen.getByLabelText('DNS name'), 'example.test');
    await user.click(screen.getByRole('button', { name: 'Inspect CAA' }));

    expect(screen.getByRole('status', { name: 'CAA run status' })).toHaveTextContent(
      'CAA inspection in progress.',
    );

    await act(async () => {
      deferred.resolve(
        report({
          foundFor: 'example.test',
          records: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }],
          source: 'example.test',
          ttl: 300,
        }),
      );
      await deferred.promise;
    });

    expect(screen.getByRole('status', { name: 'CAA run status' })).toHaveTextContent(
      'CAA inspection complete.',
    );
    expect(screen.getByRole('region', { name: 'CAA policy records' })).toHaveAttribute(
      'tabindex',
      '0',
    );

    await user.type(screen.getByLabelText('DNS name'), 'x');
    expect(screen.getByRole('status', { name: 'CAA run status' })).toBeEmptyDOMElement();
    expect(
      screen.queryByRole('region', { name: 'CAA policy records' }),
    ).not.toBeInTheDocument();
  });

  it('announces partial DNS evidence without treating it as a complete result', async () => {
    discoverCaaPolicyMock.mockResolvedValue(
      report({ errors: ['example.test: resolver returned SERVFAIL'] }),
    );
    const user = userEvent.setup();
    render(<CaaPage />);

    await user.type(screen.getByLabelText('DNS name'), 'example.test');
    await user.click(screen.getByRole('button', { name: 'Inspect CAA' }));

    await waitFor(() =>
      expect(screen.getByRole('status', { name: 'CAA run status' })).toHaveTextContent(
        'CAA inspection complete with partial DNS evidence.',
      ),
    );
    expect(screen.getByText('Partial')).toBeVisible();
  });

  it('announces unexpected failures and cancelled walks', async () => {
    discoverCaaPolicyMock.mockRejectedValueOnce(new Error('unexpected failure'));
    const user = userEvent.setup();
    const { unmount } = render(<CaaPage />);

    await user.type(screen.getByLabelText('DNS name'), 'failure.test');
    await user.click(screen.getByRole('button', { name: 'Inspect CAA' }));

    await waitFor(() =>
      expect(screen.getByRole('status', { name: 'CAA run status' })).toHaveTextContent(
        'CAA inspection could not be completed.',
      ),
    );
    expect(screen.getByRole('alert')).toHaveTextContent(
      /try again or choose another resolver/iu,
    );

    unmount();
    const deferred = deferredReport();
    discoverCaaPolicyMock.mockReturnValueOnce(deferred.promise);
    render(<CaaPage />);

    await user.type(screen.getByLabelText('DNS name'), 'cancel.test');
    await user.click(screen.getByRole('button', { name: 'Inspect CAA' }));
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    await act(async () => {
      deferred.resolve(report({ requested: 'cancel.test' }));
      await deferred.promise;
    });

    expect(screen.getByRole('status', { name: 'CAA run status' })).toHaveTextContent(
      'The CAA walk was cancelled.',
    );
  });
});
