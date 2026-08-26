import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it } from 'vitest';

import { App } from './App';

describe('application shell', () => {
  afterEach(() => {
    window.history.replaceState(null, '', '/');
  });

  it('leads with the configuration workflows', () => {
    render(<App />);

    expect(screen.getByRole('heading', { level: 1, name: 'Untangle DNS.' })).toBeVisible();
    expect(screen.getByRole('link', { name: /Inspect DNSSEC/ })).toHaveAttribute(
      'href',
      '/dnssec/',
    );
    expect(screen.getByRole('link', { name: 'Source' })).toHaveAttribute('href', '/SOURCE.md');
    expect(screen.getByRole('link', { name: 'Terms' })).toHaveAttribute('href', '/TERMS.md');
  });

  it('offers a keyboard-operable theme control', async () => {
    const user = userEvent.setup();
    render(<App />);

    const control = screen.getByRole('button', { name: 'Use light theme' });
    await user.click(control);

    expect(screen.getByRole('button', { name: 'Use dark theme' })).toBeVisible();
    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
  });

  it('groups tools into native, keyboard-operable navigation disclosures', async () => {
    const user = userEvent.setup();
    render(<App />);

    const navigation = screen.getByRole('navigation', { name: 'Primary navigation' });
    const inspectSummary = within(navigation).getByText('Inspect');
    const prepareSummary = within(navigation).getByText('Prepare');

    expect(inspectSummary.tagName).toBe('SUMMARY');
    expect(prepareSummary.tagName).toBe('SUMMARY');
    expect(inspectSummary.closest('details')).not.toHaveAttribute('open');
    expect(prepareSummary.closest('details')).not.toHaveAttribute('open');

    inspectSummary.focus();
    expect(inspectSummary).toHaveFocus();
    await user.click(inspectSummary);
    expect(inspectSummary.closest('details')).toHaveAttribute('open');
    expect(within(navigation).getByRole('link', { name: 'DNSSEC' })).toHaveAttribute(
      'href',
      '/dnssec/',
    );
    expect(within(navigation).getByRole('link', { name: 'Snapshots' })).toHaveAttribute(
      'href',
      '/snapshots/',
    );

    await user.click(prepareSummary);
    expect(prepareSummary.closest('details')).toHaveAttribute('open');
    expect(inspectSummary.closest('details')).not.toHaveAttribute('open');

    window.history.pushState(null, '', '/dmarc/');
    act(() => {
      window.dispatchEvent(new PopStateEvent('popstate'));
    });

    await waitFor(() => expect(inspectSummary.closest('details')).not.toHaveAttribute('open'));
    expect(within(navigation).getByRole('link', { name: 'DMARC' })).toHaveAttribute(
      'aria-current',
      'page',
    );
  });

  it('marks the active nested link without opening its disclosure', () => {
    window.history.replaceState(null, '', '/dmarc/');
    render(<App />);

    const navigation = screen.getByRole('navigation', { name: 'Primary navigation' });
    const activeLink = within(navigation).getByRole('link', { name: 'DMARC' });

    expect(activeLink).toHaveAttribute('aria-current', 'page');
    expect(activeLink.closest('details')).not.toHaveAttribute('open');
    expect(within(navigation).getAllByRole('link')).toHaveLength(12);
  });

  it('updates the document title for known and unknown routes', async () => {
    window.history.replaceState(null, '', '/lookup/');
    render(<App />);

    await waitFor(() => expect(document.title).toBe('DNS record lookup — ZoneSkein'));

    window.history.pushState(null, '', '/missing/');
    act(() => {
      window.dispatchEvent(new PopStateEvent('popstate'));
    });

    await waitFor(() => expect(document.title).toBe('Page not found — ZoneSkein'));
  });

  it('follows browser history and focuses the new main view', async () => {
    render(<App />);

    window.history.pushState(null, '', '/about/');
    act(() => {
      window.dispatchEvent(new PopStateEvent('popstate'));
    });

    expect(
      await screen.findByRole('heading', { level: 1, name: 'A workbench, not a scanner.' }),
    ).toBeVisible();
    expect(document.querySelector('#main-content')).toHaveFocus();
  });

  it('keeps explicit tool hand-offs in memory and focuses their destination', async () => {
    const user = userEvent.setup();
    window.history.replaceState(null, '', '/studio/');
    render(<App />);

    const prepareSummary = within(
      screen.getByRole('navigation', { name: 'Primary navigation' }),
    ).getByText('Prepare');
    await user.click(prepareSummary);
    expect(prepareSummary.closest('details')).toHaveAttribute('open');

    await user.type(
      await screen.findByRole('textbox', { name: 'Owner name' }),
      'www.example.com.',
    );
    await user.type(screen.getByRole('textbox', { name: 'IPv4 address' }), '192.0.2.10');
    await user.click(screen.getByRole('button', { name: 'Add valid record' }));
    await user.click(screen.getByRole('button', { name: 'Open in Change Workspace' }));

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'Carry a DNS change without a backend.',
      }),
    ).toBeVisible();
    expect(window.location.pathname).toBe('/workspace/');
    expect(window.history.state).toBeNull();
    expect(document.querySelector('#main-content')).toHaveFocus();
    expect(prepareSummary.closest('details')).not.toHaveAttribute('open');
    expect(screen.getByLabelText('Intended BIND-style zone text')).toHaveValue(
      'www.example.com. 3600 IN A 192.0.2.10',
    );
  });

  it('round-trips partial semantics and separate origins through Change Lab', async () => {
    const user = userEvent.setup();
    window.history.replaceState(null, '', '/workspace/');
    render(<App />);

    const current = within(await screen.findByRole('group', { name: 'Current zone state' }));
    const intended = within(screen.getByRole('group', { name: 'Intended zone state' }));
    await user.selectOptions(current.getByLabelText('Availability'), 'partial');
    await user.selectOptions(intended.getByLabelText('Availability'), 'complete');
    fireEvent.change(current.getByLabelText('Current origin (optional)'), {
      target: { value: 'observed.example.' },
    });
    fireEvent.change(current.getByLabelText('Current BIND-style zone text'), {
      target: { value: 'www 300 IN A 192.0.2.1' },
    });
    fireEvent.change(current.getByLabelText('Why current state is partial'), {
      target: { value: 'Only selected address records were observed.' },
    });
    fireEvent.change(intended.getByLabelText('Intended origin (optional)'), {
      target: { value: 'planned.example.' },
    });
    fireEvent.change(intended.getByLabelText('Intended BIND-style zone text'), {
      target: { value: 'www 300 IN A 192.0.2.2' },
    });
    await user.click(screen.getByRole('button', { name: 'Apply edits' }));
    await user.click(screen.getByRole('button', { name: 'Open in Change Lab' }));

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'Compare records and plan a bounded rollout.',
      }),
    ).toBeVisible();
    expect(screen.getByLabelText('Origin for relative names')).toHaveValue('observed.example.');
    expect(screen.getByLabelText('Proposed snapshot origin')).toHaveValue('planned.example.');
    await user.click(screen.getByRole('button', { name: 'Compare snapshots' }));
    expect(screen.getByRole('alert')).toHaveTextContent(
      /Current zone state is partial.*Only selected address records were observed/iu,
    );
    expect(screen.queryByText('Change set')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Return to Change Workspace' }));
    expect(
      await screen.findByRole('heading', { name: 'Untitled change workspace' }),
    ).toBeVisible();
    expect(screen.getByLabelText('Current origin (optional)')).toHaveValue('observed.example.');
    expect(screen.getByLabelText('Why current state is partial')).toHaveValue(
      'Only selected address records were observed.',
    );
    expect(screen.getByLabelText('Intended origin (optional)')).toHaveValue('planned.example.');
  });
});
