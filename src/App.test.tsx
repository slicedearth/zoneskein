import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { App } from './App';

describe('application shell', () => {
  it('leads with the configuration workflows', () => {
    render(<App />);

    expect(screen.getByRole('heading', { level: 1, name: 'Untangle DNS.' })).toBeVisible();
    expect(screen.getByRole('link', { name: /Inspect DNSSEC/ })).toHaveAttribute(
      'href',
      '/dnssec/',
    );
  });

  it('offers a keyboard-operable theme control', async () => {
    const user = userEvent.setup();
    render(<App />);

    const control = screen.getByRole('button', { name: 'Use light theme' });
    await user.click(control);

    expect(screen.getByRole('button', { name: 'Use dark theme' })).toBeVisible();
    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
  });
});
