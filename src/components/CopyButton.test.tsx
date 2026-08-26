import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { CopyButton } from './CopyButton';

describe('CopyButton', () => {
  it('announces a successful clipboard action through a polite status region', async () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    render(<CopyButton label="Copy report" text="evidence" />);

    fireEvent.click(screen.getByRole('button', { name: 'Copy report' }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith('evidence'));
    expect(screen.getByRole('status')).toHaveTextContent('Copy report succeeded.');
    expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument();
  });

  it('does not expose a disabled draft to the clipboard', () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    render(<CopyButton disabled label="Copy record" text="invalid draft" />);

    const button = screen.getByRole('button', { name: 'Copy record' });
    expect(button).toBeDisabled();
    fireEvent.click(button);

    expect(writeText).not.toHaveBeenCalled();
  });
});
