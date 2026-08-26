import { render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { PublicDocumentPage, SourceChecksumPage } from './PublicDocumentPage';

afterEach(() => vi.unstubAllGlobals());

describe('public document routes', () => {
  it('renders Markdown notices with semantic headings and an explicit raw download', () => {
    render(<PublicDocumentPage documentId="privacy" />);

    expect(screen.getByRole('heading', { level: 1, name: 'Privacy' })).toBeVisible();
    expect(screen.getByRole('heading', { level: 2, name: 'Browser storage' })).toBeVisible();
    expect(screen.getByRole('link', { name: 'Download raw PRIVACY.md' })).toHaveAttribute(
      'href',
      '/PRIVACY.md',
    );
  });

  it('keeps document cross-references on semantic routes and renders tables accessibly', () => {
    const { rerender } = render(<PublicDocumentPage documentId="source" />);

    expect(screen.getByRole('link', { name: 'View its SHA-256 checksum' })).toHaveAttribute(
      'href',
      '/source-checksum/',
    );

    rerender(<PublicDocumentPage documentId="third-party-notices" />);
    const table = screen.getByRole('region', { name: 'Document table' });
    expect(table).toHaveAttribute('tabindex', '0');
    expect(table).toHaveTextContent('@dnsquery/dns-packet');
  });

  it('places the controlling plain-text licence inside a titled document', () => {
    render(<PublicDocumentPage documentId="licence" />);

    expect(
      screen.getByRole('heading', { level: 1, name: 'GNU Affero General Public License' }),
    ).toBeVisible();
    expect(screen.getByText(/END OF TERMS AND CONDITIONS/iu)).toBeVisible();
  });

  it('loads the build-specific source checksum without treating it as a signature', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response(`${'a'.repeat(64)}  zoneskein-corresponding-source.tar.gz\n`, {
          status: 200,
        }),
      ),
    );
    render(<SourceChecksumPage />);

    expect(screen.getByRole('heading', { name: 'Source archive checksum' })).toBeVisible();
    await waitFor(() =>
      expect(screen.getByText(new RegExp(`^${'a'.repeat(64)}`, 'u'))).toBeVisible(),
    );
    expect(screen.getByText(/not a signature/iu)).toBeVisible();
    expect(screen.getByRole('link', { name: 'Download raw SOURCE_SHA256' })).toHaveAttribute(
      'href',
      '/SOURCE_SHA256',
    );
  });
});
