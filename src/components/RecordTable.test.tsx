import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { DnsRecord } from '../core/dns/types';
import { RecordTable } from './RecordTable';

const mxRecord: DnsRecord = {
  class: 'IN',
  data: { exchange: 'mail.example.com', preference: 10 },
  owner: 'example.com',
  rawRdata: new Uint8Array(),
  section: 'answer',
  ttl: 300,
  type: 'MX',
  typeCode: 15,
};

describe('RecordTable', () => {
  it('provides a labelled keyboard-focusable scroll region', () => {
    render(<RecordTable label="Answer records" records={[mxRecord]} />);

    const region = screen.getByRole('region', { name: 'Answer records table' });
    expect(region).toHaveAttribute('tabindex', '0');
    expect(screen.getByRole('table', { name: 'Answer records' })).toBeInTheDocument();
  });

  it('keeps parsed fields collapsed in compact mode', () => {
    render(<RecordTable compact records={[mxRecord]} />);

    const summary = screen.getByText('Parsed fields');
    expect(summary.closest('details')).not.toHaveAttribute('open');
    expect(screen.getByText('mail.example.com 10')).toBeInTheDocument();
  });

  it('isolates visible TXT escapes and exposes exact raw RDATA without expanding the row', () => {
    const chunk = Uint8Array.from(new TextEncoder().encode('safe\u202e\n'));
    render(
      <RecordTable
        compact
        records={[
          {
            class: 'IN',
            data: [chunk],
            owner: 'example.test.',
            rawRdata: Uint8Array.from([chunk.length, ...chunk]),
            section: 'answer',
            ttl: 300,
            type: 'TXT',
            typeCode: 16,
          },
        ]}
      />,
    );

    const value = screen.getByText('"safe\\u{202E}\\n"');
    expect(value).toHaveAttribute('dir', 'ltr');
    expect(value).toHaveClass('technical-value');
    const raw = screen.getByText(/Raw RDATA/iu).closest('details');
    expect(raw).not.toHaveAttribute('open');
    expect(raw).toHaveTextContent(/Base64:/u);
    expect(document.body.textContent).not.toContain('\u202e');
  });

  it('keeps literal owner escape notation distinct from an actual direction control', () => {
    const control = String.fromCodePoint(0x202e);
    render(
      <RecordTable
        records={[
          {
            ...mxRecord,
            owner: String.raw`literal\u{202E}.actual` + control + '.example.',
          },
        ]}
      />,
    );

    const owner = screen.getByText(String.raw`literal\\u{202E}.actual\u{202E}.example.`);
    expect(owner).toHaveAttribute('dir', 'ltr');
    expect(owner).not.toHaveTextContent(control);
  });
});
