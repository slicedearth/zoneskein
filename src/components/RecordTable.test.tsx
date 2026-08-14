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
});
