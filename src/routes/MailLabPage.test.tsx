import { act, fireEvent, render, screen } from '@testing-library/react';
import { StrictMode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { MailLabPage } from './MailLabPage';
import { inspectCertificate, verifyTlsaAssociation } from '../core/mail/certificate';
import { extractMailReportPayloadsAsync } from '../core/mail/report-archive-client';

vi.mock('../core/mail/certificate', () => ({
  inspectCertificate: vi.fn(),
  verifyTlsaAssociation: vi.fn(),
}));
vi.mock('../core/mail/report-archive-client', () => ({
  extractMailReportPayloadsAsync: vi.fn(),
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

function certificate(subject: string): Awaited<ReturnType<typeof inspectCertificate>> {
  return {
    der: new Uint8Array([1]),
    inspection: {
      subject,
      issuer: 'Fixture issuer',
      extensions: [],
      fingerprintSha256: '00',
      notBefore: '2026-01-01',
      notAfter: '2027-01-01',
      publicKeyAlgorithm: 'fixture',
      serialHex: '00',
      signatureAlgorithm: 'fixture',
      spki: new Uint8Array([1]),
    },
  };
}

function startCertificate(value: string): void {
  fireEvent.change(screen.getByLabelText('X.509 certificate'), { target: { value } });
  fireEvent.click(screen.getByRole('button', { name: 'Inspect certificate' }));
}

beforeEach(() => {
  vi.mocked(inspectCertificate).mockReset();
  vi.mocked(verifyTlsaAssociation).mockReset();
  vi.mocked(extractMailReportPayloadsAsync).mockReset();
});

describe('Mail Lab request ownership', () => {
  it('reports rejected prefixed SVG content without rendering it or claiming certification', () => {
    render(<MailLabPage />);
    fireEvent.click(screen.getByRole('button', { name: 'BIMI' }));
    fireEvent.change(screen.getByLabelText('Optional local SVG logo'), {
      target: {
        value:
          '<svg xmlns="http://www.w3.org/2000/svg" xmlns:s="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 1 1"><title>X</title><s:script id="untrusted-script">alert(1)</s:script></svg>',
      },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Inspect BIMI inputs' }));
    expect(screen.getByText(/Element <s:script> is outside/u)).toBeInTheDocument();
    expect(screen.getByText('static profile review')).toBeInTheDocument();
    expect(screen.getByText(/not full profile certification/u)).toBeInTheDocument();
    expect(document.getElementById('untrusted-script')).toBeNull();
  });

  it('shows a multi-label MTA-STS wildcard miss as uncovered', () => {
    render(<MailLabPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Transport policy' }));
    fireEvent.change(screen.getByLabelText('MTA-STS policy'), {
      target: { value: 'version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 300' },
    });
    fireEvent.change(screen.getByLabelText('Published MX hosts'), {
      target: { value: 'foo.bar.example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Check transport policy' }));
    expect(screen.getByText('uncovered', { exact: true })).toBeInTheDocument();
    expect(screen.queryByText('covered', { exact: true })).not.toBeInTheDocument();
  });

  it.each(['resolve', 'reject'] as const)(
    'ignores an old certificate %s after a newer result',
    async (outcome) => {
      const first = deferred<Awaited<ReturnType<typeof inspectCertificate>>>();
      vi.mocked(inspectCertificate)
        .mockReturnValueOnce(first.promise)
        .mockResolvedValueOnce(certificate('Current certificate'));
      render(
        <StrictMode>
          <MailLabPage />
        </StrictMode>,
      );
      fireEvent.click(screen.getByRole('button', { name: 'Certificate & TLSA' }));
      startCertificate('first');
      startCertificate('second');
      expect(await screen.findByText('Current certificate')).toBeInTheDocument();
      await act(async () => {
        await Promise.resolve();
        if (outcome === 'resolve') first.resolve(certificate('Stale certificate'));
        else first.reject(new Error('Stale error'));
      });
      expect(screen.queryByText('Stale certificate')).not.toBeInTheDocument();
      expect(screen.queryByText('Stale error')).not.toBeInTheDocument();
      expect(screen.getByText('Current certificate')).toBeInTheDocument();
    },
  );

  it('does not let an old finally clear a newer busy state', async () => {
    const first = deferred<Awaited<ReturnType<typeof inspectCertificate>>>();
    const second = deferred<Awaited<ReturnType<typeof inspectCertificate>>>();
    vi.mocked(inspectCertificate)
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);
    render(<MailLabPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Certificate & TLSA' }));
    startCertificate('first');
    startCertificate('second');
    await act(async () => {
      await Promise.resolve();
      first.reject(new Error('Old failure'));
    });
    expect(screen.getByRole('button', { name: 'Inspecting…' })).toBeDisabled();
    await act(async () => {
      await Promise.resolve();
      second.resolve(certificate('Second result'));
    });
    expect(screen.getByText('Second result')).toBeInTheDocument();
  });

  it('invalidates pending TLSA digest results on input edits and mode changes', async () => {
    const digest = deferred<Awaited<ReturnType<typeof verifyTlsaAssociation>>>();
    vi.mocked(inspectCertificate).mockResolvedValue(certificate('Old certificate'));
    vi.mocked(verifyTlsaAssociation).mockReturnValue(digest.promise);
    render(<MailLabPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Certificate & TLSA' }));
    fireEvent.change(screen.getByLabelText('Optional TLSA RDATA'), {
      target: { value: '3 1 1 00' },
    });
    await act(async () => {
      await Promise.resolve();
      startCertificate('first');
    });
    fireEvent.change(screen.getByLabelText('Optional TLSA RDATA'), {
      target: { value: '3 1 1 11' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Reports' }));
    await act(async () => {
      await Promise.resolve();
      digest.resolve({ matches: true, reason: 'Stale match' });
    });
    expect(screen.queryByText('Certificate evidence')).not.toBeInTheDocument();
    expect(screen.queryByText('Stale match')).not.toBeInTheDocument();
  });

  it.each(['resolve', 'reject'] as const)(
    'invalidates an outstanding local file %s before it reaches the worker',
    async (outcome) => {
      const pending = deferred<ArrayBuffer>();
      const file = new File(['x'], 'report.xml');
      Object.defineProperty(file, 'arrayBuffer', { value: () => pending.promise });
      render(<MailLabPage />);
      fireEvent.change(screen.getByLabelText('Choose XML, JSON, gzip, or ZIP reports'), {
        target: { files: [file] },
      });
      fireEvent.click(screen.getByRole('button', { name: 'Transport policy' }));
      await act(async () => {
        await Promise.resolve();
        if (outcome === 'resolve') pending.resolve(new ArrayBuffer(1));
        else pending.reject(new Error('Stale read error'));
      });
      expect(extractMailReportPayloadsAsync).not.toHaveBeenCalled();
      expect(screen.queryByText('Stale read error')).not.toBeInTheDocument();
      expect(screen.queryByText('Parsing bounded local input.')).not.toBeInTheDocument();
    },
  );

  it('aborts a worker import on unmount and exposes explicit cancellation', async () => {
    const pending = deferred<Awaited<ReturnType<typeof extractMailReportPayloadsAsync>>>();
    vi.mocked(extractMailReportPayloadsAsync).mockReturnValue(pending.promise);
    const file = new File(['x'], 'report.xml');
    Object.defineProperty(file, 'arrayBuffer', {
      value: () => Promise.resolve(new ArrayBuffer(1)),
    });
    const view = render(<MailLabPage />);
    await act(async () => {
      await Promise.resolve();
      fireEvent.change(screen.getByLabelText('Choose XML, JSON, gzip, or ZIP reports'), {
        target: { files: [file] },
      });
    });
    const signal = vi.mocked(extractMailReportPayloadsAsync).mock.calls[0]?.[2].signal;
    expect(signal?.aborted).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel local operation' }));
    expect(screen.getByText('Local operation cancelled.')).toBeInTheDocument();
    expect(signal?.aborted).toBe(true);
    view.unmount();
    await act(async () => {
      await Promise.resolve();
      pending.reject(new Error('Cancelled'));
    });
  });
});
