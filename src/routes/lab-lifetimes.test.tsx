import { act, fireEvent, render, screen } from '@testing-library/react';
import { StrictMode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { DnsResponse } from '../core/dns/types';
import { decodeDnsMessage } from '../core/dns/wire';
import { analyseDnssecLifecycle, type DnssecLifecycleReport } from '../core/dnssec/lifecycle';
import { DnsQueryRun } from '../core/doh/query-run';
import {
  runGlobalpingDns,
  type GlobalpingDnsMeasurement,
} from '../core/measurement/globalping';
import { DelegationPage } from './DelegationPage';
import { EvidenceMapPage } from './EvidenceMapPage';
import { ProtocolLabPage } from './ProtocolLabPage';
import { ZoneExchangePage } from './ZoneExchangePage';

vi.mock('../core/dnssec/lifecycle', () => ({ analyseDnssecLifecycle: vi.fn() }));
vi.mock('../core/measurement/globalping', () => ({
  reserveGlobalpingRun: () => ({ ok: true }),
  runGlobalpingDns: vi.fn(),
}));
vi.mock('../core/doh/query-run', () => ({
  DnsQueryRun: class {
    cancelled = false;
    query() {
      return Promise.reject(new Error('Unconfigured offline fixture'));
    }
    cancel() {
      this.cancelled = true;
    }
  },
}));
vi.mock('../components/EvidenceGraph', () => ({
  EvidenceGraph: () => <div>Graph fixture</div>,
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
function change(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}
function click(name: string) {
  fireEvent.click(screen.getByRole('button', { name }));
}
async function settle(action: () => void) {
  await act(async () => {
    action();
    await Promise.resolve();
  });
}
function lifecycle(message: string): DnssecLifecycleReport {
  return {
    derivedDs: [],
    dsRecords: [],
    keys: [],
    stages: [],
    parsedRecords: 1,
    status: 'partial',
    findings: [{ code: 'fixture', message, tone: 'information' }],
  };
}
function measurement(id: string): GlobalpingDnsMeasurement {
  return {
    completedAt: '2026-10-11T00:00:00Z',
    id,
    probesCount: 0,
    results: [],
    target: 'example.com',
  };
}
function dns(): DnsResponse {
  return {
    cache: 'miss',
    queryTimeMs: 1,
    receivedAt: '2026-10-11T00:00:00Z',
    resolver: {
      id: 'google',
      label: 'Fixture resolver',
      endpoint: 'https://resolver.example/dns-query',
      httpMethod: 'POST',
      privacyUrl: 'https://resolver.example/privacy',
    },
    question: {
      name: {
        absolute: 'example.com.',
        ascii: 'example.com',
        display: 'example.com',
        hadRootDot: false,
        unicode: false,
      },
      type: 'TYPE66',
    },
    // Independent empty response with numeric question 66 (DSYNC).
    message: decodeDnsMessage(
      Uint8Array.from([
        0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99,
        111, 109, 0, 0, 66, 0, 1,
      ]),
    ),
  };
}

beforeEach(() => vi.restoreAllMocks());

describe('lab operation ownership', () => {
  it.each(['resolve', 'reject', 'resolve-after', 'reject-after'] as const)(
    'ignores an old lifecycle %s and finally during a newer run',
    async (outcome) => {
      const a = deferred<DnssecLifecycleReport>();
      const b = deferred<DnssecLifecycleReport>();
      vi.mocked(analyseDnssecLifecycle)
        .mockReset()
        .mockReturnValueOnce(a.promise)
        .mockReturnValueOnce(b.promise);
      render(
        <StrictMode>
          <DelegationPage />
        </StrictMode>,
      );
      click('DNSSEC lifecycle');
      change('DNSSEC and delegation records', 'first');
      click('Model lifecycle');
      change('DNSSEC and delegation records', 'second');
      click('Model lifecycle');
      if (outcome.endsWith('-after'))
        await settle(() => b.resolve(lifecycle('Current lifecycle')));
      await settle(() =>
        outcome.startsWith('resolve')
          ? a.resolve(lifecycle('Stale result'))
          : a.reject(new Error('Stale error')),
      );
      if (!outcome.endsWith('-after'))
        expect(screen.getByRole('button', { name: 'Checking…' })).toBeDisabled();
      expect(screen.queryByText(/Stale/u)).not.toBeInTheDocument();
      if (!outcome.endsWith('-after'))
        await settle(() => b.resolve(lifecycle('Current lifecycle')));
      expect(screen.getByText('Current lifecycle')).toBeInTheDocument();
    },
  );

  it('invalidates lifecycle completion on mode changes and unmount', async () => {
    const pending = deferred<DnssecLifecycleReport>();
    vi.mocked(analyseDnssecLifecycle).mockReset().mockReturnValue(pending.promise);
    const view = render(<DelegationPage />);
    click('DNSSEC lifecycle');
    change('DNSSEC and delegation records', 'first');
    click('Model lifecycle');
    click('Delegation trace');
    view.unmount();
    await settle(() => pending.resolve(lifecycle('Stale result')));
    render(<DelegationPage />);
    expect(screen.queryByText('Stale result')).not.toBeInTheDocument();
  });

  it('keeps superseded measurement cancellation silent and active cancellation explicit', async () => {
    const a = deferred<GlobalpingDnsMeasurement>();
    const b = deferred<GlobalpingDnsMeasurement>();
    vi.mocked(runGlobalpingDns)
      .mockReset()
      .mockReturnValueOnce(a.promise)
      .mockReturnValueOnce(b.promise);
    render(<DelegationPage />);
    change('Public DNS name', 'example.com');
    fireEvent.click(screen.getByRole('checkbox'));
    click('Trace delegation');
    const oldSignal = vi.mocked(runGlobalpingDns).mock.calls[0]?.[1];
    change('Public DNS name', 'example.net');
    click('Trace delegation');
    expect(oldSignal?.aborted).toBe(true);
    await settle(() => a.reject(new Error('Old aborted request')));
    expect(screen.getByRole('button', { name: 'Measuring…' })).toBeDisabled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    click('Cancel');
    expect(screen.getByRole('alert')).toHaveTextContent(
      'The external measurement was cancelled.',
    );
    await settle(() => b.resolve(measurement('stale')));
    expect(screen.queryByText('Delegation strands')).not.toBeInTheDocument();
  });

  it.each(['resolve', 'reject', 'resolve-after', 'reject-after'] as const)(
    'guards protocol %s, numeric default and explicit cancellation',
    async (outcome) => {
      const a = deferred<DnsResponse>();
      const b = deferred<DnsResponse>();
      // The prototype seam exercises the real route while keeping every query offline.
      const query = vi
        .spyOn(DnsQueryRun.prototype, 'query')
        .mockReturnValueOnce(a.promise)
        .mockReturnValueOnce(b.promise);
      render(
        <StrictMode>
          <ProtocolLabPage />
        </StrictMode>,
      );
      change('DNS name', 'example.com');
      click('Query data type');
      expect(query.mock.calls[0]?.[1].type).toBe('TYPE66');
      change('DNS name', 'example.net');
      click('Query data type');
      if (outcome.endsWith('-after')) await settle(() => b.resolve(dns()));
      await settle(() =>
        outcome.startsWith('resolve')
          ? a.resolve(dns())
          : a.reject(new Error('Stale protocol error')),
      );
      if (!outcome.endsWith('-after'))
        expect(screen.getByRole('button', { name: 'Querying…' })).toBeDisabled();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
      if (!outcome.endsWith('-after')) await settle(() => b.resolve(dns()));
      expect(screen.getByRole('heading', { name: 'example.net' })).toBeInTheDocument();
    },
  );

  it('discards protocol completions after mode change, cancellation and unmount', async () => {
    const pending = deferred<DnsResponse>();
    vi.spyOn(DnsQueryRun.prototype, 'query').mockReturnValue(pending.promise);
    const view = render(<ProtocolLabPage />);
    change('DNS name', 'example.com');
    click('Query data type');
    click('Cancel');
    expect(screen.getByRole('alert')).toHaveTextContent('The protocol query was cancelled.');
    click('ECH decoder');
    view.unmount();
    await settle(() => pending.reject(new Error('Stale query')));
  });

  it.each([false, true])(
    'keeps map ownership with newer completion first: %s',
    async (newerFirst) => {
      const a = deferred<DnsResponse>();
      const b = deferred<DnsResponse>();
      let calls = 0;
      vi.spyOn(DnsQueryRun.prototype, 'query').mockImplementation(() =>
        ++calls <= 10 ? a.promise : b.promise,
      );
      render(
        <StrictMode>
          <EvidenceMapPage />
        </StrictMode>,
      );
      change('DNS name', 'example.com');
      click('Build evidence map');
      change('DNS name', 'example.net');
      click('Build evidence map');
      if (newerFirst) await settle(() => b.resolve(dns()));
      await settle(() => a.reject(new Error('Old cancelled run')));
      if (!newerFirst)
        expect(screen.getByRole('button', { name: 'Following strands…' })).toBeDisabled();
      expect(screen.queryByText('The evidence run was cancelled.')).not.toBeInTheDocument();
      if (!newerFirst) await settle(() => b.resolve(dns()));
      expect(screen.getByRole('heading', { name: 'example.net.' })).toBeInTheDocument();
    },
  );

  it('retains explicit map cancellation without a later result', async () => {
    const pending = deferred<DnsResponse>();
    vi.spyOn(DnsQueryRun.prototype, 'query').mockReturnValue(pending.promise);
    const view = render(<EvidenceMapPage />);
    change('DNS name', 'example.com');
    click('Build evidence map');
    click('Cancel');
    expect(screen.getByText('The evidence run was cancelled.')).toBeInTheDocument();
    view.unmount();
    await settle(() => pending.resolve(dns()));
  });

  it.each(['resolve', 'reject'] as const)(
    'ignores stale zone-file %s after a newer selection',
    async (outcome) => {
      const pending = deferred<ArrayBuffer>();
      const first = new File(['old'], 'old.zone');
      const second = new File(['new'], 'current.zone');
      for (const file of [first, second])
        Object.defineProperty(file, 'webkitRelativePath', { value: '' });
      Object.defineProperty(first, 'arrayBuffer', { value: () => pending.promise });
      Object.defineProperty(second, 'arrayBuffer', {
        value: () => Promise.resolve(new TextEncoder().encode('www IN A 192.0.2.1').buffer),
      });
      render(
        <StrictMode>
          <ZoneExchangePage />
        </StrictMode>,
      );
      fireEvent.change(screen.getByLabelText('Choose files'), { target: { files: [first] } });
      await settle(() =>
        fireEvent.change(screen.getByLabelText('Choose files'), {
          target: { files: [second] },
        }),
      );
      await settle(() =>
        outcome === 'resolve'
          ? pending.resolve(new ArrayBuffer(1))
          : pending.reject(new Error('Stale file error')),
      );
      expect(screen.getByRole('option', { name: 'current.zone' })).toBeInTheDocument();
      expect(screen.queryByText('Stale file error')).not.toBeInTheDocument();
      expect(screen.queryByText('Reading local files…')).not.toBeInTheDocument();
    },
  );

  it('invalidates zone-file reads on clear, mode changes and unmount', async () => {
    const pending = deferred<ArrayBuffer>();
    const file = new File(['old'], 'old.zone');
    Object.defineProperty(file, 'webkitRelativePath', { value: '' });
    Object.defineProperty(file, 'arrayBuffer', { value: () => pending.promise });
    const view = render(<ZoneExchangePage />);
    fireEvent.change(screen.getByLabelText('Choose files'), { target: { files: [file] } });
    click('Clear');
    fireEvent.change(screen.getByLabelText('Choose files'), { target: { files: [file] } });
    click('Service template');
    view.unmount();
    await settle(() => pending.reject(new Error('Stale file')));
  });
});
