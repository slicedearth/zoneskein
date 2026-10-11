import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  extractMailReportPayloadsAsync,
  MAIL_ARCHIVE_DEADLINE_MS,
} from './report-archive-client';
import type { MailArchiveResponse } from './report-archive-worker';

class LocalWorker {
  static created: LocalWorker[] = [];
  onmessage: ((event: MessageEvent<MailArchiveResponse>) => void) | null = null;
  onerror: (() => void) | null = null;
  onmessageerror: (() => void) | null = null;
  postMessage = vi.fn();
  terminate = vi.fn();
  constructor() {
    LocalWorker.created.push(this);
  }
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  LocalWorker.created = [];
});

describe('local archive worker lifecycle', () => {
  it('terminates and clears the deadline after receiving transferable payloads', async () => {
    vi.useFakeTimers();
    vi.stubGlobal('Worker', LocalWorker);
    const bytes = new Uint8Array([1, 2]);
    const result = extractMailReportPayloadsAsync('report.xml', bytes, {
      signal: new AbortController().signal,
      expandedOctets: 100,
    });
    const worker = LocalWorker.created[0];
    expect(worker?.postMessage).toHaveBeenCalledWith({
      name: 'report.xml',
      source: bytes,
      expandedOctets: 100,
    });
    worker?.onmessage?.(
      new MessageEvent('message', {
        data: { ok: true, payloads: [{ name: 'report.xml', bytes }] },
      }),
    );
    await expect(result).resolves.toEqual([{ name: 'report.xml', bytes }]);
    expect(worker?.terminate).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(['abort', 'deadline', 'error', 'messageerror', 'failure'] as const)(
    'releases the worker on %s',
    async (kind) => {
      vi.useFakeTimers();
      vi.stubGlobal('Worker', LocalWorker);
      const controller = new AbortController();
      const result = extractMailReportPayloadsAsync('report.gz', new Uint8Array([1]), {
        signal: controller.signal,
      });
      const failed =
        kind === 'abort'
          ? expect(result).rejects.toMatchObject({
              name: 'AbortError',
              message: 'Report import cancelled.',
            })
          : expect(result).rejects.toThrow();
      const worker = LocalWorker.created[0];
      if (kind === 'abort') controller.abort();
      if (kind === 'deadline') await vi.advanceTimersByTimeAsync(MAIL_ARCHIVE_DEADLINE_MS);
      if (kind === 'error') worker?.onerror?.();
      if (kind === 'messageerror') worker?.onmessageerror?.();
      if (kind === 'failure')
        worker?.onmessage?.(
          new MessageEvent('message', { data: { ok: false, error: 'Bound exceeded.' } }),
        );
      await failed;
      expect(worker?.terminate).toHaveBeenCalledOnce();
      expect(worker?.onmessage).toBeNull();
      expect(vi.getTimerCount()).toBe(0);
    },
  );

  it('does not create a worker for an already cancelled request', async () => {
    vi.stubGlobal('Worker', LocalWorker);
    const controller = new AbortController();
    controller.abort();
    await expect(
      extractMailReportPayloadsAsync('report.gz', new Uint8Array([1]), {
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(LocalWorker.created).toHaveLength(0);
  });
});
