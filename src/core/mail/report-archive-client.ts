import { MAIL_REPORT_ARCHIVE_LIMITS, type MailReportPayload } from './report-archive';
import type { MailArchiveRequest, MailArchiveResponse } from './report-archive-worker';

export const MAIL_ARCHIVE_DEADLINE_MS = 60_000;

/** Run untrusted decompression in a disposable, same-origin module worker. */
export function extractMailReportPayloadsAsync(
  name: string,
  source: Uint8Array,
  options: { readonly signal: AbortSignal; readonly expandedOctets?: number },
): Promise<readonly MailReportPayload[]> {
  return new Promise((resolve, reject) => {
    const { signal } = options;
    if (signal.aborted) {
      reject(new DOMException('Report import cancelled.', 'AbortError'));
      return;
    }
    if (source.length === 0 || source.length > MAIL_REPORT_ARCHIVE_LIMITS.archiveOctets) {
      reject(new Error('The report is empty or exceeds the compressed-input safety limit.'));
      return;
    }
    // No synchronous fallback: unsupported workers must not move decompression
    // onto the main thread or weaken the hard streaming bound.
    const worker = new Worker(new URL('./report-archive-worker.ts', import.meta.url), {
      type: 'module',
    });
    const finish = (result: MailArchiveResponse | Error) => {
      clearTimeout(timer);
      signal.removeEventListener('abort', abort);
      worker.onmessage = null;
      worker.onerror = null;
      worker.onmessageerror = null;
      worker.terminate();
      if (result instanceof Error) reject(result);
      else if (result.ok) resolve(result.payloads);
      else reject(new Error(result.error));
    };
    const abort = () => finish(new DOMException('Report import cancelled.', 'AbortError'));
    const timer = setTimeout(
      () => finish(new Error('The report import exceeded its processing deadline.')),
      MAIL_ARCHIVE_DEADLINE_MS,
    );
    signal.addEventListener('abort', abort, { once: true });
    worker.onmessage = (event: MessageEvent<MailArchiveResponse>) => finish(event.data);
    worker.onerror = () =>
      finish(new Error('The local report worker could not process this file.'));
    worker.onmessageerror = () =>
      finish(new Error('The local report worker returned unreadable data.'));
    const request: MailArchiveRequest = {
      name,
      source,
      expandedOctets: options.expandedOctets ?? MAIL_REPORT_ARCHIVE_LIMITS.expandedOctets,
    };
    try {
      worker.postMessage(request);
    } catch (cause) {
      finish(
        cause instanceof Error
          ? cause
          : new Error('The report could not be sent to its local worker.'),
      );
    }
  });
}
