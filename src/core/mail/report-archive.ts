import { Gunzip, Unzip, UnzipInflate, UnzipPassThrough } from 'fflate';

export const MAIL_REPORT_ARCHIVE_LIMITS = Object.freeze({
  archiveOctets: 5 * 1024 * 1024,
  entries: 20,
  expandedOctets: 10 * 1024 * 1024,
  entryOctets: 5 * 1024 * 1024,
  feedOctets: 128,
});

// RFC 1951: a stored block holds at most 65,535 bytes; a length symbol emits
// at most 258. Reserve a whole buffered stored block, every newly fed bit as
// a length symbol, and 64 look-ahead bits. This deliberately overestimates
// the output of one streaming push, independently of archive size fields.
export const MAIL_REPORT_MAX_FEED_OUTPUT = 65_535 + (128 * 8 + 64) * 258;

export interface MailArchiveProgress {
  readonly inputOctets: number;
  readonly outputOctets: number;
  readonly retainedOctets: number;
  readonly largestChunkOctets: number;
  readonly pushes: number;
}

export interface MailArchiveOptions {
  readonly expandedOctets?: number;
  readonly entryOctets?: number;
  readonly onProgress?: (progress: MailArchiveProgress) => void;
}

function limit(value: number | undefined, maximum: number): number {
  if (value === undefined) return maximum;
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum)
    throw new Error(
      'The archive budget must be a non-negative integer within the safety limit.',
    );
  return value;
}

class ArchiveBudget {
  readonly expanded: number;
  readonly entry: number;
  readonly observer: MailArchiveOptions['onProgress'];
  inputOctets = 0;
  outputOctets = 0;
  retainedOctets = 0;
  largestChunkOctets = 0;
  pushes = 0;

  constructor(options: MailArchiveOptions) {
    this.expanded = limit(options.expandedOctets, MAIL_REPORT_ARCHIVE_LIMITS.expandedOctets);
    this.entry = limit(options.entryOctets, MAIL_REPORT_ARCHIVE_LIMITS.entryOctets);
    this.observer = options.onProgress;
  }

  retain(chunk: Uint8Array, entryTotal: number, entryLimit: number): void {
    this.outputOctets += chunk.length;
    this.largestChunkOctets = Math.max(this.largestChunkOctets, chunk.length);
    if (
      chunk.length > MAIL_REPORT_MAX_FEED_OUTPUT ||
      entryTotal > entryLimit ||
      this.outputOctets > this.expanded
    )
      throw new Error('The archive output exceeds the expanded-report safety limit.');
    this.retainedOctets += chunk.length;
  }

  feed(stream: { push(chunk: Uint8Array, final: boolean): void }, bytes: Uint8Array): void {
    for (
      let offset = 0;
      offset < bytes.length;
      offset += MAIL_REPORT_ARCHIVE_LIMITS.feedOctets
    ) {
      const end = Math.min(bytes.length, offset + MAIL_REPORT_ARCHIVE_LIMITS.feedOctets);
      this.inputOctets = end;
      this.pushes += 1;
      try {
        stream.push(bytes.subarray(offset, end), end === bytes.length);
      } finally {
        this.observer?.({
          inputOctets: this.inputOctets,
          outputOctets: this.outputOctets,
          retainedOctets: this.retainedOctets,
          largestChunkOctets: this.largestChunkOctets,
          pushes: this.pushes,
        });
      }
    }
  }
}

export interface MailReportPayload {
  readonly bytes: Uint8Array;
  readonly name: string;
}

function joined(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function safeEntryName(value: string): boolean {
  let containsControlCharacter = false;
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint !== undefined && (codePoint <= 31 || codePoint === 127)) {
      containsControlCharacter = true;
      break;
    }
  }
  return (
    value.length > 0 &&
    value.length <= 1_024 &&
    !value.startsWith('/') &&
    !value.includes('\\') &&
    !value.split('/').some((part) => part === '' || part === '.' || part === '..') &&
    !containsControlCharacter
  );
}

function gunzip(name: string, bytes: Uint8Array, budget: ArchiveBudget): MailReportPayload {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const stream = new Gunzip((chunk) => {
    total += chunk.length;
    budget.retain(chunk, total, budget.expanded);
    chunks.push(chunk);
  });
  budget.feed(stream, bytes);
  return { bytes: joined(chunks, total), name: name.replace(/\.gz$/iu, '') || 'report' };
}

function unzip(bytes: Uint8Array, budget: ArchiveBudget): readonly MailReportPayload[] {
  const payloads: MailReportPayload[] = [];
  let discovered = 0;
  const stream = new Unzip((file) => {
    discovered += 1;
    if (discovered > MAIL_REPORT_ARCHIVE_LIMITS.entries) {
      throw new Error('The ZIP archive contains too many entries.');
    }
    if (!safeEntryName(file.name) || !/\.(?:json|xml)$/iu.test(file.name)) return;
    if (file.originalSize !== undefined && file.originalSize > budget.entry) {
      throw new Error(`ZIP entry ${file.name} exceeds the expanded-entry safety limit.`);
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    file.ondata = (error, chunk, final) => {
      if (error !== null) {
        throw new Error(`ZIP entry ${file.name} could not be expanded.`, {
          cause: error,
        });
      }
      total += chunk.length;
      budget.retain(chunk, total, budget.entry);
      chunks.push(chunk);
      if (final) payloads.push({ bytes: joined(chunks, total), name: file.name });
    };
    file.start();
  });
  stream.register(UnzipInflate);
  stream.register(UnzipPassThrough);
  budget.feed(stream, bytes);
  if (payloads.length === 0)
    throw new Error('The ZIP archive contains no bounded XML or JSON reports.');
  return payloads;
}

export function extractMailReportPayloads(
  name: string,
  source: Uint8Array,
  options: MailArchiveOptions = {},
): readonly MailReportPayload[] {
  if (source.length === 0) throw new Error('The report file is empty.');
  if (source.length > MAIL_REPORT_ARCHIVE_LIMITS.archiveOctets)
    throw new Error('The report file exceeds the compressed-input safety limit.');
  const budget = new ArchiveBudget(options);
  const lower = name.toLowerCase();
  if (lower.endsWith('.zip') || (source[0] === 0x50 && source[1] === 0x4b))
    return unzip(source, budget);
  if (lower.endsWith('.gz') || (source[0] === 0x1f && source[1] === 0x8b))
    return [gunzip(name, source, budget)];
  if (source.length > budget.expanded)
    throw new Error('The report exceeds the expanded-report safety limit.');
  return [{ bytes: source.slice(), name }];
}
