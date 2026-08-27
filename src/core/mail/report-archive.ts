import { Gunzip, Unzip, UnzipInflate, UnzipPassThrough } from 'fflate';

export const MAIL_REPORT_ARCHIVE_LIMITS = Object.freeze({
  archiveOctets: 5 * 1024 * 1024,
  entries: 20,
  expandedOctets: 10 * 1024 * 1024,
  entryOctets: 5 * 1024 * 1024,
});

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

function gunzip(name: string, bytes: Uint8Array): MailReportPayload {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const stream = new Gunzip((chunk) => {
    total += chunk.length;
    if (total > MAIL_REPORT_ARCHIVE_LIMITS.expandedOctets)
      throw new Error('The gzip output exceeds the expanded-report safety limit.');
    chunks.push(chunk.slice());
  });
  stream.push(bytes, true);
  return { bytes: joined(chunks, total), name: name.replace(/\.gz$/iu, '') || 'report' };
}

function unzip(bytes: Uint8Array): readonly MailReportPayload[] {
  const payloads: MailReportPayload[] = [];
  let aggregate = 0;
  let discovered = 0;
  const state: { failure: Error | null } = { failure: null };
  const stream = new Unzip((file) => {
    discovered += 1;
    if (discovered > MAIL_REPORT_ARCHIVE_LIMITS.entries) {
      state.failure = new Error('The ZIP archive contains too many entries.');
      return;
    }
    if (!safeEntryName(file.name) || !/\.(?:json|xml)$/iu.test(file.name)) return;
    if (
      file.originalSize !== undefined &&
      file.originalSize > MAIL_REPORT_ARCHIVE_LIMITS.entryOctets
    ) {
      state.failure = new Error(
        `ZIP entry ${file.name} exceeds the expanded-entry safety limit.`,
      );
      return;
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    file.ondata = (error, chunk, final) => {
      if (error !== null) {
        state.failure = new Error(`ZIP entry ${file.name} could not be expanded.`, {
          cause: error,
        });
        return;
      }
      total += chunk.length;
      aggregate += chunk.length;
      if (
        total > MAIL_REPORT_ARCHIVE_LIMITS.entryOctets ||
        aggregate > MAIL_REPORT_ARCHIVE_LIMITS.expandedOctets
      ) {
        state.failure = new Error('The ZIP output exceeds the expanded-report safety limit.');
        file.terminate();
        return;
      }
      chunks.push(chunk.slice());
      if (final) payloads.push({ bytes: joined(chunks, total), name: file.name });
    };
    file.start();
  });
  stream.register(UnzipInflate);
  stream.register(UnzipPassThrough);
  stream.push(bytes, true);
  if (state.failure instanceof Error) throw state.failure;
  if (payloads.length === 0)
    throw new Error('The ZIP archive contains no bounded XML or JSON reports.');
  return payloads;
}

export function extractMailReportPayloads(
  name: string,
  source: Uint8Array,
): readonly MailReportPayload[] {
  if (source.length === 0) throw new Error('The report file is empty.');
  if (source.length > MAIL_REPORT_ARCHIVE_LIMITS.archiveOctets)
    throw new Error('The report file exceeds the compressed-input safety limit.');
  const lower = name.toLowerCase();
  if (lower.endsWith('.zip') || (source[0] === 0x50 && source[1] === 0x4b))
    return unzip(source);
  if (lower.endsWith('.gz') || (source[0] === 0x1f && source[1] === 0x8b))
    return [gunzip(name, source)];
  return [{ bytes: source.slice(), name }];
}
