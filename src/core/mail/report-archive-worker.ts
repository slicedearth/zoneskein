import { extractMailReportPayloads, type MailReportPayload } from './report-archive';

export interface MailArchiveRequest {
  readonly name: string;
  readonly source: Uint8Array;
  readonly expandedOctets: number;
}

export type MailArchiveResponse =
  | { readonly ok: true; readonly payloads: readonly MailReportPayload[] }
  | { readonly ok: false; readonly error: string };

const scope = globalThis as unknown as {
  onmessage: ((event: MessageEvent<MailArchiveRequest>) => void) | null;
  postMessage(value: MailArchiveResponse, transfer: Transferable[]): void;
};

scope.onmessage = ({ data }) => {
  try {
    const payloads = extractMailReportPayloads(data.name, data.source, {
      expandedOctets: data.expandedOctets,
    });
    scope.postMessage(
      { ok: true, payloads },
      payloads.map((payload) => payload.bytes.buffer as ArrayBuffer),
    );
  } catch (cause) {
    scope.postMessage(
      {
        ok: false,
        error: cause instanceof Error ? cause.message : 'The archive could not be expanded.',
      },
      [],
    );
  }
};
