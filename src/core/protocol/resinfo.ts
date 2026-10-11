import type { DnsMessage, DnsRecord } from '../dns/types';

export interface ResinfoAttribute {
  readonly key: string;
  readonly known: boolean;
  readonly valid: boolean;
  readonly value: string | null;
}

export interface ResinfoReport {
  readonly attributes: readonly ResinfoAttribute[];
  readonly explanation: string;
  readonly state: 'accepted' | 'discarded' | 'not-found' | 'malformed';
}

function characterStrings(record: DnsRecord): readonly Uint8Array[] | null {
  const chunks: Uint8Array[] = [];
  let offset = 0;
  while (offset < record.rawRdata.length) {
    const length = record.rawRdata[offset];
    if (length === undefined || offset + 1 + length > record.rawRdata.length) return null;
    chunks.push(record.rawRdata.slice(offset + 1, offset + 1 + length));
    offset += 1 + length;
  }
  return chunks;
}

function attribute(value: string): ResinfoAttribute {
  const separator = value.indexOf('=');
  const key = (separator < 0 ? value : value.slice(0, separator)).toLowerCase();
  const content = separator < 0 ? null : value.slice(separator + 1);
  if (!/^[a-z0-9-]{1,63}$/u.test(key))
    return { key, known: false, valid: false, value: content };
  if (key === 'qnamemin') return { key, known: true, valid: content === null, value: content };
  if (key === 'exterr')
    return {
      key,
      known: true,
      valid:
        content !== null &&
        content !== '' &&
        content.split(',').every((part) => {
          const range = /^(\d{1,5})(?:-(\d{1,5}))?$/u.exec(part);
          if (range?.[1] === undefined) return false;
          const start = Number(range[1]);
          const end = range[2] === undefined ? start : Number(range[2]);
          return start <= end && end <= 65_535;
        }),
      value: content,
    };
  if (key === 'infourl') {
    let valid = false;
    if (content !== null) {
      try {
        const url = new URL(content);
        valid =
          url.protocol === 'https:' &&
          url.hostname !== '' &&
          url.username === '' &&
          url.password === '';
      } catch {
        valid = false;
      }
    }
    return { key, known: true, valid, value: content };
  }
  return { key, known: false, valid: true, value: content };
}

export function inspectResinfo(message: DnsMessage): ResinfoReport {
  if (!message.flags.authoritativeAnswer)
    return {
      attributes: [],
      explanation:
        'RFC 9606 requires the response to be discarded because its AA flag is clear.',
      state: 'discarded',
    };
  const records = message.answers.filter((record) => record.typeCode === 261);
  if (records.length === 0)
    return {
      attributes: [],
      explanation: 'The authoritative response did not contain a RESINFO record.',
      state: 'not-found',
    };
  if (records.length !== 1)
    return {
      attributes: [],
      explanation: 'RFC 9606 requires exactly one RESINFO record.',
      state: 'malformed',
    };
  const record = records[0];
  if (record === undefined)
    return {
      attributes: [],
      explanation: 'The RESINFO answer disappeared during bounded processing.',
      state: 'malformed',
    };
  const chunks = characterStrings(record);
  if (chunks === null || chunks.length === 0 || chunks.length > 64)
    return {
      attributes: [],
      explanation:
        'The RESINFO TXT-style character strings are malformed or exceed the local work limit.',
      state: 'malformed',
    };
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let values: readonly string[];
  try {
    values = chunks.map((chunk) => decoder.decode(chunk));
  } catch {
    return {
      attributes: [],
      explanation: 'The RESINFO record contains text that is not valid UTF-8.',
      state: 'malformed',
    };
  }
  const attributes = values.map(attribute);
  const keys = attributes.map((item) => item.key);
  if (attributes.some((item) => !item.valid) || new Set(keys).size !== keys.length)
    return {
      attributes,
      explanation:
        'The self-published resolver information contains an invalid or repeated attribute.',
      state: 'malformed',
    };
  return {
    attributes,
    explanation:
      'The resolver authoritatively returned syntactically valid self-published information. Its claims have not been independently verified.',
    state: 'accepted',
  };
}
