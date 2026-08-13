import { failure, success, type Result } from '../result';
import type { ValidatedDnsName } from './types';

const MAX_INPUT_CHARACTERS = 2048;
const MAX_NAME_OCTETS = 253;
const MAX_LABEL_OCTETS = 63;
const textEncoder = new TextEncoder();

export type DnsNameErrorCode =
  | 'control-character'
  | 'empty'
  | 'invalid-hostname'
  | 'invalid-label'
  | 'label-too-long'
  | 'name-too-long'
  | 'url-components'
  | 'wildcard';

export interface DnsNameError {
  readonly code: DnsNameErrorCode;
  readonly message: string;
}

function error(code: DnsNameErrorCode, message: string): Result<never, DnsNameError> {
  return failure({ code, message });
}

function extractAccidentalUrl(value: string): Result<string, DnsNameError> {
  if (!value.includes('://')) return success(value);

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return error('invalid-hostname', 'The value looks like a URL but could not be parsed.');
  }

  if (
    (url.protocol !== 'http:' && url.protocol !== 'https:') ||
    url.username !== '' ||
    url.password !== '' ||
    url.port !== '' ||
    (url.pathname !== '' && url.pathname !== '/') ||
    url.search !== '' ||
    url.hash !== ''
  ) {
    return error(
      'url-components',
      'Enter a DNS name only. URLs with credentials, ports, paths, queries, or fragments are not accepted.',
    );
  }

  return success(url.hostname);
}

export function validateDnsName(input: string): Result<ValidatedDnsName, DnsNameError> {
  const trimmed = input.trim();
  if (trimmed.length === 0) return error('empty', 'Enter a DNS name.');
  if (trimmed.length > MAX_INPUT_CHARACTERS) {
    return error('name-too-long', 'The input is too long to be a DNS name.');
  }
  if (/\p{Cc}/u.test(trimmed)) {
    return error('control-character', 'DNS names cannot contain control characters.');
  }
  if (trimmed.includes('*')) {
    return error('wildcard', 'Wildcards are not accepted for live DNS questions.');
  }

  const extracted = extractAccidentalUrl(trimmed);
  if (!extracted.ok) return extracted;

  const hadRootDot = extracted.value.endsWith('.');
  const source = hadRootDot ? extracted.value.slice(0, -1) : extracted.value;
  if (source.length === 0 || /[\s/@\\:[\]]/u.test(source)) {
    return error(
      'invalid-hostname',
      'Enter a hostname without a scheme, path, port, or address syntax.',
    );
  }
  if (source.startsWith('.') || source.endsWith('.') || source.includes('..')) {
    return error('invalid-label', 'DNS labels must contain between 1 and 63 octets.');
  }

  let ascii: string;
  try {
    const parsed = new URL(`https://${source}/`);
    ascii = parsed.hostname.toLowerCase();
  } catch {
    return error('invalid-hostname', 'The hostname could not be converted to IDNA ASCII.');
  }

  if (ascii.length === 0 || ascii.includes('%') || ascii.includes(':')) {
    return error(
      'invalid-hostname',
      'The hostname could not be converted to a valid DNS name.',
    );
  }

  const labels = ascii.split('.');
  for (const label of labels) {
    const length = textEncoder.encode(label).length;
    if (length === 0) return error('invalid-label', 'DNS labels cannot be empty.');
    if (length > MAX_LABEL_OCTETS) {
      return error('label-too-long', `The label “${label}” exceeds 63 octets.`);
    }
    if (!/^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/u.test(label)) {
      return error(
        'invalid-label',
        `The label “${label}” contains characters that are not valid in this DNS workbench.`,
      );
    }
  }

  if (textEncoder.encode(ascii).length > MAX_NAME_OCTETS) {
    return error('name-too-long', 'The complete DNS name exceeds 253 octets.');
  }

  return success({
    absolute: `${ascii}.`,
    ascii,
    display: hadRootDot ? `${source}.` : source,
    hadRootDot,
    unicode: source.toLowerCase() !== ascii,
  });
}

export function parentZone(name: ValidatedDnsName): ValidatedDnsName | null {
  const labels = name.ascii.split('.');
  if (labels.length < 2) return null;
  const ascii = labels.slice(1).join('.');
  return {
    absolute: `${ascii}.`,
    ascii,
    display: ascii,
    hadRootDot: false,
    unicode: false,
  };
}
