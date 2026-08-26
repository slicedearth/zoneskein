import { parseStrictIpAddress } from '../dns/ip';
import { validateDnsName } from '../dns/names';
import { failure, success, type Result } from '../result';

export interface MailFromIdentity {
  readonly domain: string;
  readonly localPart: string;
  readonly nullReversePath: boolean;
}

const encoder = new TextEncoder();
const DOT_ATOM_PART = /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+$/u;

function isQuotedLocalPart(value: string): boolean {
  if (!value.startsWith('"') || !value.endsWith('"')) return false;
  for (let index = 1; index < value.length - 1; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x5c) {
      index += 1;
      const escaped = value.charCodeAt(index);
      if (index >= value.length - 1 || escaped < 0x20 || escaped > 0x7e) return false;
      continue;
    }
    if (
      code === 0x20 ||
      code === 0x21 ||
      (code >= 0x23 && code <= 0x5b) ||
      (code >= 0x5d && code <= 0x7e)
    )
      continue;
    return false;
  }
  return true;
}

export function validateMailFromLocalPart(localPart: string): string | null {
  if (encoder.encode(localPart).length > 64)
    return 'The MAIL FROM local-part exceeds the RFC 5321 limit of 64 octets.';
  const dotString = localPart.split('.');
  if (
    (dotString.length > 0 && dotString.every((part) => DOT_ATOM_PART.test(part))) ||
    isQuotedLocalPart(localPart)
  )
    return null;
  return 'The MAIL FROM local-part must be a valid dot-string or quoted-string.';
}

export function parseSenderClientIp(input: string): Result<string, string> {
  const parsed = parseStrictIpAddress(input);
  return parsed === null
    ? failure('Enter a valid IPv4 or IPv6 address.')
    : success(parsed.toString());
}

export function parseSenderDomain(
  input: string,
  label: 'HELO/EHLO' | 'receiver',
): Result<string, string> {
  const parsed = validateDnsName(input);
  if (!parsed.ok || !parsed.value.ascii.includes('.'))
    return failure(`The ${label} domain must be a well-formed multi-label DNS name.`);
  return success(parsed.value.ascii);
}

export function parseMailFromIdentity(input: string): Result<MailFromIdentity, string> {
  const trimmed = input.trim();
  if (trimmed === '' || trimmed === '<>')
    return success({ domain: '', localPart: '', nullReversePath: true });

  const hasOpeningBracket = trimmed.startsWith('<');
  const hasClosingBracket = trimmed.endsWith('>');
  if (hasOpeningBracket !== hasClosingBracket)
    return failure('MAIL FROM angle brackets must be balanced.');
  const mailbox = hasOpeningBracket ? trimmed.slice(1, -1) : trimmed;
  const separator = mailbox.lastIndexOf('@');
  if (separator <= 0 || separator === mailbox.length - 1)
    return failure('Enter a MAIL FROM mailbox such as sender@example.com, or <> for null.');

  const localPart = mailbox.slice(0, separator);
  const localPartError = validateMailFromLocalPart(localPart);
  if (localPartError !== null) return failure(localPartError);
  const parsedDomain = validateDnsName(mailbox.slice(separator + 1));
  if (!parsedDomain.ok || !parsedDomain.value.ascii.includes('.'))
    return failure('The MAIL FROM domain must be a well-formed multi-label DNS name.');
  return success({
    domain: parsedDomain.value.ascii,
    localPart,
    nullReversePath: false,
  });
}
