import { failure, success, type Result } from '../result';
import { parseStrictIpAddress } from './ip';

export interface ReverseName {
  readonly address: string;
  readonly family: 4 | 6;
  readonly name: string;
}

export function reverseNameFromAddress(input: string): Result<ReverseName, string> {
  const value = input.trim();
  const parsed = parseStrictIpAddress(value);
  if (parsed === null) return failure('Enter a valid IPv4 or IPv6 address.');

  if (parsed.kind() === 'ipv4') {
    const bytes = parsed.toByteArray();
    return success({
      address: parsed.toString(),
      family: 4,
      name: `${bytes.reverse().join('.')}.in-addr.arpa.`,
    });
  }

  const nibbles = parsed
    .toByteArray()
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .split('')
    .reverse()
    .join('.');
  return success({
    address: parsed.toNormalizedString(),
    family: 6,
    name: `${nibbles}.ip6.arpa.`,
  });
}
