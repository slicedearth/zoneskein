import ipaddr from 'ipaddr.js';

import { failure, success, type Result } from '../result';

export interface ReverseName {
  readonly address: string;
  readonly family: 4 | 6;
  readonly name: string;
}

export function reverseNameFromAddress(input: string): Result<ReverseName, string> {
  const value = input.trim();
  if (!ipaddr.isValid(value)) return failure('Enter a valid IPv4 or IPv6 address.');
  const parsed = ipaddr.parse(value);

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
