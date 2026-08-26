import ipaddr from 'ipaddr.js';

export type ParsedIpAddress = ReturnType<typeof ipaddr.parse>;
export type ProcessedIpAddress = ReturnType<typeof ipaddr.process>;

function strictIpv4Syntax(value: string): boolean {
  const parts = value.split('.');
  return (
    parts.length === 4 &&
    parts.every((part) => /^(?:0|[1-9][0-9]{0,2})$/u.test(part) && Number(part) <= 255)
  );
}

function strictIpv6Syntax(value: string): boolean {
  if (!value.includes(':') || value.includes('%') || !/^[0-9A-Fa-f:.]+$/u.test(value))
    return false;
  if (value.includes('.')) {
    const embeddedIpv4 = value.slice(value.lastIndexOf(':') + 1);
    if (!strictIpv4Syntax(embeddedIpv4)) return false;
  }
  return true;
}

export function parseStrictIpAddress(input: string): ParsedIpAddress | null {
  const value = input.trim();
  if (!strictIpv4Syntax(value) && !strictIpv6Syntax(value)) return null;
  try {
    return ipaddr.parse(value);
  } catch {
    return null;
  }
}

export function processStrictIpAddress(input: string): ProcessedIpAddress | null {
  const value = input.trim();
  if (parseStrictIpAddress(value) === null) return null;
  try {
    return ipaddr.process(value);
  } catch {
    return null;
  }
}

export function normaliseStrictIpAddress(input: string): string | null {
  const parsed = parseStrictIpAddress(input);
  return parsed?.toNormalizedString() ?? null;
}
