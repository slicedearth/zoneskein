export const SVCB_KEY_NUMBERS = {
  mandatory: 0,
  alpn: 1,
  'no-default-alpn': 2,
  port: 3,
  ipv4hint: 4,
  ech: 5,
  ipv6hint: 6,
  dohpath: 7,
  ohttp: 8,
  'tls-supported-groups': 9,
  docpath: 10,
  pvd: 11,
  oots: 12,
} as const satisfies Readonly<Record<string, number>>;

const SVCB_KEY_NAMES = new Map<number, string>(
  Object.entries(SVCB_KEY_NUMBERS).map(([name, number]) => [number, name]),
);
const SVCB_KEY_NUMBER_LOOKUP: Readonly<Record<string, number>> = SVCB_KEY_NUMBERS;

export function svcbKeyNumber(key: string): number | null {
  const named = SVCB_KEY_NUMBER_LOOKUP[key];
  if (named !== undefined) return named;
  const match = /^key(0|[1-9]\d{0,4})$/u.exec(key);
  if (match?.[1] === undefined) return null;
  const parsed = Number(match[1]);
  return parsed <= 65_534 ? parsed : null;
}

export function canonicalSvcbKey(key: string): string {
  const number = svcbKeyNumber(key);
  return number === null ? key : (SVCB_KEY_NAMES.get(number) ?? `key${String(number)}`);
}

export function decodeBase64(value: string): Uint8Array | null {
  const compact = value.replaceAll(/\s+/gu, '');
  if (compact === '' || !/^[A-Za-z0-9+/]+={0,2}$/u.test(compact) || compact.length % 4 === 1)
    return null;
  try {
    const decoded = atob(compact);
    return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function uint16(bytes: Uint8Array, offset: number): number | null {
  const high = bytes[offset];
  const low = bytes[offset + 1];
  return high === undefined || low === undefined ? null : (high << 8) | low;
}

export function isValidEchConfigList(value: string): boolean {
  const bytes = decodeBase64(value);
  if (bytes === null || bytes.length < 6 || uint16(bytes, 0) !== bytes.length - 2) return false;

  let offset = 2;
  let configurations = 0;
  while (offset < bytes.length) {
    const contentLength = uint16(bytes, offset + 2);
    if (contentLength === null) return false;
    offset += 4 + contentLength;
    if (offset > bytes.length) return false;
    configurations += 1;
  }
  return offset === bytes.length && configurations > 0;
}
