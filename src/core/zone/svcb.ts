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

export interface EchCipherSuite {
  readonly aeadId: number;
  readonly kdfId: number;
}

export interface EchConfigReport {
  readonly cipherSuites: readonly EchCipherSuite[];
  readonly extensionsOctets: number | null;
  readonly kemId: number | null;
  readonly maximumNameLength: number | null;
  readonly publicKeyOctets: number | null;
  readonly publicName: string | null;
  readonly supportedVersion: boolean;
  readonly version: number;
}

export interface EchConfigListReport {
  readonly configurations: readonly EchConfigReport[];
  readonly error?: string;
  readonly status: 'valid' | 'invalid' | 'unsupported';
  readonly totalOctets: number;
}

function vector16(
  bytes: Uint8Array,
  offset: number,
  end: number,
): { readonly end: number; readonly value: Uint8Array } | null {
  const length = uint16(bytes, offset);
  if (length === null || offset + 2 + length > end) return null;
  return { end: offset + 2 + length, value: bytes.slice(offset + 2, offset + 2 + length) };
}

function publicName(bytes: Uint8Array): string | null {
  if (bytes.length === 0 || bytes.length > 253) return null;
  const value = String.fromCharCode(...bytes).toLowerCase();
  return /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/u.test(value) && !value.includes('..')
    ? value
    : null;
}

export function decodeEchConfigList(value: string): EchConfigListReport {
  const bytes = decodeBase64(value);
  if (bytes === null)
    return {
      configurations: [],
      error: 'ECHConfigList must be valid non-empty Base64.',
      status: 'invalid',
      totalOctets: 0,
    };
  const declared = uint16(bytes, 0);
  if (declared === null || declared !== bytes.length - 2)
    return {
      configurations: [],
      error: 'The outer ECHConfigList length does not match its encoded contents.',
      status: 'invalid',
      totalOctets: bytes.length,
    };
  const configurations: EchConfigReport[] = [];
  let offset = 2;
  while (offset < bytes.length) {
    const version = uint16(bytes, offset);
    const length = uint16(bytes, offset + 2);
    if (version === null || length === null || offset + 4 + length > bytes.length)
      return {
        configurations,
        error: 'An ECHConfig header or content vector is truncated.',
        status: 'invalid',
        totalOctets: bytes.length,
      };
    const start = offset + 4;
    const end = start + length;
    offset = end;
    if (version !== 0xfe0d) {
      configurations.push({
        cipherSuites: [],
        extensionsOctets: null,
        kemId: null,
        maximumNameLength: null,
        publicKeyOctets: null,
        publicName: null,
        supportedVersion: false,
        version,
      });
      continue;
    }
    const kemId = uint16(bytes, start);
    const key = vector16(bytes, start + 2, end);
    const suites = key === null ? null : vector16(bytes, key.end, end);
    if (
      kemId === null ||
      key === null ||
      suites === null ||
      suites.value.length === 0 ||
      suites.value.length % 4 !== 0
    )
      return {
        configurations,
        error: 'A supported ECHConfig has malformed KEM, public-key, or cipher-suite vectors.',
        status: 'invalid',
        totalOctets: bytes.length,
      };
    const maximumNameLength = bytes[suites.end];
    const nameLength = bytes[suites.end + 1];
    if (
      maximumNameLength === undefined ||
      nameLength === undefined ||
      suites.end + 2 + nameLength > end
    )
      return {
        configurations,
        error: 'A supported ECHConfig has a truncated public name.',
        status: 'invalid',
        totalOctets: bytes.length,
      };
    const nameBytes = bytes.slice(suites.end + 2, suites.end + 2 + nameLength);
    const name = publicName(nameBytes);
    const extensions = vector16(bytes, suites.end + 2 + nameLength, end);
    if (name === null || extensions?.end !== end)
      return {
        configurations,
        error: 'A supported ECHConfig has an invalid public name or extensions vector.',
        status: 'invalid',
        totalOctets: bytes.length,
      };
    const cipherSuites: EchCipherSuite[] = [];
    for (let suiteOffset = 0; suiteOffset < suites.value.length; suiteOffset += 4) {
      const kdfId = uint16(suites.value, suiteOffset);
      const aeadId = uint16(suites.value, suiteOffset + 2);
      if (kdfId === null || aeadId === null)
        throw new Error('Cipher-suite length was checked before decoding.');
      cipherSuites.push({ aeadId, kdfId });
    }
    configurations.push({
      cipherSuites,
      extensionsOctets: extensions.value.length,
      kemId,
      maximumNameLength,
      publicKeyOctets: key.value.length,
      publicName: name,
      supportedVersion: true,
      version,
    });
    if (configurations.length > 32)
      return {
        configurations: [],
        error: 'ECHConfigList exceeds the 32-configuration work limit.',
        status: 'invalid',
        totalOctets: bytes.length,
      };
  }
  if (configurations.length === 0)
    return {
      configurations: [],
      error: 'ECHConfigList contains no configurations.',
      status: 'invalid',
      totalOctets: bytes.length,
    };
  return {
    configurations,
    status: configurations.some((configuration) => configuration.supportedVersion)
      ? 'valid'
      : 'unsupported',
    totalOctets: bytes.length,
  };
}
