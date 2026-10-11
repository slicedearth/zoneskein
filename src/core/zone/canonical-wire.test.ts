import { describe, expect, it } from 'vitest';

import { parseZoneSnippet } from './parser';
import { canonicalRecordRdata } from './zonemd';

// Independently assembled RFC 1035/3403 wire octets, not copied RFC signatures.
const vectors = [
  ['MX 10 mail', '000a046d61696c076578616d706c65047465737400'],
  [String.raw`CNAME a\.b`, '03612e62076578616d706c65047465737400'],
  [String.raw`TXT "\255\000" "a  b"`, '02ff000461202062'],
  ['NAPTR 10 20 "u" "sip" "a  b" .', '000a0014017503736970046120206200'],
] as const;

describe('independent fixed RDATA bytes', () => {
  it.each(vectors)('encodes %s exactly', (rdata, hex) => {
    const record = parseZoneSnippet(`$ORIGIN example.test.\n@ 300 IN ${rdata}`).records[0];
    if (record === undefined) throw new Error('Fixture did not parse');
    const result = canonicalRecordRdata(record);
    expect(result.ok).toBe(true);
    if (result.ok)
      expect(
        Array.from(result.bytes, (byte) => byte.toString(16).padStart(2, '0')).join(''),
      ).toBe(hex);
  });
});
