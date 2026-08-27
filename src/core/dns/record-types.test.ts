import { describe, expect, it } from 'vitest';

import { parseGenericRecordType, wireRecordType } from './record-types';

describe('generic data record types', () => {
  it('encodes safe numeric data types using RFC 3597 packet notation', () => {
    expect(parseGenericRecordType('TYPE261')).toEqual({
      ok: true,
      type: 'TYPE261',
      typeCode: 261,
    });
    expect(wireRecordType('TYPE261')).toBe('UNKNOWN_261');
  });

  it.each(['0', '41', '249', '250', '251', '252', '255', '65535'])(
    'refuses pseudo, transfer, authentication, meta-query, or reserved type %s',
    (value) => {
      expect(parseGenericRecordType(value).ok).toBe(false);
    },
  );
});
