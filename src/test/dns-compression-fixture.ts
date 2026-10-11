import { decodeDnsMessage } from '../core/dns/wire';

// Hand-built RFC 1035 sections: no production DNS encoder is used by this fixture.
const NAME = [7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0];
const UPPER_NAME = [7, 69, 88, 65, 77, 80, 76, 69, 3, 67, 79, 77, 0];

export function compressionFixture(
  type: 2 | 5 | 6 | 15,
  layout: 'literal' | 'question-pointer' | 'owner-pointer',
  options: {
    readonly authority?: boolean;
    readonly changed?: boolean;
    readonly ttl?: number;
  } = {},
) {
  const target =
    layout === 'literal' ? NAME : layout === 'question-pointer' ? [0xc0, 12] : [0xc0, 29];
  const numeric = [
    0,
    0,
    0,
    options.changed === true ? 2 : 1,
    0,
    0,
    14,
    16,
    0,
    0,
    2,
    88,
    0,
    1,
    81,
    128,
    0,
    0,
    1,
    44,
  ];
  const rdata =
    type === 6
      ? [...target, ...target, ...numeric]
      : type === 15
        ? [0, options.changed === true ? 20 : 10, ...target]
        : options.changed === true
          ? [5, 111, 116, 104, 101, 114, 3, 99, 111, 109, 0]
          : target;
  const ttl = options.ttl ?? 300;
  return decodeDnsMessage(
    Uint8Array.from([
      0,
      1,
      0x81,
      0x80,
      0,
      1,
      0,
      options.authority === true ? 0 : 1,
      0,
      options.authority === true ? 1 : 0,
      0,
      0,
      ...UPPER_NAME,
      0,
      type,
      0,
      1,
      ...(layout === 'owner-pointer' ? NAME : [0xc0, 12]),
      0,
      type,
      0,
      1,
      0,
      0,
      ttl >>> 8,
      ttl & 255,
      0,
      rdata.length,
      ...rdata,
    ]),
  );
}
