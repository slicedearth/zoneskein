import { encode, type Packet } from '@dnsquery/dns-packet';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import type { DnsMessage } from './types';
import { decodeDnsMessage } from './wire';

const WIRE_PROPERTY_SEED = 0x5a0e_5e1;
const WIRE_PROPERTY_RUNS = 384;
const MAX_GENERATED_WIRE_BYTES = 2_048;
const LABEL_CHARACTERS = Array.from('abcdefghijklmnopqrstuvwxyz0123456789');

interface DecodeError {
  readonly kind: 'error';
  readonly message: string;
  readonly name: string;
}

interface DecodeSuccess {
  readonly kind: 'success';
  readonly message: DnsMessage;
}

type DecodeOutcome = DecodeError | DecodeSuccess;

const labelArbitrary = fc
  .array(fc.constantFrom(...LABEL_CHARACTERS), {
    maxLength: 24,
    minLength: 1,
  })
  .map((characters) => characters.join(''));

const validResponseArbitrary = fc
  .record({
    address: fc.tuple(
      fc.integer({ max: 255, min: 0 }),
      fc.integer({ max: 255, min: 0 }),
      fc.integer({ max: 255, min: 0 }),
      fc.integer({ max: 255, min: 0 }),
    ),
    id: fc.integer({ max: 65_535, min: 0 }),
    label: labelArbitrary,
    ttl: fc.integer({ max: 86_400, min: 0 }),
  })
  .map(({ address, id, label, ttl }) => {
    const name = `${label}.example.test.`;
    const packet: Packet = {
      answers: [
        {
          class: 'IN',
          data: address.join('.'),
          name,
          ttl,
          type: 'A',
        },
      ],
      flags: 0x8180,
      id,
      questions: [{ class: 'IN', name, type: 'A' }],
      type: 'response',
    };
    return encode(packet);
  });

const wireInputArbitrary = fc.oneof(
  fc.uint8Array({ maxLength: MAX_GENERATED_WIRE_BYTES }),
  validResponseArbitrary,
);

function decodeOutcome(bytes: Uint8Array): DecodeOutcome {
  try {
    return { kind: 'success', message: decodeDnsMessage(bytes) };
  } catch (error: unknown) {
    if (!(error instanceof Error) || error.constructor !== Error) {
      throw new Error('DNS wire decoding raised a non-standard error.', { cause: error });
    }
    return { kind: 'error', message: error.message, name: error.name };
  }
}

function expectBoundedMessage(message: DnsMessage, input: Uint8Array): void {
  const records = [...message.answers, ...message.authorities, ...message.additionals];

  expect(message.messageBytes).toBe(input.length);
  expect(message.raw).toEqual(input);
  expect(message.raw).not.toBe(input);
  expect(message.questions.length + records.length).toBeLessThanOrEqual(input.length);

  for (const question of message.questions) {
    const canonicalName = question.canonicalNameWire;
    if (canonicalName === undefined)
      throw new Error('A decoded question is missing its canonical wire name.');
    expect(canonicalName.length).toBeLessThanOrEqual(255);
  }
  for (const record of records) {
    const canonicalOwner = record.canonicalOwnerWire;
    if (canonicalOwner === undefined)
      throw new Error('A decoded record is missing its canonical wire owner.');
    expect(canonicalOwner.length).toBeLessThanOrEqual(255);
    expect(record.rawRdata.length).toBeLessThanOrEqual(input.length);
  }
}

describe('DNS wire decoder properties', () => {
  it('decodes or rejects bounded wire input deterministically without mutating it', () => {
    fc.assert(
      fc.property(wireInputArbitrary, (bytes) => {
        const original = bytes.slice();
        const first = decodeOutcome(bytes);
        const second = decodeOutcome(bytes);

        expect(second).toEqual(first);
        expect(bytes).toEqual(original);
        if (first.kind === 'success') expectBoundedMessage(first.message, bytes);
      }),
      {
        numRuns: WIRE_PROPERTY_RUNS,
        seed: WIRE_PROPERTY_SEED,
      },
    );
  }, 10_000);
});
