import { describe, expect, it } from 'vitest';

import fixtures from '../../test/fixtures/dns/responses-v1.json';
import { decodeDnsMessage } from './wire';

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

describe('versioned DNS wire-response fixtures', () => {
  it.each(fixtures.responses)('decodes $id', (fixture) => {
    const message = decodeDnsMessage(decodeBase64(fixture.wireBase64));

    expect(message.responseCode).toBe(fixture.expectedResponseCode);
    expect(message.answers).toHaveLength(fixture.expectedAnswerCount);
    if ('expectedTxtChunks' in fixture) {
      const data = message.answers[0]?.data;
      const chunks = Array.isArray(data)
        ? data.map((chunk) =>
            chunk instanceof Uint8Array ? new TextDecoder().decode(chunk) : String(chunk),
          )
        : [];
      expect(chunks).toEqual(fixture.expectedTxtChunks);
    }
  });

  it.each(fixtures.malformed)('rejects $id', (fixture) => {
    expect(() => decodeDnsMessage(decodeBase64(fixture.wireBase64))).toThrow();
  });
});
