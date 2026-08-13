import { describe, expect, it } from 'vitest';

import { inspectDkimKey, parseDkimKeyRecord, validateDkimSelector } from './parser';

describe('DKIM key record inspection', () => {
  it('parses and imports an Ed25519 key', async () => {
    const key = parseDkimKeyRecord(
      `v=DKIM1; k=ed25519; p=${btoa(String.fromCharCode(...new Uint8Array(32).fill(7)))}`,
    );
    expect(key.valid).toBe(true);
    await expect(inspectDkimKey(key)).resolves.toMatchObject({ bits: 256, status: 'valid' });
  });

  it('identifies revoked and malformed keys', async () => {
    const revoked = parseDkimKeyRecord('v=DKIM1; p=');
    const malformed = parseDkimKeyRecord('v=DKIM2; p=***');
    await expect(inspectDkimKey(revoked)).resolves.toMatchObject({ status: 'revoked' });
    expect(malformed.valid).toBe(false);
  });

  it('validates selectors locally', () => {
    expect(validateDkimSelector('selector-2026')).toBeNull();
    expect(validateDkimSelector('bad.selector')).not.toBeNull();
  });
});
