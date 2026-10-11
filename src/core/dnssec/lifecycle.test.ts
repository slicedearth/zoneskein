import { describe, expect, it } from 'vitest';

import { dnskeyDigest, hex } from './digest';
import { analyseDnssecLifecycle } from './lifecycle';

describe('DNSSEC lifecycle analysis', () => {
  it('binds DS and child signalling comparisons to the canonical owner', async () => {
    const key = '257 3 13 AQIDBAUGBwg=';
    const initial = await analyseDnssecLifecycle(`a.example. 300 IN DNSKEY ${key}`);
    const ds = initial.derivedDs.find((record) => record.digestType === 2);
    if (ds === undefined) throw new Error('Expected a derived DS.');
    const fields = `${String(ds.keyTag)} 13 2 ${ds.digest}`;
    const wrong = await analyseDnssecLifecycle(
      `a.example. 300 IN DNSKEY ${key}\nb.example. 300 IN DS ${fields}\nb.example. 300 IN CDNSKEY ${key}\na.example. 300 IN CDS ${fields}`,
    );
    expect(wrong.findings.map((item) => item.code)).toEqual(
      expect.arrayContaining(['orphan-ds', 'cdnskey-divergence', 'cds-parent-divergence']),
    );
    expect(wrong.findings.some((item) => item.code === 'supplied-link-consistent')).toBe(false);
    const correct = await analyseDnssecLifecycle(
      `a.example. 300 IN DNSKEY ${key}\nA.EXAMPLE. 300 IN DS ${fields}\na.example. 300 IN CDNSKEY ${key}`,
    );
    expect(correct.status).toBe('complete');
    expect(correct.findings).toContainEqual(
      expect.objectContaining({ code: 'supplied-link-consistent', tone: 'pass' }),
    );
  });

  it.each([false, true])(
    'does not claim universal consistency with an unsupported digest (mixed=%s)',
    async (mixed) => {
      const source = 'example. 300 IN DNSKEY 257 3 13 AQIDBAUGBwg=';
      const initial = await analyseDnssecLifecycle(source);
      const ds = initial.derivedDs[0];
      if (ds === undefined) throw new Error('Expected a DS.');
      const report = await analyseDnssecLifecycle(
        `${source}\nexample. 300 IN DS ${String(ds.keyTag)} 13 99 AABB${mixed ? `\nexample. 300 IN DS ${String(ds.keyTag)} 13 ${String(ds.digestType)} ${ds.digest}` : ''}`,
      );
      expect(report.status).toBe('partial');
      expect(report.findings.some((item) => item.code === 'unsupported-ds-digest')).toBe(true);
      expect(report.findings.some((item) => item.code === 'supplied-link-consistent')).toBe(
        false,
      );
    },
  );

  it('derives modern DS candidates and classifies key roles', async () => {
    const report = await analyseDnssecLifecycle(
      '$ORIGIN example.com.\n@ 3600 IN DNSKEY 257 3 13 AQIDBAUGBwg=\n',
    );
    expect(report.keys).toMatchObject([{ algorithm: 13, role: 'KSK', sourceType: 'DNSKEY' }]);
    expect(report.derivedDs.map((record) => record.digestType)).toEqual([2, 4]);
    expect(report.stages[1]?.earliestOffsetSeconds).toBe(3600);
    expect(report.status).toBe('partial');
  });

  it('retains an unmatched parent DS as an error', async () => {
    const report = await analyseDnssecLifecycle(
      '$ORIGIN example.com.\n@ 3600 IN DNSKEY 257 3 13 AQIDBAUGBwg=\n@ 3600 IN DS 12345 13 2 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n',
    );
    expect(report.findings).toContainEqual(
      expect.objectContaining({ code: 'orphan-ds', tone: 'error' }),
    );
    expect(report.status).toBe('partial');
  });

  it('matches a supplied legacy SHA-1 DS without offering it as a new candidate', async () => {
    const rdata = new Uint8Array([1, 1, 3, 13, 1, 2, 3, 4, 5, 6, 7, 8]);
    const digest = hex(await dnskeyDigest('example.com.', rdata, 1));
    const initial = await analyseDnssecLifecycle(
      '$ORIGIN example.com.\n@ 3600 IN DNSKEY 257 3 13 AQIDBAUGBwg=\n',
    );
    const keyTag = initial.keys[0]?.keyTag;
    if (keyTag === undefined) throw new Error('Expected one DNSKEY.');
    const report = await analyseDnssecLifecycle(
      `$ORIGIN example.com.\n@ 3600 IN DNSKEY 257 3 13 AQIDBAUGBwg=\n@ 7200 IN DS ${String(keyTag)} 13 1 ${digest}\n`,
    );

    expect(report.derivedDs.map((record) => record.digestType)).toEqual([2, 4]);
    expect(report.findings).toContainEqual(
      expect.objectContaining({ code: 'sha1-ds', tone: 'warning' }),
    );
    expect(report.findings).not.toContainEqual(expect.objectContaining({ code: 'orphan-ds' }));
    expect(report.stages[3]?.earliestOffsetSeconds).toBe(10_800);
  });

  it('recognises authenticated deletion signals without deriving unusable DS candidates', async () => {
    const report = await analyseDnssecLifecycle(
      '$ORIGIN example.com.\n@ 3600 IN CDS 0 0 0 00\n@ 3600 IN CDNSKEY 0 3 0 AA==\n',
    );

    expect(report.keys).toMatchObject([{ role: 'delete-signal', sourceType: 'CDNSKEY' }]);
    expect(report.derivedDs).toEqual([]);
    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'cds-delete-signal', tone: 'warning' }),
        expect.objectContaining({ code: 'cdnskey-delete-signal', tone: 'warning' }),
      ]),
    );
    expect(report.findings).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'zone-bit-clear' }),
        expect.objectContaining({ code: 'cdnskey-divergence' }),
      ]),
    );
    expect(report.status).toBe('partial');
  });

  it('rejects malformed known digest lengths before lifecycle comparison', async () => {
    const report = await analyseDnssecLifecycle(
      '$ORIGIN example.com.\n@ 3600 IN CDS 12345 13 2 AABB\n',
    );

    expect(report.findings).toContainEqual(
      expect.objectContaining({ code: 'ds-record-invalid', tone: 'error' }),
    );
    expect(report.dsRecords).toEqual([]);
  });

  it('interprets bounded CSYNC and DSYNC delegation signals without claiming execution', async () => {
    const report = await analyseDnssecLifecycle(
      [
        '$ORIGIN example.com.',
        '@ 3600 IN DNSKEY 257 3 13 AQIDBAUGBwg=',
        '@ 3600 IN CSYNC 42 3 NS A AAAA',
        '_dsync 3600 IN DSYNC CDS NOTIFY 5359 receiver.example.net.',
      ].join('\n'),
    );

    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'csync-signal', tone: 'information' }),
        expect.objectContaining({ code: 'csync-consistency-unverified', tone: 'warning' }),
        expect.objectContaining({ code: 'dsync-endpoint', tone: 'information' }),
      ]),
    );
    expect(report.status).toBe('partial');
  });

  it('rejects multiple CSYNC records and duplicate DSYNC type-scheme combinations', async () => {
    const report = await analyseDnssecLifecycle(
      [
        '$ORIGIN example.com.',
        '@ IN CSYNC 42 0 NS',
        '@ IN CSYNC 43 0 NS',
        '_dsync IN DSYNC CDS NOTIFY 5359 first.example.net.',
        '_dsync IN DSYNC CDS 1 5360 second.example.net.',
      ].join('\n'),
    );

    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'csync-multiple', tone: 'error' }),
        expect.objectContaining({ code: 'dsync-duplicate', tone: 'error' }),
      ]),
    );
    expect(report.findings).not.toEqual(
      expect.arrayContaining([expect.objectContaining({ code: 'csync-signal' })]),
    );
  });

  it('bounds the key material analysed by the lifecycle model', async () => {
    const records = Array.from(
      { length: 257 },
      (_, index) => `key${String(index)} 3600 IN DNSKEY 257 3 13 AQIDBAUGBwg=`,
    );
    const report = await analyseDnssecLifecycle(
      ['$ORIGIN example.com.', ...records].join('\n'),
    );

    expect(report.keys).toHaveLength(256);
    expect(report.derivedDs).toHaveLength(512);
    expect(report.findings).toContainEqual(
      expect.objectContaining({ code: 'key-input-limit', tone: 'error' }),
    );
  });
});
