import { gunzipSync, gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import {
  createCorrespondingSourceArchive,
  parseCorrespondingSourceArchive,
  SOURCE_MANIFEST_NAME,
  sourceArchiveDigest,
} from '../../scripts/source-archive.ts';

const entries = [
  { content: new TextEncoder().encode('console.log("bounded");\n'), path: 'src/main.ts' },
  { content: new TextEncoder().encode('{"name":"zoneskein"}\n'), path: 'package.json' },
] as const;

describe('corresponding-source archive', () => {
  it('creates a deterministic, manifest-bound tar.gz archive', () => {
    const first = createCorrespondingSourceArchive(entries);
    const second = createCorrespondingSourceArchive([...entries].reverse());

    expect(first).toStrictEqual(second);
    expect(sourceArchiveDigest(first)).toMatch(/^[a-f0-9]{64}$/u);

    const parsed = parseCorrespondingSourceArchive(first);
    expect([...parsed.keys()].sort()).toEqual([
      SOURCE_MANIFEST_NAME,
      'package.json',
      'src/main.ts',
    ]);
    expect(new TextDecoder().decode(parsed.get('src/main.ts'))).toBe(
      'console.log("bounded");\n',
    );
  });

  it('rejects unsafe paths, duplicates, and content that no longer matches the manifest', () => {
    expect(() =>
      createCorrespondingSourceArchive([{ content: new Uint8Array(), path: '../secret' }]),
    ).toThrow(/unsafe source path/iu);
    expect(() => createCorrespondingSourceArchive([...entries, entries[0]])).toThrow(
      /duplicate source path/iu,
    );

    const archive = createCorrespondingSourceArchive(entries);
    const tar = gunzipSync(archive);
    const marker = tar.indexOf(Buffer.from('console.log("bounded");'));
    expect(marker).toBeGreaterThan(0);
    tar[marker] = 'C'.charCodeAt(0);
    expect(() => parseCorrespondingSourceArchive(gzipSync(tar))).toThrow(
      /does not match src\/main\.ts/iu,
    );

    const paddingTar = gunzipSync(archive);
    const packageContent = Buffer.from('{"name":"zoneskein"}\n');
    const packageMarker = paddingTar.indexOf(packageContent);
    expect(packageMarker).toBeGreaterThan(0);
    paddingTar[packageMarker + packageContent.length] = 1;
    expect(() => parseCorrespondingSourceArchive(gzipSync(paddingTar))).toThrow(
      /malformed padding/iu,
    );
  });
});
