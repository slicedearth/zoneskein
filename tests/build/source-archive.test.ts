import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';

import { afterEach, describe, expect, it } from 'vitest';

import {
  collectCorrespondingSource,
  createCorrespondingSourceArchive,
  SOURCE_FILE_LIST_NAME,
  parseCorrespondingSourceArchive,
  SOURCE_MANIFEST_NAME,
  SOURCE_REPOSITORY_DIRECTORIES,
  SOURCE_REPOSITORY_ROOT_FILES,
  sourceArchiveDigest,
} from '../../scripts/source-archive.ts';

const entries = [
  { content: new TextEncoder().encode('console.log("bounded");\n'), path: 'src/main.ts' },
  { content: new TextEncoder().encode('{"name":"zoneskein"}\n'), path: 'package.json' },
] as const;

const temporaryRoots: string[] = [];

async function sourceFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'zoneskein-source-'));
  temporaryRoots.push(root);
  await Promise.all(
    SOURCE_REPOSITORY_DIRECTORIES.map((directory) =>
      mkdir(join(root, directory), { recursive: true }),
    ),
  );
  await Promise.all(
    SOURCE_REPOSITORY_ROOT_FILES.map((fileName) => writeFile(join(root, fileName), '')),
  );
  await writeFile(
    join(root, 'package-lock.json'),
    `${JSON.stringify({ packages: { '': {}, 'node_modules/runtime': {} } })}\n`,
  );
  const declared = [...SOURCE_REPOSITORY_ROOT_FILES].sort();
  await writeFile(join(root, SOURCE_FILE_LIST_NAME), `${JSON.stringify(declared, null, 2)}\n`);
  await Promise.all(
    ['runtime', 'rolldown', 'vite'].map(async (packageName) => {
      const packageRoot = join(root, 'node_modules', packageName);
      await mkdir(packageRoot, { recursive: true });
      await writeFile(
        join(packageRoot, 'package.json'),
        `${JSON.stringify({ name: packageName, version: '1.0.0' })}\n`,
      );
    }),
  );
  return root;
}

async function declareSourceFile(root: string, path: string): Promise<void> {
  const declared = [...SOURCE_REPOSITORY_ROOT_FILES, path].sort();
  await writeFile(join(root, SOURCE_FILE_LIST_NAME), `${JSON.stringify(declared, null, 2)}\n`);
}

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true })));
});

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

  it('collects only the exact declared repository and package source files', async () => {
    const root = await sourceFixture();
    const collected = await collectCorrespondingSource(root);

    expect(collected.map((entry) => entry.path)).toContain(SOURCE_FILE_LIST_NAME);
    expect(collected.map((entry) => entry.path)).toContain('vendor/npm/runtime/package.json');

    await writeFile(join(root, 'src', 'undeclared.ts'), 'export {};\n');
    await expect(collectCorrespondingSource(root)).rejects.toThrow(
      /does not exactly enumerate the source directories/iu,
    );

    await rm(join(root, 'src', 'undeclared.ts'));
    await writeFile(join(root, '.env.production'), 'VITE_UNDECLARED=value\n');
    await expect(collectCorrespondingSource(root)).rejects.toThrow(
      /undeclared local build input/iu,
    );
  });

  it('rejects symbolic links in repository and package inputs', async () => {
    const repositoryRoot = await sourceFixture();
    await declareSourceFile(repositoryRoot, 'src/linked.ts');
    await symlink(join(repositoryRoot, 'LICENSE'), join(repositoryRoot, 'src', 'linked.ts'));
    await expect(collectCorrespondingSource(repositoryRoot)).rejects.toThrow(
      /not a regular file|symbolic link/iu,
    );

    const packageRoot = await sourceFixture();
    await rm(join(packageRoot, 'node_modules', 'runtime'), { recursive: true });
    await symlink(
      join(packageRoot, 'node_modules', 'vite'),
      join(packageRoot, 'node_modules', 'runtime'),
    );
    await expect(collectCorrespondingSource(packageRoot)).rejects.toThrow(/symbolic link/iu);
  });

  it('rejects package-lock paths that can leave an installed package root', async () => {
    const root = await sourceFixture();
    await writeFile(
      join(root, 'package-lock.json'),
      `${JSON.stringify({
        packages: {
          '': {},
          'node_modules/runtime': {},
          'node_modules/runtime/../../outside': {},
        },
      })}\n`,
    );

    await expect(collectCorrespondingSource(root)).rejects.toThrow(/unsafe path/iu);
  });
});
