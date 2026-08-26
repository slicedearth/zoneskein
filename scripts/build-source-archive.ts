import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import {
  collectCorrespondingSource,
  createCorrespondingSourceArchive,
  SOURCE_ARCHIVE_DIGEST_NAME,
  SOURCE_ARCHIVE_NAME,
  sourceArchiveDigest,
} from './source-archive.ts';

const root = resolve(import.meta.dirname, '..');
const output = join(root, 'dist');
const source = await collectCorrespondingSource(root);
const archive = createCorrespondingSourceArchive(source);
const digest = sourceArchiveDigest(archive);

await mkdir(output, { recursive: true });
await Promise.all([
  writeFile(join(output, SOURCE_ARCHIVE_NAME), archive),
  writeFile(join(output, SOURCE_ARCHIVE_DIGEST_NAME), `${digest}  ${SOURCE_ARCHIVE_NAME}\n`),
]);

process.stdout.write(
  `Built ${SOURCE_ARCHIVE_NAME} from ${String(source.length)} source files (${String(archive.length)} octets, sha256-${digest}).\n`,
);
