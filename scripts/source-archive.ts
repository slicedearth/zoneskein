import { createHash } from 'node:crypto';
import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, resolve, sep } from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';

export const SOURCE_ARCHIVE_NAME = 'zoneskein-corresponding-source.tar.gz';
export const SOURCE_ARCHIVE_DIGEST_NAME = 'SOURCE_SHA256';
export const SOURCE_MANIFEST_NAME = 'SOURCE_MANIFEST.sha256';

const MAX_SOURCE_FILES = 768;
const MAX_SOURCE_FILE_OCTETS = 2 * 1024 * 1024;
const MAX_SOURCE_TOTAL_OCTETS = 16 * 1024 * 1024;
const TAR_BLOCK_OCTETS = 512;

const SOURCE_DIRECTORIES = [
  '.github',
  'docs',
  'netlify',
  'public',
  'scripts',
  'src',
  'tests',
] as const;

const SOURCE_ROOT_FILES = [
  '.gitignore',
  '.npmrc',
  '.nvmrc',
  '.prettierignore',
  '.prettierrc.json',
  'CHANGELOG.md',
  'CONTRIBUTING.md',
  'LICENSE',
  'LIMITATIONS.md',
  'PRIVACY.md',
  'README.md',
  'SECURITY.md',
  'SOURCE.md',
  'TERMS.md',
  'THIRD_PARTY_NOTICES.md',
  'TRADEMARKS.md',
  'eslint.config.js',
  'index.html',
  'netlify.toml',
  'package-lock.json',
  'package.json',
  'playwright.config.ts',
  'tsconfig.app.json',
  'tsconfig.json',
  'tsconfig.node.json',
  'vite.config.ts',
  'vitest.config.ts',
] as const;

const EMITTED_HELPER_SOURCE_PACKAGES = ['rolldown', 'vite'] as const;

export interface SourceArchiveEntry {
  readonly content: Uint8Array;
  readonly path: string;
}

function fail(message: string): never {
  throw new Error(`Corresponding-source archive: ${message}`);
}

function comparePaths(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function safePath(value: string): string {
  const normalised = value.split(sep).join('/');
  let containsControlCharacter = false;
  for (let index = 0; index < normalised.length; index += 1) {
    const codeUnit = normalised.charCodeAt(index);
    if (codeUnit < 0x20 || codeUnit === 0x7f) {
      containsControlCharacter = true;
      break;
    }
  }
  if (
    normalised === '' ||
    normalised.startsWith('/') ||
    normalised.includes('\\') ||
    normalised.split('/').some((part) => part === '' || part === '.' || part === '..') ||
    containsControlCharacter ||
    Buffer.byteLength(normalised) > 100
  ) {
    fail(`unsafe source path ${JSON.stringify(value)}.`);
  }
  return normalised;
}

async function filesBelow(
  root: string,
  directory: string,
  skipNestedNodeModules = false,
): Promise<readonly string[]> {
  const found: string[] = [];
  const pending = [join(root, directory)];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) break;
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) {
        if (!(skipNestedNodeModules && entry.name === 'node_modules')) pending.push(path);
      } else if (entry.isFile()) found.push(path);
      else fail(`source input ${relative(root, path)} is not a regular file.`);
      if (found.length > MAX_SOURCE_FILES) fail('source input contains too many files.');
    }
  }
  return found;
}

function isObject(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function productionPackagePaths(root: string): Promise<readonly string[]> {
  let lockfile: unknown;
  try {
    lockfile = JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8')) as unknown;
  } catch {
    fail('package-lock.json is not valid JSON.');
  }
  if (!isObject(lockfile) || !isObject(lockfile['packages']))
    fail('package-lock.json does not contain a package map.');

  const paths: string[] = [];
  for (const [path, metadata] of Object.entries(lockfile['packages'])) {
    if (!path.startsWith('node_modules/')) continue;
    if (!isObject(metadata)) fail(`package-lock entry ${path} is malformed.`);
    if (
      (metadata['dev'] !== undefined && typeof metadata['dev'] !== 'boolean') ||
      (metadata['link'] !== undefined && typeof metadata['link'] !== 'boolean')
    ) {
      fail(`package-lock entry ${path} has invalid flags.`);
    }
    if (metadata['dev'] !== true && metadata['link'] !== true) paths.push(path);
  }
  if (paths.length === 0) fail('package-lock.json identifies no production packages.');
  return paths.sort(comparePaths);
}

export async function collectCorrespondingSource(
  repositoryRoot: string,
): Promise<readonly SourceArchiveEntry[]> {
  const root = resolve(repositoryRoot);
  const repositoryPaths = [
    ...SOURCE_ROOT_FILES.map((path) => join(root, path)),
    ...(await Promise.all(SOURCE_DIRECTORIES.map((path) => filesBelow(root, path)))).flat(),
  ];
  const seen = new Set<string>();
  const entries: SourceArchiveEntry[] = [];
  let totalOctets = 0;

  async function add(path: string, archivePath: string): Promise<void> {
    const name = safePath(archivePath);
    if (seen.has(name)) fail(`duplicate source path ${name}.`);
    seen.add(name);
    const details = await stat(path);
    if (!details.isFile()) fail(`source input ${name} is not a regular file.`);
    if (details.size > MAX_SOURCE_FILE_OCTETS)
      fail(`${name} exceeds ${String(MAX_SOURCE_FILE_OCTETS)} octets.`);
    totalOctets += details.size;
    if (totalOctets > MAX_SOURCE_TOTAL_OCTETS)
      fail(`source input exceeds ${String(MAX_SOURCE_TOTAL_OCTETS)} octets.`);
    entries.push({ content: await readFile(path), path: name });
  }

  for (const path of repositoryPaths) await add(path, relative(root, path));

  const packagePaths = [
    ...new Set([
      ...(await productionPackagePaths(root)),
      ...EMITTED_HELPER_SOURCE_PACKAGES.map((packageName) => join('node_modules', packageName)),
    ]),
  ].sort(comparePaths);
  for (const packagePath of packagePaths) {
    const packageRoot = join(root, packagePath);
    const archivePackagePath = packagePath.slice('node_modules/'.length);
    for (const path of await filesBelow(root, packagePath, true)) {
      await add(path, join('vendor', 'npm', archivePackagePath, relative(packageRoot, path)));
    }
  }

  if (entries.length > MAX_SOURCE_FILES) fail('source input contains too many files.');
  return entries.sort((left, right) => comparePaths(left.path, right.path));
}

function sha256(content: Uint8Array): string {
  return createHash('sha256').update(content).digest('hex');
}

function manifest(entries: readonly SourceArchiveEntry[]): Buffer {
  return Buffer.from(
    `${entries.map((entry) => `${sha256(entry.content)}  ${entry.path}`).join('\n')}\n`,
    'utf8',
  );
}

function writeText(target: Buffer, offset: number, length: number, value: string): void {
  const encoded = Buffer.from(value, 'utf8');
  if (encoded.length > length) fail(`tar header value ${JSON.stringify(value)} is too long.`);
  encoded.copy(target, offset);
}

function writeOctal(target: Buffer, offset: number, length: number, value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) fail('tar header integer is invalid.');
  const encoded = `${value.toString(8).padStart(length - 1, '0')}\0`;
  if (encoded.length !== length) fail('tar header integer is too large.');
  writeText(target, offset, length, encoded);
}

function tarHeader(entry: SourceArchiveEntry): Buffer {
  const header = Buffer.alloc(TAR_BLOCK_OCTETS);
  writeText(header, 0, 100, safePath(entry.path));
  writeOctal(header, 100, 8, 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, entry.content.byteLength);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = '0'.charCodeAt(0);
  writeText(header, 257, 6, 'ustar\0');
  writeText(header, 263, 2, '00');
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  writeText(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `);
  return header;
}

export function createCorrespondingSourceArchive(
  sourceEntries: readonly SourceArchiveEntry[],
): Buffer {
  const ordered = [...sourceEntries].sort((left, right) => comparePaths(left.path, right.path));
  const seen = new Set<string>();
  let totalOctets = 0;
  for (const entry of ordered) {
    const name = safePath(entry.path);
    if (name === SOURCE_MANIFEST_NAME) fail(`${SOURCE_MANIFEST_NAME} is generated internally.`);
    if (seen.has(name)) fail(`duplicate source path ${name}.`);
    seen.add(name);
    totalOctets += entry.content.byteLength;
    if (entry.content.byteLength > MAX_SOURCE_FILE_OCTETS)
      fail(`${name} exceeds ${String(MAX_SOURCE_FILE_OCTETS)} octets.`);
    if (totalOctets > MAX_SOURCE_TOTAL_OCTETS)
      fail(`source input exceeds ${String(MAX_SOURCE_TOTAL_OCTETS)} octets.`);
  }
  if (ordered.length === 0 || ordered.length + 1 > MAX_SOURCE_FILES)
    fail('source entry count is outside the permitted range.');

  const entries = [...ordered, { content: manifest(ordered), path: SOURCE_MANIFEST_NAME }].sort(
    (left, right) => comparePaths(left.path, right.path),
  );
  const blocks: Buffer[] = [];
  for (const entry of entries) {
    const content = Buffer.from(entry.content);
    blocks.push(tarHeader(entry), content);
    const padding = (TAR_BLOCK_OCTETS - (content.length % TAR_BLOCK_OCTETS)) % TAR_BLOCK_OCTETS;
    if (padding > 0) blocks.push(Buffer.alloc(padding));
  }
  blocks.push(Buffer.alloc(TAR_BLOCK_OCTETS * 2));
  return gzipSync(Buffer.concat(blocks), { level: 9 });
}

function parseOctal(field: Uint8Array, label: string): number {
  const value = Buffer.from(field).toString('ascii').replaceAll('\0', '').trim();
  if (!/^[0-7]+$/u.test(value)) fail(`tar ${label} field is malformed.`);
  const parsed = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(parsed)) fail(`tar ${label} field is too large.`);
  return parsed;
}

function verifyManifest(entries: ReadonlyMap<string, Uint8Array>): void {
  const rawManifest = entries.get(SOURCE_MANIFEST_NAME);
  if (rawManifest === undefined) fail(`${SOURCE_MANIFEST_NAME} is missing.`);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(rawManifest);
  const observed = new Map<string, string>();
  for (const line of text.split('\n')) {
    if (line === '') continue;
    const match = /^([a-f0-9]{64}) {2}(.+)$/u.exec(line);
    if (match?.[1] === undefined || match[2] === undefined)
      fail(`${SOURCE_MANIFEST_NAME} contains a malformed line.`);
    const path = safePath(match[2]);
    if (path === SOURCE_MANIFEST_NAME || observed.has(path))
      fail(`${SOURCE_MANIFEST_NAME} contains an invalid path.`);
    observed.set(path, match[1]);
  }
  const expected = [...entries.keys()]
    .filter((path) => path !== SOURCE_MANIFEST_NAME)
    .sort(comparePaths);
  if (observed.size !== expected.length || expected.some((path) => !observed.has(path)))
    fail(`${SOURCE_MANIFEST_NAME} does not enumerate the archive exactly.`);
  for (const path of expected) {
    const content = entries.get(path);
    if (content === undefined || observed.get(path) !== sha256(content))
      fail(`${SOURCE_MANIFEST_NAME} does not match ${path}.`);
  }
}

export function parseCorrespondingSourceArchive(
  archive: Uint8Array,
): ReadonlyMap<string, Uint8Array> {
  let tar: Buffer;
  try {
    tar = gunzipSync(archive, { maxOutputLength: MAX_SOURCE_TOTAL_OCTETS + 1024 * 1024 });
  } catch {
    fail('gzip stream is invalid or exceeds the expanded-size limit.');
  }
  if (tar.length % TAR_BLOCK_OCTETS !== 0) fail('tar stream is not block aligned.');
  const entries = new Map<string, Uint8Array>();
  let offset = 0;
  let terminated = false;
  while (offset + TAR_BLOCK_OCTETS <= tar.length) {
    const header = tar.subarray(offset, offset + TAR_BLOCK_OCTETS);
    if (header.every((byte) => byte === 0)) {
      const remaining = tar.subarray(offset);
      if (remaining.length < TAR_BLOCK_OCTETS * 2 || !remaining.every((byte) => byte === 0))
        fail('tar terminator is malformed.');
      terminated = true;
      break;
    }
    const storedChecksum = parseOctal(header.subarray(148, 156), 'checksum');
    const checksumHeader = Buffer.from(header);
    checksumHeader.fill(0x20, 148, 156);
    if (checksumHeader.reduce((sum, byte) => sum + byte, 0) !== storedChecksum)
      fail('tar header checksum does not match.');
    const nul = header.subarray(0, 100).indexOf(0);
    let decodedPath: string;
    try {
      decodedPath = new TextDecoder('utf-8', { fatal: true }).decode(
        header.subarray(0, nul === -1 ? 100 : nul),
      );
    } catch {
      fail('tar entry path is not valid UTF-8.');
    }
    const path = safePath(decodedPath);
    if (header[156] !== 0 && header[156] !== '0'.charCodeAt(0))
      fail(`tar entry ${path} is not a regular file.`);
    const size = parseOctal(header.subarray(124, 136), 'size');
    if (size > MAX_SOURCE_FILE_OCTETS) fail(`tar entry ${path} is too large.`);
    const contentStart = offset + TAR_BLOCK_OCTETS;
    const contentEnd = contentStart + size;
    if (contentEnd > tar.length) fail(`tar entry ${path} is truncated.`);
    if (entries.has(path)) fail(`tar entry ${path} is duplicated.`);
    entries.set(path, Uint8Array.from(tar.subarray(contentStart, contentEnd)));
    if (entries.size > MAX_SOURCE_FILES) fail('tar contains too many entries.');
    const paddedEnd = contentStart + Math.ceil(size / TAR_BLOCK_OCTETS) * TAR_BLOCK_OCTETS;
    if (
      paddedEnd > tar.length ||
      !tar.subarray(contentEnd, paddedEnd).every((byte) => byte === 0)
    )
      fail(`tar entry ${path} has malformed padding.`);
    offset = paddedEnd;
  }
  if (!terminated) fail('tar terminator is missing.');
  verifyManifest(entries);
  return entries;
}

export function sourceArchiveDigest(archive: Uint8Array): string {
  return sha256(archive);
}
