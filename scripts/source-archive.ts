import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { join, relative, resolve, sep } from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';

export const SOURCE_ARCHIVE_NAME = 'zoneskein-corresponding-source.tar.gz';
export const SOURCE_ARCHIVE_DIGEST_NAME = 'SOURCE_SHA256';
export const SOURCE_FILE_LIST_NAME = 'SOURCE_FILES.json';
export const SOURCE_MANIFEST_NAME = 'SOURCE_MANIFEST.sha256';

const MAX_SOURCE_FILES = 768;
const MAX_SOURCE_FILE_OCTETS = 2 * 1024 * 1024;
const MAX_SOURCE_TOTAL_OCTETS = 20 * 1024 * 1024;
const TAR_BLOCK_OCTETS = 512;
const TAR_NAME_OCTETS = 100;
const TAR_PREFIX_OCTETS = 155;
const MAX_SOURCE_PATH_OCTETS = TAR_PREFIX_OCTETS + 1 + TAR_NAME_OCTETS;

export const SOURCE_REPOSITORY_DIRECTORIES = [
  '.github',
  'docs',
  'netlify',
  'public',
  'scripts',
  'src',
  'tests',
] as const;

export const SOURCE_REPOSITORY_ROOT_FILES = [
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
  SOURCE_FILE_LIST_NAME,
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
const FORBIDDEN_LOCAL_BUILD_INPUTS = [
  '.env',
  '.env.local',
  '.env.production',
  '.env.production.local',
] as const;
const PACKAGE_PATH_PATTERN =
  /^node_modules\/(?:@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*|[a-z0-9][a-z0-9._~-]*)(?:\/node_modules\/(?:@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*|[a-z0-9][a-z0-9._~-]*))*$/u;

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
    Buffer.byteLength(normalised) > MAX_SOURCE_PATH_OCTETS
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

function containedPath(root: string, path: string, label: string): string {
  const absolute = resolve(path);
  const fromRoot = relative(root, absolute);
  if (fromRoot === '' || fromRoot === '..' || fromRoot.startsWith(`..${sep}`)) {
    fail(`${label} escapes the repository root.`);
  }
  return absolute;
}

async function assertRegularPath(root: string, path: string, label: string): Promise<void> {
  const absolute = containedPath(root, path, label);
  const fromRoot = relative(root, absolute);
  let current = root;
  for (const part of fromRoot.split(sep)) {
    current = join(current, part);
    const details = await lstat(current);
    if (details.isSymbolicLink()) fail(`${label} contains a symbolic link.`);
    if (current === absolute ? !details.isFile() : !details.isDirectory()) {
      fail(`${label} is not a regular repository file.`);
    }
  }
}

async function readRegularFile(root: string, path: string, label: string): Promise<Buffer> {
  const absolute = containedPath(root, path, label);
  await assertRegularPath(root, absolute, label);
  const handle = await open(absolute, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const details = await handle.stat();
    if (!details.isFile()) fail(`${label} is not a regular file.`);
    if (details.size > MAX_SOURCE_FILE_OCTETS)
      fail(`${label} exceeds ${String(MAX_SOURCE_FILE_OCTETS)} octets.`);
    const content = await handle.readFile();
    if (content.byteLength !== details.size) fail(`${label} changed while it was read.`);
    return content;
  } finally {
    await handle.close();
  }
}

function parseSourceFileList(content: Uint8Array): readonly string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(content)) as unknown;
  } catch {
    fail(`${SOURCE_FILE_LIST_NAME} is not valid UTF-8 JSON.`);
  }
  if (!Array.isArray(parsed))
    fail(`${SOURCE_FILE_LIST_NAME} must be an array of source paths.`);
  const paths = parsed.map((path: unknown) => {
    if (typeof path !== 'string')
      fail(`${SOURCE_FILE_LIST_NAME} must be an array of source paths.`);
    return safePath(path);
  });
  if (
    paths.length === 0 ||
    paths.length > MAX_SOURCE_FILES ||
    new Set(paths).size !== paths.length
  ) {
    fail(`${SOURCE_FILE_LIST_NAME} has an invalid path count.`);
  }
  const ordered = [...paths].sort(comparePaths);
  if (ordered.some((path, index) => path !== paths[index])) {
    fail(`${SOURCE_FILE_LIST_NAME} must be sorted.`);
  }
  const rootFiles = new Set(SOURCE_REPOSITORY_ROOT_FILES);
  const directories = new Set(SOURCE_REPOSITORY_DIRECTORIES);
  for (const path of paths) {
    const slash = path.indexOf('/');
    if (
      slash < 0
        ? !rootFiles.has(path as (typeof SOURCE_REPOSITORY_ROOT_FILES)[number])
        : !directories.has(
            path.slice(0, slash) as (typeof SOURCE_REPOSITORY_DIRECTORIES)[number],
          )
    ) {
      fail(`${SOURCE_FILE_LIST_NAME} contains an unapproved path ${path}.`);
    }
  }
  for (const required of SOURCE_REPOSITORY_ROOT_FILES) {
    if (!paths.includes(required)) fail(`${SOURCE_FILE_LIST_NAME} is missing ${required}.`);
  }
  return paths;
}

async function declaredRepositoryPaths(root: string): Promise<readonly string[]> {
  for (const input of FORBIDDEN_LOCAL_BUILD_INPUTS) {
    try {
      await lstat(join(root, input));
      fail(`undeclared local build input ${input} is present.`);
    } catch (cause) {
      if (
        typeof cause !== 'object' ||
        cause === null ||
        !('code' in cause) ||
        cause.code !== 'ENOENT'
      ) {
        throw cause;
      }
    }
  }
  const fileList = await readRegularFile(
    root,
    join(root, SOURCE_FILE_LIST_NAME),
    SOURCE_FILE_LIST_NAME,
  );
  const declared = parseSourceFileList(fileList);
  const observed = (
    await Promise.all(
      SOURCE_REPOSITORY_DIRECTORIES.map((directory) => filesBelow(root, directory)),
    )
  )
    .flat()
    .map((path) => relative(root, path).split(sep).join('/'))
    .sort(comparePaths);
  const expected = declared.filter((path) => path.includes('/'));
  if (
    observed.length !== expected.length ||
    observed.some((path, index) => path !== expected[index])
  ) {
    fail(`${SOURCE_FILE_LIST_NAME} does not exactly enumerate the source directories.`);
  }
  return declared;
}

function isObject(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function productionPackagePaths(root: string): Promise<readonly string[]> {
  let lockfile: unknown;
  try {
    lockfile = JSON.parse(
      (
        await readRegularFile(root, join(root, 'package-lock.json'), 'package-lock.json')
      ).toString('utf8'),
    ) as unknown;
  } catch {
    fail('package-lock.json is not valid JSON.');
  }
  if (!isObject(lockfile) || !isObject(lockfile['packages']))
    fail('package-lock.json does not contain a package map.');

  const paths: string[] = [];
  for (const [path, metadata] of Object.entries(lockfile['packages'])) {
    if (!path.startsWith('node_modules/')) continue;
    if (!PACKAGE_PATH_PATTERN.test(path))
      fail(`package-lock entry ${path} has an unsafe path.`);
    if (!isObject(metadata)) fail(`package-lock entry ${path} is malformed.`);
    if (
      (metadata['dev'] !== undefined && typeof metadata['dev'] !== 'boolean') ||
      (metadata['link'] !== undefined && typeof metadata['link'] !== 'boolean')
    ) {
      fail(`package-lock entry ${path} has invalid flags.`);
    }
    if (metadata['dev'] !== true && metadata['link'] !== true) paths.push(path);
    if (paths.length > MAX_SOURCE_FILES)
      fail('package-lock.json identifies too many production packages.');
  }
  if (paths.length === 0) fail('package-lock.json identifies no production packages.');
  return paths.sort(comparePaths);
}

export async function collectCorrespondingSource(
  repositoryRoot: string,
): Promise<readonly SourceArchiveEntry[]> {
  const root = await realpath(resolve(repositoryRoot));
  const repositoryPaths = (await declaredRepositoryPaths(root)).map((path) => join(root, path));
  const seen = new Set<string>();
  const entries: SourceArchiveEntry[] = [];
  let totalOctets = 0;

  async function add(path: string, archivePath: string): Promise<void> {
    const name = safePath(archivePath);
    if (seen.has(name)) fail(`duplicate source path ${name}.`);
    seen.add(name);
    const content = await readRegularFile(root, path, `source input ${name}`);
    totalOctets += content.byteLength;
    if (totalOctets > MAX_SOURCE_TOTAL_OCTETS)
      fail(`source input exceeds ${String(MAX_SOURCE_TOTAL_OCTETS)} octets.`);
    entries.push({ content, path: name });
    if (entries.length >= MAX_SOURCE_FILES) fail('source input contains too many files.');
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

function splitTarPath(value: string): { readonly name: string; readonly prefix: string } {
  const path = safePath(value);
  if (Buffer.byteLength(path) <= TAR_NAME_OCTETS) return { name: path, prefix: '' };

  const parts = path.split('/');
  for (let index = parts.length - 1; index > 0; index -= 1) {
    const prefix = parts.slice(0, index).join('/');
    const name = parts.slice(index).join('/');
    if (
      Buffer.byteLength(prefix) <= TAR_PREFIX_OCTETS &&
      Buffer.byteLength(name) <= TAR_NAME_OCTETS
    )
      return { name, prefix };
  }
  fail(`tar entry path ${JSON.stringify(value)} cannot fit a ustar header.`);
}

function readTarText(
  header: Uint8Array,
  offset: number,
  length: number,
  label: string,
): string {
  const field = header.subarray(offset, offset + length);
  const nul = field.indexOf(0);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(
      field.subarray(0, nul === -1 ? length : nul),
    );
  } catch {
    fail(`tar ${label} is not valid UTF-8.`);
  }
}

function tarHeader(entry: SourceArchiveEntry): Buffer {
  const header = Buffer.alloc(TAR_BLOCK_OCTETS);
  const path = splitTarPath(entry.path);
  writeText(header, 0, TAR_NAME_OCTETS, path.name);
  writeOctal(header, 100, 8, 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, entry.content.byteLength);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = '0'.charCodeAt(0);
  writeText(header, 257, 6, 'ustar\0');
  writeText(header, 263, 2, '00');
  writeText(header, 345, TAR_PREFIX_OCTETS, path.prefix);
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
    const name = readTarText(header, 0, TAR_NAME_OCTETS, 'entry name');
    const prefix = readTarText(header, 345, TAR_PREFIX_OCTETS, 'entry prefix');
    const decodedPath = prefix === '' ? name : `${prefix}/${name}`;
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
