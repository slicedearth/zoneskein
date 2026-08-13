import { createHash } from 'node:crypto';
import { readdir, readFile, stat } from 'node:fs/promises';
import { extname, join, relative, resolve, sep } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const output = join(root, 'dist');
const MAX_FILES = 128;
const MAX_TOTAL_OCTETS = 4 * 1024 * 1024;
const MAX_SINGLE_ASSET_OCTETS = 512 * 1024;
const HASHED_ASSET_NAME = /^assets\/[A-Za-z0-9_-]+-[A-Za-z0-9_-]{8}\.(?:css|js)$/u;
const REQUIRED_ROOT_FILES = new Set([
  'LICENSE',
  'THIRD_PARTY_NOTICES.md',
  '_headers',
  '_redirects',
  'favicon.svg',
  'index.html',
  'robots.txt',
]);
const ALLOWED_ASSET_EXTENSIONS = new Set(['.css', '.js']);

function fail(message: string): never {
  throw new Error(`Build verification failed: ${message}`);
}

async function filesBelow(directory: string): Promise<readonly string[]> {
  const found: string[] = [];
  const pending = [directory];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) break;
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else if (entry.isFile()) found.push(path);
      else fail(`unexpected non-file output entry ${relative(output, path)}.`);
      if (found.length > MAX_FILES)
        fail(`output contains more than ${String(MAX_FILES)} files.`);
    }
  }
  return found.sort();
}

async function requireExactCopy(sourceName: string, outputName = sourceName): Promise<void> {
  const [source, built] = await Promise.all([
    readFile(join(root, sourceName)),
    readFile(join(output, outputName)),
  ]);
  if (!source.equals(built)) fail(`${outputName} does not exactly match ${sourceName}.`);
}

function directiveValues(policy: string, directive: string): ReadonlySet<string> {
  const match = new RegExp(`(?:^|;)\\s*${directive}\\s+([^;]+)`, 'u').exec(policy);
  if (match?.[1] === undefined) fail(`CSP is missing ${directive}.`);
  return new Set(match[1].trim().split(/\s+/u));
}

function assertSameSet(
  observed: ReadonlySet<string>,
  expected: ReadonlySet<string>,
  label: string,
): void {
  if (observed.size !== expected.size || [...observed].some((value) => !expected.has(value))) {
    fail(`${label} is not aligned with the fixed resolver origins.`);
  }
}

const files = await filesBelow(output);
let totalOctets = 0;
for (const path of files) {
  const name = relative(output, path).split(sep).join('/');
  const details = await stat(path);
  totalOctets += details.size;
  if (totalOctets > MAX_TOTAL_OCTETS)
    fail(`output exceeds ${String(MAX_TOTAL_OCTETS)} octets.`);
  if (name.includes('..') || name.startsWith('.') || name.endsWith('.map'))
    fail(`unexpected output file ${name}.`);
  if (name.startsWith('assets/')) {
    if (!HASHED_ASSET_NAME.test(name))
      fail(`asset name is not a one-level hashed path: ${name}.`);
    if (!ALLOWED_ASSET_EXTENSIONS.has(extname(name)))
      fail(`unexpected asset extension in ${name}.`);
    if (details.size > MAX_SINGLE_ASSET_OCTETS)
      fail(`${name} exceeds the ${String(MAX_SINGLE_ASSET_OCTETS)}-octet asset limit.`);
  } else if (!REQUIRED_ROOT_FILES.has(name)) {
    fail(`unexpected root output file ${name}.`);
  }
}

for (const required of REQUIRED_ROOT_FILES) {
  if (!files.includes(join(output, required)))
    fail(`required output file ${required} is missing.`);
}

await Promise.all([
  requireExactCopy('LICENSE'),
  requireExactCopy('THIRD_PARTY_NOTICES.md'),
  requireExactCopy('public/_headers', '_headers'),
  requireExactCopy('public/_redirects', '_redirects'),
  requireExactCopy('public/favicon.svg', 'favicon.svg'),
  requireExactCopy('public/robots.txt', 'robots.txt'),
]);

const [html, headers, redirects, resolverSource, netlifyConfig] = await Promise.all([
  readFile(join(output, 'index.html'), 'utf8'),
  readFile(join(output, '_headers'), 'utf8'),
  readFile(join(output, '_redirects'), 'utf8'),
  readFile(join(root, 'src/core/doh/resolvers.ts'), 'utf8'),
  readFile(join(root, 'netlify.toml'), 'utf8'),
]);

if (!redirects.split(/\r?\n/u).includes('/*  /index.html  200'))
  fail('SPA fallback redirect is missing.');
if (/\[(?:edge_)?functions\]|functions\s*=|edge_functions\s*=/iu.test(netlifyConfig))
  fail('Netlify configuration declares server-side functions.');

const resolverOrigins = new Set(
  [...resolverSource.matchAll(/endpoint:\s*'([^']+)'/gu)].map((match) => {
    if (match[1] === undefined) fail('resolver endpoint extraction failed.');
    return new URL(match[1]).origin;
  }),
);
if (resolverOrigins.size !== 3) fail('expected exactly three fixed resolver origins.');
const expectedConnections = new Set(["'self'", ...resolverOrigins]);

const headerPolicy = /^\s*Content-Security-Policy:\s*(.+)$/mu.exec(headers)?.[1];
const metaPolicy = /http-equiv="Content-Security-Policy"\s+content="([^"]+)"/u.exec(html)?.[1];
if (headerPolicy === undefined || metaPolicy === undefined)
  fail('CSP is missing from the output.');
assertSameSet(directiveValues(headerPolicy, 'connect-src'), expectedConnections, 'Header CSP');
assertSameSet(directiveValues(metaPolicy, 'connect-src'), expectedConnections, 'HTML CSP');

const referencedAssets = [
  ...html.matchAll(/(?:src|href)="(\/assets\/[A-Za-z0-9_-]+\.(?:css|js))"/gu),
].map((match) => match[1]);
if (referencedAssets.length < 2 || referencedAssets.some((value) => value === undefined))
  fail('HTML does not reference the expected hashed entry assets.');
for (const asset of referencedAssets as string[]) {
  if (!files.includes(join(output, asset.slice(1)))) fail(`HTML references missing ${asset}.`);
}
if (/<script(?![^>]+\bsrc=)[^>]*>/iu.test(html)) fail('HTML contains an inline script.');

const entryHashes = await Promise.all(
  (referencedAssets as string[]).map(async (asset) => {
    const digest = createHash('sha256')
      .update(await readFile(join(output, asset.slice(1))))
      .digest('hex');
    return `${asset.slice(1)} sha256-${digest}`;
  }),
);

process.stdout.write(
  `Verified ${String(files.length)} static build files (${String(totalOctets)} octets).\n${entryHashes.join('\n')}\n`,
);
