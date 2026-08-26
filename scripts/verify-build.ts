import { createHash } from 'node:crypto';
import { readdir, readFile, stat } from 'node:fs/promises';
import { extname, join, relative, resolve, sep } from 'node:path';

import {
  collectCorrespondingSource,
  parseCorrespondingSourceArchive,
  SOURCE_ARCHIVE_DIGEST_NAME,
  SOURCE_ARCHIVE_NAME,
  SOURCE_MANIFEST_NAME,
  sourceArchiveDigest,
} from './source-archive.ts';

const root = resolve(import.meta.dirname, '..');
const output = join(root, 'dist');
const functionsDirectory = join(root, 'netlify', 'functions');
const MAX_FILES = 160;
const MAX_TOTAL_OCTETS = 4 * 1024 * 1024;
const MAX_SINGLE_ASSET_OCTETS = 512 * 1024;
const MAX_FUNCTION_SOURCE_OCTETS = 64 * 1024;
const MAX_SOURCE_ARCHIVE_OCTETS = 3 * 1024 * 1024;
const HASHED_ASSET_NAME = /^assets\/[A-Za-z0-9_-]+-[A-Za-z0-9_-]{8}\.(?:css|js)$/u;
const REQUIRED_ROOT_FILES = new Set([
  'LICENSE',
  'PRIVACY.md',
  'SECURITY.md',
  'SOURCE.md',
  SOURCE_ARCHIVE_DIGEST_NAME,
  SOURCE_ARCHIVE_NAME,
  'TERMS.md',
  'THIRD_PARTY_NOTICES.md',
  'TRADEMARKS.md',
  '_headers',
  '_redirects',
  'favicon.svg',
  'index.html',
  'logo.svg',
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

async function verifyCorrespondingSource(): Promise<string> {
  const [archive, digestFile, expectedEntries] = await Promise.all([
    readFile(join(output, SOURCE_ARCHIVE_NAME)),
    readFile(join(output, SOURCE_ARCHIVE_DIGEST_NAME), 'utf8'),
    collectCorrespondingSource(root),
  ]);
  if (archive.length > MAX_SOURCE_ARCHIVE_OCTETS)
    fail(`${SOURCE_ARCHIVE_NAME} exceeds ${String(MAX_SOURCE_ARCHIVE_OCTETS)} octets.`);
  const digest = sourceArchiveDigest(archive);
  if (digestFile !== `${digest}  ${SOURCE_ARCHIVE_NAME}\n`)
    fail(`${SOURCE_ARCHIVE_DIGEST_NAME} does not match ${SOURCE_ARCHIVE_NAME}.`);

  let archivedEntries: ReadonlyMap<string, Uint8Array>;
  try {
    archivedEntries = parseCorrespondingSourceArchive(archive);
  } catch (cause) {
    fail(cause instanceof Error ? cause.message : 'corresponding-source archive is invalid.');
  }
  if (archivedEntries.size !== expectedEntries.length + 1)
    fail('corresponding-source archive does not contain the exact source file set.');
  for (const expected of expectedEntries) {
    const archived = archivedEntries.get(expected.path);
    if (archived === undefined || !Buffer.from(archived).equals(Buffer.from(expected.content)))
      fail(`corresponding-source archive does not exactly match ${expected.path}.`);
  }
  if (!archivedEntries.has(SOURCE_MANIFEST_NAME))
    fail(`corresponding-source archive is missing ${SOURCE_MANIFEST_NAME}.`);
  return digest;
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

function requireSourcePattern(source: string, pattern: RegExp, label: string): void {
  if (!pattern.test(source)) fail(`Quad9 relay source is missing its ${label}.`);
}

async function quad9RelaySource(): Promise<string> {
  const entries = await readdir(functionsDirectory, { withFileTypes: true });
  if (entries.length !== 1 || entries[0]?.name !== 'quad9-doh.ts' || !entries[0].isFile()) {
    fail('netlify/functions must contain exactly the quad9-doh.ts function source.');
  }
  const sourcePath = join(functionsDirectory, 'quad9-doh.ts');
  if ((await stat(sourcePath)).size > MAX_FUNCTION_SOURCE_OCTETS)
    fail(`quad9-doh.ts exceeds ${String(MAX_FUNCTION_SOURCE_OCTETS)} octets.`);
  return readFile(sourcePath, 'utf8');
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
  requireExactCopy('PRIVACY.md'),
  requireExactCopy('SECURITY.md'),
  requireExactCopy('SOURCE.md'),
  requireExactCopy('TERMS.md'),
  requireExactCopy('THIRD_PARTY_NOTICES.md'),
  requireExactCopy('TRADEMARKS.md'),
  requireExactCopy('public/_headers', '_headers'),
  requireExactCopy('public/_redirects', '_redirects'),
  requireExactCopy('public/favicon.svg', 'favicon.svg'),
  requireExactCopy('public/logo.svg', 'logo.svg'),
  requireExactCopy('public/robots.txt', 'robots.txt'),
]);

const sourceDigest = await verifyCorrespondingSource();

const [html, headers, redirects, resolverSource, netlifyConfig, relaySource] =
  await Promise.all([
    readFile(join(output, 'index.html'), 'utf8'),
    readFile(join(output, '_headers'), 'utf8'),
    readFile(join(output, '_redirects'), 'utf8'),
    readFile(join(root, 'src/core/doh/resolvers.ts'), 'utf8'),
    readFile(join(root, 'netlify.toml'), 'utf8'),
    quad9RelaySource(),
  ]);

if (!redirects.split(/\r?\n/u).includes('/*  /index.html  200'))
  fail('SPA fallback redirect is missing.');
if (/\[edge_functions\]|edge_functions\s*=/iu.test(netlifyConfig))
  fail('Netlify configuration declares an Edge Function.');
if (/\[functions(?:\.|\])|functions\s*=/iu.test(netlifyConfig))
  fail('Netlify configuration overrides the checked default function directory.');

requireSourcePattern(relaySource, /from\s+['"]node:http2['"]/u, 'Node.js HTTP/2 transport');
requireSourcePattern(relaySource, /path:\s*['"]\/api\/doh\/quad9['"]/u, 'fixed route');
requireSourcePattern(relaySource, /method:\s*['"]POST['"]/u, 'POST-only route configuration');
requireSourcePattern(relaySource, /action:\s*['"]rate_limit['"]/u, 'rate-limit action');
requireSourcePattern(
  relaySource,
  /aggregateBy:\s*\[\s*['"]ip['"]\s*,\s*['"]domain['"]\s*\]/u,
  'IP-and-domain rate-limit aggregation',
);
requireSourcePattern(relaySource, /windowLimit:\s*120\b/u, '120-request rate limit');
requireSourcePattern(relaySource, /windowSize:\s*60\b/u, '60-second rate-limit window');
requireSourcePattern(
  relaySource,
  /MAX_RELAY_QUERY_BYTES\s*=\s*4_096\b/u,
  '4,096-octet request limit',
);
requireSourcePattern(
  relaySource,
  /MAX_RELAY_RESPONSE_BYTES\s*=\s*65_535\b/u,
  '65,535-octet response limit',
);
requireSourcePattern(
  relaySource,
  /QUAD9_RELAY_TIMEOUT_MS\s*=\s*7_000\b/u,
  'seven-second upstream timeout',
);
requireSourcePattern(
  relaySource,
  /requestUrl\.search\s*!==\s*['"]['"]/u,
  'empty query-string check',
);
requireSourcePattern(
  relaySource,
  /['"]Cache-Control['"]:\s*['"]no-store,/u,
  'no-store response policy',
);
if (/\bprocess\.env\b|\bconsole\s*\./u.test(relaySource))
  fail('Quad9 relay source uses an environment override or application logging.');
if (/(?:from\s+|import\s*\(|require\s*\()\s*['"](?:\.{1,2}\/|\/)/u.test(relaySource))
  fail('Quad9 relay source imports a repository-local or absolute module.');

const relayUrls = relaySource.match(/https?:\/\/[^'"\s`)]+/gu) ?? [];
if (relayUrls.length !== 1 || relayUrls[0] !== 'https://dns.quad9.net/dns-query')
  fail('Quad9 relay source does not contain exactly one fixed upstream URL.');

const resolverEndpoints = [...resolverSource.matchAll(/endpoint:\s*'([^']+)'/gu)].map(
  (match) => {
    if (match[1] === undefined) fail('resolver endpoint extraction failed.');
    return match[1];
  },
);
if (
  resolverEndpoints.length !== 4 ||
  resolverEndpoints.filter((endpoint) => endpoint === '/api/doh/quad9').length !== 1
) {
  fail('expected three direct resolver endpoints and one fixed Quad9 relay endpoint.');
}
const resolverOrigins = new Set(
  resolverEndpoints
    .filter((endpoint) => endpoint.startsWith('https://'))
    .map((endpoint) => new URL(endpoint).origin),
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
  `Verified ${String(files.length)} static build files (${String(totalOctets)} octets).\n${entryHashes.join('\n')}\n${SOURCE_ARCHIVE_NAME} sha256-${sourceDigest}\n`,
);
