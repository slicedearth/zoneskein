import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open, readdir, readFile, stat } from 'node:fs/promises';
import { extname, join, relative, resolve, sep } from 'node:path';

import {
  collectCorrespondingSource,
  parseCorrespondingSourceArchive,
  SOURCE_ARCHIVE_DIGEST_NAME,
  SOURCE_ARCHIVE_NAME,
  SOURCE_MANIFEST_NAME,
  sourceArchiveDigest,
} from './source-archive.ts';
import {
  renderSeoHead,
  replaceSeoHead,
  SEO_ROUTES,
  sitemapXml,
  STRUCTURED_DATA_JSON,
} from '../src/seo.ts';

const root = resolve(import.meta.dirname, '..');
const output = join(root, 'dist');
const functionsDirectory = join(root, 'netlify', 'functions');
const MAX_FILES = 160;
const MAX_TOTAL_OCTETS = 7 * 1024 * 1024;
const MAX_SINGLE_ASSET_OCTETS = 512 * 1024;
const MAX_FUNCTION_SOURCE_OCTETS = 64 * 1024;
const MAX_SOURCE_ARCHIVE_OCTETS = 5 * 1024 * 1024;
const HASHED_ASSET_NAME = /^assets\/[A-Za-z0-9_-]+-[A-Za-z0-9_-]{8}\.(?:css|js|woff2)$/u;
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
  'apple-touch-icon.png',
  'favicon.ico',
  'index.html',
  'logo.svg',
  'robots.txt',
  'sitemap.xml',
  'social-card.jpg',
]);
const ROUTE_HTML_FILES = new Set(
  SEO_ROUTES.filter((route) => route.path !== '').map((route) => `${route.path}/index.html`),
);
const ALLOWED_ASSET_EXTENSIONS = new Set(['.css', '.js', '.woff2']);

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

async function verifyFaviconIco(): Promise<void> {
  const favicon = await readFile(join(root, 'public/favicon.ico'));
  const expectedSizes = [16, 32, 48, 64, 128, 256] as const;
  const directoryOctets = 6 + expectedSizes.length * 16;
  if (
    favicon.length < directoryOctets ||
    favicon.readUInt16LE(0) !== 0 ||
    favicon.readUInt16LE(2) !== 1 ||
    favicon.readUInt16LE(4) !== expectedSizes.length
  ) {
    fail('favicon.ico has an invalid icon directory.');
  }
  let expectedImageOffset = directoryOctets;
  const pngSignature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  for (const [index, expectedSize] of expectedSizes.entries()) {
    const entryOffset = 6 + index * 16;
    const width = favicon[entryOffset] === 0 ? 256 : favicon[entryOffset];
    const height = favicon[entryOffset + 1] === 0 ? 256 : favicon[entryOffset + 1];
    const imageOctets = favicon.readUInt32LE(entryOffset + 8);
    const imageOffset = favicon.readUInt32LE(entryOffset + 12);
    const imageEnd = imageOffset + imageOctets;
    if (
      width !== expectedSize ||
      height !== expectedSize ||
      favicon.readUInt16LE(entryOffset + 4) !== 1 ||
      favicon.readUInt16LE(entryOffset + 6) !== 32 ||
      imageOctets < 24 ||
      imageOffset !== expectedImageOffset ||
      imageEnd > favicon.length ||
      !favicon.subarray(imageOffset, imageOffset + 8).equals(pngSignature) ||
      favicon.subarray(imageOffset + 12, imageOffset + 16).toString('ascii') !== 'IHDR' ||
      favicon.readUInt32BE(imageOffset + 16) !== expectedSize ||
      favicon.readUInt32BE(imageOffset + 20) !== expectedSize
    ) {
      fail(`favicon.ico has an invalid ${String(expectedSize)}-pixel image.`);
    }
    expectedImageOffset = imageEnd;
  }
  if (expectedImageOffset !== favicon.length) fail('favicon.ico has unexpected trailing data.');
}

async function verifyPng(
  sourceName: string,
  expectedWidth: number,
  expectedHeight: number,
  maximumOctets: number,
): Promise<void> {
  const png = await readFile(join(root, sourceName));
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (
    png.length < 45 ||
    png.length > maximumOctets ||
    !png.subarray(0, 8).equals(signature) ||
    png.readUInt32BE(8) !== 13 ||
    png.subarray(12, 16).toString('ascii') !== 'IHDR' ||
    png.readUInt32BE(16) !== expectedWidth ||
    png.readUInt32BE(20) !== expectedHeight ||
    png.readUInt32BE(png.length - 12) !== 0 ||
    png.subarray(png.length - 8, png.length - 4).toString('ascii') !== 'IEND'
  ) {
    fail(
      `${sourceName} is not a bounded ${String(expectedWidth)} by ${String(expectedHeight)} PNG.`,
    );
  }
}

async function verifyJpeg(
  sourceName: string,
  expectedWidth: number,
  expectedHeight: number,
  maximumOctets: number,
): Promise<void> {
  const jpeg = await readFile(join(root, sourceName));
  if (
    jpeg.length < 16 ||
    jpeg.length > maximumOctets ||
    jpeg[0] !== 0xff ||
    jpeg[1] !== 0xd8 ||
    jpeg[jpeg.length - 2] !== 0xff ||
    jpeg[jpeg.length - 1] !== 0xd9
  ) {
    fail(`${sourceName} is not a bounded JPEG image.`);
  }
  const startOfFrame = new Set([
    0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf,
  ]);
  let offset = 2;
  while (offset + 8 < jpeg.length) {
    if (jpeg[offset] !== 0xff) fail(`${sourceName} has an invalid JPEG marker boundary.`);
    while (jpeg[offset] === 0xff) offset += 1;
    const marker = jpeg[offset];
    offset += 1;
    if (marker === undefined || marker === 0xd9 || marker === 0xda) break;
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) continue;
    if (offset + 2 > jpeg.length) fail(`${sourceName} has a truncated JPEG segment.`);
    const length = jpeg.readUInt16BE(offset);
    if (length < 2 || offset + length > jpeg.length) {
      fail(`${sourceName} has an invalid JPEG segment length.`);
    }
    if (startOfFrame.has(marker)) {
      if (
        length < 8 ||
        jpeg.readUInt16BE(offset + 3) !== expectedHeight ||
        jpeg.readUInt16BE(offset + 5) !== expectedWidth
      ) {
        fail(
          `${sourceName} is not a ${String(expectedWidth)} by ${String(expectedHeight)} JPEG.`,
        );
      }
      return;
    }
    offset += length;
  }
  fail(`${sourceName} has no supported JPEG frame header.`);
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
  const handle = await open(sourcePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) fail('quad9-doh.ts must remain a regular file.');
    if (before.size > BigInt(MAX_FUNCTION_SOURCE_OCTETS))
      fail(`quad9-doh.ts exceeds ${String(MAX_FUNCTION_SOURCE_OCTETS)} octets.`);

    const buffer = Buffer.alloc(MAX_FUNCTION_SOURCE_OCTETS + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > MAX_FUNCTION_SOURCE_OCTETS)
      fail(`quad9-doh.ts exceeds ${String(MAX_FUNCTION_SOURCE_OCTETS)} octets.`);

    const after = await handle.stat({ bigint: true });
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs
    )
      fail('quad9-doh.ts changed while it was being verified.');
    return buffer.subarray(0, offset).toString('utf8');
  } finally {
    await handle.close();
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
  } else if (!REQUIRED_ROOT_FILES.has(name) && !ROUTE_HTML_FILES.has(name)) {
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
  requireExactCopy('public/apple-touch-icon.png', 'apple-touch-icon.png'),
  requireExactCopy('public/favicon.ico', 'favicon.ico'),
  requireExactCopy('public/logo.svg', 'logo.svg'),
  requireExactCopy('public/robots.txt', 'robots.txt'),
  requireExactCopy('public/sitemap.xml', 'sitemap.xml'),
  requireExactCopy('public/social-card.jpg', 'social-card.jpg'),
]);

const sourceDigest = await verifyCorrespondingSource();
await Promise.all([
  verifyFaviconIco(),
  verifyPng('public/apple-touch-icon.png', 180, 180, 128 * 1024),
  verifyJpeg('public/social-card.jpg', 1200, 630, 256 * 1024),
]);

const [
  html,
  headers,
  redirects,
  resolverSource,
  measurementSource,
  netlifyConfig,
  relaySource,
] = await Promise.all([
  readFile(join(output, 'index.html'), 'utf8'),
  readFile(join(output, '_headers'), 'utf8'),
  readFile(join(output, '_redirects'), 'utf8'),
  readFile(join(root, 'src/core/doh/resolvers.ts'), 'utf8'),
  readFile(join(root, 'src/core/measurement/globalping.ts'), 'utf8'),
  readFile(join(root, 'netlify.toml'), 'utf8'),
  quad9RelaySource(),
]);

if (
  !/<link\b(?=[^>]*\brel="icon")(?=[^>]*\bhref="\/favicon\.ico")(?=[^>]*\btype="image\/x-icon")[^>]*>/u.test(
    html,
  )
) {
  fail('the document does not declare the stable favicon.ico asset.');
}
if (
  !/<link\b(?=[^>]*\brel="apple-touch-icon")(?=[^>]*\bhref="\/apple-touch-icon\.png")(?=[^>]*\bsizes="180x180")[^>]*>/u.test(
    html,
  )
) {
  fail('the document does not declare the 180-pixel Apple touch icon.');
}

const homeSeo = renderSeoHead(SEO_ROUTES[0]);
if (!html.includes(homeSeo)) fail('index.html does not contain the exact home-page metadata.');
for (const route of SEO_ROUTES) {
  if (route.path === '') continue;
  const routeHtml = await readFile(join(output, route.path, 'index.html'), 'utf8');
  if (routeHtml !== replaceSeoHead(html, route)) {
    fail(`${route.path}/index.html does not contain the exact route metadata.`);
  }
}

const [robots, sitemap] = await Promise.all([
  readFile(join(output, 'robots.txt'), 'utf8'),
  readFile(join(output, 'sitemap.xml'), 'utf8'),
]);
if (sitemap !== sitemapXml()) fail('sitemap.xml does not match the indexable route set.');
if (
  robots
    .split(/\r?\n/u)
    .filter((line) => line === 'Sitemap: https://www.zoneskein.com/sitemap.xml').length !== 1
) {
  fail('robots.txt does not declare the canonical sitemap exactly once.');
}

if (!redirects.split(/\r?\n/u).includes('/*  /index.html  200'))
  fail('SPA fallback redirect is missing.');
if (
  !/^\s*Strict-Transport-Security:\s*max-age=63072000; includeSubDomains\s*$/mu.test(headers)
) {
  fail('the two-year HSTS policy is missing or has changed.');
}
for (const [path, contentType] of [
  ['/LICENSE', 'text/plain; charset=UTF-8'],
  ['/*.md', 'text/markdown; charset=UTF-8'],
  ['/SOURCE_SHA256', 'text/plain; charset=UTF-8'],
] as const) {
  const escapedPath = path.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const escapedContentType = contentType.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  if (
    !new RegExp(
      `(?:^|\\n)${escapedPath}\\n\\s+Content-Type: ${escapedContentType}(?:\\n|$)`,
      'u',
    ).test(headers)
  )
    fail(`${path} is missing its explicit UTF-8 content type.`);
}
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
  'seven-second lifecycle timeout',
);
requireSourcePattern(
  relaySource,
  /maxReservedRemoteStreams:\s*0\b/u,
  'disabled HTTP/2 push reservation',
);
requireSourcePattern(relaySource, /enablePush:\s*false\b/u, 'disabled HTTP/2 server push');
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
const measurementUrls = measurementSource.match(/https?:\/\/[^'"\s`)]+/gu) ?? [];
if (
  measurementUrls.length !== 1 ||
  measurementUrls[0] !== 'https://api.globalping.io/v1/measurements'
) {
  fail('external measurement source does not contain exactly one fixed API URL.');
}
const expectedConnections = new Set([
  "'self'",
  ...resolverOrigins,
  new URL(measurementUrls[0]).origin,
]);
const structuredDataHash = `'sha256-${createHash('sha256')
  .update(STRUCTURED_DATA_JSON)
  .digest('base64')}'`;
const expectedScripts = new Set(["'self'", structuredDataHash]);

const headerPolicy = /^\s*Content-Security-Policy:\s*(.+)$/mu.exec(headers)?.[1];
const metaPolicy = /http-equiv="Content-Security-Policy"\s+content="([^"]+)"/u.exec(html)?.[1];
if (headerPolicy === undefined || metaPolicy === undefined)
  fail('CSP is missing from the output.');
assertSameSet(directiveValues(headerPolicy, 'connect-src'), expectedConnections, 'Header CSP');
assertSameSet(directiveValues(metaPolicy, 'connect-src'), expectedConnections, 'HTML CSP');
assertSameSet(
  directiveValues(headerPolicy, 'script-src'),
  expectedScripts,
  'Header script CSP',
);
assertSameSet(directiveValues(metaPolicy, 'script-src'), expectedScripts, 'HTML script CSP');

const referencedAssets = [
  ...html.matchAll(/(?:src|href)="(\/assets\/[A-Za-z0-9_-]+\.(?:css|js))"/gu),
].map((match) => match[1]);
if (referencedAssets.length < 2 || referencedAssets.some((value) => value === undefined))
  fail('HTML does not reference the expected hashed entry assets.');
for (const asset of referencedAssets as string[]) {
  if (!files.includes(join(output, asset.slice(1)))) fail(`HTML references missing ${asset}.`);
}
const inlineScripts = [
  ...html.matchAll(/<script\b(?![^>]*\bsrc=)([^>]*)>([\s\S]*?)<\/script>/giu),
];
if (
  inlineScripts.length !== 1 ||
  !/\bid="zoneskein-structured-data"/u.test(inlineScripts[0]?.[1] ?? '') ||
  !/\btype="application\/ld\+json"/u.test(inlineScripts[0]?.[1] ?? '') ||
  inlineScripts[0]?.[2] !== STRUCTURED_DATA_JSON
) {
  fail('HTML does not contain exactly the checked structured-data script.');
}

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
