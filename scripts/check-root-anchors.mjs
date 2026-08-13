import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const DATA_URL = 'https://data.iana.org/root-anchors/root-anchors.xml';
const SIGNATURE_URL = 'https://data.iana.org/root-anchors/root-anchors.p7s';
const committedPath = new URL('../src/core/dnssec/root-anchors.json', import.meta.url);
const pinnedCaPath = fileURLToPath(new URL('./icann-root-ca.pem', import.meta.url));
const MAX_DOWNLOAD_BYTES = 1_048_576;
const EXPECTED_SIGNER = 'DNSSEC Trust Anchor Verification';
const EXPECTED_SIGNER_EMAIL = 'dnssec@iana.org';
const EXPECTED_CA_FINGERPRINT =
  'AE:E8:99:06:D7:CC:60:C5:E1:51:F3:BB:92:3A:BF:8A:1B:28:DC:85:5D:5E:21:27:CB:52:4E:AD:4A:AD:60:3D';

async function download(url) {
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(15_000) });
  if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}.`);
  const declaredLength = Number(response.headers.get('Content-Length'));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_DOWNLOAD_BYTES)
    throw new Error(`${url} exceeds the download size bound.`);
  const reader = response.body?.getReader();
  if (reader === undefined) throw new Error(`${url} returned no response body.`);
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > MAX_DOWNLOAD_BYTES) {
        await reader.cancel();
        throw new Error(`${url} exceeds the download size bound.`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

function text(bytes) {
  return new TextDecoder().decode(bytes);
}

function field(body, name) {
  const match = new RegExp(`<${name}>([^<]+)</${name}>`, 'u').exec(body);
  if (match?.[1] === undefined) throw new Error(`IANA XML is missing ${name}.`);
  return match[1].trim();
}

function currentAnchors(xml, now = Date.now()) {
  return [...xml.matchAll(/<KeyDigest\s+([^>]+)>([\s\S]*?)<\/KeyDigest>/gu)]
    .filter((match) => {
      const until = /validUntil="([^"]+)"/u.exec(match[1] ?? '')?.[1];
      return until === undefined || Date.parse(until) > now;
    })
    .map((match) => {
      const attributes = match[1] ?? '';
      const body = match[2] ?? '';
      const id = /id="([^"]+)"/u.exec(attributes)?.[1];
      const validFrom = /validFrom="([^"]+)"/u.exec(attributes)?.[1];
      const validUntil = /validUntil="([^"]+)"/u.exec(attributes)?.[1];
      if (id === undefined || validFrom === undefined)
        throw new Error('IANA XML contains an incomplete KeyDigest entry.');
      return {
        algorithm: Number(field(body, 'Algorithm')),
        digest: field(body, 'Digest').toUpperCase(),
        digestType: Number(field(body, 'DigestType')),
        id,
        keyTag: Number(field(body, 'KeyTag')),
        validFrom,
        ...(validUntil === undefined ? {} : { validUntil }),
      };
    })
    .sort((left, right) => left.keyTag - right.keyTag);
}

const temporary = await mkdtemp(join(tmpdir(), 'zoneskein-root-anchors-'));
try {
  const caFingerprint = execFileSync(
    'openssl',
    ['x509', '-in', pinnedCaPath, '-noout', '-fingerprint', '-sha256'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  if (!caFingerprint.includes(EXPECTED_CA_FINGERPRINT))
    throw new Error('The committed ICANN root certificate fingerprint is unexpected.');
  const [xmlBytes, signatureBytes] = await Promise.all([
    download(DATA_URL),
    download(SIGNATURE_URL),
  ]);
  const xmlPath = join(temporary, 'root-anchors.xml');
  const signaturePath = join(temporary, 'root-anchors.p7s');
  const verifiedPath = join(temporary, 'verified.xml');
  const signersPath = join(temporary, 'signers.pem');
  await Promise.all([writeFile(xmlPath, xmlBytes), writeFile(signaturePath, signatureBytes)]);
  execFileSync(
    'openssl',
    [
      'cms',
      '-verify',
      '-binary',
      '-inform',
      'DER',
      '-in',
      signaturePath,
      '-content',
      xmlPath,
      '-CAfile',
      pinnedCaPath,
      '-signer',
      signersPath,
      '-out',
      verifiedPath,
    ],
    { stdio: 'pipe' },
  );
  const signerSubject = execFileSync(
    'openssl',
    ['x509', '-in', signersPath, '-noout', '-subject', '-ext', 'extendedKeyUsage'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  if (
    !signerSubject.includes(EXPECTED_SIGNER) ||
    !signerSubject.includes(EXPECTED_SIGNER_EMAIL) ||
    !signerSubject.includes('E-mail Protection')
  )
    throw new Error('The CMS signer identity does not match the reviewed IANA signer.');
  const verifiedXml = new Uint8Array(await readFile(verifiedPath));
  if (Buffer.compare(verifiedXml, xmlBytes) !== 0)
    throw new Error('OpenSSL did not reproduce the downloaded anchor XML exactly.');

  const committed = JSON.parse(await readFile(committedPath, 'utf8'));
  const observed = currentAnchors(text(xmlBytes));
  const expected = [...committed.anchors]
    .map(({ algorithm, digest, digestType, id, keyTag, validFrom, validUntil }) => ({
      algorithm,
      digest,
      digestType,
      id,
      keyTag,
      validFrom,
      ...(validUntil === undefined ? {} : { validUntil }),
    }))
    .sort((left, right) => left.keyTag - right.keyTag);
  if (JSON.stringify(observed) !== JSON.stringify(expected)) {
    process.stderr.write(`${JSON.stringify({ expected, observed }, null, 2)}\n`);
    throw new Error('The verified IANA root trust-anchor set differs from the committed set.');
  }
  process.stdout.write(`Verified ${observed.length} current IANA root trust anchors.\n`);
} finally {
  await rm(temporary, { force: true, recursive: true });
}
