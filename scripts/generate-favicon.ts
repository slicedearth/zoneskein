import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { chromium } from '@playwright/test';

const root = resolve(import.meta.dirname, '..');
const sourcePath = resolve(root, 'public/logo.svg');
const faviconPath = resolve(root, 'public/favicon.ico');
const appleTouchIconPath = resolve(root, 'public/apple-touch-icon.png');
const socialCardPath = resolve(root, 'public/social-card.jpg');
const socialCardSha256 = '3ec4db71df64596b0ae980440a45c5864f8689ca25b56ba82f9032d4f2b31488';
const displayFontPath = resolve(
  root,
  'node_modules/@fontsource-variable/bricolage-grotesque/files/bricolage-grotesque-latin-wght-normal.woff2',
);
const sizes = [16, 32, 48, 64, 128, 256] as const;
const checking = process.argv.includes('--check');

function encodeIco(images: readonly Buffer[]): Buffer {
  const directory = Buffer.alloc(6 + images.length * 16);
  directory.writeUInt16LE(0, 0);
  directory.writeUInt16LE(1, 2);
  directory.writeUInt16LE(images.length, 4);
  let imageOffset = directory.length;
  for (const [index, image] of images.entries()) {
    const size = sizes[index];
    if (size === undefined)
      throw new Error('Favicon image count does not match its size list.');
    const entryOffset = 6 + index * 16;
    directory[entryOffset] = size === 256 ? 0 : size;
    directory[entryOffset + 1] = size === 256 ? 0 : size;
    directory[entryOffset + 2] = 0;
    directory[entryOffset + 3] = 0;
    directory.writeUInt16LE(1, entryOffset + 4);
    directory.writeUInt16LE(32, entryOffset + 6);
    directory.writeUInt32LE(image.length, entryOffset + 8);
    directory.writeUInt32LE(imageOffset, entryOffset + 12);
    imageOffset += image.length;
  }
  return Buffer.concat([directory, ...images]);
}

async function writeOrCheck(path: string, value: Buffer): Promise<void> {
  if (checking) {
    const committed = await readFile(path);
    if (!committed.equals(value)) {
      throw new Error(`${path.slice(root.length + 1)} is not current.`);
    }
  } else {
    await writeFile(path, value);
  }
}

const [svg, displayFont] = await Promise.all([readFile(sourcePath), readFile(displayFontPath)]);
const sourceUrl = `data:image/svg+xml;base64,${svg.toString('base64')}`;
const displayFontUrl = `data:font/woff2;base64,${displayFont.toString('base64')}`;

const browser = await chromium.launch({ headless: true });
const images: Buffer[] = [];
let appleTouchIcon: Buffer;
let socialCard: Buffer;
try {
  for (const size of sizes) {
    const page = await browser.newPage({
      deviceScaleFactor: 1,
      viewport: { height: size, width: size },
    });
    await page.setContent(
      `<style>html,body{margin:0;width:100%;height:100%;background:transparent}.tile{display:grid;width:100%;height:100%;place-items:center;border-radius:24%;background:#211438}.tile img{display:block;width:87.5%;height:auto}</style><div class="tile"><img alt="" src="${sourceUrl}"></div>`,
    );
    images.push(
      await page.locator('.tile').screenshot({
        animations: 'disabled',
        omitBackground: true,
        type: 'png',
      }),
    );
    await page.close();
  }
  const iconPage = await browser.newPage({
    deviceScaleFactor: 1,
    viewport: { height: 180, width: 180 },
  });
  await iconPage.setContent(
    `<style>html,body{margin:0;width:100%;height:100%;background:transparent}.tile{display:grid;width:100%;height:100%;place-items:center;border-radius:24%;background:#211438}.tile img{display:block;width:87.5%;height:auto}</style><div class="tile"><img alt="" src="${sourceUrl}"></div>`,
  );
  appleTouchIcon = await iconPage.locator('.tile').screenshot({
    animations: 'disabled',
    omitBackground: true,
    type: 'png',
  });
  await iconPage.close();

  const socialPage = await browser.newPage({
    deviceScaleFactor: 1,
    viewport: { height: 630, width: 1200 },
  });
  await socialPage.setContent(`
    <style>
      @font-face{font-family:Bricolage;src:url('${displayFontUrl}') format('woff2');font-style:normal;font-weight:200 800}
      *{box-sizing:border-box}
      html,body{margin:0;width:100%;height:100%;overflow:hidden;background:#17102f}
      .card{position:relative;width:1200px;height:630px;overflow:hidden;background:radial-gradient(circle at 86% 18%,#4b3476 0 15%,transparent 38%),linear-gradient(135deg,#17102f 0%,#261743 54%,#17102f 100%);color:#fff3dc;font-family:Bricolage,Arial,sans-serif}
      .grain{position:absolute;inset:0;opacity:.12;background-image:radial-gradient(#fff3dc 1px,transparent 1px);background-size:21px 21px;mask-image:linear-gradient(90deg,transparent,#000 35%,#000)}
      .strands{position:absolute;inset:0;width:100%;height:100%;filter:drop-shadow(0 12px 18px rgba(8,4,25,.35))}
      .strand{fill:none;stroke-linecap:round;stroke-width:22}
      .coral{stroke:#ff6d65}.mango{stroke:#ffbd59}.mint{stroke:#67e6bd}.sky{stroke:#6bc8ff}
      .content{position:absolute;left:72px;top:64px;width:650px}
      .brand{display:flex;align-items:center;gap:24px;margin-bottom:72px}
      .mark{display:grid;width:116px;height:116px;place-items:center;border:3px solid rgba(255,243,220,.28);border-radius:31px;background:#211438;box-shadow:0 18px 40px rgba(8,4,25,.38)}
      .mark img{display:block;width:102px;height:auto}
      .wordmark{font-size:58px;font-weight:780;letter-spacing:-2.5px;line-height:1}
      .wordmark .zone{color:#ff7b71}.wordmark .skein{color:#67e6bd}
      h1{margin:0 0 18px;font-size:80px;font-weight:780;letter-spacing:-4px;line-height:.94}
      p{margin:0;max-width:650px;color:#e8dcff;font-size:28px;font-weight:470;line-height:1.32}
      .tag{position:absolute;left:72px;bottom:56px;padding:13px 20px;border:2px solid rgba(255,243,220,.3);border-radius:999px;background:rgba(23,16,47,.74);color:#fff3dc;font-size:21px;font-weight:650;letter-spacing:.2px}
    </style>
    <div class="card">
      <div class="grain"></div>
      <svg class="strands" viewBox="0 0 1200 630" aria-hidden="true">
        <path class="strand coral" d="M760 -40 C1120 75 770 205 1005 320 C1135 384 1132 498 1235 526" />
        <path class="strand mango" d="M906 -40 C722 106 1138 183 910 328 C790 405 1038 510 948 672" />
        <path class="strand mint" d="M1050 -40 C846 89 1094 224 844 315 C690 371 860 551 744 672" />
        <path class="strand sky" d="M1218 48 C976 92 830 177 1055 289 C1202 362 861 476 1120 672" />
      </svg>
      <div class="content">
        <div class="brand">
          <div class="mark"><img alt="" src="${sourceUrl}"></div>
          <div class="wordmark"><span class="zone">Zone</span><span class="skein">Skein</span></div>
        </div>
        <h1>Untangle DNS.</h1>
        <p>Follow live answers, trust chains, mail policy and change plans without losing the thread.</p>
      </div>
      <div class="tag">Evidence first · private by design</div>
    </div>
  `);
  await socialPage.evaluate(() => document.fonts.ready);
  socialCard = await socialPage.locator('.card').screenshot({
    animations: 'disabled',
    quality: 88,
    type: 'jpeg',
  });
  await socialPage.close();
} finally {
  await browser.close();
}

const ico = encodeIco(images);
await Promise.all([
  writeOrCheck(faviconPath, ico),
  writeOrCheck(appleTouchIconPath, appleTouchIcon),
]);

let reportedSocialCard = socialCard;
if (checking) {
  reportedSocialCard = await readFile(socialCardPath);
  const digest = createHash('sha256').update(reportedSocialCard).digest('hex');
  if (digest !== socialCardSha256)
    throw new Error('public/social-card.jpg does not match its reviewed canonical asset.');
} else {
  await writeFile(socialCardPath, socialCard);
}

const action = checking ? 'Verified' : 'Generated';
for (const [name, asset] of [
  ['public/favicon.ico', ico],
  ['public/apple-touch-icon.png', appleTouchIcon],
] as const) {
  const digest = createHash('sha256').update(asset).digest('hex');
  process.stdout.write(
    `${action} ${name} (${String(asset.length)} octets, sha256-${digest}).\n`,
  );
}
process.stdout.write(
  `${action} public/social-card.jpg (${String(reportedSocialCard.length)} octets, sha256-${createHash('sha256').update(reportedSocialCard).digest('hex')}).\n`,
);
