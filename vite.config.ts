import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

import react from '@vitejs/plugin-react';
import { defineConfig, type Plugin } from 'vite';

import { renderSeoHead, replaceSeoHead, SEO_ROUTES, seoRoute } from './src/seo.ts';

const repositoryRoot = realpathSync(import.meta.dirname);

function publicDocumentSource(fileName: string): string {
  const path = resolve(repositoryRoot, fileName);
  const fromRoot = relative(repositoryRoot, path);
  if (fromRoot === '' || fromRoot === '..' || fromRoot.startsWith(`..${sep}`)) {
    throw new Error(`Public document ${fileName} escapes the repository root.`);
  }
  let current = repositoryRoot;
  for (const part of fromRoot.split(sep)) {
    current = join(current, part);
    const details = lstatSync(current);
    if (details.isSymbolicLink()) {
      throw new Error(`Public document ${fileName} contains a symbolic link.`);
    }
    if (current === path ? !details.isFile() : !details.isDirectory()) {
      throw new Error(`Public document ${fileName} is not a regular repository file.`);
    }
  }
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const size = fstatSync(descriptor).size;
    const source = readFileSync(descriptor, 'utf8');
    if (Buffer.byteLength(source) !== size) {
      throw new Error(`Public document ${fileName} changed while it was read.`);
    }
    return source;
  } finally {
    closeSync(descriptor);
  }
}

function publicDocuments(): Plugin {
  const files = [
    'LICENSE',
    'PRIVACY.md',
    'SECURITY.md',
    'SOURCE.md',
    'TERMS.md',
    'THIRD_PARTY_NOTICES.md',
    'TRADEMARKS.md',
  ] as const;
  return {
    apply: 'build',
    buildStart() {
      for (const fileName of files) {
        this.emitFile({
          fileName,
          source: publicDocumentSource(fileName),
          type: 'asset',
        });
      }
    },
    name: 'zoneskein-public-documents',
  };
}

function routeMetadataPages(): Plugin {
  const marker = '<!-- zoneskein:seo -->';
  return {
    generateBundle: {
      handler(_options, bundle) {
        const entry = bundle['index.html'];
        if (entry?.type !== 'asset') {
          throw new Error('The Vite build did not produce an index.html asset.');
        }
        const source =
          typeof entry.source === 'string'
            ? entry.source
            : new TextDecoder().decode(entry.source);
        for (const route of SEO_ROUTES) {
          if (route.path === '') continue;
          this.emitFile({
            fileName: `${route.path}/index.html`,
            source: replaceSeoHead(source, route),
            type: 'asset',
          });
        }
      },
      order: 'post',
    },
    name: 'zoneskein-route-metadata-pages',
    transformIndexHtml: {
      handler(html, context) {
        const matches = html.split(marker).length - 1;
        if (matches !== 1) {
          throw new Error('Expected exactly one ZoneSkein SEO marker.');
        }
        const route = seoRoute(context.path) ?? SEO_ROUTES[0];
        return html.replace(marker, renderSeoHead(route));
      },
      order: 'pre',
    },
  };
}

function developmentStyleCompatibility(): Plugin {
  const metaPolicy = /\s*<meta\s+http-equiv="Content-Security-Policy"\s+content="[^"]+"\s*\/>/u;
  return {
    apply: 'serve',
    name: 'zoneskein-development-style-compatibility',
    transformIndexHtml(html) {
      const matches = html.match(new RegExp(metaPolicy.source, 'gu'));
      if (matches?.length !== 1) {
        throw new Error('Expected exactly one HTML Content Security Policy meta element.');
      }
      return html.replace(metaPolicy, '');
    },
  };
}

export default defineConfig({
  root: repositoryRoot,
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
  plugins: [routeMetadataPages(), react(), developmentStyleCompatibility(), publicDocuments()],
});
