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
  plugins: [react(), developmentStyleCompatibility(), publicDocuments()],
});
