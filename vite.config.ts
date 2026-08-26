import { readFileSync } from 'node:fs';

import react from '@vitejs/plugin-react';
import { defineConfig, type Plugin } from 'vite';

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
          source: readFileSync(fileName, 'utf8'),
          type: 'asset',
        });
      }
    },
    name: 'zoneskein-public-documents',
  };
}

export default defineConfig({
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
  plugins: [react(), publicDocuments()],
});
