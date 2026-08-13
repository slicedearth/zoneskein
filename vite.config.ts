import { readFileSync } from 'node:fs';

import react from '@vitejs/plugin-react';
import { defineConfig, type Plugin } from 'vite';

function legalAssets(): Plugin {
  const files = ['LICENSE', 'THIRD_PARTY_NOTICES.md'] as const;
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
    name: 'zoneskein-legal-assets',
  };
}

export default defineConfig({
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
  plugins: [react(), legalAssets()],
});
