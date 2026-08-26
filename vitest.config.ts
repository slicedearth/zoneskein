import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  test: {
    coverage: {
      exclude: ['src/main.tsx', 'src/test/**'],
      provider: 'v8',
      reporter: ['text', 'html'],
      thresholds: {
        branches: 72,
        functions: 85,
        lines: 84,
        statements: 80,
      },
    },
    environment: 'jsdom',
    environmentOptions: {
      jsdom: { url: 'https://zoneskein.test/' },
    },
    include: ['src/**/*.test.{ts,tsx}', 'tests/{build,functions}/**/*.test.ts'],
    restoreMocks: true,
    setupFiles: ['./src/test/setup.ts'],
  },
});
