import { defineConfig, devices } from '@playwright/test';

const isCI = Boolean(process.env['CI']);

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  failOnFlakyTests: isCI,
  forbidOnly: isCI,
  retries: isCI ? 1 : 0,
  workers: 2,
  reporter: isCI
    ? [
        ['list'],
        ['github'],
        ['json', { outputFile: 'playwright-results.json' }],
        ['html', { open: 'never' }],
      ]
    : 'list',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      testIgnore: /accessibility\.spec\.ts/u,
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      testIgnore: /accessibility\.spec\.ts/u,
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      testIgnore: /accessibility\.spec\.ts/u,
      use: { ...devices['Desktop Safari'] },
    },
    {
      name: 'mobile-chromium',
      testIgnore: /accessibility\.spec\.ts/u,
      use: { ...devices['Pixel 7'] },
    },
    {
      name: 'accessibility-chromium',
      testMatch: /accessibility\.spec\.ts/u,
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: 'npm run build && npm run preview -- --host 127.0.0.1',
    reuseExistingServer: !isCI,
    timeout: 120_000,
    url: 'http://127.0.0.1:4173',
  },
});
