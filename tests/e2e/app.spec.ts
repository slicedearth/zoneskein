import { decode, encode } from '@dnsquery/dns-packet';
import { expect, test, type Page, type Route } from '@playwright/test';

async function allowCors(route: Route): Promise<boolean> {
  if (route.request().method() !== 'OPTIONS') return false;
  await route.fulfill({
    headers: {
      'Access-Control-Allow-Headers': 'content-type',
      'Access-Control-Allow-Methods': 'GET, POST',
      'Access-Control-Allow-Origin': '*',
    },
    status: 204,
  });
  return true;
}

async function mockDns(page: Page): Promise<void> {
  await page.route('**/dns-query*', async (route) => {
    if (await allowCors(route)) return;
    const request = route.request();
    const body = request.postDataBuffer();
    const encoded = new URL(request.url()).searchParams.get('dns');
    const bytes =
      body ??
      (encoded === null
        ? null
        : Buffer.from(encoded.replaceAll('-', '+').replaceAll('_', '/'), 'base64'));
    if (bytes === null) throw new Error('Expected a DNS wire request.');
    const query = decode(new Uint8Array(bytes));
    const question = query.questions?.[0];
    if (question === undefined) throw new Error('Expected one DNS question.');
    const answers =
      question.type === 'A'
        ? [
            {
              class: 'IN' as const,
              data: '192.0.2.25',
              name: question.name,
              ttl: 300,
              type: 'A' as const,
            },
          ]
        : [];
    const response = encode({
      answers,
      flags: 0x8180,
      id: query.id,
      questions: [question],
      type: 'response',
    });
    await route.fulfill({
      body: Buffer.from(response),
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/dns-message',
      },
      status: 200,
    });
  });
}

test('all static routes load directly and the shell remains usable', async ({ page }) => {
  const routes = [
    '/',
    '/lookup/',
    '/dnssec/',
    '/spf/',
    '/zone-lint/',
    '/diff/',
    '/dmarc/',
    '/dkim/',
    '/caa/',
    '/snapshots/',
    '/about/',
  ];
  for (const path of routes) {
    await page.goto(path);
    await expect(page.locator('main h1')).toBeVisible();
  }

  await page.goto('/');
  const theme = page.getByRole('button', { name: /Use (?:light|dark) theme/u });
  const initialName = await theme.getAttribute('aria-label');
  await theme.focus();
  await page.keyboard.press('Enter');
  await expect(theme).not.toHaveAttribute('aria-label', initialName ?? '');
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
  ).toBe(true);
});

test('lookup decodes a mocked DNS wire answer', async ({ page }) => {
  await mockDns(page);
  await page.goto('/lookup/');
  for (const type of ['AAAA', 'MX', 'TXT']) {
    await page.getByRole('checkbox', { name: type, exact: true }).uncheck();
  }
  await page.getByLabel('DNS name').fill('example.com');
  await page.getByRole('button', { name: 'Inspect records' }).click();

  await expect(page.getByText('Completed 1 DNS questions.')).toBeVisible();
  await expect(page.getByText('192.0.2.25', { exact: true })).toBeVisible();
  await expect(page.getByText('56 bytes')).toBeVisible();
});

test('a DNS run can be cancelled while the request is pending', async ({ page }) => {
  let release: (() => void) | undefined;
  await page.route('**/dns-query*', async (route) => {
    if (await allowCors(route)) return;
    await new Promise<void>((resolve) => {
      release = resolve;
    });
    await route.abort('aborted').catch(() => undefined);
  });
  await page.goto('/lookup/');
  for (const type of ['AAAA', 'MX', 'TXT']) {
    await page.getByRole('checkbox', { name: type, exact: true }).uncheck();
  }
  await page.getByLabel('DNS name').fill('example.com');
  await page.getByRole('button', { name: 'Inspect records' }).click();
  await page.getByRole('button', { name: 'Cancel' }).click();

  await expect(page.getByText('The run was cancelled.')).toBeVisible();
  release?.();
});

test('zone linting runs entirely locally', async ({ page }) => {
  await page.goto('/zone-lint/');
  await page.getByLabel('Origin when $ORIGIN is absent').fill('example.com');
  await page
    .getByLabel('Zone snippet')
    .fill('@ 300 IN CNAME target.example.net.\n@ 300 IN A 192.0.2.1');
  await page.getByRole('button', { name: 'Lint snippet' }).click();

  await expect(page.getByText(/Parsed 2 records and produced/)).toBeVisible();
  await expect(page.getByText('cname-conflict')).toBeVisible();
});

test('local snapshots require opt-in and a separate save', async ({ page }) => {
  await page.goto('/snapshots/');
  await expect(page.getByRole('button', { name: 'Save locally' })).toBeDisabled();
  await page.getByRole('button', { name: 'Enable local snapshots' }).click();
  await page.getByLabel('Title').fill('Local test report');
  await page.getByLabel('Report content').fill('example evidence');
  await page.getByRole('button', { name: 'Save locally' }).click();

  await expect(page.getByText('Snapshot saved in this browser.')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Local test report' })).toBeVisible();
});
