import AxeBuilder from '@axe-core/playwright';
import { decode, encode } from '@dnsquery/dns-packet';
import { expect, test, type Page, type Route } from '@playwright/test';

const STATIC_ROUTES = [
  '/',
  '/lookup/',
  '/dnssec/',
  '/spf/',
  '/zone-lint/',
  '/studio/',
  '/diff/',
  '/workspace/',
  '/dmarc/',
  '/dkim/',
  '/caa/',
  '/snapshots/',
  '/about/',
] as const;

const REFLOW_WIDTHS = [320, 375, 768, 821, 1024, 1280] as const;

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

async function mockLongTxtAnswer(page: Page): Promise<void> {
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
    const response = encode({
      answers: [
        {
          class: 'IN' as const,
          data: [`site-verification=${'bounded-dns-evidence-'.repeat(8)}end`],
          name: question.name,
          ttl: 300,
          type: 'TXT' as const,
        },
      ],
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

function summariseViolations(
  violations: readonly { id: string; nodes: readonly { target: unknown }[] }[],
): string {
  return violations
    .map(
      (violation) =>
        `${violation.id}: ${violation.nodes.map((node) => JSON.stringify(node.target)).join(', ')}`,
    )
    .join('\n');
}

for (const route of STATIC_ROUTES) {
  test(`${route} has no detectable WCAG A or AA violations`, async ({ page }) => {
    await page.goto(route);
    await expect(page.locator('main h1')).toBeVisible();

    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
      .analyze();

    expect(results.violations, summariseViolations(results.violations)).toEqual([]);
  });
}

test('every static route reflows without document-level horizontal scrolling', async ({
  page,
}) => {
  for (const width of REFLOW_WIDTHS) {
    await page.setViewportSize({ height: 900, width });
    for (const route of STATIC_ROUTES) {
      await page.goto(route);
      await expect(page.locator('main h1')).toBeVisible();
      const dimensions = await page.evaluate(() => ({
        clientWidth: document.documentElement.clientWidth,
        scrollWidth: document.documentElement.scrollWidth,
      }));
      expect(
        dimensions.scrollWidth,
        `${route} overflowed at ${String(width)} CSS pixels`,
      ).toBeLessThanOrEqual(dimensions.clientWidth + 1);
    }
  }
});

test('a populated lookup remains accessible and bounded across target widths', async ({
  page,
}) => {
  await mockLongTxtAnswer(page);
  await page.setViewportSize({ height: 900, width: 375 });
  await page.goto('/lookup/');

  await expect(page.getByRole('status')).toHaveCount(1);
  for (const type of ['A', 'AAAA', 'MX']) {
    await page.getByRole('checkbox', { name: type, exact: true }).uncheck();
  }
  await page
    .getByLabel('DNS name')
    .fill('long-owner-label.long-owner-label.long-owner-label.example.com');
  await page.getByRole('button', { name: 'Inspect records' }).click();
  await expect(page.getByText('Completed 1 DNS questions.')).toBeVisible();

  const tableRegion = page.locator('.table-scroll').first();
  await expect(tableRegion).toHaveAttribute('aria-label', /\S/u);
  await expect(tableRegion).toHaveAttribute('tabindex', '0');
  await tableRegion.focus();
  await expect(tableRegion).toBeFocused();

  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();
  expect(results.violations, summariseViolations(results.violations)).toEqual([]);

  for (const width of REFLOW_WIDTHS) {
    await page.setViewportSize({ height: 900, width });
    const dimensions = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(
      dimensions.scrollWidth,
      `populated lookup overflowed at ${String(width)} CSS pixels`,
    ).toBeLessThanOrEqual(dimensions.clientWidth + 1);
    const tableDimensions = await tableRegion.evaluate((element) => ({
      clientWidth: element.clientWidth,
      scrollWidth: element.scrollWidth,
    }));
    expect(
      tableDimensions.scrollWidth,
      `record table overflowed at ${String(width)} CSS pixels`,
    ).toBeLessThanOrEqual(tableDimensions.clientWidth + 1);
    const navigationTargetHeights = await page
      .locator('.primary-nav > a, .primary-nav > .nav-group > summary')
      .evaluateAll((elements) =>
        elements.map((element) => element.getBoundingClientRect().height),
      );
    expect(navigationTargetHeights).toHaveLength(4);
    expect(
      navigationTargetHeights.every((height) => height >= 43.5),
      `primary navigation targets were too short at ${String(width)} CSS pixels`,
    ).toBe(true);
  }
});

test('the keyboard skip link moves focus to the main content', async ({ page }) => {
  await page.goto('/');
  await page.keyboard.press('Tab');

  const skipLink = page.getByRole('link', { name: 'Skip to main content' });
  await expect(skipLink).toBeFocused();
  await expect(skipLink).toBeVisible();
  await page.keyboard.press('Enter');
  await expect(page.locator('#main-content')).toBeFocused();
});

test('forced colours preserve visible controls and focus', async ({ page }) => {
  await page.emulateMedia({ forcedColors: 'active', reducedMotion: 'reduce' });
  await page.goto('/lookup/');

  const input = page.getByLabel('DNS name');
  await input.focus();
  await expect(input).toBeFocused();
  await expect(input).toBeVisible();
  await expect(page.getByRole('button', { name: 'Inspect records' })).toBeVisible();

  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
    .analyze();
  expect(results.violations, summariseViolations(results.violations)).toEqual([]);
});
