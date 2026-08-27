import AxeBuilder from '@axe-core/playwright';
import { decode, encode } from '@dnsquery/dns-packet';
import { expect, test, type Page, type Route } from '@playwright/test';

const STATIC_ROUTES = [
  '/',
  '/lookup/',
  '/map/',
  '/delegation/',
  '/dnssec/',
  '/protocol/',
  '/spf/',
  '/mail/',
  '/zone-lint/',
  '/zone-exchange/',
  '/studio/',
  '/diff/',
  '/workspace/',
  '/dmarc/',
  '/dkim/',
  '/caa/',
  '/snapshots/',
  '/about/',
  '/licence/',
  '/privacy/',
  '/security/',
  '/source/',
  '/source-checksum/',
  '/terms/',
  '/third-party-notices/',
  '/trademarks/',
] as const;

const REFLOW_WIDTHS = [305, 320, 375, 768, 821, 1024, 1280] as const;

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

test('a populated evidence graph remains accessible and reflows at target widths', async ({
  page,
}) => {
  await mockLongTxtAnswer(page);
  await page.goto('/map/');
  await page.getByLabel('DNS name').fill('example.com');
  await page.getByRole('button', { name: 'Build evidence map' }).click();
  await expect(page.getByText(/nodes and .* relationships mapped/u)).toBeVisible();

  const graph = page.locator('svg.evidence-graph');
  const firstNode = graph.getByRole('button').first();
  await firstNode.focus();
  await page.keyboard.press('Enter');
  await expect(firstNode).toHaveAttribute('aria-pressed', 'true');

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
      `populated evidence graph overflowed at ${String(width)} CSS pixels`,
    ).toBeLessThanOrEqual(dimensions.clientWidth + 1);
  }
});

test('maximum-length local content remains bounded on narrow screens', async ({ page }) => {
  for (const width of [320, 390]) {
    await page.setViewportSize({ height: 900, width });
    await page.goto('/workspace/');
    await page.getByLabel('Workspace title').fill('W'.repeat(120));
    await page.getByRole('button', { name: 'Apply edits' }).click();
    await expect(page.getByRole('heading', { name: 'W'.repeat(120) })).toBeVisible();

    const dimensions = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(
      dimensions.scrollWidth,
      `maximum workspace content overflowed at ${String(width)} CSS pixels`,
    ).toBeLessThanOrEqual(dimensions.clientWidth + 1);
  }
});

test('WCAG text spacing does not create horizontal document scrolling', async ({ page }) => {
  await page.setViewportSize({ height: 900, width: 320 });
  await page.goto('/lookup/');
  const appliedSpacing = await page.evaluate(() => {
    for (const element of document.querySelectorAll<HTMLElement>('*')) {
      element.style.setProperty('line-height', '1.5', 'important');
      element.style.setProperty('letter-spacing', '0.12em', 'important');
      element.style.setProperty('word-spacing', '0.16em', 'important');
      if (element.tagName === 'P')
        element.style.setProperty('margin-bottom', '2em', 'important');
    }
    const body = getComputedStyle(document.body);
    return {
      letterSpacing: body.letterSpacing,
      lineHeight: body.lineHeight,
      wordSpacing: body.wordSpacing,
    };
  });
  expect(appliedSpacing).toEqual({
    letterSpacing: '1.92px',
    lineHeight: '24px',
    wordSpacing: '2.56px',
  });

  const dimensions = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth + 1);
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

for (const theme of ['light', 'dark'] as const) {
  test(`forced colours preserve visible controls and focus in ${theme} mode`, async ({
    page,
  }) => {
    await page.emulateMedia({ forcedColors: 'active', reducedMotion: 'reduce' });
    await page.goto('/lookup/');
    const themeControl = page.getByRole('button', {
      name: /Theme: (?:Light|Dark)/u,
    });
    if ((await page.locator('html').getAttribute('data-theme')) !== theme) {
      await themeControl.click();
    }

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
}
