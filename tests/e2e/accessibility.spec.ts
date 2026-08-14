import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

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
  await page.setViewportSize({ height: 800, width: 320 });

  for (const route of STATIC_ROUTES) {
    await page.goto(route);
    await expect(page.locator('main h1')).toBeVisible();
    const dimensions = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(dimensions.scrollWidth, `${route} overflowed at 320 CSS pixels`).toBeLessThanOrEqual(
      dimensions.clientWidth + 1,
    );
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
