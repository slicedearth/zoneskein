import { decode, encode, type Answer } from '@dnsquery/dns-packet';
import { expect, test, type Page, type Route } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';

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
    const opt = query.additionals?.find((answer) => answer.type === 'OPT') as
      | (Answer & {
          readonly options?: readonly {
            readonly code?: number | string;
            readonly data?: Uint8Array;
            readonly type?: string;
          }[];
        })
      | undefined;
    const padding = opt?.options?.find(
      (option) => option.code === 12 || option.type === 'PADDING',
    );
    if (
      bytes.length % 128 !== 0 ||
      !(padding?.data instanceof Uint8Array) ||
      !padding.data.every((byte) => byte === 0)
    )
      throw new Error('Expected RFC 8467 all-zero query padding.');
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

for (const path of STATIC_ROUTES) {
  test(`${path} loads directly`, async ({ page }) => {
    await page.goto(path);
    await expect(page.locator('main h1')).toBeVisible();
  });
}

test('the shell remains keyboard usable', async ({ page }) => {
  await page.goto('/');
  const theme = page.getByRole('button', {
    name: /Theme: (?:Light|Dark)/u,
  });
  const initialText = await theme.innerText();
  await theme.focus();
  await page.keyboard.press('Enter');
  await expect(theme).not.toHaveText(initialText);
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
  await page.getByText('Protocol details', { exact: true }).click();
  await expect(page.getByText('56 bytes')).toBeVisible();
});

test('evidence map renders an explorable graph from bounded DNS observations', async ({
  page,
}) => {
  await mockDns(page);
  await page.goto('/map/');
  await page.getByLabel('DNS name').fill('example.com');
  await page.getByRole('button', { name: 'Build evidence map' }).click();

  await expect(page.getByText(/nodes and .* relationships mapped/u)).toBeVisible();
  const graph = page.locator('svg.evidence-graph');
  await expect(graph).toBeVisible();
  const addressNode = graph.getByRole('button', { name: /record: A .*192\.0\.2\.25/u });
  await addressNode.focus();
  await page.keyboard.press('Enter');
  await expect(addressNode).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByRole('heading', { name: /A .*192\.0\.2\.25/u })).toBeVisible();
  await page.getByRole('button', { name: 'Reset view' }).click();
  await page.getByText(/Accessible evidence tables/u).click();
  await expect(page.getByRole('region', { name: 'Evidence graph data' })).toBeVisible();
});

test('protocol lab decodes an ECH configuration entirely locally', async ({ page }) => {
  await page.goto('/protocol/');
  await page.getByRole('button', { name: 'ECH decoder' }).click();
  await page
    .getByLabel('ECHConfigList values')
    .fill('ACL+DQAeACAAAqq7AAQAAQABQA5wdWJsaWMuZXhhbXBsZQAA');
  await page.getByRole('button', { name: 'Decode ECH' }).click();

  await expect(page.getByRole('heading', { name: 'ECH configurations' })).toBeVisible();
  await expect(page.getByText('public.example', { exact: true })).toBeVisible();
  await expect(page.getByText('KDF 1 / AEAD 1', { exact: true })).toBeVisible();
});

test('mail imports a gzip report through a local worker without network disclosure', async ({
  page,
}) => {
  const externalRequests: string[] = [];
  const failures: string[] = [];
  page.on('pageerror', (error) => failures.push(error.message));
  await page.route(/^https:\/\//u, async (route) => {
    externalRequests.push(route.request().url());
    await route.abort();
  });
  await page.goto('/mail/');
  const workerStarted = page.waitForEvent('worker');
  await page.locator('#mail-report-files').setInputFiles({
    name: 'local-report.json.gz',
    mimeType: 'application/gzip',
    buffer: gzipSync(
      Buffer.from(
        JSON.stringify({
          'organization-name': 'Local fixture receiver',
          'report-id': 'worker-fixture',
          policies: [
            {
              policy: { 'policy-domain': 'example.com', 'policy-type': 'sts' },
              summary: {
                'total-successful-session-count': 11,
                'total-failure-session-count': 2,
              },
            },
          ],
        }),
      ),
    ),
  });
  expect((await workerStarted).url()).toContain('/assets/report-archive-worker-');
  await expect(
    page.getByRole('heading', { name: 'Delivery evidence', exact: true }),
  ).toBeVisible();
  await expect(page.getByText('Local fixture receiver', { exact: true })).toBeVisible();
  expect(externalRequests).toEqual([]);
  expect(failures).toEqual([]);
});

test('mail lab checks transport policy entirely locally', async ({ page }) => {
  await page.goto('/mail/');
  await page.getByRole('button', { name: 'Transport policy' }).click();
  await page
    .getByLabel('MTA-STS policy')
    .fill('version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800');
  await page.getByLabel('Published MX hosts').fill('mail.example.com');
  await page.getByLabel('TLS-RPT TXT value').fill('v=TLSRPTv1; rua=mailto:reports@example.com');
  await page.getByRole('button', { name: 'Check transport policy' }).click();

  await expect(page.getByRole('heading', { name: 'Mail transport policy' })).toBeVisible();
  const tlsPanel = page.locator('article.result-panel').filter({
    has: page.getByRole('heading', { name: 'TLS-RPT' }),
  });
  await expect(tlsPanel.locator('.status-badge')).toContainText('syntax valid');
  await expect(page.locator('.diagnostic-list .status-badge')).toContainText('covered');
});

test('delegation lab models a DNSSEC lifecycle without a network request', async ({ page }) => {
  await page.goto('/delegation/');
  await page.getByRole('button', { name: 'DNSSEC lifecycle' }).click();
  await page
    .getByLabel('DNSSEC and delegation records')
    .fill('$ORIGIN example.com.\n@ 3600 IN DNSKEY 257 3 13 AQIDBAUGBwg=');
  await page.getByRole('button', { name: 'Model lifecycle' }).click();

  await expect(page.getByRole('heading', { name: 'DNSSEC lifecycle' })).toBeVisible();
  await expect(page.getByText('KSK', { exact: true })).toBeVisible();
  await page.getByText('Derived SHA-256 and SHA-384 DS candidates').click();
  await expect(page.getByRole('region', { name: 'Derived DS candidates' })).toBeVisible();
});

test('zone exchange safely previews a local service template', async ({ page }) => {
  await page.goto('/zone-exchange/');
  await page.getByRole('button', { name: 'Service template' }).click();
  await page.getByRole('button', { name: 'Load safe example' }).click();
  await page.getByRole('button', { name: 'Preview records' }).click();

  await expect(page.getByRole('heading', { name: 'Instantiated record plan' })).toBeVisible();
  await expect(page.getByText('service.example / website', { exact: true })).toBeVisible();
  await expect(page.locator('pre.record-value')).toContainText('192.0.2.10');
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
  await page.getByRole('button', { name: 'Lint zone input' }).click();

  await expect(page.getByText(/Parsed 2 records and produced/)).toBeVisible();
  await expect(page.getByText('cname-conflict')).toBeVisible();
});

test('record studio builds and lints a modern service record locally', async ({ page }) => {
  await page.goto('/studio/');
  await page.getByLabel('Owner name').fill('service.example.com.');
  await page.getByLabel('Record type').selectOption('HTTPS');
  await page.getByLabel('Target name').fill('.');
  await page.getByLabel('Service parameters').fill('mandatory=alpn,port\nalpn=h2,h3\nport=443');

  await expect(page.getByText('Ready to add').first()).toBeVisible();
  await expect(page.getByText(/IN HTTPS 1 \. mandatory=/u)).toBeVisible();
  await page.getByRole('button', { name: 'Add valid record' }).click();
  const workingSet = page.getByRole('region', { name: 'Working set' });
  await workingSet.getByRole('button', { name: 'Lint working set' }).click();
  await expect(workingSet.getByText('No diagnostics')).toBeVisible();
});

test('change comparison builds a risk-aware staged rollout', async ({ page }) => {
  await page.goto('/diff/');
  await page
    .getByLabel('Current or earlier snapshot')
    .fill('@ 3600 IN MX 10 old-mail.example.net.');
  await page
    .getByLabel('Proposed or later snapshot')
    .fill('@ 300 IN MX 10 new-mail.example.net.');
  await page.getByLabel('Origin for relative names').fill('example.com');
  await page.getByRole('button', { name: 'Compare snapshots' }).click();

  const planPanel = page.locator('article.change-plan-summary');
  await expect(
    planPanel.getByRole('heading', { name: 'Preflight and rollout plan' }),
  ).toBeVisible();
  await expect(planPanel.locator('.status-badge')).toContainText('high risk');
  await expect(page.getByText('3600 seconds', { exact: true })).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'Publish in dependency order' }),
  ).toBeVisible();
});

test('offline examples require explicit replacement and keep uncertainty visible', async ({
  page,
}) => {
  await page.goto('/workspace/');
  await page.getByText('Try a synthetic offline example', { exact: true }).click();
  expect(
    await page
      .getByLabel('Example scenario')
      .evaluate((element) => element.getBoundingClientRect().height),
  ).toBeGreaterThanOrEqual(44);
  await page.getByLabel('Example scenario').selectOption('incomplete');
  await page.getByRole('button', { name: 'Prepare offline example' }).click();
  await expect(page.getByRole('heading', { name: 'Import ready for review' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Untitled change workspace' })).toBeVisible();
  await page.getByRole('button', { name: 'Replace active workspace' }).click();
  await expect(
    page.getByRole('heading', { name: 'Synthetic: Incomplete resolver evidence' }),
  ).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'Synthetic: Incomplete resolver evidence' }),
  ).toBeFocused();
  await expect(
    page.locator('.status-badge').filter({ hasText: 'Overall risk unknown' }),
  ).toBeVisible();
  await page.getByLabel('Workspace title').fill('Pending local edit');
  await expect(page.getByRole('button', { name: 'Export JSON', exact: true })).toBeDisabled();
  await expect(page.getByText(/Unapplied edits\. Apply them/u)).toBeVisible();
  await page.getByRole('button', { name: 'Apply edits' }).click();
  await expect(page.getByRole('button', { name: 'Export JSON', exact: true })).toBeEnabled();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export validation report' }).click();
  const reportDownload = await download;
  expect(reportDownload.suggestedFilename()).toBe(
    'zoneskein-pending-local-edit.validation.json',
  );
  const reportPath = await reportDownload.path();
  const report: unknown = JSON.parse(await readFile(reportPath, 'utf8'));
  expect(report).toMatchObject({
    format: 'zoneskein-workspace-validation-report-v1',
    workspaceSchema: 'zoneskein-project-v1',
    build: {
      revision: expect.stringMatching(/^[a-f0-9]{40}$/u),
      sourceSha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
    },
    validation: {
      schema: 'validated',
      integrity: 'fresh-internal-consistency-digest',
      authenticity: 'not-established',
      analysisSource: 'supplied-or-prior-analysis-not-recomputed',
    },
  });
});

test('change workspace keeps unavailable records unknown and edits locally', async ({
  page,
}) => {
  await page.goto('/workspace/');

  await expect(page.getByText(/absence is not treated as an empty zone/iu)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Reanalyse' })).toBeDisabled();
  await page.getByLabel('Workspace title').fill('Mail migration');
  await page
    .getByRole('group', { name: 'Current zone state' })
    .getByLabel('Availability')
    .selectOption('complete');
  await page
    .getByLabel('Current BIND-style zone text')
    .fill('@ 3600 IN MX 10 old-mail.example.net.');
  await page
    .getByRole('group', { name: 'Intended zone state' })
    .getByLabel('Availability')
    .selectOption('complete');
  await page
    .getByLabel('Intended BIND-style zone text')
    .fill('@ 300 IN MX 10 new-mail.example.net.');
  await page.getByLabel('Current origin (optional)').fill('example.com');
  await page.getByLabel('Intended origin (optional)').fill('example.com');
  await page.getByRole('button', { name: 'Apply edits' }).click();
  await page.getByRole('button', { name: 'Reanalyse' }).click();

  await expect(page.getByRole('heading', { name: 'Mail migration' })).toBeVisible();
  await expect(page.getByText('Analysed changes')).toBeVisible();
  await expect(page.getByText('3600 seconds', { exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Staged rollout' })).toBeVisible();
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
  await page.getByRole('button', { name: 'Disable and erase all' }).click();

  await expect(
    page.getByText('Local snapshots and the opt-in preference were erased.'),
  ).toBeVisible();
  await expect(page.getByRole('button', { name: 'Enable local snapshots' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Local test report' })).toHaveCount(0);
});
