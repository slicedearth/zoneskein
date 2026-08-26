export const SITE_ORIGIN = 'https://www.zoneskein.com';
export const SOCIAL_IMAGE_URL = `${SITE_ORIGIN}/social-card.jpg`;

export interface SeoRoute {
  readonly description: string;
  readonly path: string;
  readonly sitemap: boolean;
  readonly title: string;
}

export const SEO_ROUTES = [
  {
    description:
      'Inspect DNS evidence, analyse email policy, lint zone snippets, and review changes before publishing.',
    path: '',
    sitemap: true,
    title: 'ZoneSkein — Untangle DNS.',
  },
  {
    description:
      'Explore ZoneSkein’s privacy-conscious DNS inspection, validation, authoring, and change-review tools.',
    path: 'about',
    sitemap: true,
    title: 'About — ZoneSkein',
  },
  {
    description:
      'Inspect effective CAA certificate-issuance policy through aliases and parent labels, then author records locally.',
    path: 'caa',
    sitemap: true,
    title: 'CAA inspection — ZoneSkein',
  },
  {
    description:
      'Compare DNS zone states, separate material and TTL-only changes, and prepare bounded rollout and rollback guidance.',
    path: 'diff',
    sitemap: true,
    title: 'Change Lab — ZoneSkein',
  },
  {
    description:
      'Inspect DKIM selector records or verify bounded RSA-SHA256 and Ed25519-SHA256 signatures locally in the browser.',
    path: 'dkim',
    sitemap: true,
    title: 'DKIM inspection — ZoneSkein',
  },
  {
    description:
      'Discover DMARC policy, assess identifier alignment, and inspect external aggregate-report authorisation evidence.',
    path: 'dmarc',
    sitemap: true,
    title: 'DMARC analysis — ZoneSkein',
  },
  {
    description:
      'Validate selected DNSSEC trust chains in the browser from bundled root trust anchors to application records.',
    path: 'dnssec',
    sitemap: true,
    title: 'DNSSEC inspection — ZoneSkein',
  },
  {
    description:
      'Query and compare bounded DNS wire evidence from Google Public DNS, Cloudflare 1.1.1.1, and Quad9.',
    path: 'lookup',
    sitemap: true,
    title: 'DNS record lookup — ZoneSkein',
  },
  {
    description: 'Read the GNU AGPL-3.0-only software licence that applies to ZoneSkein.',
    path: 'licence',
    sitemap: true,
    title: 'Software licence — ZoneSkein',
  },
  {
    description:
      'Read how ZoneSkein handles DNS questions, local inputs, browser storage, exports, and the Quad9 relay boundary.',
    path: 'privacy',
    sitemap: true,
    title: 'Privacy — ZoneSkein',
  },
  {
    description:
      'Review ZoneSkein’s security model, abuse controls, vulnerability-reporting process, and deployment responsibilities.',
    path: 'security',
    sitemap: true,
    title: 'Security — ZoneSkein',
  },
  {
    description:
      'Download and verify the exact corresponding source offered for the deployed ZoneSkein build.',
    path: 'source',
    sitemap: true,
    title: 'Corresponding source — ZoneSkein',
  },
  {
    description:
      'Read the deployed SHA-256 checksum for ZoneSkein’s corresponding-source archive.',
    path: 'source-checksum',
    sitemap: false,
    title: 'Source archive checksum — ZoneSkein',
  },
  {
    description:
      'Opt in to bounded browser-local DNS evidence snapshots, inspect saved reports, and erase them explicitly.',
    path: 'snapshots',
    sitemap: true,
    title: 'Local snapshots — ZoneSkein',
  },
  {
    description:
      'Trace SPF includes, redirects, address paths, protocol limits, and sender-context evaluation evidence.',
    path: 'spf',
    sitemap: true,
    title: 'SPF analysis — ZoneSkein',
  },
  {
    description:
      'Author and validate common DNS records locally, then carry a bounded working set into change review.',
    path: 'studio',
    sitemap: true,
    title: 'Record Studio — ZoneSkein',
  },
  {
    description:
      'Read the acceptable-use, third-party service, evidence, warranty, and hosted-service terms for ZoneSkein.',
    path: 'terms',
    sitemap: true,
    title: 'Hosted service terms — ZoneSkein',
  },
  {
    description:
      'Review licences and notices for third-party packages distributed with ZoneSkein.',
    path: 'third-party-notices',
    sitemap: true,
    title: 'Third-party notices — ZoneSkein',
  },
  {
    description: 'Read the trade-mark and project-branding notice for ZoneSkein.',
    path: 'trademarks',
    sitemap: true,
    title: 'Trade-marks — ZoneSkein',
  },
  {
    description:
      'Keep current and intended DNS states, analysis, timing, rollback guidance, and resolver evidence in one local workspace.',
    path: 'workspace',
    sitemap: true,
    title: 'Change Workspace — ZoneSkein',
  },
  {
    description:
      'Lint bounded BIND-style zone snippets for syntax, record-shape, and cross-record conflicts before publication.',
    path: 'zone-lint',
    sitemap: true,
    title: 'Zone Lint — ZoneSkein',
  },
] as const satisfies readonly SeoRoute[];

export const STRUCTURED_DATA_JSON = JSON.stringify({
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@id': `${SITE_ORIGIN}/#website`,
      '@type': 'WebSite',
      description:
        'A static-first workbench for following DNS evidence from question to change plan.',
      inLanguage: 'en-AU',
      name: 'ZoneSkein',
      url: `${SITE_ORIGIN}/`,
    },
    {
      '@id': `${SITE_ORIGIN}/#application`,
      '@type': 'WebApplication',
      applicationCategory: 'DeveloperApplication',
      browserRequirements: 'Requires JavaScript, Web Crypto, and DNS-over-HTTPS support.',
      description:
        'Inspect DNS evidence, validate selected DNSSEC chains, analyse mail policy, author records, and review changes locally.',
      image: SOCIAL_IMAGE_URL,
      isAccessibleForFree: true,
      license: `${SITE_ORIGIN}/licence/`,
      name: 'ZoneSkein',
      offers: {
        '@type': 'Offer',
        price: '0',
        priceCurrency: 'AUD',
      },
      operatingSystem: 'Any operating system with a supported web browser',
      url: `${SITE_ORIGIN}/`,
    },
  ],
});

const ROUTES_BY_PATH = new Map<string, SeoRoute>(
  SEO_ROUTES.map((route) => [route.path, route]),
);

export function normaliseSeoPath(path: string): string {
  return path.replace(/[?#].*$/u, '').replace(/^\/+|\/+$/gu, '');
}

export function seoRoute(path: string): SeoRoute | undefined {
  return ROUTES_BY_PATH.get(normaliseSeoPath(path));
}

export function canonicalUrl(route: SeoRoute): string {
  return route.path === '' ? `${SITE_ORIGIN}/` : `${SITE_ORIGIN}/${route.path}/`;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

export function renderSeoHead(route: SeoRoute): string {
  const url = canonicalUrl(route);
  const title = escapeHtml(route.title);
  const description = escapeHtml(route.description);
  const robots = route.sitemap
    ? 'index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1'
    : 'noindex, follow';
  const structuredData =
    route.path === ''
      ? `<script id="zoneskein-structured-data" type="application/ld+json">${STRUCTURED_DATA_JSON}</script>`
      : '';
  return [
    '<meta data-zoneskein-seo="start" name="application-name" content="ZoneSkein" />',
    `<title>${title}</title>`,
    `<meta name="description" content="${description}" />`,
    `<meta name="robots" content="${robots}" />`,
    `<link rel="canonical" href="${url}" />`,
    '<meta property="og:locale" content="en_AU" />',
    '<meta property="og:site_name" content="ZoneSkein" />',
    '<meta property="og:type" content="website" />',
    `<meta property="og:title" content="${title}" />`,
    `<meta property="og:description" content="${description}" />`,
    `<meta property="og:url" content="${url}" />`,
    `<meta property="og:image" content="${SOCIAL_IMAGE_URL}" />`,
    '<meta property="og:image:width" content="1200" />',
    '<meta property="og:image:height" content="630" />',
    '<meta property="og:image:type" content="image/jpeg" />',
    '<meta property="og:image:alt" content="ZoneSkein interwoven Z and S mark beside the words Untangle DNS" />',
    '<meta name="twitter:card" content="summary_large_image" />',
    `<meta name="twitter:title" content="${title}" />`,
    `<meta name="twitter:description" content="${description}" />`,
    `<meta name="twitter:image" content="${SOCIAL_IMAGE_URL}" />`,
    structuredData,
    '<meta data-zoneskein-seo="end" name="twitter:image:alt" content="ZoneSkein interwoven Z and S mark beside the words Untangle DNS" />',
  ]
    .filter((line) => line !== '')
    .join('\n    ');
}

const SEO_HEAD_PATTERN =
  /<meta\b[^>]*data-zoneskein-seo="start"[^>]*>[\s\S]*?<meta\b[^>]*data-zoneskein-seo="end"[^>]*>/u;

export function replaceSeoHead(html: string, route: SeoRoute): string {
  if (!SEO_HEAD_PATTERN.test(html)) {
    throw new Error('The built HTML does not contain the complete ZoneSkein SEO block.');
  }
  return html.replace(SEO_HEAD_PATTERN, renderSeoHead(route));
}

function setMetaContent(document: Document, selector: string, content: string): void {
  document.querySelector<HTMLMetaElement>(selector)?.setAttribute('content', content);
}

export function applyDocumentSeo(path: string, document: Document): void {
  const route = seoRoute(path);
  const canonical = document.querySelector<HTMLLinkElement>('link[rel="canonical"]');
  const structuredData = document.querySelector<HTMLScriptElement>(
    '#zoneskein-structured-data',
  );
  if (route === undefined) {
    document.title = 'Page not found — ZoneSkein';
    setMetaContent(
      document,
      'meta[name="description"]',
      'The requested page is not available in ZoneSkein.',
    );
    setMetaContent(document, 'meta[name="robots"]', 'noindex, follow');
    canonical?.remove();
    structuredData?.remove();
    return;
  }

  const url = canonicalUrl(route);
  document.title = route.title;
  setMetaContent(document, 'meta[name="description"]', route.description);
  setMetaContent(
    document,
    'meta[name="robots"]',
    route.sitemap
      ? 'index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1'
      : 'noindex, follow',
  );
  setMetaContent(document, 'meta[property="og:title"]', route.title);
  setMetaContent(document, 'meta[property="og:description"]', route.description);
  setMetaContent(document, 'meta[property="og:url"]', url);
  setMetaContent(document, 'meta[name="twitter:title"]', route.title);
  setMetaContent(document, 'meta[name="twitter:description"]', route.description);

  if (canonical === null) {
    const link = document.createElement('link');
    link.rel = 'canonical';
    link.href = url;
    document.head.append(link);
  } else {
    canonical.href = url;
  }

  if (route.path === '') {
    if (structuredData === null) {
      const script = document.createElement('script');
      script.id = 'zoneskein-structured-data';
      script.type = 'application/ld+json';
      script.textContent = STRUCTURED_DATA_JSON;
      document.head.append(script);
    }
  } else {
    structuredData?.remove();
  }
}

export function sitemapXml(): string {
  const urls = SEO_ROUTES.filter((route) => route.sitemap)
    .map((route) => `  <url><loc>${canonicalUrl(route)}</loc></url>`)
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`;
}
