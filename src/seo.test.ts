import { beforeEach, describe, expect, it } from 'vitest';

import {
  applyDocumentSeo,
  canonicalUrl,
  renderSeoHead,
  replaceSeoHead,
  SEO_ROUTES,
  seoRoute,
  sitemapXml,
  SITE_ORIGIN,
  STRUCTURED_DATA_JSON,
} from './seo';

describe('search metadata', () => {
  beforeEach(() => {
    document.head.innerHTML = renderSeoHead(SEO_ROUTES[0]);
    window.history.replaceState(null, '', '/');
  });

  it('keeps every route unique and canonical on the primary www origin', () => {
    const paths = SEO_ROUTES.map((route) => route.path);
    const titles = SEO_ROUTES.map((route) => route.title);

    expect(new Set(paths).size).toBe(paths.length);
    expect(new Set(titles).size).toBe(titles.length);
    for (const route of SEO_ROUTES) {
      expect(canonicalUrl(route)).toMatch(/^https:\/\/www\.zoneskein\.com\//u);
      expect(canonicalUrl(route)).toMatch(/\/$/u);
      expect(route.description.length).toBeGreaterThan(40);
      expect(route.description.length).toBeLessThanOrEqual(170);
    }
  });

  it('renders home structured data without copying it into route shells', () => {
    const home = renderSeoHead(SEO_ROUTES[0]);
    const lookup = seoRoute('/lookup/');
    if (lookup === undefined) throw new Error('Lookup metadata is missing.');

    expect(home).toContain(STRUCTURED_DATA_JSON);
    const shell = replaceSeoHead(`<head>${home}</head>`, lookup);
    expect(shell).toContain('<title>DNS record lookup — ZoneSkein</title>');
    expect(shell).toContain('href="https://www.zoneskein.com/lookup/"');
    expect(shell).not.toContain('application/ld+json');
  });

  it('updates route metadata and fails closed for an unknown client route', () => {
    applyDocumentSeo('/privacy/', document);

    expect(document.title).toBe('Privacy — ZoneSkein');
    expect(document.querySelector('link[rel="canonical"]')).toHaveAttribute(
      'href',
      `${SITE_ORIGIN}/privacy/`,
    );
    expect(document.querySelector('meta[property="og:url"]')).toHaveAttribute(
      'content',
      `${SITE_ORIGIN}/privacy/`,
    );
    expect(document.querySelector('#zoneskein-structured-data')).toBeNull();

    applyDocumentSeo('/missing/', document);
    expect(document.title).toBe('Page not found — ZoneSkein');
    expect(document.querySelector('meta[name="robots"]')).toHaveAttribute(
      'content',
      'noindex, follow',
    );
    expect(document.querySelector('link[rel="canonical"]')).toBeNull();

    applyDocumentSeo('/', document);
    expect(document.querySelector('link[rel="canonical"]')).toHaveAttribute(
      'href',
      `${SITE_ORIGIN}/`,
    );
    expect(document.querySelector('#zoneskein-structured-data')?.textContent).toBe(
      STRUCTURED_DATA_JSON,
    );
  });

  it('publishes exactly the indexable canonical routes in the sitemap', () => {
    const sitemap = sitemapXml();
    for (const route of SEO_ROUTES) {
      expect(sitemap.includes(`<loc>${canonicalUrl(route)}</loc>`)).toBe(route.sitemap);
    }
    expect(sitemap.match(/<url>/gu)).toHaveLength(
      SEO_ROUTES.filter((route) => route.sitemap).length,
    );
    const checksum = seoRoute('/source-checksum/');
    if (checksum === undefined) throw new Error('Checksum metadata is missing.');
    expect(renderSeoHead(checksum)).toContain('name="robots" content="noindex, follow"');
  });
});
