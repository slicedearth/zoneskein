import type { ResolverDefinition, ResolverId } from '../dns/types';

export const RESOLVERS: Readonly<Record<ResolverId, ResolverDefinition>> = {
  cloudflare: {
    endpoint: 'https://cloudflare-dns.com/dns-query',
    httpMethod: 'POST',
    id: 'cloudflare',
    label: 'Cloudflare 1.1.1.1',
    privacyUrl: 'https://www.cloudflare.com/privacypolicy/',
  },
  google: {
    endpoint: 'https://dns.google/dns-query',
    httpMethod: 'GET',
    id: 'google',
    label: 'Google Public DNS',
    privacyUrl: 'https://developers.google.com/speed/public-dns/privacy',
  },
  quad9: {
    endpoint: 'https://dns.quad9.net/dns-query',
    httpMethod: 'GET',
    id: 'quad9',
    label: 'Quad9 (direct)',
    privacyUrl: 'https://quad9.net/privacy/policy/',
    transportNote:
      'Quad9 requires an end-to-end HTTP/2 or HTTP/3 DNS-over-HTTPS path. A browser, VPN, or inspection proxy that downgrades the request to HTTP/1.1 can make Quad9 unavailable on that path; choose another resolver or a compatible network path.',
  },
  'quad9-relay': {
    endpoint: '/api/doh/quad9',
    httpMethod: 'POST',
    id: 'quad9-relay',
    label: 'Quad9 (compatibility mode)',
    privacyUrl: 'https://www.netlify.com/privacy/',
    relay: {
      operator: 'Netlify',
      upstreamEndpoint: 'https://dns.quad9.net/dns-query',
      upstreamLabel: 'Quad9',
      upstreamPrivacyUrl: 'https://quad9.net/privacy/policy/',
    },
    selectionNote:
      'Compatibility relay mode sends the DNS question and connection metadata to Netlify before the fixed Quad9 upstream. It is never selected as a silent fallback.',
    transportNote: 'The ZoneSkein compatibility relay could not return a valid Quad9 response.',
  },
};

export function resolverById(id: ResolverId): ResolverDefinition {
  return RESOLVERS[id];
}
