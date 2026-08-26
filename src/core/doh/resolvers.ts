import type { DnsResolver, ResolverDefinition, ResolverId } from '../dns/types';
import { Quad9AutoResolver } from './quad9-auto-resolver';
import { WireDnsResolver, type WireResolverDependencies } from './wire-resolver';

export const SELECTABLE_RESOLVER_IDS = [
  'cloudflare',
  'google',
  'quad9',
] as const satisfies readonly ResolverId[];

export type SelectableResolverId = (typeof SELECTABLE_RESOLVER_IDS)[number];

export const RESOLVERS: Readonly<Record<ResolverId, ResolverDefinition>> = {
  cloudflare: {
    endpoint: 'https://cloudflare-dns.com/dns-query',
    httpMethod: 'POST',
    id: 'cloudflare',
    label: 'Cloudflare 1.1.1.1',
    privacyUrl: 'https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/',
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
      'Quad9 requires an end-to-end HTTP/2 or HTTP/3 DNS-over-HTTPS path. A browser, VPN, or inspection proxy that downgrades the request to HTTP/1.1 can make the direct path unavailable.',
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
      'Compatibility mode sends the DNS question and connection metadata to Netlify before the fixed Quad9 upstream. Results identify when this automatic fallback was used.',
    transportNote: 'The ZoneSkein compatibility relay could not return a valid Quad9 response.',
  },
};

export function resolverById(id: ResolverId): ResolverDefinition {
  return RESOLVERS[id];
}

export function resolverOptionLabel(id: SelectableResolverId): string {
  return id === 'quad9' ? 'Quad9' : RESOLVERS[id].label;
}

export function resolverSelectionNote(id: SelectableResolverId): string | undefined {
  if (id !== 'quad9') return RESOLVERS[id].selectionNote ?? RESOLVERS[id].transportNote;
  return 'Quad9 starts with direct browser DNS-over-HTTPS, which requires an end-to-end HTTP/2 or HTTP/3 DNS-over-HTTPS path. A browser, VPN, or inspection proxy that downgrades it to HTTP/1.1 can make the direct path unavailable. If the first direct request has a qualifying transport, timeout, or HTTP failure, this run switches once to the same-origin compatibility relay. Results always identify the path used; compatibility mode lets Netlify observe the DNS question and connection metadata.';
}

export function createDnsResolver(
  id: SelectableResolverId,
  dependencies: WireResolverDependencies = {},
): DnsResolver {
  return id === 'quad9'
    ? new Quad9AutoResolver(RESOLVERS.quad9, RESOLVERS['quad9-relay'], dependencies)
    : new WireDnsResolver(RESOLVERS[id], dependencies);
}
