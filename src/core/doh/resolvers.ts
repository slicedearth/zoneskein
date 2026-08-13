import type { ResolverDefinition, ResolverId } from '../dns/types';

export const RESOLVERS: Readonly<Record<ResolverId, ResolverDefinition>> = {
  cloudflare: {
    endpoint: 'https://cloudflare-dns.com/dns-query',
    id: 'cloudflare',
    label: 'Cloudflare 1.1.1.1',
    privacyUrl: 'https://www.cloudflare.com/privacypolicy/',
  },
  google: {
    endpoint: 'https://dns.google/dns-query',
    id: 'google',
    label: 'Google Public DNS',
    privacyUrl: 'https://developers.google.com/speed/public-dns/privacy',
  },
  quad9: {
    endpoint: 'https://dns.quad9.net/dns-query',
    id: 'quad9',
    label: 'Quad9',
    privacyUrl: 'https://quad9.net/privacy/policy/',
  },
};

export function resolverById(id: ResolverId): ResolverDefinition {
  return RESOLVERS[id];
}
