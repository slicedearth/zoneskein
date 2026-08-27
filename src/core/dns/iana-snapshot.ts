export const IANA_DNS_PARAMETER_SNAPSHOT = Object.freeze({
  registryLastUpdated: '2026-08-24',
  reviewedAt: '2026-08-27',
  source: 'https://www.iana.org/assignments/dns-parameters',
  recordTypes: Object.freeze([
    { code: 1, name: 'A', purpose: 'IPv4 address' },
    { code: 2, name: 'NS', purpose: 'Authoritative server' },
    { code: 5, name: 'CNAME', purpose: 'Canonical-name alias' },
    { code: 6, name: 'SOA', purpose: 'Start of authority' },
    { code: 15, name: 'MX', purpose: 'Mail exchange' },
    { code: 16, name: 'TXT', purpose: 'Text strings' },
    { code: 28, name: 'AAAA', purpose: 'IPv6 address' },
    { code: 33, name: 'SRV', purpose: 'Service location' },
    { code: 43, name: 'DS', purpose: 'Delegation signer' },
    { code: 46, name: 'RRSIG', purpose: 'DNSSEC signature' },
    { code: 47, name: 'NSEC', purpose: 'Authenticated denial' },
    { code: 48, name: 'DNSKEY', purpose: 'DNSSEC public key' },
    { code: 50, name: 'NSEC3', purpose: 'Hashed authenticated denial' },
    { code: 52, name: 'TLSA', purpose: 'TLS certificate association' },
    { code: 59, name: 'CDS', purpose: 'Child delegation signer' },
    { code: 60, name: 'CDNSKEY', purpose: 'Child DNSKEY' },
    { code: 62, name: 'CSYNC', purpose: 'Child-to-parent synchronisation' },
    { code: 63, name: 'ZONEMD', purpose: 'Zone digest' },
    { code: 64, name: 'SVCB', purpose: 'Service binding' },
    { code: 65, name: 'HTTPS', purpose: 'HTTPS service binding' },
    { code: 66, name: 'DSYNC', purpose: 'Delegation synchronisation' },
    { code: 257, name: 'CAA', purpose: 'Certification authority authorisation' },
    { code: 261, name: 'RESINFO', purpose: 'Resolver information' },
  ]),
} as const);

export function knownIanaRecordType(
  value: string,
): { readonly code: number; readonly name: string; readonly purpose: string } | null {
  const upper = value.trim().toUpperCase();
  return (
    IANA_DNS_PARAMETER_SNAPSHOT.recordTypes.find((record) => record.name === upper) ?? null
  );
}
