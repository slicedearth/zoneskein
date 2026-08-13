# DNSSEC evidence model

## Questions

For a requested zone, ZoneSkein asks the selected recursive resolver for DNSKEY and DS data twice:

- checking enabled (`CD=0`, `DO=1`);
- checking disabled (`CD=1`, `DO=1`).

The comparison helps distinguish a resolver validation failure from an inability to retrieve DNSSEC material. An eight-second timeout, fixed endpoint, shared concurrency limit, rate controls, and per-run question budget apply.

## Local calculations

ZoneSkein parses DNSKEY flags, protocol, algorithm, public key data, and key tag. It implements the RFC 4034 key-tag algorithm.

For every compatible DS and DNSKEY candidate, it hashes the canonical owner name followed by DNSKEY RDATA using Web Crypto:

- DS digest type 2: SHA-256;
- DS digest type 4: SHA-384.

It compares the complete digest, key tag, and algorithm. A match demonstrates that the returned parent DS identifies the returned child key. It does not authenticate the DS response by itself.

RRSIG inception and expiration are compared with current time. For a returned RRSIG covering DNSKEY, ZoneSkein constructs canonical DNSKEY RRset signed data and attempts local verification for:

- RSA/SHA-1 algorithms 5 and 7;
- RSA/SHA-256 algorithm 8;
- RSA/SHA-512 algorithm 10;
- ECDSA P-256/SHA-256 algorithm 13;
- ECDSA P-384/SHA-384 algorithm 14;
- Ed25519 algorithm 15.

Availability still depends on the browser’s Web Crypto implementation. Unsupported algorithms remain unsupported rather than invalid.

## Conclusions

- **DS match + local DNSKEY signature**: a supported published DS matches a returned DNSKEY and a returned signature over the DNSKEY RRset verified locally.
- **Parent DS matches child DNSKEY**: the local digest matches, but a DNSKEY RRset signature was not locally verified.
- **Resolver validated**: the validating response carries AD, while stronger local evidence was not established.
- **Likely bogus**: the validating path returns SERVFAIL while checking-disabled retrieval exposes relevant DNSSEC material.
- **Unsigned delegation**: only when an AD-marked response contains authenticated NSEC or NSEC3 denial for the child DS RRset.
- **Indeterminate**: evidence is missing, unsupported, unmatched, or ambiguous.
- **Query failed**: neither DNSKEY path produced a DNS response.

`AD=false` alone never proves that a delegation is unsigned.

## Trust boundary

ZoneSkein does not bundle or update a root trust anchor and does not independently validate the parent DS RRset through every ancestor. It does not verify every application RRset or prove NSEC/NSEC3 denial. The selected resolver remains part of the trust and evidence model.
