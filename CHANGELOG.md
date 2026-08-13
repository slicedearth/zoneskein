# Changelog

All notable changes to ZoneSkein are documented here.

## Unreleased

- Corrected DNSSEC algorithm policy for RFC 9905: legacy RSA/SHA-1 signatures remain verifiable, but algorithm 5 or 7 DS records can no longer establish a secure delegation.
- Completed bounded DNSSEC validation for application NODATA, NXDOMAIN, wildcard-positive and wildcard-NODATA proof sets, RFC 9824 compact denial, and authenticated CNAME, DNAME, SVCB, and HTTPS alias continuation.
- Added fail-closed parser, diagnostic, record, change, and finding limits to Change Lab and replaced repeated dense-record scans with indexed comparison.
- Separated positive, negative, and resolution-failure cache lifetimes so transient failures receive only a bounded five-second to five-minute backoff.
- Made local snapshot erasure cross-tab aware and delayed the disabled/erased confirmation until IndexedDB deletion succeeds.
- Added a checked, source-map-free static build artefact; tagged archive, CycloneDX SBOM, checksum, and provenance generation; enforced coverage and dependency/security scanning; and Chromium, Firefox, WebKit, and mobile Chromium browser coverage.
- Added deterministic bounded property tests for DNS wire, zone parsing, and semantic comparison, plus automated WCAG route, reflow, keyboard, forced-colours, and reduced-motion checks.

## 0.1.0 — 2026-08-13

- Added a static React, Vite, strict TypeScript, Vitest, and Playwright application configured for Netlify.
- Added RFC 8484 wire-format DNS-over-HTTPS with fixed resolver choices, zero-prefix EDNS Client Subnet privacy signalling, TTL caching, in-flight deduplication, cancellation, shared concurrency, run budgets, cross-tab rate signals, and cooldown circuits.
- Added the DNS record explorer, resolver comparison, PTR conversion, parsed record fields, exact message sizes, and four export formats.
- Added independent DNSSEC delegation-chain validation from bundled IANA root trust anchors, exact DS and DNSKEY RRset verification at one common instant, fail-closed NSEC/NSEC3 denial handling, explicit Opt-Out uncertainty, aggregate work bounds, published cryptographic vectors, and replayable raw evidence.
- Added recursive SPF analysis and guarded point-in-time flattening with provenance, TTL-derived recheck guidance, TXT chunking, and response-size warnings.
- Added sender-context SPF evaluation with ordered mechanisms, macro expansion, bounded DNS work, publisher explanations, and an evidence trace.
- Added zone-snippet linting and DNS Record Studio authoring for 18 explicit record types with a bounded local working set.
- Added Change Lab semantic comparison, preflight risk findings, TTL preparation and rollback timing, and staged rollout guidance.
- Added RFC 9989 DMARC DNS Tree Walk discovery and conditional alignment assessment from supplied prior authentication evidence, with RFC 9990 and RFC 9991 external-reporting authorisation checks.
- Added DKIM selector-key inspection and bounded local signature verification for pasted messages and byte-preserving `.eml` files.
- Added CAA inheritance inspection and record authoring, including account URI, validation-method, wildcard, and S/MIME issuance controls.
- Added EDNS Extended DNS Error decoding, complete extended RCODEs, bounded DNS response streaming, and DNSSEC-aware cache lifetimes.
- Added explicit opt-in IndexedDB snapshots and fragment-only report sharing.
- Added dark and light themes, responsive layouts, accessible status text, keyboard controls, and reduced-motion behaviour.
