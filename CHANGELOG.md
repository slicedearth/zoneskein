# Changelog

All notable changes to ZoneSkein are documented here.

## 0.1.0 — 2026-08-13

- Added a static React, Vite, strict TypeScript, Vitest, and Playwright application configured for Netlify.
- Added RFC 8484 wire-format DNS-over-HTTPS with fixed resolver choices, TTL caching, in-flight deduplication, cancellation, shared concurrency, run budgets, cross-tab rate signals, and cooldown circuits.
- Added the DNS record explorer, resolver comparison, PTR conversion, parsed record fields, exact message sizes, and four export formats.
- Added DNSSEC evidence inspection, local key tags and DS digests, signature-time checks, and supported DNSKEY RRset cryptographic verification.
- Added recursive SPF analysis and guarded point-in-time flattening with provenance, TTL-derived recheck guidance, TXT chunking, and response-size warnings.
- Added zone-snippet linting and semantic DNS change comparison.
- Added DMARC, DKIM, and CAA inspection and CAA record authoring.
- Updated DMARC discovery to the bounded DNS Tree Walk and current policy-tag model.
- Added CAA account URI, validation-method, and S/MIME issuance controls.
- Added EDNS Extended DNS Error decoding and SOA-derived negative-cache lifetimes.
- Added explicit opt-in IndexedDB snapshots and fragment-only report sharing.
- Added dark and light themes, responsive layouts, accessible status text, keyboard controls, and reduced-motion behavior.
