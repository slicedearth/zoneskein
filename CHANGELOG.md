# Changelog

All notable changes to ZoneSkein are documented here.

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
