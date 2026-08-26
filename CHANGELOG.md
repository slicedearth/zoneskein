# Changelog

All notable changes to ZoneSkein are documented here.

## Unreleased

- Clarified the colour-theme control by showing the active state, aligned the home-page actions on one display type scale, kept the smallest hero lock-up intact, balanced the mobile navigation, normalised navigation title casing, and refreshed high-visibility product and repository copy around the skein metaphor without weakening technical, privacy, or operational boundaries.
- Recast the interface around an expressive skein identity, with a custom interwoven Z-and-S SVG mark, matching generated ICO and Apple touch icons, a branded social preview, a coral-and-mint wordmark, a vibrant high-contrast colour system, self-hosted open-licensed display and reading fonts, playful responsive geometry, and a clearer home-page path into the workbench while retaining compact technical evidence.
- Added canonical `www.zoneskein.com` route metadata, unique search and social descriptions, truthful WebSite and WebApplication structured data, a checked XML sitemap, a canonical robots declaration, and route-specific static HTML entry files while retaining client-side route updates and `noindex` handling for unknown paths.
- Updated the independent Marked test parser to 18.0.11 and the React refresh lint plugin to 0.5.5; retained Node 24 type definitions to match the pinned production runtime.
- Added RFC 8467 all-zero EDNS query padding to 128-octet blocks on every direct and relayed DNS-over-HTTPS request, with exact-length tests and strict compatibility-relay rejection of missing, malformed, excessive, or non-zero padding. Also aligned the relay allowlist with live ZONEMD inspection.
- Added a bounded privacy-minimised SPF and DKIM evidence hand-off into DMARC alignment, with in-memory route transfer, strict versioned JSON import and export, inert resolver provenance, reconstruction caveats, exact schema validation, and automatic provenance detachment after edits.
- Added bounded in-house complete-zone integrity verification and publication-record generation with SHA-384 and SHA-512, canonical DNS wire ordering, generic numeric RDATA, standard vectors, explicit completeness consent, checksum-only caveats, and live DNSSEC support for published ZONEMD RRsets.
- Added Ed448 DNSSEC signature verification with a corrected published interoperability vector, explicit cryptographic dependency boundary, versioned evidence-expiry metadata, and visible trust-anchor and pinned-certificate maintenance state.
- Added a deployed AGPL corresponding-source archive with a per-file manifest and checksum, public source, hosted-use and trade-mark links, explicit contribution licensing, authorised-data warnings, and build/release verification that binds the archive to the exact source tree.
- Reworked the crowded primary navigation into accessible tool groups, introduced a restrained first-party SVG mark, added active-route titles, and tightened responsive workbench spacing and touch targets.
- Added forward-record select-all and default-reset controls, compact type-major resolver results, keyboard-accessible record tables, stale-result invalidation, and provenance-preserving lookup exports.
- Added resolver-specific Quad9 transport guidance for browser, VPN, or inspection paths that cannot preserve its required HTTP/2-or-newer DNS-over-HTTPS connection.
- Consolidated Quad9 into one resolver choice with automatic path selection. Each run uses its first real question as a bounded direct capability probe, selects compatibility mode only after a qualifying transport, timeout, or HTTP failure, prevents concurrent retry bursts, and preserves the actual path in results and exports. Compatibility mode retains its fixed Node.js HTTP/2 upstream, strict DNS wire and resource bounds, no application logging or server-side cache, and Netlify-enforced 120-request-per-minute limit per source IP address and site domain.
- Split tagged artefacts into the existing browser-only static archive and a separately bounded, checksummed, and attested complete Netlify deployment archive containing the exact static output, Quad9 function, deployment configuration, package manifests, and legal notices.

- Corrected DNSSEC algorithm policy for RFC 9905: legacy RSA/SHA-1 signatures remain verifiable, but algorithm 5 or 7 DS records can no longer establish a secure delegation.
- Completed bounded DNSSEC validation for application NODATA, NXDOMAIN, wildcard-positive and wildcard-NODATA proof sets, RFC 9824 compact denial, and authenticated CNAME, DNAME, SVCB, and HTTPS alias continuation.
- Added fail-closed parser, diagnostic, record, change, and finding limits to Change Lab and replaced repeated dense-record scans with indexed comparison.
- Separated positive, negative, and resolution-failure cache lifetimes so transient failures receive only a bounded five-second to five-minute backoff.
- Made local snapshot erasure cross-tab aware and delayed the disabled/erased confirmation until IndexedDB deletion succeeds.
- Added a checked, source-map-free static build artefact; tagged archive, CycloneDX SBOM, checksum, and provenance generation; enforced coverage and dependency/security scanning; and Chromium, Firefox, WebKit, and mobile Chromium browser coverage.
- Added deterministic bounded property tests for DNS wire, zone parsing, and semantic comparison, plus automated WCAG route, reflow, keyboard, forced-colours, and reduced-motion checks.
- Added a bounded, versioned Change Workspace workflow with Record Studio and Change Lab hand-offs, strict local JSON import and export, structured analysis and rollback guidance, explicit unavailable or partial inputs, inert resolver provenance, and SHA-256 consistency checks.

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
