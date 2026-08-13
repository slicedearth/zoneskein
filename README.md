# ZoneSkein

**Untangle DNS.**

ZoneSkein is a static, privacy-conscious DNS inspection, validation, and record-authoring workbench. It helps domain owners, developers, and operators inspect evidence, understand email-policy dependencies, lint proposed records, and compare changes before publishing.

It is not a subdomain scanner, reconnaissance platform, monitoring service, DNS publisher, or provider account manager. Every live DNS question begins with a name and record types selected by the visitor.

## Features

- DNS record explorer with A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, PTR, DS, DNSKEY, RRSIG, NSEC, NSEC3, TLSA, HTTPS, and SVCB support.
- RFC 8484 wire-format DNS-over-HTTPS to fixed Google Public DNS, Cloudflare 1.1.1.1, and Quad9 endpoints, using the browser-compatible GET or POST method each endpoint supports.
- Side-by-side recursive-resolver comparison, exact DNS message sizes, EDNS Extended DNS Error explanations, RFC 2308 negative-cache TTLs, normalised record fields, PTR conversion, and plain, BIND, JSON, or Markdown exports.
- Independent DNSSEC chain validation from bundled IANA root trust anchors, with authenticated DS and DNSKEY RRsets, SHA-1/SHA-256/SHA-384 DS matching, exact NSEC/NSEC3 delegation proofs, explicit NSEC3 Opt-Out uncertainty, and browser-supported RSA, ECDSA, and Ed25519 verification.
- Ordered SPF lexer and parser, recursive include/redirect graph, path-aware ten-term and void-lookup analysis, A/MX expansion, cycle detection, and guarded point-in-time snapshots with provenance.
- Recoverable zone-snippet parser and linter for common records, directives, inherited owners, multiline records, TXT chunks, and cross-record conflicts.
- Semantic DNS change comparison with unordered RRsets, TTL-only and formatting-only categories, MX priority changes, disruptive-change flags, and rollout guidance.
- Current DMARC DNS Tree Walk discovery and external-report authorisation checks, DKIM key inspection, and CAA inheritance analysis and authoring for web, wildcard, and S/MIME issuance.
- Explicitly enabled, manual IndexedDB snapshots and fragment-only share links. Persistent storage is off by default.

## Architecture and privacy

ZoneSkein builds to static files. It has no application backend, server routes, functions, database service, authentication, analytics, advertising, telemetry, or error-reporting service.

Parsing, cryptography, linting, policy evaluation, diffing, report generation, and local snapshots run in the browser. DNS questions go directly from the browser to the selected resolver. The resolver receives those questions and its privacy policy applies. Netlify still receives ordinary page and asset requests and may log connection information.

Queries are not persisted by default. Enabling local snapshots stores only manually saved reports in IndexedDB. The opt-in preference contains no domain name. Share links are created only on request and use the URL fragment, which is not sent to the hosting server; browser history and link recipients can still see its contents.

See [PRIVACY.md](PRIVACY.md), [SECURITY.md](SECURITY.md), and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Abuse controls

Normal browser use is bounded by:

- four active DNS requests across all tools and resolvers;
- an eight-second timeout;
- a token bucket with a four-request burst and two requests per second per resolver;
- a rolling limit of 120 requests per minute and resolver, coordinated across tabs with replay-resistant events and a bounded anonymous local ledger where browser facilities are available;
- a first-in-first-out queue capped at 256 waiting requests per resolver, with complete cancellation cleanup;
- an 80-unique-question budget for each user-initiated run;
- in-flight deduplication and TTL-aware memory caching;
- cooldown circuits after resolver HTTP 429 responses;
- bounded recursion depth, graph size, pasted input size, and snapshot size;
- bounded DNS response streaming and aggregate DNSSEC record, digest, signature, and NSEC3 hashing work;
- cancellation, cycle detection, no ANY queries, no unrestricted batches, and no user-supplied fetch target.

These controls reduce accidental and ordinary abuse. They cannot enforce policy against someone who modifies a fully client-side application.

## Local development

Use Node.js 24.19.0 or a newer release satisfying `>=24.19.0`, with npm. The
repository's `.nvmrc` keeps local and hosted builds on the tested LTS release.

```sh
npm ci
npm run dev
```

The project uses the current TypeScript 7 native compiler for application type checking. A current TypeScript 6 compiler API is installed alongside it for the ESLint parser until that toolchain supports TypeScript 7 directly.

Useful commands:

```sh
npm run format:check
npm run lint
npm run check
npm run check:dnssec-anchors
npm test
npm run build
npm run test:e2e
npm run test:live
```

`npm run test:live` is an optional manual check against current public resolvers. It is excluded from normal tests and continuous integration. Unit and browser tests use deterministic fixtures and mocked network responses.

## Netlify deployment

1. Create a Netlify site from the repository.
2. Use `npm run build` as the build command and `dist` as the publish directory. The committed `netlify.toml` supplies both.
3. Deploy. No environment variables, functions, API keys, or paid services are required by ZoneSkein itself.
4. Verify the security headers and all direct routes after deployment.

The rewrite in `public/_redirects` sends direct application routes to `index.html`; static assets retain their own paths. `public/_headers` supplies the restrictive Content Security Policy and other Netlify response headers. Hosting-provider plans and terms can change, so “free forever” cannot be guaranteed.

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Important limits

ZoneSkein reports evidence conservatively:

- recursive answers are point-in-time observations, not authoritative answers or proof of global propagation;
- DNSSEC validates the delegation chain from bundled IANA root trust anchors at one common instant, but does not validate arbitrary application RRsets or complete NXDOMAIN proofs; an NSEC3 Opt-Out interval cannot authenticate whether a covered delegation exists;
- SPF flattening is a time-bound snapshot and is withheld whenever preserving the effective pass set would require guessing or sender context;
- the zone parser is a practical subset, not a complete BIND or provider-specific parser;
- a published DMARC, DKIM, or CAA record does not prove message alignment, signature use, receiver enforcement, or certificate issuance.

See [LIMITATIONS.md](LIMITATIONS.md), [docs/DNSSEC-MODEL.md](docs/DNSSEC-MODEL.md), and [docs/SPF-FLATTENING-MODEL.md](docs/SPF-FLATTENING-MODEL.md).

## Licence

ZoneSkein’s original source code is free software licensed under **GNU AGPL-3.0-only**. The complete terms in [LICENSE](LICENSE) control. The software is provided without warranty.

Third-party packages retain their own licences; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
