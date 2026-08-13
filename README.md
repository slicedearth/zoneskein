# ZoneSkein

**Untangle DNS.**

ZoneSkein is a static, privacy-conscious DNS inspection, validation, and record-authoring workbench. It helps domain owners, developers, and operators inspect evidence, understand email-policy dependencies, lint proposed records, and compare changes before publishing.

It is not a subdomain scanner, reconnaissance platform, monitoring service, DNS publisher, or provider account manager. Every live DNS question begins with a name and record types selected by the visitor.

## Features

- DNS record explorer with A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, PTR, DS, DNSKEY, RRSIG, NSEC, NSEC3, TLSA, HTTPS, and SVCB support.
- RFC 8484 wire-format DNS-over-HTTPS to fixed Google Public DNS, Cloudflare 1.1.1.1, and Quad9 endpoints, using the browser-compatible GET or POST method each endpoint supports.
- Side-by-side recursive-resolver comparison, exact DNS message sizes, EDNS Extended DNS Error explanations, RFC 2308 negative-cache TTLs, normalised record fields, PTR conversion, and plain, BIND, JSON, or Markdown exports.
- Independent DNSSEC chain and exact-positive RRset validation from bundled IANA root trust anchors, with authenticated DS and DNSKEY RRsets, selected application RRsets, SHA-1/SHA-256/SHA-384 DS matching, exact NSEC/NSEC3 delegation proofs, explicit NSEC3 Opt-Out uncertainty, and browser-supported RSA, ECDSA, and Ed25519 verification.
- Ordered SPF lexer and parser, recursive include/redirect graph, path-aware ten-term and void-lookup analysis, A/MX expansion, cycle detection, and guarded point-in-time snapshots with provenance.
- Sender-context SPF evaluation for a supplied SMTP client IP, MAIL FROM identity, HELO/EHLO domain, and optional receiver name, with ordered mechanism evaluation, bounded macro expansion and DNS work, publisher explanations, and a replayable evidence trace.
- Recoverable zone-snippet parser and linter for common records, directives, inherited owners, multiline records, TXT chunks, and cross-record conflicts.
- DNS Record Studio for locally authoring A, AAAA, CAA, CNAME, DNSKEY, DS, HTTPS, MX, NAPTR, NS, PTR, SOA, SRV, SSHFP, SVCB, TLSA, TXT, and URI records, with diagnostics, BIND and JSON output, safe TXT chunks, a deduplicated bounded working set, and local linting. It never publishes DNS.
- Change Lab semantic comparison with unordered RRsets, TTL-only and presentation-only categories, risk findings, preparation deadlines, rollback cache horizons, and staged rollout guidance. It neither publishes records nor assigns a universal propagation-complete time.
- RFC 9989 DMARC DNS Tree Walk discovery and conditional identifier-alignment assessment from supplied prior authentication results, plus RFC 9990 and RFC 9991 external-reporting authorisation checks.
- DKIM selector-key inspection and bounded RSA-SHA256 or Ed25519-SHA256 signature verification for pasted text or byte-preserving `.eml` files, plus CAA inheritance analysis and authoring for web, wildcard, and S/MIME issuance.
- Explicitly enabled, manual IndexedDB snapshots and fragment-only share links. Persistent storage is off by default.

## Architecture and privacy

ZoneSkein builds to static files. It has no application backend, server routes, functions, database service, authentication, analytics, advertising, telemetry, or error-reporting service.

Parsing, cryptography, linting, policy evaluation, diffing, report generation, and local snapshots run in the browser. DNS questions go directly from the browser to the selected resolver. The resolver receives those questions and its privacy policy applies. Netlify still receives ordinary page and asset requests and may log connection information.

SPF sender mode can place parts of a supplied mailbox, IP address, HELO/EHLO name, or receiver name into resolver-visible DNS questions when a policy uses macros. DKIM message mode keeps the raw message in page memory and sends only derived selector TXT questions. See the privacy documentation before using real sender or message data.

Queries are not persisted by default. A bounded anonymous rate-limit ledger stores only opaque request identifiers, timestamps, resolver buckets, and cooldown expiries in local storage; it contains no questions, answers, names, or pasted content. Enabling local snapshots stores only manually saved reports in IndexedDB. The opt-in preference contains no domain name. Share links are created only on request and use the URL fragment, which is not sent to the hosting server; browser history and link recipients can still see its contents.

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
- bounded five-second to five-minute in-memory backoff after repeated resolution failures;
- bounded recursion depth, graph size, pasted input size, raw-message bytes, header and signature work, and snapshot size;
- bounded DNS response streaming and aggregate DNSSEC record, digest, signature, and NSEC3 hashing work;
- cancellation, cycle detection, no ANY queries, no unrestricted batches, and no user-supplied fetch target.

These controls reduce accidental and ordinary abuse. They cannot enforce policy against someone who modifies a fully client-side application.

## Local development

Use Node.js 24.19.0 or a newer release satisfying `>=24.19.0`, with npm 12.0.2.
The repository's `.nvmrc` keeps local and hosted builds on the tested LTS
release, while `package.json`, Netlify, and continuous integration pin the
tested package-manager release.

```sh
npm install --global npm@12.0.2
npm --version
npm ci
npm run dev
```

Application and protocol source is strict TypeScript. The `typescript7` npm alias selects stable TypeScript 7.0.2 for project type checking; its small JavaScript `tsc` launcher starts TypeScript 7's platform-native compiler implementation. A separate `typescript` alias to the official TypeScript 6 compatibility package supplies the JavaScript compiler API required by typescript-eslint until it supports TypeScript 7 directly; it is a tooling dependency, not application source. Vite transpiles and bundles the checked TypeScript and TSX into browser JavaScript because browsers do not execute TypeScript directly. The only tracked `.js` source is the ESLint configuration.

Useful commands:

```sh
npm run format:check
npm run lint
npm run check
npm run check:dnssec-anchors
npm test
npm run build
npm run check:build
npm run test:e2e
npm run test:live
```

`npm run build` also verifies the bounded static output, legal assets, CSP resolver allowlist, SPA rewrite, and entry-asset hashes. `npm run check:build` repeats that verification for an existing `dist` directory. Production source maps are not emitted. Browser tests exercise deterministic, mocked workflows in Chromium, Firefox, WebKit, and a mobile Chromium viewport.

`npm run test:live` is an optional manual check against current public resolvers. It is excluded from normal tests and continuous integration. Unit and browser tests otherwise use deterministic fixtures and mocked network responses.

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
- DNSSEC validates the delegation chain and selected exact-positive application RRsets from bundled IANA root trust anchors at one common instant. Complete NXDOMAIN, application NODATA, wildcard-denial, and CNAME or DNAME target-continuation proofs remain incomplete; an NSEC3 Opt-Out interval cannot authenticate whether a covered delegation exists;
- SPF flattening is a time-bound snapshot and is withheld whenever preserving the effective pass set would require guessing or sender context;
- the zone parser is a practical subset, not a complete BIND or provider-specific parser;
- DMARC policy publication does not prove alignment. Alignment mode evaluates supplied prior SPF and DKIM authentication results; DKIM message mode verifies supported signatures but does not establish DMARC alignment, ARC handling, reputation, or delivery; CAA publication does not guarantee issuance.

See [LIMITATIONS.md](LIMITATIONS.md), [docs/DNSSEC-MODEL.md](docs/DNSSEC-MODEL.md), and [docs/SPF-FLATTENING-MODEL.md](docs/SPF-FLATTENING-MODEL.md).

## Licence

ZoneSkein’s original source code is free software licensed under **GNU AGPL-3.0-only**. The complete terms in [LICENSE](LICENSE) control. The software is provided without warranty.

Third-party packages retain their own licences; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
