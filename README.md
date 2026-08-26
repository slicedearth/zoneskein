# ZoneSkein

**Untangle DNS.**

ZoneSkein is a static-first, privacy-conscious DNS inspection, validation, and record-authoring workbench. It helps domain owners, developers, and operators inspect evidence, understand email-policy dependencies, lint proposed records, and compare changes before publishing.

It is not a subdomain scanner, reconnaissance platform, monitoring service, DNS publisher, or provider account manager. Every live DNS question begins with a name and record types selected by the visitor.

## Features

- DNS record explorer with A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, PTR, DS, DNSKEY, RRSIG, NSEC, NSEC3, TLSA, ZONEMD, HTTPS, and SVCB support.
- RFC 8484 wire-format DNS-over-HTTPS to fixed Google Public DNS, Cloudflare 1.1.1.1, and Quad9 endpoints, using the GET or POST method expected by each endpoint. Every query carries zero-prefix EDNS Client Subnet signalling and RFC 8467 padding to a 128-octet block. **Quad9 (direct)** remains the default Quad9 path, with explicit **Quad9 (compatibility mode)** for browser paths that cannot preserve HTTP/2 or HTTP/3.
- Side-by-side recursive-resolver comparison, exact DNS message sizes, EDNS Extended DNS Error explanations, RFC 2308 negative-cache TTLs, normalised record fields, PTR conversion, and plain, BIND, JSON, or Markdown exports.
- Independent DNSSEC validation from bundled IANA root trust anchors, with authenticated DS and DNSKEY chains, positive and negative selected application answers, wildcard proofs, bounded CNAME/DNAME/SVCB/HTTPS alias continuation, SHA-1/SHA-256/SHA-384 DS matching, explicit NSEC3 Opt-Out uncertainty, browser-native RSA/ECDSA/Ed25519 verification, and bounded Ed448 verification through an independently reviewed primitive.
- Ordered SPF lexer and parser, recursive include/redirect graph, path-aware ten-term and void-lookup analysis, A/MX expansion, cycle detection, and guarded point-in-time snapshots with provenance.
- Sender-context SPF evaluation for a supplied SMTP client IP, MAIL FROM identity, HELO/EHLO domain, and optional receiver name, with ordered mechanism evaluation, bounded macro expansion and DNS work, publisher explanations, and a replayable evidence trace.
- Recoverable zone-snippet parser and linter for common records, directives, inherited owners, multiline records, TXT chunks, and cross-record conflicts.
- Explicit complete-zone ZONEMD verification and SHA-384 or SHA-512 record generation using an in-house canonical DNS encoder, numeric-type ordering, standard duplicate and exclusion rules, and published interoperability vectors.
- DNS Record Studio for locally authoring A, AAAA, CAA, CNAME, DNSKEY, DS, HTTPS, MX, NAPTR, NS, PTR, SOA, SRV, SSHFP, SVCB, TLSA, TXT, and URI records, with diagnostics, BIND and JSON output, safe TXT chunks, a deduplicated bounded working set, and local linting. It never publishes DNS.
- Change Lab semantic comparison with unordered RRsets, TTL-only and presentation-only categories, risk findings, preparation deadlines, rollback cache horizons, and staged rollout guidance. It neither publishes records nor assigns a universal propagation-complete time.
- Portable Change Workspace files for carrying bounded current and intended zone states, explicit incomplete states, structured analysis, rollout and rollback guidance, historical resolver evidence, and SHA-256 internal-consistency checks between Record Studio and Change Lab. Imports remain local and never turn retained resolver endpoints into network targets.
- RFC 9989 DMARC DNS Tree Walk discovery and conditional identifier-alignment assessment from supplied prior authentication results, plus RFC 9990 and RFC 9991 external-reporting authorisation checks. Passing SPF and DKIM results can move into that assessment through a bounded in-memory hand-off or a strict minimal JSON transfer that excludes mailbox local parts, client addresses, raw messages, selectors, policy text, and trace data.
- DKIM selector-key inspection and bounded RSA-SHA256 or Ed25519-SHA256 signature verification for pasted text or byte-preserving `.eml` files, plus CAA inheritance analysis and authoring for web, wildcard, and S/MIME issuance.
- Explicitly enabled, manual IndexedDB snapshots and fragment-only share links. Persistent storage is off by default.

## Architecture and privacy

ZoneSkein is static-first. The built browser application contains no server-rendered routes, database service, authentication, analytics, advertising, telemetry, or error-reporting service. Its only server-side component is a bounded Netlify Function for the explicitly selected Quad9 compatibility relay.

Parsing, cryptography, linting, policy evaluation, diffing, report generation, and local snapshots run in the browser. Google, Cloudflare, and **Quad9 (direct)** questions go directly from the browser to the selected resolver. The resolver receives those questions and its privacy policy applies. Netlify receives ordinary page and asset requests and may log connection information.

Quad9 no longer accepts DNS-over-HTTPS over HTTP/1.1. A browser, VPN, enterprise inspection product, or network proxy that downgrades Quad9 requests can therefore make that resolver unavailable even while Google or Cloudflare works. **Quad9 (direct)** remains the default Quad9 path. A visitor can explicitly opt into **Quad9 (compatibility mode)**, which sends the DNS wire question in a bounded POST body to `/api/doh/quad9`; Netlify then forwards it only to `https://dns.quad9.net/dns-query` through a fixed Node.js HTTP/2 client. Netlify can observe that question and ordinary connection metadata in compatibility mode. The relay uses no request query string, cookies, credentials, application logging, or server-side response cache. Google and Cloudflare evidence remains independent, and no recursive answer is treated as authoritative or globally representative.

SPF sender mode can place parts of a supplied mailbox, IP address, HELO/EHLO name, or receiver name into resolver-visible DNS questions when a policy uses macros. DKIM message mode keeps the raw message in page memory and sends only derived selector TXT questions. The optional DMARC hand-off retains only the authenticated domain, result provenance, capture time and reconstruction caveat required for later alignment assessment; copying it places that minimal JSON on the clipboard. Use real personal, customer, employee, sender, or message data only when authorised; prefer synthetic values for demonstrations.

Queries are not persisted by default. A bounded anonymous rate-limit ledger stores only opaque request identifiers, timestamps, resolver buckets, and cooldown expiries in local storage; it contains no questions, answers, names, or pasted content. Enabling local snapshots stores only manually saved reports in IndexedDB. The opt-in preference contains no domain name. Share links are created only on request and use the URL fragment, which is not sent to the hosting server; browser history and link recipients can still see its contents.

Change Workspaces remain in page memory unless explicitly downloaded as a bounded JSON file. Importing one reads it locally, performs strict schema and SHA-256 consistency checks, and never contacts resolver endpoints retained as provenance. Import validation does not reproduce or endorse stored analysis; treat it as supplied historical data until running local reanalysis. A mismatch shows that the content no longer matches the included digest. A match shows internal consistency only: because the digest is stored with the file and can be recomputed, it provides no authenticity, authorisation, or tamper resistance. Downloaded files can contain DNS names, records, operational timing, and historical resolver evidence, so they should be handled as sensitive operational documents.

See [PRIVACY.md](PRIVACY.md), [SECURITY.md](SECURITY.md), [TERMS.md](TERMS.md), [docs/ZONEMD-MODEL.md](docs/ZONEMD-MODEL.md), and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Abuse controls

Normal browser use is bounded by:

- four active DNS requests across all tools and resolvers;
- an eight-second timeout;
- a token bucket with a four-request burst and two requests per second per resolver;
- a rolling limit of 120 requests per minute and resolver, coordinated across tabs with origin-wide reservation locks where available, replay-resistant events, and a bounded anonymous local ledger;
- a Netlify-enforced limit of 120 requests per minute per source IP address and site domain for the optional Quad9 relay;
- a first-in-first-out queue capped at 256 waiting requests per resolver, with complete cancellation cleanup;
- an 80-unique-question budget for each user-initiated run;
- in-flight deduplication and TTL-aware memory caching;
- cooldown circuits after resolver HTTP 429 responses;
- bounded five-second to five-minute in-memory backoff after repeated resolution failures;
- bounded recursion depth, graph size, pasted input size, raw-message bytes, header and signature work, and snapshot size;
- bounded DNS response streaming and aggregate DNSSEC record, digest, signature, and NSEC3 hashing work;
- cancellation, cycle detection, no ANY queries, no unrestricted batches, and no user-supplied fetch target.

These controls reduce accidental and ordinary abuse. The browser controls cannot enforce policy against someone who modifies the client; the optional relay separately enforces its server-side request, media, size, time, work, target, and rate limits.

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
npm run test:a11y
npm run test:e2e
npm run test:live
```

`npm run build` also creates and verifies a deterministic corresponding-source archive, its per-file manifest and SHA-256 checksum, the bounded static output, public legal documents, CSP resolver allowlist, SPA rewrite, entry-asset hashes, and the single allowlisted Netlify Function contract. `npm run check:build` repeats that verification for an existing `dist` directory and the current source, relay, and configuration. Production source maps are not emitted because the complete source is offered separately. Browser tests exercise deterministic, mocked workflows in Chromium, Firefox, WebKit, and a mobile Chromium viewport. The dedicated accessibility project checks every static route with axe, 320-CSS-pixel reflow, keyboard skip-link focus, forced colours, and reduced motion. Property tests use fixed seeds and bounded generated inputs so failures remain locally reproducible.

`npm run test:live` is an optional manual check against current public resolvers. It is excluded from normal tests and continuous integration. Unit and browser tests otherwise use deterministic fixtures and mocked network responses.

The Vite development and preview servers exercise the static client but do not execute Netlify Functions. Direct resolver modes work there; an end-to-end Quad9 relay check requires a Netlify local runtime or a deployed preview. The deterministic function tests still cover its request validation and HTTP/2 transport without contacting Quad9.

Version tags produce a browser-only static archive, a bounded complete Netlify deployment archive, and the exact corresponding-source archive also served by the built site. Release files are checksummed; deployment artefacts receive provenance and SBOM attestations, and the source archive receives its own provenance attestation. The workflow does not deploy the site.

## Netlify deployment

1. Create a Netlify site from the repository.
2. Use `npm run build` as the build command and `dist` as the publish directory. The committed `netlify.toml` supplies both.
3. Deploy the static application and the committed `quad9-doh` Netlify Function. No application environment variables, API keys, database, or scheduled jobs are required.
4. Verify the security headers, all direct routes, and the bounded `/api/doh/quad9` endpoint after deployment.

The rewrite in `public/_redirects` sends direct application routes to `index.html`; static assets retain their own paths. `public/_headers` supplies the restrictive Content Security Policy and other Netlify response headers. Hosting-provider plans and terms can change, so “free forever” cannot be guaranteed.

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Important limits

ZoneSkein reports evidence conservatively:

- recursive answers are point-in-time observations, not authoritative answers or proof of global propagation;
- DNSSEC validates supported delegation, positive, NODATA, NXDOMAIN, wildcard, and alias-continuation proof paths from bundled IANA root trust anchors at one common instant. It is still a bounded selected-type validator rather than a general recursive resolver, and an NSEC3 Opt-Out interval cannot authenticate whether a covered delegation exists;
- SPF flattening is a work- and cardinality-bounded snapshot tied to absolute source expiries; it is withheld whenever preserving the effective pass set would require guessing, sender context, invalid protocol paths, or partial evidence;
- the zone parser is a practical subset, not a complete BIND or provider-specific parser; complete-zone digest mode stops when that subset cannot encode a record exactly and never infers that a snippet is complete;
- DMARC policy publication does not prove alignment. Alignment mode evaluates supplied prior SPF and DKIM authentication results; DKIM message mode verifies supported signatures but does not establish DMARC alignment, ARC handling, reputation, or delivery; CAA publication does not guarantee issuance.

See [LIMITATIONS.md](LIMITATIONS.md), [docs/DNSSEC-MODEL.md](docs/DNSSEC-MODEL.md), and [docs/SPF-FLATTENING-MODEL.md](docs/SPF-FLATTENING-MODEL.md).

## Licence

ZoneSkein’s original source code is free software licensed under **GNU AGPL-3.0-only**. The complete terms in [LICENSE](LICENSE) control. The software is provided without warranty.

Every production build offers its exact, machine-readable corresponding source as described in [SOURCE.md](SOURCE.md). Hosted use is described separately in [TERMS.md](TERMS.md), without restricting the AGPL rights in distributed copies. Third-party packages retain their own licences; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Project branding is addressed in [TRADEMARKS.md](TRADEMARKS.md).
