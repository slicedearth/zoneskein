<p align="center">
  <img src="public/logo.svg" width="152" alt="ZoneSkein interwoven Z and S strands">
</p>

<h1 align="center">ZoneSkein</h1>

<p align="center">
  <strong>Untangle DNS.</strong><br>
  A static-first workbench for following DNS evidence from question to change plan.
</p>

<p align="center">
  <a href="#follow-the-threads">What it does</a> ·
  <a href="#privacy-with-clear-boundaries">Privacy</a> ·
  <a href="#local-development">Development</a> ·
  <a href="#netlify-deployment">Deployment</a> ·
  <a href="#important-limits">Limits</a>
</p>

Start with a name, then follow the strands through live answers, trust chains, mail policy, record authoring, and staged change plans. ZoneSkein helps domain owners, developers, and operators inspect the evidence, understand dependencies, and prepare DNS work before anything reaches production.

> [!IMPORTANT]
> ZoneSkein is a workbench, not a scanner or DNS control plane. It does not discover subdomains, monitor infrastructure, publish records, or manage provider accounts. Every live DNS question starts with a name and record types chosen by the visitor.

## Follow the threads

### Inspect what DNS is saying

- **Record explorer:** query A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, PTR, DS, DNSKEY, RRSIG, NSEC, NSEC3, TLSA, ZONEMD, HTTPS, and SVCB records. Compare fixed Google Public DNS, Cloudflare 1.1.1.1, and Quad9 resolvers side by side, then export plain, BIND, JSON, or Markdown evidence.
- **Exact resolver evidence:** inspect DNS message sizes, EDNS Extended DNS Error explanations, RFC 2308 negative-cache TTLs, normalised record fields, and PTR conversion. Queries use RFC 8484 wire-format DNS-over-HTTPS, zero-prefix EDNS Client Subnet signalling, and RFC 8467 padding to a 128-octet block.
- **Skein Map:** turn ten bounded record questions into an interactive D3 evidence graph with keyboard-accessible tables, resolver provenance, capture times, TTLs, named dependencies, and explicit loose ends. Comparison mode separates answer, response-code, TTL, authenticated-data, extended-error, unavailable, and incomplete differences across the three resolvers without claiming which observation is correct.
- **Delegation Lab:** trace a name or test intended authoritative servers from up to three explicitly requested external vantage points. The browser talks directly to one fixed measurement API after consent, applies a six-run-per-hour local limit, and keeps every result point-in-time and source-labelled. A separate local lifecycle model checks DNSKEY, DS, CDS, and CDNSKEY material, recognises standard deletion signals, structurally interprets CSYNC and DSYNC records, and explains common rollover stages.
- **Independent DNSSEC validation:** follow authenticated DS and DNSKEY chains from bundled IANA root trust anchors through positive and negative selected answers, wildcard proofs, and bounded CNAME, DNAME, SVCB, or HTTPS alias continuation. Validation supports SHA-1, SHA-256, and SHA-384 DS matching; browser-native RSA, ECDSA, and Ed25519 verification; bounded Ed448 verification through an independently reviewed primitive; and explicit NSEC3 Opt-Out uncertainty.
- **Protocol Lab:** query safe registered or numeric resource-record types, inspect exact wire evidence, retain unknown RFC 3597 RDATA, request resolver information with recursion disabled, and decode ECH configuration lists from HTTPS or SVCB records locally.
- **SPF analysis:** parse policies with an ordered lexer, map recursive `include` and `redirect` dependencies, expand A and MX paths, detect cycles, and account for the ten-term and void-lookup limits. Guarded point-in-time snapshots retain provenance.
- **Sender-context SPF evaluation:** test a supplied SMTP client IP, MAIL FROM identity, HELO/EHLO domain, and optional receiver name with ordered mechanism evaluation, bounded macro expansion and DNS work, publisher explanations, and a replayable evidence trace.
- **Mail and issuance policy:** trace RFC 9989 DMARC DNS Tree Walk discovery, conditional identifier alignment, and RFC 9990 or RFC 9991 external-reporting authorisation. Inspect DKIM selector keys, verify bounded RSA-SHA256 or Ed25519-SHA256 signatures from pasted text or byte-preserving `.eml` files, and analyse or author inherited CAA policy for web, wildcard, and S/MIME issuance.
- **Mail Lab:** open bounded DMARC aggregate and TLS report files locally from XML, JSON, gzip, or ZIP; inspect and author MTA-STS and TLS reporting policy; match a supplied certificate against TLSA associations; and review BIMI or ARC structure without treating structural checks as cryptographic verification.

### Prepare the next change

- **Zone linting:** recover common records, directives, inherited owners, multiline records, and TXT chunks from BIND-style snippets, then report syntax and cross-record conflicts without pretending the practical parser is a complete name-server implementation.
- **ZONEMD:** verify a complete zone or generate SHA-384 and SHA-512 records with an in-house, escape- and origin-aware canonical DNS encoder, semantic numeric-type handling, standard duplicate and exclusion rules, and published interoperability vectors.
- **Record Studio:** author A, AAAA, CAA, CNAME, DNSKEY, DS, HTTPS, MX, NAPTR, NS, PTR, SOA, SRV, SSHFP, SVCB, TLSA, TXT, and URI records locally. Diagnostics, safe TXT chunks, BIND and JSON output, a deduplicated bounded working set, and local linting help catch loose records before publication. The studio never publishes DNS.
- **Change Lab:** compare unordered RRsets semantically, separate TTL-only and presentation-only changes, surface bounded risk findings, calculate preparation deadlines and rollback cache horizons, and build staged rollout guidance. It neither publishes records nor assigns a universal propagation-complete time.
- **Change Workspace:** carry bounded current and intended zone states, explicit incomplete states, structured analysis, rollout and rollback guidance, and historical resolver evidence between Record Studio and Change Lab. Portable files use SHA-256 internal-consistency checks, remain local, and never turn retained resolver endpoints into network targets.
- **Zone Exchange:** expand bounded local `$INCLUDE` and `$GENERATE` bundles with line provenance, rehearse common service-template records, and create conservative portable configuration drafts. Unsupported or provider-specific behaviour is diagnosed and omitted instead of translated by guesswork; nothing signs in to or changes a DNS provider.

### Keep evidence on your terms

- Exports and reports preserve the resolver, capture time, exact wire evidence, and important uncertainty instead of collapsing partial observations into certainty.
- Persistent storage is off by default. Manual, bounded IndexedDB snapshots are available only after the visitor enables them.
- Share links are created only on request and store their payload in the URL fragment rather than sending it to the hosting server.
- Passing SPF and DKIM results can move into DMARC assessment through a bounded in-memory hand-off or strict minimal JSON. The transfer excludes mailbox local parts, client addresses, raw messages, selectors, policy text, and trace data.
- A validated domain can follow the visitor between related tools in current application memory. It is not placed in storage, a URL, or a network request until the visitor starts a relevant live action.

## Privacy with clear boundaries

Most of the work stays exactly where you are: in the browser. Parsing, cryptography, linting, policy evaluation, diffing, report generation, and local snapshots do not need an application server. The built application has no server-rendered routes, database, authentication, analytics, advertising, telemetry, or error-reporting service.

Google and Cloudflare send questions directly from the browser to the selected recursive resolver. Quad9 starts on its direct path and can switch to the compatibility path described below. The resolver receives the question and its privacy policy applies. Netlify receives ordinary page and asset requests and may log connection information.

Quad9 no longer accepts DNS-over-HTTPS over HTTP/1.1. A browser, VPN, enterprise inspection product, or network proxy that downgrades the connection can therefore make its direct path unavailable even while the other resolvers work. The single **Quad9** option tries direct browser DNS-over-HTTPS with the first question in each run. A qualifying transport, timeout, or HTTP failure switches that run once to **Quad9 (compatibility mode)**; concurrent questions wait for this decision, so an unavailable direct path cannot create a retry burst. Compatibility mode sends a bounded DNS wire POST body to `/api/doh/quad9`, and the sole Netlify Function forwards it to `https://dns.quad9.net/dns-query` through a fixed Node.js HTTP/2 client. Netlify can then observe the DNS question and ordinary connection metadata. The interface and exports identify the path actually used. The relay uses no request query string, cookies, credentials, application logging, or server-side response cache. Google and Cloudflare evidence remains independent, and no recursive answer is presented as authoritative or globally representative.

SPF sender mode can place parts of a supplied mailbox, IP address, HELO/EHLO name, or receiver name into resolver-visible DNS questions when a policy uses macros. DKIM message mode keeps the raw message in page memory and sends only derived selector TXT questions. The optional DMARC hand-off retains only the authenticated domain, result provenance, capture time, and reconstruction caveat required for later alignment assessment; copying it places that minimal JSON on the clipboard. Use real personal, customer, employee, sender, or message data only when authorised. Prefer synthetic values for demonstrations.

Delegation Lab is the other optional external path. After explicit consent, the browser sends the chosen DNS name, record type, protocol, location request, probe count, and any intended authoritative server directly to the fixed measurement service. That service and the selected probes can observe the requested question and ordinary connection or measurement metadata under their own policies. Mail reports, certificates, BIMI input, zone bundles, templates, and portable exports remain local unless the visitor deliberately copies or downloads them.

Queries are not persisted by default. A bounded anonymous rate-limit ledger stores only opaque request identifiers, timestamps, resolver buckets, and cooldown expiries in local storage; it contains no questions, answers, names, or pasted content. The snapshot opt-in preference contains no domain name. Fragment-only share data is not sent to the hosting server, although browser history and link recipients can still see it.

Change Workspaces remain in page memory unless explicitly downloaded as bounded JSON. Imports are read locally, checked against a strict schema and SHA-256 digest, and never contact resolver endpoints retained as provenance. Import validation does not reproduce or endorse stored analysis: it remains supplied historical data until locally reanalysed. A digest mismatch shows that the content changed. A match shows internal consistency only, not authenticity, authorisation, or tamper resistance. Workspace files can contain DNS names, records, operational timing, and historical resolver evidence, so handle them as sensitive operational documents.

Read the full boundaries in [PRIVACY.md](PRIVACY.md), [SECURITY.md](SECURITY.md), [TERMS.md](TERMS.md), [the ZONEMD model](docs/ZONEMD-MODEL.md), and [the threat model](docs/THREAT-MODEL.md).

## Guardrails against abuse

DNS tools can create real load. Normal browser use is deliberately bounded by:

- four active DNS requests across all tools and resolvers;
- an eight-second timeout;
- a token bucket with a four-request burst and two requests per second per resolver;
- a rolling limit of 120 requests per minute and resolver, coordinated across tabs with origin-wide reservation locks where available, replay-resistant events, and a bounded anonymous local ledger;
- a Netlify-enforced limit of 120 requests per minute per source IP address and site domain for Quad9 compatibility traffic;
- no more than three external probes per Delegation Lab run and six external measurement runs per rolling hour in the browser;
- a first-in-first-out queue capped at 256 waiting requests per resolver, with complete cancellation cleanup;
- an 80-unique-question budget for each user-initiated run;
- in-flight deduplication and TTL-aware memory caching;
- cooldown circuits after resolver HTTP 429 responses;
- bounded five-second to five-minute in-memory backoff after repeated resolution failures;
- bounded recursion depth, graph size, pasted input size, raw-message bytes, header and signature work, and snapshot size;
- bounded DNS response streaming and aggregate DNSSEC record, digest, signature, and NSEC3 hashing work;
- cancellation, cycle detection, no ANY queries, no unrestricted batches, and no user-supplied fetch target.

These controls reduce accidental and ordinary abuse. Client-side controls cannot enforce policy against someone who modifies the application; Quad9 compatibility mode separately enforces server-side request, media, size, time, work, target, and rate limits.

## Local development

### Get running

Use Node.js 24.19.0 or a newer release satisfying `>=24.19.0`, with npm 12.0.2. The repository’s `.nvmrc` keeps local and hosted builds on the tested LTS release, while `package.json`, Netlify, and continuous integration pin the tested package-manager release.

```sh
npm install --global npm@12.0.2
npm --version
npm ci
npm run dev
```

Application and protocol source is strict TypeScript. The `typescript7` npm alias selects stable TypeScript 7.0.2 for project type checking; its small JavaScript `tsc` launcher starts TypeScript 7’s platform-native compiler implementation. A separate `typescript` alias to the official TypeScript 6 compatibility package supplies the JavaScript compiler API required by typescript-eslint until it supports TypeScript 7 directly. It is a tooling dependency, not application source.

Vite transpiles and bundles checked TypeScript and TSX into browser JavaScript because browsers do not execute TypeScript directly. The only tracked `.js` source is the ESLint configuration.

### Verify the workbench

```sh
npm run format:check
npm run lint
npm run check
npm run check:dnssec-anchors
npm run security:codeql
npm run generate:favicon
npm test
npm run build
npm run check:build
npm run test:a11y
npm run test:e2e
npm run test:live
```

`npm run build` creates and verifies the bounded static output plus a deterministic corresponding-source archive, per-file manifest, and SHA-256 checksum. It also checks route-specific canonical metadata, the sitemap, public legal documents, branded image dimensions, the CSP resolver and structured-data allowlists, SPA rewrite, entry-asset hashes, and the single allowlisted Netlify Function contract. `npm run check:build` repeats that verification for an existing `dist` directory and the current source, relay, and configuration. Production source maps are not emitted because the complete source is offered separately.

Browser tests exercise deterministic mocked workflows in Chromium, Firefox, WebKit, and a mobile Chromium viewport. The accessibility project checks every static route with axe, 320-CSS-pixel reflow, keyboard skip-link focus, forced colours, and reduced motion. Property tests use fixed seeds and bounded generated inputs so failures remain locally reproducible.

The CodeQL command uses the same path exclusions and `security-extended` query suite as continuous integration, builds a disposable JavaScript and TypeScript database, fails when any alert is present, prints a bounded finding summary, and removes the database afterwards. Install the current official CodeQL bundle with `codeql` on `PATH`, or set `CODEQL_PATH` to its absolute executable path. Run it before pushing security-relevant changes. The wrapper fixes the language and query suite, bounds process time, output, memory, threads, SARIF size, and displayed findings, and fails closed if the scan or cleanup is incomplete.

`npm run generate:favicon` renders the canonical SVG logo into the committed 16, 32, 48, 64, 128, and 256-pixel ICO favicon, 180-pixel Apple touch icon, and 1,200-by-630 social preview. Run it after changing the mark; continuous integration reproduces the assets with the locked browser, while production verification checks their declarations, exact static copies, formats, dimensions, bounds, and favicon directory structure.

`npm run test:live` is an optional manual check against current public resolvers. It is excluded from normal tests and continuous integration. Unit and browser tests otherwise use deterministic fixtures and mocked network responses.

The Vite development and preview servers exercise the static client but do not execute Netlify Functions. Direct resolver modes work there; an end-to-end automatic Quad9 fallback check requires a Netlify local runtime or a deployed preview. Deterministic tests cover path selection, relay request validation, and HTTP/2 transport without contacting Quad9.

The development server omits the HTML meta Content Security Policy because Vite injects local hot-reload styles. Production builds retain and verify both the restrictive meta policy and matching Netlify response header; `npm run preview` serves that production form.

Version tags produce a browser-only static archive, a bounded complete Netlify deployment archive, and the exact corresponding-source archive also served by the built site. Release files are checksummed; deployment artefacts receive provenance and SBOM attestations, and the source archive receives its own provenance attestation. The workflow does not deploy the site.

## Netlify deployment

1. Create a Netlify site from the repository.
2. Use `npm run build` as the build command and `dist` as the publish directory. The committed `netlify.toml` supplies both.
3. Deploy the static application and committed `quad9-doh` Netlify Function. No application environment variables, API keys, database, or scheduled jobs are required.
4. Add `zoneskein.com` and `www.zoneskein.com` in Netlify, set `www.zoneskein.com` as the primary domain, and keep the Netlify-facing Cloudflare records in DNS-only mode.
5. Verify the canonical metadata, sitemap, security headers, every direct route, and the bounded `/api/doh/quad9` endpoint after deployment.

The rewrite in `public/_redirects` sends direct application routes to `index.html`; static assets retain their own paths. `public/_headers` supplies the restrictive Content Security Policy and other Netlify response headers. Hosting-provider plans and terms can change, so “free forever” cannot be guaranteed.

See [the deployment guide](docs/DEPLOYMENT.md) for the complete procedure.

## Important limits

ZoneSkein shows its loose ends rather than smoothing them over:

- recursive answers are point-in-time observations, not authoritative answers or proof of global propagation;
- an external-vantage sample is still bounded and cannot establish worldwide propagation, while disagreement between resolvers or probes does not identify the cause or the correct answer;
- DNSSEC validates supported delegation, positive, NODATA, NXDOMAIN, wildcard, and alias-continuation proof paths from bundled IANA root trust anchors at one common instant. It is still a bounded selected-type validator rather than a general recursive resolver, and an NSEC3 Opt-Out interval cannot authenticate whether a covered delegation exists;
- SPF flattening is a work- and cardinality-bounded snapshot tied to absolute source expiries. It is withheld whenever preserving the effective pass set would require guessing, sender context, invalid protocol paths, or partial evidence;
- the zone parser is a practical subset, not a complete BIND or provider-specific parser. Complete-zone digest mode stops when that subset cannot encode a record exactly and never infers that a snippet is complete;
- Zone Exchange exports only a conservative common record subset and never represents a draft as provider-ready without review;
- DMARC policy publication does not prove alignment. Alignment mode evaluates supplied prior SPF and DKIM authentication results; DKIM message mode verifies supported signatures but does not establish DMARC alignment, ARC handling, reputation, or delivery; local report, BIMI and ARC inspection does not reproduce a receiver’s processing; CAA publication does not guarantee issuance.

Read [LIMITATIONS.md](LIMITATIONS.md), [the DNSSEC model](docs/DNSSEC-MODEL.md), and [the SPF flattening model](docs/SPF-FLATTENING-MODEL.md) before relying on the output operationally.

## Licence

ZoneSkein’s original source code is free software licensed under **GNU AGPL-3.0-only**. The complete terms in [LICENSE](LICENSE) control. The software is provided without warranty.

Every production build offers its exact, machine-readable corresponding source as described in [SOURCE.md](SOURCE.md). Hosted use is described separately in [TERMS.md](TERMS.md), without restricting the AGPL rights in distributed copies. Third-party packages retain their own licences; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Project branding is addressed in [TRADEMARKS.md](TRADEMARKS.md).
