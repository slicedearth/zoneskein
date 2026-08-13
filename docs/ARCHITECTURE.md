# Architecture

## Deployment shape

ZoneSkein is a single Vite client build deployed as static files on Netlify. All application paths are rewritten to `index.html`. There are no server routes, Netlify Functions, Edge Functions, service workers, hosted application jobs, authentication services, or server-side databases. A repository workflow periodically checks the bundled DNSSEC trust anchors, but it is not part of the deployed application.

Routes are loaded with dynamic imports. The home shell remains small; protocol-heavy modules such as SPF analysis load only when needed.

## TypeScript toolchain

Application, protocol, test, and build-configuration source is strict TypeScript or TSX. The `typescript7` npm alias selects stable TypeScript 7.0.2 for project type checking; its small JavaScript `tsc` launcher starts TypeScript 7's platform-native compiler implementation. The separately aliased official TypeScript 6 compatibility package supplies the JavaScript compiler API required by typescript-eslint until that parser supports TypeScript 7 directly; it does not compile the application. Vite transpiles and bundles the checked TypeScript and TSX into browser JavaScript because browsers do not execute TypeScript directly. The only tracked `.js` source is `eslint.config.js`, which configures linting rather than the application.

## Layering

`src/core` contains framework-independent TypeScript:

- `dns` validates names, models questions and responses, encodes or decodes DNS wire messages, parses record views, and formats exports;
- `doh` owns fixed resolver definitions, timeouts, caching, deduplication, concurrency, rate limiting, cooldowns, cancellation, and per-run budgets;
- `dnssec` anchors trust in a bundled IANA root set, validates exact DS and DNSKEY RRsets, compares DS digests, evaluates bounded authenticated-denial proofs, and verifies selected exact-positive application RRsets from losslessly bound raw-wire evidence;
- `spf` lexes and parses ordered terms, resolves bounded dependency graphs, measures worst-case paths, constructs guarded snapshots, and evaluates bounded sender context with macro and DNS evidence;
- `zone` tokenises and lints recoverable zone snippets and serialises supported authoring records;
- `diff` normalises records, classifies semantic changes, and derives bounded preflight, risk, timing, rollback, and staged-rollout guidance;
- `dmarc` performs RFC 9989 discovery and conditional alignment assessment from supplied prior authentication evidence, plus RFC 9990 and RFC 9991 reporting-destination checks;
- `dkim` parses selector keys and locally canonicalises and verifies bounded messages;
- `caa` performs bounded inheritance analysis and record authoring;
- `snapshots` owns bounded opt-in IndexedDB persistence and fragment serialisation.

`src/routes` orchestrates user actions and renders typed results. `src/components` contains reusable presentation controls. React components do not define the authoritative DNSSEC, SPF, DMARC, DKIM, CAA, CIDR, zone-parser, or DNS-wire algorithms.

## DNS request flow

1. A route validates the user’s name locally.
2. It creates one `DnsQueryRun`, which owns cancellation and an 80-unique-question budget.
3. `WireDnsResolver` creates an RFC 8484 wire request with a fixed endpoint and transport: POST for Cloudflare, and base64url GET for Google and Quad9 because those methods are compatible with direct browser CORS. Every request carries a zero-prefix EDNS Client Subnet option so downstream answers are not requested for an address-derived subnet; this does not hide the connection address from the selected resolver. Credentials and referrers are omitted, and an eight-second abort timer applies.
4. Shared rate and concurrency controls authorise the request. Identical in-flight requests are deduplicated. Completed responses enter a bounded cache classified as positive, resolver-AD negative, ordinary negative, or resolution failure. This classification controls lifetime only; it does not elevate the resolver AD flag into a local DNSSEC conclusion.
5. The response media type and declared length are checked before reading. A bounded stream reader rejects a body beyond 65,535 octets before it can be materialised, and the wire decoder checks the complete message structure and question binding. Negative responses derive their cache lifetime from the authority SOA. Resolution failures use a separate five-second exponential backoff capped at five minutes and cannot inherit authority TTLs; Extended DNS Error evidence never overrides the DNS RCODE or useful answer data. Cached thrown failures retain only a sanitised category and timing value.
6. Framework-independent record views feed the route. Untrusted values remain text.

No ANY query, arbitrary URL, or unrestricted batch input is exposed.

## State

Ordinary form and response state lives in React memory. DNS caching is memory-only. The theme is selected from browser preference and is not persisted. Cross-tab rate coordination writes only a bounded ledger of opaque request identifiers, timestamps, resolver buckets, and cooldown expiries to local storage; it never writes questions or answers.

Snapshot persistence is separate. A boolean opt-in preference contains no DNS value. Only explicit saves write to IndexedDB. Disabling the feature asks other ZoneSkein tabs to close database handles, waits for confirmed IndexedDB deletion, and only then clears the preference; blocked or failed deletion remains visible. Share state is created only on request, bounded, encoded in a URL fragment, and runtime-validated when read.

Raw DKIM messages, SPF sender inputs, and DMARC alignment inputs remain in current React memory, and those routes provide no snapshot or share control for them. DKIM verification sends only derived selector TXT questions. SPF macros can place parts of supplied sender context into resolver-visible DNS questions. Record Studio working sets remain temporary unless the visitor explicitly saves one through the snapshot control.

## Failure semantics

Protocol modules use explicit typed results, discriminated unions, bounded exceptions, or diagnostic collections. The interface distinguishes idle, loading, success, partial, error, cancelled, unsupported, Opt-Out, alias-boundary, and indeterminate states. Missing evidence is never silently converted to a safety conclusion.
