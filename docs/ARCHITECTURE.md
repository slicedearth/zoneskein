# Architecture

## Deployment shape

ZoneSkein is static-first: a single Vite client build is deployed as static files on Netlify, and all application paths are rewritten to `index.html`. The only server-side application component is `netlify/functions/quad9-doh.ts`, exposed at the fixed same-origin path `/api/doh/quad9` for an explicitly selected Quad9 compatibility relay. There are no server-rendered routes, Edge Functions, service workers, hosted application jobs, authentication services, or server-side databases. A repository workflow periodically checks the bundled DNSSEC trust anchors, but it is not part of the deployed application.

Routes are loaded with dynamic imports. The home shell remains small; protocol-heavy modules such as SPF analysis load only when needed.

## TypeScript toolchain

Application, protocol, test, and build-configuration source is strict TypeScript or TSX. The `typescript7` npm alias selects stable TypeScript 7.0.2 for project type checking; its small JavaScript `tsc` launcher starts TypeScript 7's platform-native compiler implementation. The separately aliased official TypeScript 6 compatibility package supplies the JavaScript compiler API required by typescript-eslint until that parser supports TypeScript 7 directly; it does not compile the application. Vite transpiles and bundles the checked TypeScript and TSX into browser JavaScript because browsers do not execute TypeScript directly. The only tracked `.js` source is `eslint.config.js`, which configures linting rather than the application.

## Layering

`src/core` contains framework-independent TypeScript:

- `dns` validates names, models questions and responses, encodes or decodes DNS wire messages, parses record views, and formats exports;
- `doh` owns fixed resolver definitions, timeouts, caching, deduplication, concurrency, rate limiting, cooldowns, cancellation, and per-run budgets;
- `dnssec` anchors trust in a bundled IANA root set, validates DS and DNSKEY chains, compares DS digests, evaluates bounded NSEC/NSEC3 denial proofs, follows authenticated aliases, and verifies selected positive or negative application results from losslessly bound raw-wire evidence;
- `spf` lexes and parses ordered terms, resolves bounded dependency graphs, measures worst-case paths, constructs guarded snapshots, and evaluates bounded sender context with macro and DNS evidence;
- `zone` tokenises and lints recoverable zone snippets and serialises supported authoring records;
- `diff` normalises records, classifies semantic changes, and derives bounded preflight, risk, timing, rollback, and staged-rollout guidance;
- `project` validates and serialises the versioned Change Workspace format, constructs Record Studio and Change Lab hand-offs, and reruns bounded local comparison without network or storage access;
- `dmarc` performs RFC 9989 discovery and conditional alignment assessment from supplied prior authentication evidence, plus RFC 9990 and RFC 9991 reporting-destination checks;
- `dkim` parses selector keys and locally canonicalises and verifies bounded messages;
- `caa` performs bounded inheritance analysis and record authoring;
- `snapshots` owns bounded opt-in IndexedDB persistence and fragment serialisation.

`src/routes` orchestrates user actions and renders typed results. `src/components` contains reusable presentation controls. React components do not define the authoritative DNSSEC, SPF, DMARC, DKIM, CAA, CIDR, zone-parser, or DNS-wire algorithms.

## DNS request flow

1. A route validates the user’s name locally.
2. It creates one `DnsQueryRun`, which owns cancellation and an 80-unique-question budget.
3. `WireDnsResolver` creates an RFC 8484 wire request with a fixed endpoint and transport: POST for Cloudflare, and base64url GET for Google and **Quad9 (direct)** because those methods are compatible with direct browser CORS. Quad9 requires an end-to-end HTTP/2 or HTTP/3 path, so an HTTP/1.1-only browser, VPN, or inspection proxy produces an explicit transport-unavailable result rather than a DNS conclusion. Quad9 (direct) remains the default Quad9 path and ZoneSkein never silently substitutes a transport or resolver. Every request carries a zero-prefix EDNS Client Subnet option so downstream answers are not requested for an address-derived subnet; this does not hide the connection address from the selected resolver. Credentials and referrers are omitted, and an eight-second abort timer applies.
4. If the visitor explicitly enables **Quad9 (compatibility mode)**, the resolver sends the same bounded wire question as a same-origin POST to `/api/doh/quad9`. The function rejects other methods, media types, query strings, oversized bodies, malformed messages, unsupported question shapes, and excess DNS work. Browser credentials are omitted, and the function neither uses nor forwards cookies or credentials. It accepts at most 4,096 request octets and 65,535 response octets, applies a fixed timeout, and opens a Node.js HTTP/2 connection only to `https://dns.quad9.net/dns-query`. No caller-controlled upstream is available. The function does not write question bodies to application logs or cache responses, and Netlify enforces 120 requests per minute aggregated by source IP address and site domain.
5. Shared browser rate and concurrency controls authorise the request. Identical in-flight requests are deduplicated. Completed responses enter a bounded cache classified as positive, resolver-AD negative, ordinary negative, or resolution failure. This classification controls lifetime only; it does not elevate the resolver AD flag into a local DNSSEC conclusion. Relay responses themselves use `Cache-Control: no-store`; only the same bounded in-browser cache applies after validation.
6. The response media type and declared length are checked before reading. A bounded stream reader rejects a body beyond 65,535 octets before it can be materialised, and the wire decoder checks the complete message structure and question binding. Negative responses derive their cache lifetime from the authority SOA. Resolution failures use a separate five-second exponential backoff capped at five minutes and cannot inherit authority TTLs; Extended DNS Error evidence never overrides the DNS RCODE or useful answer data. Cached thrown failures retain only a sanitised category and timing value.
7. Framework-independent record views feed the route. Untrusted values remain text. Successful Google, Cloudflare, direct Quad9, and relayed Quad9 observations remain independently attributed; no recursive observation is elevated to an authoritative or globally representative answer.

No ANY query, arbitrary URL, or unrestricted batch input is exposed. The relay does not provide a general-purpose proxy.

## State

Ordinary form and response state lives in React memory. DNS caching is memory-only. The Quad9 relay has no application response cache or durable application state. The theme is selected from browser preference and is not persisted. Cross-tab rate coordination writes only a bounded ledger of opaque request identifiers, timestamps, resolver buckets, and cooldown expiries to local storage; it never writes questions or answers.

Snapshot persistence is separate. A boolean opt-in preference contains no DNS value. Only explicit saves write to IndexedDB. Disabling the feature asks other ZoneSkein tabs to close database handles, waits for confirmed IndexedDB deletion, and only then clears the preference; blocked or failed deletion remains visible. Share state is created only on request, bounded, encoded in a URL fragment, and runtime-validated when read.

Raw DKIM messages, SPF sender inputs, and DMARC alignment inputs remain in current React memory, and those routes provide no snapshot or share control for them. DKIM verification sends only derived selector TXT questions. SPF macros can place parts of supplied sender context into resolver-visible DNS questions. Record Studio working sets remain temporary unless the visitor explicitly saves one through the snapshot control.

Change Workspace state is also memory-only. Record Studio and Change Lab can hand bounded typed state to it through application-owned React callbacks; browser history holds only the route. Explicit file export produces canonical JSON with a SHA-256 integrity field, and strict import reconstructs plain inert values without reproducing or endorsing stored analysis. Imported resolver endpoints are never passed to `WireDnsResolver`. Opening a workspace in Change Lab transfers both zone states, their omission reasons and distinct origins, and the exact in-memory workspace into pasted comparison mode. Incomplete inputs cannot produce a new comparison and can return losslessly.

## Failure semantics

Protocol modules use explicit typed results, discriminated unions, bounded exceptions, or diagnostic collections. The interface distinguishes idle, loading, success, partial, error, cancelled, unsupported, Opt-Out, alias-boundary, and indeterminate states. Missing evidence is never silently converted to a safety conclusion.
