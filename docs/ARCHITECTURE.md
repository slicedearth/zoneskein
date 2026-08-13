# Architecture

## Deployment shape

ZoneSkein is a single Vite client build deployed as static files on Netlify. All application paths are rewritten to `index.html`. There are no server routes, Netlify Functions, Edge Functions, service workers, scheduled jobs, authentication services, or server-side databases.

Routes are loaded with dynamic imports. The home shell remains small; protocol-heavy modules such as public-suffix data and SPF analysis load only when needed.

## Layering

`src/core` contains framework-independent TypeScript:

- `dns` validates names, models questions and responses, encodes or decodes DNS wire messages, parses record views, and formats exports;
- `doh` owns fixed resolver definitions, timeouts, caching, deduplication, concurrency, rate limiting, cooldowns, cancellation, and per-run budgets;
- `dnssec` parses DNSSEC records, calculates key tags and DS digests, classifies evidence, and verifies supported DNSKEY RRset signatures;
- `spf` lexes and parses ordered terms, resolves bounded dependency graphs, measures worst-case paths, and constructs guarded snapshots;
- `zone` tokenizes recoverable zone snippets and applies local lint rules;
- `diff` normalizes records and classifies semantic changes;
- `dmarc`, `dkim`, and `caa` implement policy-specific parsing and validation;
- `snapshots` owns bounded opt-in IndexedDB persistence and fragment serialization.

`src/routes` orchestrates user actions and renders typed results. `src/components` contains reusable presentation controls. React components do not define the authoritative DNSSEC, SPF, DMARC, DKIM, CAA, CIDR, zone-parser, or DNS-wire algorithms.

## DNS request flow

1. A route validates the user’s name locally.
2. It creates one `DnsQueryRun`, which owns cancellation and an 80-unique-question budget.
3. `WireDnsResolver` creates an RFC 8484 wire request with a fixed endpoint and transport: POST for Cloudflare, and base64url GET for Google and Quad9 because those methods are compatible with direct browser CORS. Credentials and referrers are omitted, and an eight-second abort timer applies.
4. Shared rate and concurrency controls authorize the request. Identical in-flight requests are deduplicated and completed responses enter the bounded TTL cache.
5. The response media type and message bounds are checked before decoding.
6. Framework-independent record views feed the route. Untrusted values remain text.

No ANY query, arbitrary URL, or unrestricted batch input is exposed.

## State

Ordinary form and response state lives in React memory. DNS caching is memory-only. The theme is selected from browser preference and is not persisted.

Snapshot persistence is separate. A boolean opt-in preference contains no DNS value. Only explicit saves write to IndexedDB. Disabling the feature deletes the database. Share state is created only on request, bounded, encoded in a URL fragment, and runtime-validated when read.

## Failure semantics

Protocol modules use explicit typed results, discriminated unions, bounded exceptions, or diagnostic collections. The interface distinguishes idle, loading, success, partial, error, cancelled, unsupported, and indeterminate states. Missing evidence is never silently converted to a safety conclusion.
