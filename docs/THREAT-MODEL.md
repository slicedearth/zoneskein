# Threat model

## Assets

- DNS names and configuration snippets entered by a visitor;
- accuracy of protocol conclusions and generated records;
- availability of public DNS-over-HTTPS resolvers;
- local snapshot contents;
- integrity of the deployed static application.

## Trust boundaries

The visitor trusts the delivered static files, browser runtime, selected resolver, Netlify’s static hosting, and their own device. ZoneSkein does not operate an application backend.

Resolver responses, DNS record text, pasted zone data, URL fragments, and imported snapshot data are untrusted. Browser extensions and local malware are outside the application’s protection boundary.

## Threats and controls

### Arbitrary requests and SSRF-like behaviour

All resolver definitions and endpoints are compile-time allowlisted. The UI accepts no URL, host, or protocol for network destinations. CSP `connect-src` repeats the allowlist. Credentials are omitted and referrers are suppressed.

### Resolver abuse

Shared concurrency, token buckets, a rolling request window, cross-tab signals, run budgets, timeouts, cooldown circuits, TTL caching, in-flight deduplication, depth limits, cycle detection, and bounded targets reduce accidental amplification. There is no bulk input, subdomain generation, ANY query, or automatic retry storm.

A modified client can bypass browser-side controls. Public resolvers must enforce their own service limits.

### Resource exhaustion

Names, zone snippets, snapshot records, fragments, graph depth, MX expansion, unique questions, cache entries, snapshot count, and snapshot size are bounded. DNSSEC also has whole-run limits for records, keys, signatures, digests, cryptographic attempts, and NSEC3 hash rounds. Long-running work observes cancellation between bounded cryptographic operations. DNS response bodies are streamed through the DNS wire limit rather than allocated without a bound.

### Untrusted content execution

React renders record and pasted values as text. No `dangerouslySetInnerHTML`, arbitrary HTML, third-party UI script, remote font, or record-derived URL navigation is used. CSP blocks objects, frames, unexpected connections, and non-self scripts.

### Privacy leakage

DNS questions never enter page or Netlify URLs. Cloudflare receives POST wire bodies; Google and Quad9 receive base64url-encoded RFC 8484 GET parameters so their endpoints work under browser CORS. Resolver URLs are fixed, and the selected resolver can read or log the question under either method. There is no application proxy, analytics, telemetry, tracking pixel, or default query history. Snapshot storage and fragment sharing require explicit actions and are explained before use.

The selected resolver still sees the DNS question. Netlify still sees ordinary page requests. Fragments remain visible to the browser and recipients.

### Misleading security conclusions

Statuses are evidence-scoped. Recursive data is not called authoritative or global. Missing DNSSEC AD is not called unsigned. NSEC3 Opt-Out is not called a proven insecure delegation, and unsupported cryptography is not called invalid. Unsafe SPF input receives no flattened output. Partial lookup failures remain visible.

### Supply chain and deployment

Runtime dependencies use MIT, BSD-2-Clause, or ISC licences and are version-locked. Dependency lifecycle scripts require version-pinned approval, and quality automation performs a vulnerability audit before format, lint, strict type checking, deterministic tests, browser tests, and a static build. Netlify security headers are committed and should be verified after deployment.
