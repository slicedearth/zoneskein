# Threat model

## Assets

- DNS names, SMTP sender identities, client addresses, and configuration snippets entered by a visitor;
- raw email messages and locally derived authentication evidence;
- accuracy of protocol conclusions and generated records;
- availability of public DNS-over-HTTPS resolvers;
- local snapshot contents;
- integrity of the deployed static application.

## Trust boundaries

The visitor trusts the delivered static files, browser runtime, selected resolver, Netlify’s static hosting, and their own device. ZoneSkein does not operate an application backend.

Resolver responses, DNS record text, pasted zone or message data, SMTP sender inputs, URL fragments, and imported snapshot data are untrusted. Browser extensions and local malware are outside the application's protection boundary.

## Threats and controls

### Arbitrary requests and SSRF-like behaviour

All resolver definitions and endpoints are compile-time allowlisted. The UI accepts no URL, host, or protocol for network destinations. CSP `connect-src` repeats the allowlist. Credentials are omitted and referrers are suppressed.

### Resolver abuse

Shared concurrency, token buckets, a rolling request window, bounded first-in-first-out queues, cross-tab signals, replay-resistant opaque request identifiers, run budgets, timeouts, cooldown circuits, TTL caching, in-flight deduplication, depth limits, cycle detection, and bounded targets reduce accidental amplification. Cross-tab state has strict shapes, size and age limits, contains no questions or answers, and fails back to tab-local coordination when browser messaging or storage is unavailable. There is no bulk input, subdomain generation, ANY query, or automatic retry storm.

A modified client can bypass browser-side controls. Public resolvers must enforce their own service limits.

### Resource exhaustion

Names, zone snippets, raw-message bytes, header fields, DKIM signatures, SPF macro output, evidence traces, snapshot records, fragments, graph depth, MX expansion, unique questions, cache entries, snapshot count, and snapshot size are bounded. DNSSEC also has whole-run limits for records, keys, signatures, digests, cryptographic attempts, and NSEC3 hash rounds. Long-running work observes cancellation between bounded cryptographic operations. DNS response bodies are streamed through the DNS wire limit rather than allocated without a bound.

### Untrusted content execution

React renders record and pasted values as text. No `dangerouslySetInnerHTML`, arbitrary HTML, third-party UI script, remote font, or record-derived URL navigation is used. CSP blocks objects, frames, unexpected connections, and non-self scripts.

### Privacy leakage

Live tools do not place visitor-supplied DNS names in the Netlify request path or query string. Explicit report sharing can place names and record data in the URL fragment, which is not sent to Netlify but remains visible to the browser, its history, and recipients. Cloudflare receives POST wire bodies; Google and Quad9 receive base64url-encoded RFC 8484 GET parameters so their endpoints work under browser CORS. Resolver URLs are fixed, and the selected resolver can read or log the question under either method. There is no application proxy, analytics, telemetry, tracking pixel, or default query history.

SPF macros can place parts of supplied mailbox, IP, HELO/EHLO, or receiver values into resolver-visible DNS questions. DKIM message verification keeps the raw message in page memory and sends only derived selector TXT questions. DMARC alignment sends boundary questions derived from supplied domains. Netlify still sees ordinary page requests. Local storage contains the snapshot opt-in boolean and the anonymous bounded rate-limit ledger, but no query history, DNS content, or pasted input.

### Misleading security conclusions

Statuses are evidence-scoped. Recursive data is not called authoritative or global. Missing DNSSEC AD is not called unsigned. NSEC3 Opt-Out is not called a proven insecure delegation, and unsupported cryptography is not called invalid. Unsafe SPF input receives no flattened output, and a sender result describes only one supplied context. DMARC alignment conclusions are conditional on supplied prior authentication evidence. A DKIM pass authenticates only the signed content for its signing domain and does not imply DMARC alignment or delivery. Partial lookup failures remain visible.

### Supply chain and deployment

Runtime dependencies use MIT, BSD-2-Clause, or ISC licences and are version-locked. Dependency lifecycle scripts require version-pinned approval, and quality automation performs a vulnerability audit before format, lint, strict type checking, deterministic tests, browser tests, and a static build. Netlify security headers are committed and should be verified after deployment.
