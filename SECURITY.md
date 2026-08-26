# Security

## Reporting a vulnerability

Use the repository’s private security-advisory feature for vulnerabilities that could expose visitor data, bypass an intended safety boundary, execute untrusted content, or cause material resolver abuse. Do not include sensitive details in a public issue before a fix is available.

For non-sensitive correctness bugs, open a normal repository issue with a minimal reproducible input, expected result, actual result, browser, and ZoneSkein version or commit.

## Security model

ZoneSkein is a static-first browser application with one bounded Netlify Function:

- it has no accounts, application credentials, server-side data store, server-rendered route, analytics, telemetry, or general-purpose application API;
- all DNS network targets are fixed DNS-over-HTTPS endpoints; the only server-side function accepts explicitly selected Quad9 relay requests and has one fixed upstream;
- all outbound DNS requests use RFC 8484 wire format over a fixed GET or POST transport verified for browser CORS, with omitted credentials, no referrer, an eight-second timeout, and bounded concurrency;
- direct Quad9 remains the default; its compatibility relay uses a same-origin POST with the expected DNS media type and no request query string or browser credentials, applies a 4,096-byte request cap, a 65,535-byte response cap, strict DNS message and work bounds, and a fixed timeout, and opens a fixed Node.js HTTP/2 connection to `https://dns.quad9.net/dns-query` without forwarding cookies or credentials;
- relay responses declare `Cache-Control: no-store` and relay bodies are not written to application logs; the normal bounded browser memory cache still applies after validation, and Netlify can observe the relayed question and ordinary connection metadata under its platform policies;
- names, policies, SMTP sender inputs, raw messages, zone snippets, fragments, and resolver data are validated, bounded, or narrowed before use;
- untrusted content is rendered through React text nodes and is never injected as HTML;
- the Netlify configuration sets a restrictive Content Security Policy, frame protections, a conservative referrer policy, `nosniff`, and a minimal Permissions Policy;
- raw-message canonicalisation and signature verification run locally within a 1,048,576-byte input limit, a 65,536-character header-block limit, 1,000 headers, and 20 signatures; only derived DKIM selector TXT questions cross the network;
- local snapshots require explicit opt-in and have count and size limits, while the anonymous bounded rate-limit ledger contains no questions, answers, names, or pasted content.
- portable Change Workspace imports are byte-bounded, strictly decoded and schema-validated, and quarantined on a SHA-256 mismatch; imported resolver endpoints remain inert data rather than fetch targets.

## Abuse resistance

ZoneSkein limits normal use with a shared four-request semaphore, per-resolver token buckets, a rolling request window, bounded first-in-first-out queues, origin-wide reservation locks where the browser provides them, replay-resistant cross-tab request signals, an 80-question per-run budget, TTL caching, in-flight deduplication, cancellation, graph depth limits, cycle detection, pasted-message and macro-work bounds, and capped resolver cooldown circuits. Its bounded cross-tab ledger stores only opaque request identifiers, timestamps, resolver buckets, and cooldown expiries, never questions, answers, names, or pasted content. Cross-tab signals cannot rewrite the canonical locked ledger; browsers without origin-wide locks retain a best-effort fallback. The optional Quad9 relay additionally uses Netlify's server-side rate limiting at 120 requests per minute, aggregated by source IP address and site domain.

Browser-side controls cannot prevent a modified copy from issuing different direct requests. The relay's server-side validation, fixed target, resource bounds, and rate limit still apply to relay traffic; Quad9 and Netlify retain their own service protections.

The hosted service is for lawful, authorised, interactive use. Its acceptable-use terms prohibit bypassing bounds, bulk discovery, unsolicited scanning, spam, or traffic intended to burden the hosting platform, a resolver, or an authoritative server. Those hosted-use conditions do not limit the right to run modified copies under the AGPL.

## Supported versions

Security fixes are made on the current `main` branch. There is no separate long-term-support branch during the 0.x series.

## Deployment responsibilities

Deployers should preserve the committed Netlify headers and function rate limit, keep dependencies current, review lockfile changes, run all quality gates, and retain the build artefact verifier. Production builds omit source maps and fail when output files, sizes, public legal documents, corresponding-source contents or checksum, redirects, resolver/CSP origins, or the single allowlisted function contract depart from the deployment contract. The browser gate includes route-wide WCAG A/AA automation, narrow-screen reflow, keyboard focus, and forced-colour checks; automation supplements rather than replaces manual assistive-technology review. Tagged releases distinguish the browser-only static archive, complete bounded Netlify deployment archive, and corresponding-source archive; checksums and attestations cover each applicable artefact. These artefacts do not replace verification of the deployed Netlify application and function. Verify live response headers, source download and checksum, direct resolver requests, relay rejection behaviour, and rate limiting after each deployment. A custom domain should use HTTPS and an appropriate DNS configuration.
