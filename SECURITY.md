# Security

## Reporting a vulnerability

Use the repository’s private security-advisory feature for vulnerabilities that could expose visitor data, bypass an intended safety boundary, execute untrusted content, or cause material resolver abuse. Do not include sensitive details in a public issue before a fix is available.

For non-sensitive correctness bugs, open a normal repository issue with a minimal reproducible input, expected result, actual result, browser, and ZoneSkein version or commit.

## Security model

ZoneSkein is a static browser application:

- it has no application server, credentials, accounts, or server-side data store;
- all network targets are fixed DNS-over-HTTPS endpoints;
- all outbound DNS requests use RFC 8484 wire format over a fixed GET or POST transport verified for browser CORS, with omitted credentials, no referrer, an eight-second timeout, and bounded concurrency;
- names, policies, SMTP sender inputs, raw messages, zone snippets, fragments, and resolver data are validated, bounded, or narrowed before use;
- untrusted content is rendered through React text nodes and is never injected as HTML;
- the Netlify configuration sets a restrictive Content Security Policy, frame protections, a conservative referrer policy, `nosniff`, and a minimal Permissions Policy;
- raw-message canonicalisation and signature verification run locally within a 1,048,576-byte input limit, a 65,536-character header-block limit, 1,000 headers, and 20 signatures; only derived DKIM selector TXT questions cross the network;
- local snapshots require explicit opt-in and have count and size limits, while the anonymous bounded rate-limit ledger contains no questions, answers, names, or pasted content.

## Abuse resistance

ZoneSkein limits normal use with a shared four-request semaphore, per-resolver token buckets, a rolling request window, bounded first-in-first-out queues, replay-resistant cross-tab request signals, an 80-question per-run budget, TTL caching, in-flight deduplication, cancellation, graph depth limits, cycle detection, pasted-message and macro-work bounds, and capped resolver cooldown circuits. Its bounded cross-tab ledger stores only opaque request identifiers, timestamps, resolver buckets, and cooldown expiries, never questions, answers, names, or pasted content.

Because source and execution are in the visitor’s browser, these controls cannot prevent a modified copy from issuing different requests. Resolver operators remain the authoritative enforcement boundary for hostile clients.

## Supported versions

Security fixes are made on the current `main` branch. There is no separate long-term-support branch during the 0.x series.

## Deployment responsibilities

Deployers should preserve the committed Netlify headers, keep dependencies current, review lockfile changes, run all quality gates, and verify live response headers after each deployment. A custom domain should use HTTPS and an appropriate DNS configuration.
