# Security

## Reporting a vulnerability

Use the repository’s private security-advisory feature for vulnerabilities that could expose visitor data, bypass an intended safety boundary, execute untrusted content, or cause material resolver abuse. Do not include sensitive details in a public issue before a fix is available.

For non-sensitive correctness bugs, open a normal repository issue with a minimal reproducible input, expected result, actual result, browser, and ZoneSkein version or commit.

## Security model

ZoneSkein is a static browser application:

- it has no application server, credentials, accounts, or server-side data store;
- all network targets are fixed DNS-over-HTTPS endpoints;
- all outbound DNS requests use RFC 8484 wire format over a fixed GET or POST transport verified for browser CORS, with omitted credentials, no referrer, an eight-second timeout, and bounded concurrency;
- names, policies, zone snippets, fragments, and resolver data are validated or narrowed before use;
- untrusted content is rendered through React text nodes and is never injected as HTML;
- the Netlify configuration sets a restrictive Content Security Policy, frame protections, a conservative referrer policy, `nosniff`, and a minimal Permissions Policy;
- local snapshots require explicit opt-in and have count and size limits.

## Abuse resistance

ZoneSkein limits normal use with a shared four-request semaphore, per-resolver token buckets, a rolling request window, bounded first-in-first-out queues, replay-resistant cross-tab request signals, an 80-question per-run budget, TTL caching, in-flight deduplication, cancellation, graph depth limits, cycle detection, and capped resolver cooldown circuits. Its bounded cross-tab ledger stores only opaque request identifiers, timestamps, resolver buckets, and cooldown expiries, never questions or answers.

Because source and execution are in the visitor’s browser, these controls cannot prevent a modified copy from issuing different requests. Resolver operators remain the authoritative enforcement boundary for hostile clients.

## Supported versions

Security fixes are made on the current `main` branch. There is no separate long-term-support branch during the 0.x series.

## Deployment responsibilities

Deployers should preserve the committed Netlify headers, keep dependencies current, review lockfile changes, run all quality gates, and verify live response headers after each deployment. A custom domain should use HTTPS and an appropriate DNS configuration.
