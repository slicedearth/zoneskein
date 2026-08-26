# Threat model

## Assets

- DNS names, SMTP sender identities, client addresses, and configuration snippets entered by a visitor;
- raw email messages and locally derived authentication evidence;
- accuracy of protocol conclusions and generated records;
- availability of public DNS-over-HTTPS resolvers;
- availability and bounded use of the optional Quad9 compatibility relay;
- local snapshot contents;
- integrity of the deployed static-first application and bounded relay.

## Trust boundaries

The visitor trusts the delivered static files, browser runtime, selected resolver, Netlify's hosting and optional Quad9 relay execution, and their own device. ZoneSkein is static-first; its only server-side application component is the bounded Quad9 compatibility function.

Resolver responses, DNS record text, pasted zone or message data, SMTP sender inputs, mail-authentication hand-off JSON, URL fragments, imported snapshots, and Change Workspace files are untrusted. Browser extensions and local malware are outside the application's protection boundary.

## Threats and controls

### Arbitrary requests and SSRF-like behaviour

All resolver definitions and endpoints are compile-time allowlisted. The UI accepts no URL, host, or protocol for network destinations. CSP `connect-src` repeats the browser allowlist. The Quad9 relay is exposed only at `/api/doh/quad9` and its Node.js HTTP/2 client can connect only to `https://dns.quad9.net/dns-query`; it rejects a request query string and never interprets caller input as a target. Browser credentials are omitted and referrers are suppressed. The function does not forward cookies or credentials.

### Resolver abuse

Shared concurrency, token buckets, a rolling request window, bounded first-in-first-out queues, origin-wide reservation locks where available, cross-tab signals, replay-resistant opaque request identifiers, run budgets, timeouts, cooldown circuits, TTL caching, in-flight deduplication, depth limits, cycle detection, and bounded targets reduce accidental amplification. Cross-tab state has strict shapes, size and age limits, contains no questions or answers, and falls back to best-effort coordination when browser locking, messaging, or storage is unavailable. Received messages cannot overwrite the canonical locked ledger. There is no bulk input, subdomain generation, ANY query, or automatic retry storm.

A modified client can bypass browser-side controls for direct resolver requests. The optional Quad9 relay separately accepts only one bounded DNS wire question per POST, limits request and response bytes, DNS parsing work and time, and uses Netlify's 120-request-per-minute limit aggregated by source IP address and site domain. Visitors sharing an apparent egress address can share an allowance, and distributed addresses retain separate allowances, so this is not an absolute upstream traffic cap. The relay has no arbitrary target, automatic retry loop, server-side response cache, or unrestricted request body. Quad9 and Netlify retain their own service protections.

### Resource exhaustion

Names, zone snippets, parser statements, tokens, diagnostics, records, proposed changes, plan findings, raw-message bytes, header fields, DKIM signatures, SPF macro output, evidence traces, mail-authentication hand-off bytes, JSON depth and entries, snapshot records, fragments, graph depth, MX expansion, unique questions, cache entries, snapshot count, and snapshot size are bounded. DNS responses additionally require one question and cap resource records, TXT chunks, EDNS options and expanded type-bitmap values before the general decoder can allocate from them. SVCB and HTTPS parameter presentation is bounded separately; an excessive record is shown through one explicit exact-raw fallback rather than silently truncated or expanded into an unbounded DOM. SPF analysis and snapshot construction additionally cap dependency visits, graph edges, term expansions, response bytes, answer values, retained addresses, provenance and rendered output; crossing a protocol or work bound stops traversal and exposes no partial snapshot evidence. Mail-authentication JSON is inspected for duplicate keys and excessive nesting before parsing, then accepted only through an exact schema with canonical domains and timestamps. Complete-zone digest work is additionally limited to 2 MiB of canonical wire records and fails closed before hashing when a record cannot be encoded exactly. Resource exhaustion produces an explicit incomplete result rather than a retained prefix comparison or rollout plan. DNSSEC also has whole-run limits for records, keys, signatures, digests, cryptographic attempts, and NSEC3 hash rounds. Long-running work observes cancellation between bounded cryptographic operations. Browser DNS response bodies are streamed through the DNS wire limit rather than allocated without a bound. The relay rejects requests above 4,096 octets and upstream responses above 65,535 octets before forwarding a result to the browser.

Change Workspace files are rejected before reading when their declared size exceeds the file limit, then decoded with fatal UTF-8, duplicate-key, canonical-value, schema, count, and string bounds. A mismatched digest is quarantined until explicit acknowledgement. A later file read cannot overwrite a newer clear or edit, and retained endpoint strings never become network authority.

### Untrusted content execution

React renders record and pasted values as text. No `dangerouslySetInnerHTML`, arbitrary HTML, third-party UI script, remote font, or record-derived URL navigation is used. CSP blocks objects, frames, unexpected connections, and non-self scripts.

Analyst-facing technical values are isolated left-to-right. Control characters, default-ignorable characters, replacement characters, and malformed UTF-8 are shown with visible, injective escape notation; literal backslashes are doubled so they cannot impersonate those escapes. DNS views and structured exports retain raw RDATA, EDE text, or complete message octets as Base64 where exact wire evidence is required. Malformed TXT bytes are not passed to DKIM, SPF, or policy semantics. Copied Markdown wraps each untrusted value in a delimiter-sized literal code span and protects table boundaries, so record text cannot become a link, image, raw HTML block, heading, quote, or list in a downstream CommonMark/GFM renderer.

Imported snapshot fragments are reparsed at copy and import time. Unsafe report text is copied only in visibly escaped form, with the exact UTF-8 bytes offered separately as Base64. Change Workspace files reject invisible controls, and an explicitly accepted digest mismatch remains structured session provenance through edits, reanalysis, route remounts, and an unchanged Change Lab return.

### Privacy leakage

Direct live tools do not place visitor-supplied DNS names in a Netlify page-request path or query string. Explicit report sharing can place names and record data in the URL fragment, which is not sent to Netlify but remains visible to the browser, its history, and recipients. Cloudflare receives POST wire bodies; Google and **Quad9 (direct)** receive base64url-encoded RFC 8484 GET parameters for direct browser CORS. Base64url is encoding rather than encryption, so the resolver and local browser tooling can observe that URL. Each DNS query is padded with zero octets to the next 128-octet RFC 8467 block, reducing exact query-size fingerprinting without hiding the question, block size, request timing, request count, or resolver-visible connection metadata. Quad9 requires end-to-end HTTP/2 or HTTP/3 and is reported unavailable when the client's direct network path cannot provide it. Quad9 (direct) remains the default Quad9 path.

The visitor can explicitly opt into **Quad9 (compatibility mode)**. Netlify then receives the DNS wire question in the POST body plus ordinary connection metadata, and Quad9 receives the forwarded question and the relay connection information. The fixed path and upstream contain no visitor-supplied target or request query string; the function does not use or forward cookies or credentials and has no application log or server-side response cache. Platform-level processing remains governed by Netlify's policies. Resolver URLs remain fixed, and the selected resolver can read or log the question under either direct method or compatibility mode. There is no general-purpose application proxy, analytics, telemetry, tracking pixel, or default query history.

SPF macros can place parts of supplied mailbox, IP, HELO/EHLO, or receiver values into resolver-visible DNS questions and, when Quad9 relay mode is selected, into questions visible to Netlify. DKIM message verification keeps the raw message in page memory and sends only derived selector TXT questions. The optional DMARC hand-off minimises data to domains, SPF result and bounded provenance; it excludes mailbox local parts, client addresses, raw messages, selectors, policy text, and traces. It remains in current React memory unless the visitor explicitly copies it, after which clipboard handling is outside the application boundary. DMARC alignment sends boundary questions derived from supplied domains. Netlify also sees ordinary page requests. Local storage contains snapshot control state and the anonymous bounded rate-limit ledger, but no query history, DNS content, pasted input, or mail-authentication hand-off.

### Misleading security conclusions

Statuses are evidence-scoped. Recursive data is not called authoritative or global. Missing DNSSEC AD is not called unsigned. NSEC3 Opt-Out is not called a proven insecure delegation, and unsupported cryptography is not called invalid. A matching complete-zone digest is called internal consistency rather than authenticity unless a separate trusted path authenticates the published digest, and an authenticated digest RRset is not treated as proof that unrelated local text is complete. Unsafe SPF input receives no flattened output, and a sender result describes only one supplied context. DMARC alignment conclusions are conditional on supplied prior authentication evidence. Transferred evidence is not reverified, its resolver identifier is inert provenance, and reconstructed DKIM input remains visibly qualified. A DKIM pass authenticates only the signed content for its signing domain and does not imply DMARC alignment or delivery. Partial lookup failures remain visible.

Workspace analysis preserves unavailable and partial inputs explicitly. It never converts a missing current snapshot into record removals. A digest mismatch shows internal inconsistency; a match is not described as tamper resistance, author identity, authorisation, or authenticity because the included digest can be recomputed.

### Supply chain and deployment

Runtime dependencies use MIT, BSD-2-Clause, or ISC licences and are version-locked. Dependency lifecycle scripts require version-pinned approval, and quality automation performs a vulnerability audit before format, lint, strict type checking, deterministic tests, browser tests, and a checked static-first build. The build emits the exact corresponding source under a committed file inventory, per-file manifest, archive checksum, compressed and expanded bounds, link rejection, and independent byte-for-byte verification; generated output and local configuration roots cannot enter it. Netlify security headers and the single function's route and rate-limit configuration are committed and should be verified after deployment. The build verifier rejects an unexpected source file set, function file, upstream, route, or rate-limit contract. The relay has one request-and-upstream lifecycle deadline and explicit HTTP/2 push, session-memory, concurrency, and header bounds.
