# Privacy

Last reviewed: 26 August 2026

## Summary

ZoneSkein is static-first. Its only server-side application component is an automatic Netlify compatibility relay used only after a qualifying direct Quad9 failure. The delivered browser application necessarily holds active inputs and results in page memory.

## Live DNS questions

When a visitor starts a live tool, the browser sends bounded DNS-over-HTTPS wire messages to the selected resolver path:

- Google Public DNS;
- Cloudflare 1.1.1.1; or
- Quad9.

Google and Cloudflare requests are direct. Quad9 starts directly and can switch automatically to the compatibility path described below. For direct requests, the resolver receives the DNS question and browser connection information. In compatibility mode, Netlify receives the visitor connection and Quad9 receives the function connection. Each service's privacy policy and operating jurisdiction applies. ZoneSkein cannot control platform or resolver logging or retention. Resolver URLs are fixed in source; visitors cannot supply arbitrary fetch targets.

Every wire query includes EDNS Client Subnet with a zero source prefix (`0.0.0.0/0`). This asks the recursive resolver and any downstream authority not to tailor the answer to an address-derived client subnet. It does not hide the browser's connection address from the selected resolver, force the resolver to discard that address, or replace the resolver's privacy policy.

Every query also includes an all-zero EDNS Padding option that rounds the complete DNS message up to a 128-octet block. This follows the encrypted-DNS query strategy in RFC 8467 and reduces exact query-length fingerprinting. It does not conceal the question from the resolver, make differently sized blocks indistinguishable, hide request timing or count, add cover traffic, or guarantee that a resolver pads its response.

Direct live tools do not place visitor-supplied DNS names in the Netlify page-request path or query string. Quad9 compatibility mode uses the fixed same-origin path `/api/doh/quad9` and a POST body, not a DNS-name-bearing path or query string. An explicitly created share link can contain report names and data after `#`; browsers do not send that fragment in the HTTP request to Netlify.

Cloudflare questions use RFC 8484 POST bodies. Google and direct Quad9 questions use RFC 8484 GET because their standards-compliant POST endpoints do not currently work with ordinary browser CORS; the DNS wire message is base64url-encoded in the selected resolver's `dns=` URL parameter. Base64url is readable encoding, not encryption. The selected resolver and local browser tooling or extensions can observe the encoded request URL. HTTPS protects it in transit from ordinary passive network observers. Direct Quad9 additionally requires the browser's complete network path to preserve HTTP/2 or HTTP/3.

The single Quad9 option uses the first real question as its direct capability probe. A valid response locks the run to direct mode. A qualifying transport, timeout, or HTTP failure instead switches the run once to **Quad9 (compatibility mode)** and retries that question; concurrent questions wait for the decision. Cancellation, rate limiting, a DNS response, an invalid response, cooldown, or a local work-bound failure does not trigger compatibility mode. The interface discloses this behaviour before a run, and results and exports identify the actual path.

In compatibility mode, the browser sends one bounded RFC 8484 wire question in a POST body to `/api/doh/quad9`. Netlify receives the question and ordinary connection metadata, and a fixed Node.js HTTP/2 client forwards it only to `https://dns.quad9.net/dns-query`. No user-supplied upstream, DNS-name-bearing request query string, cookie, credential, application log, or server-side response cache is used. Netlify's platform and infrastructure policies still govern any connection metadata or platform-level processing outside ZoneSkein's application code. Quad9 receives the forwarded question and the relay connection information. HTTPS protects each transport leg; it does not hide the question from Netlify in compatibility mode or from Quad9.

## Hosting requests

Netlify receives ordinary requests for ZoneSkein pages and static assets. In Quad9 compatibility mode it also receives the bounded DNS wire question described above. It may process or retain visitor connection information under its own policies. ZoneSkein's application does not log relay bodies or add analytics identifiers, advertising identifiers, tracking pixels, telemetry, or third-party error reporting.

When ZoneSkein is served on `zoneskein.com`, Cloudflare operates the authoritative DNS for the hostname and can process hostname-resolution metadata under its own policies. The verified deployment keeps Netlify-facing records in DNS-only mode, so Cloudflare does not proxy ZoneSkein page, asset, or relay HTTP traffic.

## Email and sender inputs

SPF sender mode accepts a client IP address, complete MAIL FROM identity, HELO/EHLO domain, and optional receiver name. These values remain in page memory and are not saved or shared automatically. SPF macros can place the mailbox local part, supplied IP address, HELO/EHLO name, or receiver name into DNS question labels. The selected resolver can read and log those derived questions. Copying the full evaluation explicitly places those inputs and results on the clipboard; use synthetic inputs unless the resolver and clipboard destination are authorised to receive the real values. For a pass, the separate DMARC hand-off contains the authenticated SPF identity domain, whether that identity came from MAIL FROM or from HELO for a null reverse path, the result, capture time, fixed resolver identifier, and schema metadata. For every non-pass result, it omits the unauthenticated domain and identity source. The hand-off always excludes the mailbox local part, client IP, receiver input, policy text, and evaluation trace.

DKIM message mode reads pasted message text or `.eml` bytes locally. Raw bytes, headers, addresses, and body content remain in page memory and are never sent to Netlify, a resolver, IndexedDB, or a share link. Only derived `selector._domainkey.signing-domain` TXT questions leave the browser. Copied verification JSON excludes the raw message, uploaded filename, message addresses, and body. It redacts any DKIM AUID local-part but can retain signing metadata and the AUID and signing domains. The separate DMARC hand-off is narrower: it contains only unique passing production signing domains, capture times, reconstructed-line-ending caveats, fixed resolver identifiers, and schema metadata. It excludes selectors, identities, key records, signatures, headers, body hashes, filenames, diagnostics, and message content.

DMARC alignment mode accepts domains and claimed prior authentication results, not a raw message. Those inputs remain in page memory and are not saved or shared automatically. A hand-off from the SPF or DKIM route remains in current application memory until it is replaced, cleared, edited, or the page is reloaded. A visitor can explicitly copy or paste the same minimal JSON through the clipboard; the import is UTF-8, size, nesting, duplicate-key, exact-schema, timestamp, resolver, result, domain, uniqueness, and count checked before use. The selected resolver receives the DNS boundary questions derived from the supplied domains. Imported resolver identifiers are displayed as inert provenance and never select or create a network destination.

## Browser storage

Query history is not persisted by default. Normal DNS responses use a bounded in-memory TTL cache that disappears with the page session.

To coordinate abuse controls across tabs, ZoneSkein uses an origin-wide browser reservation lock where available and stores a bounded rate-limit ledger in local storage. Replay-resistant cross-tab messages update in-memory state but do not overwrite that canonical ledger. Browsers without origin-wide locks retain a best-effort cross-tab fallback. The ledger contains only random request identifiers, timestamps, per-resolver buckets, and temporary cooldown expiry times. It contains no DNS names, record types, answers, pasted content, or report data. Request events cover a rolling one-minute window; any resolver cooldown is capped at 15 minutes, and stale state is rejected.

Local snapshots are a separate, explicit opt-in feature:

- the opt-in state contains only a boolean and an opaque storage-generation identifier, with no DNS name;
- only reports saved by a separate user action enter IndexedDB;
- at most 100 reports are retained;
- each report is limited to 256 KiB of UTF-8 content;
- imported or stored control characters are displayed and copied with visible escape notation; when controls are present, the exact report bytes are offered separately as Base64 rather than copied as visually ambiguous text;
- snapshots remain until explicitly deleted, the feature is disabled and erased, browser storage is cleared, or the oldest snapshot is evicted at the 100-report limit;
- disabling local snapshots first records an origin-wide erasure marker, invalidates the active storage generation, and blocks every new save, import, or deletion before clearing and deleting IndexedDB; the interface reports blocked or failed deletion, keeps storage disabled until a failed erasure is retried, and claims erasure only after the browser confirms it.

ZoneSkein uses no cookies. It does not use local storage for query history or DNS content; local storage holds only snapshot control state and the bounded anonymous rate-limit ledger described above.

## Change Workspace files

A Change Workspace is held only in the current page's React memory unless the visitor explicitly downloads it. Import reads a bounded local file in the browser; it does not upload the file, save it to IndexedDB, place it in a URL fragment, or contact any resolver endpoint contained in the file. Those endpoints are rendered as inert historical provenance.

An exported workspace can contain DNS names and records, availability notes, change risk and rollback guidance, timestamps, and retained resolver observations. A canonical SHA-256 mismatch shows that the content no longer matches the included digest, but a match provides no authenticity or tamper resistance because the digest is stored with the file and can be recomputed. The digest does not encrypt the file. The downloaded file, clipboard paths, browser download history, backups, and every recipient are outside ZoneSkein's control.

## Share links

Share links are created only after an explicit action. Report state is encoded in the URL fragment after `#`, which browsers do not send in the HTTP request to the hosting server.

Fragments are not secret storage. The contents may remain in browser history, clipboard history, screenshots, logs created by browser extensions, or messages where the link is shared. Anyone who receives the complete link can decode the report.

## Pasted data

Zone snippets, proposed changes, Record Studio working sets, raw messages, and sender or alignment inputs stay in the browser. A Record Studio working set enters IndexedDB only after an explicit snapshot action. The DKIM message, SPF sender, and DMARC alignment pages provide no snapshot or share action for their sensitive inputs. Their minimal mail-authentication hand-off remains memory-only unless the visitor explicitly copies it to the clipboard. Untrusted DNS and pasted text are rendered as text, never as HTML.

Only enter, query, import, copy, save, or export personal, customer, employee, message, or internal infrastructure information when you are authorised to process it and disclose it to the selected resolver, intermediary, clipboard destination, storage location, or recipient. Prefer synthetic data for demonstrations. The separate [hosted service terms](TERMS.md) describe acceptable use; they do not restrict the AGPL rights in copies of the software.
