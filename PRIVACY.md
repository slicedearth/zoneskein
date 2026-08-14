# Privacy

## Summary

ZoneSkein's operator has no application backend that receives, proxies, or stores visitor DNS names or pasted content. The delivered browser application necessarily holds active inputs and results in page memory.

## Live DNS questions

When a visitor starts a live tool, the browser sends DNS-over-HTTPS wire messages directly to the explicitly selected resolver:

- Google Public DNS;
- Cloudflare 1.1.1.1; or
- Quad9.

The resolver receives the DNS question and network connection information. Its privacy policy and operating jurisdiction apply. ZoneSkein cannot control resolver logging or retention. Resolver URLs are fixed in source; visitors cannot supply arbitrary fetch targets.

Every wire query includes EDNS Client Subnet with a zero source prefix (`0.0.0.0/0`). This asks the recursive resolver and any downstream authority not to tailor the answer to an address-derived client subnet. It does not hide the browser's connection address from the selected resolver, force the resolver to discard that address, or replace the resolver's privacy policy.

Live tools do not place visitor-supplied DNS names in the Netlify request path or query string. An explicitly created share link can contain report names and data after `#`; browsers do not send that fragment in the HTTP request to Netlify.

Cloudflare questions use RFC 8484 POST bodies. Google and Quad9 questions use RFC 8484 GET because their standards-compliant POST endpoints do not currently work with ordinary browser CORS; the DNS wire message is base64url-encoded in the selected resolver's `dns=` URL parameter. Quad9 additionally requires the browser's complete network path to preserve HTTP/2 or HTTP/3. ZoneSkein does not relay an incompatible connection through Netlify or another resolver. This is not encryption beyond HTTPS, and the selected resolver can decode or log the question and connection information.

## Hosting requests

Netlify receives ordinary requests for ZoneSkein pages and static assets. It may process or retain visitor connection information under its own policies. The application does not add analytics identifiers, advertising identifiers, tracking pixels, telemetry, or third-party error reporting.

## Email and sender inputs

SPF sender mode accepts a client IP address, complete MAIL FROM identity, HELO/EHLO domain, and optional receiver name. These values remain in page memory and are not saved or shared automatically. SPF macros can place the mailbox local part, supplied IP address, HELO/EHLO name, or receiver name into DNS question labels. The selected resolver can read and log those derived questions. Copying the evaluation explicitly places those inputs and results on the clipboard; use synthetic inputs unless the resolver and clipboard destination are authorised to receive the real values.

DKIM message mode reads pasted message text or `.eml` bytes locally. Raw bytes, headers, addresses, and body content remain in page memory and are never sent to Netlify, a resolver, IndexedDB, or a share link. Only derived `selector._domainkey.signing-domain` TXT questions leave the browser. Copied verification JSON excludes the raw message, uploaded filename, message addresses, and body. It redacts any DKIM AUID local-part but can retain signing metadata and the AUID and signing domains.

DMARC alignment mode accepts domains and claimed prior authentication results, not a raw message. Those inputs remain in page memory and are not saved or shared automatically. The selected resolver receives the DNS boundary questions derived from the supplied domains.

## Browser storage

Query history is not persisted by default. Normal DNS responses use a bounded in-memory TTL cache that disappears with the page session.

To coordinate abuse controls across tabs, ZoneSkein stores a bounded rate-limit ledger in local storage. It contains only random request identifiers, timestamps, per-resolver buckets, and temporary cooldown expiry times. It contains no DNS names, record types, answers, pasted content, or report data, and entries age out automatically.

Local snapshots are a separate, explicit opt-in feature:

- the opt-in preference is one boolean and contains no DNS name;
- only reports saved by a separate user action enter IndexedDB;
- at most 100 reports are retained;
- each report is limited to 256 KiB of UTF-8 content;
- disabling local snapshots asks other ZoneSkein tabs to release the database, erases IndexedDB, and then clears the opt-in preference; the interface reports blocked or failed deletion and claims erasure only after the browser confirms it.

ZoneSkein uses no cookies. It does not use local storage for query history or DNS content; local storage holds only the snapshot opt-in boolean and the bounded anonymous rate-limit ledger described above.

## Change Workspace files

A Change Workspace is held only in the current page's React memory unless the visitor explicitly downloads it. Import reads a bounded local file in the browser; it does not upload the file, save it to IndexedDB, place it in a URL fragment, or contact any resolver endpoint contained in the file. Those endpoints are rendered as inert historical provenance.

An exported workspace can contain DNS names and records, availability notes, change risk and rollback guidance, timestamps, and retained resolver observations. A canonical SHA-256 mismatch shows that the content no longer matches the included digest, but a match provides no authenticity or tamper resistance because the digest is stored with the file and can be recomputed. The digest does not encrypt the file. The downloaded file, clipboard paths, browser download history, backups, and every recipient are outside ZoneSkein's control.

## Share links

Share links are created only after an explicit action. Report state is encoded in the URL fragment after `#`, which browsers do not send in the HTTP request to the hosting server.

Fragments are not secret storage. The contents may remain in browser history, clipboard history, screenshots, logs created by browser extensions, or messages where the link is shared. Anyone who receives the complete link can decode the report.

## Pasted data

Zone snippets, proposed changes, Record Studio working sets, raw messages, and sender or alignment inputs stay in the browser. A Record Studio working set enters IndexedDB only after an explicit snapshot action. The DKIM message, SPF sender, and DMARC alignment pages provide no snapshot or share action for their sensitive inputs. Untrusted DNS and pasted text are rendered as text, never as HTML.
