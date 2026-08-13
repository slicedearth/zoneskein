# Privacy

## Summary

ZoneSkein has no application backend. It does not receive, proxy, or store the DNS names a visitor queries.

## Live DNS questions

When a visitor starts a live tool, the browser sends DNS-over-HTTPS wire messages directly to the explicitly selected resolver:

- Google Public DNS;
- Cloudflare 1.1.1.1; or
- Quad9.

The resolver receives the DNS question and network connection information. Its privacy policy and operating jurisdiction apply. ZoneSkein cannot control resolver logging or retention. Resolver URLs are fixed in source; visitors cannot supply arbitrary fetch targets.

DNS names never enter ZoneSkein page URLs or Netlify request URLs. Cloudflare questions use RFC 8484 POST bodies. Google and Quad9 questions use RFC 8484 GET because their standards-compliant POST endpoints do not currently work with ordinary browser CORS; the DNS wire message is base64url-encoded in the selected resolver’s `dns=` URL parameter. This is not encryption beyond HTTPS, and the resolver can decode or log it. In every case, the selected resolver receives the DNS name and network connection information.

## Hosting requests

Netlify receives ordinary requests for ZoneSkein pages and static assets. It may process or retain visitor connection information under its own policies. The application does not add analytics identifiers, advertising identifiers, tracking pixels, telemetry, or third-party error reporting.

## Browser storage

Query history is not persisted by default. Normal DNS responses use a bounded in-memory TTL cache that disappears with the page session.

Local snapshots are a separate, explicit opt-in feature:

- the opt-in preference is one boolean and contains no DNS name;
- only reports saved by a separate user action enter IndexedDB;
- at most 100 reports are retained;
- each report is limited to 256 KiB of UTF-8 content;
- disabling local snapshots erases the IndexedDB database and the opt-in preference.

ZoneSkein uses no cookies. It does not use local storage for query history.

## Share links

Share links are created only after an explicit action. Report state is encoded in the URL fragment after `#`, which browsers do not send in the HTTP request to the hosting server.

Fragments are not secret storage. The contents may remain in browser history, clipboard history, screenshots, logs created by browser extensions, or messages where the link is shared. Anyone who receives the complete link can decode the report.

## Pasted data

Zone snippets, proposed changes, and report generation stay in the browser. Untrusted DNS and pasted text are rendered as text, never as HTML.
