# Limitations

## DNS observations

ZoneSkein queries recursive resolvers, not authoritative nameservers directly. Results are point-in-time resolver observations affected by caches, resolver policy, DNS filtering, EDNS behaviour, and network conditions. Comparing three resolvers does not establish global propagation.

When supplied, Extended DNS Errors are resolver-provided explanations rather than independently verified conclusions. Negative-cache guidance uses the lesser of the authority SOA TTL and SOA MINIMUM field; a response without the required SOA is not cached as a negative answer by ZoneSkein. Resolution failures never inherit authority TTLs: repeated failures use a bounded in-memory backoff from five seconds to five minutes and a later successful response clears that failure history.

The browser must permit cross-origin DNS-over-HTTPS requests. Enterprise policy, extensions, regional resolver behaviour, or temporary CORS changes may block a resolver independently of DNS itself. Quad9 requires an end-to-end HTTP/2 or HTTP/3 path for direct DNS-over-HTTPS; a browser, VPN, inspection product, or network proxy that forces HTTP/1.1 can make **Quad9 (direct)** unavailable without establishing anything about the queried DNS name. Direct mode remains the default Quad9 path and ZoneSkein never silently substitutes a transport or resolver. A visitor can explicitly select **Quad9 (compatibility mode)**, which forwards the bounded wire question through the same-origin Netlify relay only to Quad9 over HTTP/2. Compatibility mode changes the privacy boundary because Netlify receives the question as well as ordinary connection metadata.

## DNSSEC

ZoneSkein starts with a bundled, reviewed IANA root trust-anchor set, verifies each root, DS, and DNSKEY RRset locally, compares DS digests, and uses authenticated NSEC or bounded NSEC3 evidence to distinguish exact insecure delegations from missing evidence. It can then validate selected exact-positive A, AAAA, CAA, CNAME, HTTPS, MX, NS, PTR, SOA, SRV, SVCB, TLSA, and TXT RRsets with the authenticated containing-zone keys. Resolver AD flags remain evidence only and never decide the local result.

The validator is intentionally narrower than a general-purpose recursive validator. For its selected application types it can authenticate exact positive and NODATA answers, NXDOMAIN, wildcard synthesis or wildcard NODATA, and bounded CNAME, DNAME, and SVCB/HTTPS AliasMode continuation. A direct CNAME inspection authenticates that CNAME RRset as the requested result; when another type is requested, every followed alias and the final RRset must authenticate. Divergent authenticated AliasMode targets remain Incomplete until bounded branch validation is implemented; ZoneSkein does not choose or query one arbitrarily. RSA, ECDSA, and Ed25519 signature operations use browser Web Crypto. Ed448 uses one locked, independently reviewed cryptographic primitive because Web Crypto does not expose Ed448; ZoneSkein retains the DNS wire binding, canonicalisation, key policy, work limits, and result classification. The validator bounds questions, alias transitions, response bytes, records, keys, signatures, digests, cryptographic attempts, NSEC3 work, and wall-clock network waits. RSA/SHA-1 algorithms 5 and 7 remain available for legacy RRSIG validation, but RFC 9905 DS records using them are treated as insecure rather than secure delegation paths. A final authenticated conclusion requires every supporting signature and trust anchor to be current at one common instant, and a secure evidence bundle records its earliest supporting signature expiry.

NSEC3 Opt-Out proves that a covered name may or may not exist as an insecure delegation. ZoneSkein therefore stops with an explicit Opt-Out result instead of labelling it an authenticated insecure delegation, and does not use Opt-Out to authenticate application NODATA, wildcard synthesis, or name existence. DNAME boundary, Unsupported, Incomplete, Insecure delegation, Not a delegation, Bogus, and Locally validated outcomes also remain distinct.

Bundled anchors are checked by a maintenance command against IANA’s detached CMS signature and a reviewed, pinned ICANN root certificate. Each result reports whether that release-time review is current, due after 45 days, or overdue after 90 days, and separately warns when the pinned certificate is within 180 days of expiry. This is not RFC 5011 automated rollover. A stale build can therefore become unable to establish current trust and must be updated.

## SPF

The analyser models lookup-causing terms and follows includes and redirects within bounded depth and question budgets. It reports policy term counts separately from the DNS-over-HTTPS questions ZoneSkein made.

The snapshot flattener refuses output when correctness depends on macros, `exists`, `ptr`, cycles, unsupported syntax, non-pass DNS mechanism qualifiers, multiple SPF records, incomplete data, or lookup failures. Generated ranges can become stale as providers change infrastructure. Snapshot output is never published automatically.

Sender-context mode models one supplied SMTP client IP, MAIL FROM identity, HELO/EHLO domain, and optional receiver name against one point-in-time resolver observation. It is not an SMTP transaction and cannot reproduce a receiver's cache, local policy, or delivery decision. SPF macros can place portions of those inputs into DNS question names sent to the selected resolver.

The response-size value is an estimate for a conventional answer and can differ with owner-name compression, DNSSEC records, EDNS, resolver additions, or authoritative-server behaviour.

## Zone snippets, Record Studio, Change Lab, and Change Workspace

The zone parser supports a practical subset of comments, quoted TXT strings, parentheses, `$ORIGIN`, `$TTL`, inherited owners, relative names, explicit TTL, IN class, and common types. It is not a complete BIND parser. Provider extensions such as ALIAS, ANAME, proprietary flattening, routing policies, health checks, and provider-side templates require provider validation.

Record Studio serialises 18 supported record types and applies the practical zone linter to a bounded local working set. It does not know provider-specific syntax, account permissions, existing authoritative records, signing policy, or the intended zone cut, and it never publishes records.

Change Lab normalisation treats ordinary RRset ordering as non-semantic and recognises selected name and numeric fields. Its risk and timing guidance is derived only from supplied or selected records. Unselected RR types, provider behaviour, application dependencies, and recursive-cache state remain outside its evidence, so it cannot assign a universal propagation-complete time.

Change Workspace carries bounded current and intended BIND-style text, explicit complete, partial, or unavailable state, structured Change Lab analysis, and optional historical resolver evidence. It does not discover missing records, poll propagation, publish DNS, persist automatically, or authenticate an author. Import validation checks structure and internal consistency; it does not reproduce or endorse stored analysis, which remains supplied historical data until local reanalysis. A SHA-256 mismatch shows that the content no longer matches the included digest; a match shows internal consistency only because anyone modifying the file can recompute its digest. Imported resolver endpoints are inert provenance and are never queried. Local reanalysis is blocked when either zone state is unavailable and remains partial when an input is partial, so unknown data is never interpreted as an empty zone.

Workspace JSON, snapshots, copied evidence, share fragments, and source-archive checksums are not encryption or signatures. Visitors are responsible for having authority to process the data they enter and for protecting every export and recipient they choose.

## DMARC, DKIM, and CAA

DMARC policy mode follows the bounded RFC 9989 DNS Tree Walk, validates published policy syntax, and checks RFC 9990 and RFC 9991 external-reporting authorisation records. Alignment mode accepts an RFC5322.From domain, already-passing DKIM `d=` domains, and an SPF result with its authenticated MAIL FROM domain. It does not parse or authenticate a message; every alignment conclusion is conditional on the supplied prior authentication evidence, the selected resolver observation, and completed organisational-boundary walks. It does not apply ARC or receiver-local policy, generate reports, test report delivery, or predict enforcement.

DKIM key mode validates one supplied selector and imports supported public keys; it does not discover selectors. Message mode locally parses a bounded pasted message or byte-preserving `.eml` file and verifies at most 20 RSA-SHA256 or Ed25519-SHA256 signatures. Other algorithms, ARC, DMARC alignment, sender reputation, and delivery are outside its scope. Pasted text with reconstructed CRLF is labelled accordingly, and an `l=` signature authenticates only its signed body prefix.

CAA inspection follows a bounded parent walk and explains the first observed policy, including standardised account, validation-method, and S/MIME controls. It does not authenticate a certificate request, interpret every CA-specific parameter, or guarantee that issuance succeeds or fails.

## Abuse controls

Browser rate limits and input bounds protect the normal direct path. Origin-wide browser locks make a shared reservation atomic where supported; browsers without them retain best-effort cross-tab coordination. These controls are not tamper-resistant and cannot constrain a modified client. The optional Quad9 relay separately enforces its own fixed target, method, media type, query shape, request and response size, DNS work, timeout, and 120-request-per-minute rate limit per source IP address and site domain. Visitors behind one apparent egress address can share that allowance, while distributed source addresses have separate allowances; it is not an absolute site-wide upstream cap. Those controls reduce abuse of this function but do not make recursive results authoritative or prove global propagation.
