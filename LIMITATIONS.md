# Limitations

## DNS observations

ZoneSkein queries recursive resolvers, not authoritative nameservers directly. Results are point-in-time resolver observations affected by caches, resolver policy, DNS filtering, EDNS behaviour, and network conditions. Comparing three resolvers does not establish global propagation.

When supplied, Extended DNS Errors are resolver-provided explanations rather than independently verified conclusions. Negative-cache guidance uses the lesser of the authority SOA TTL and SOA MINIMUM field; a response without the required SOA is not cached as a negative answer by ZoneSkein. Resolution failures never inherit authority TTLs: repeated failures use a bounded in-memory backoff from five seconds to five minutes and a later successful response clears that failure history.

The browser must permit cross-origin DNS-over-HTTPS requests. Enterprise policy, extensions, regional resolver behaviour, or temporary CORS changes may block a resolver independently of DNS itself.

## DNSSEC

ZoneSkein starts with a bundled, reviewed IANA root trust-anchor set, verifies each root, DS, and DNSKEY RRset locally, compares DS digests, and uses authenticated NSEC or bounded NSEC3 evidence to distinguish exact insecure delegations from missing evidence. It can then validate selected exact-positive A, AAAA, CAA, CNAME, HTTPS, MX, NS, PTR, SOA, SRV, SVCB, TLSA, and TXT RRsets with the authenticated containing-zone keys. Resolver AD flags remain evidence only and never decide the local result.

The validator is intentionally narrower than a general-purpose recursive validator. It does not yet complete application NODATA, NXDOMAIN, wildcard-denial, or CNAME and DNAME target-continuation proofs. An exact CNAME RRset result therefore authenticates that RRset, not its target. It supports the signing algorithms available through browser Web Crypto and bounds questions, response bytes, records, keys, signatures, digests, cryptographic attempts, NSEC3 work, and wall-clock network waits. RSA/SHA-1 algorithms 5 and 7 remain available for legacy RRSIG validation, but RFC 9905 DS records using them are treated as insecure rather than secure delegation paths. A final authenticated conclusion requires every supporting signature and trust anchor to be current at one common instant.

NSEC3 Opt-Out proves that a covered name may or may not exist as an insecure delegation. ZoneSkein therefore stops with an explicit Opt-Out result instead of labelling it an authenticated insecure delegation. DNAME boundaries, unsupported, incomplete, insecure, not-delegated, bogus, and secure outcomes also remain distinct.

Bundled anchors are checked by a maintenance command against IANA’s detached CMS signature and a reviewed, pinned ICANN root certificate. This is a release-time update process, not RFC 5011 automated rollover. A stale build can therefore become unable to establish current trust and must be updated.

## SPF

The analyser models lookup-causing terms and follows includes and redirects within bounded depth and question budgets. It reports policy term counts separately from the DNS-over-HTTPS questions ZoneSkein made.

The snapshot flattener refuses output when correctness depends on macros, `exists`, `ptr`, cycles, unsupported syntax, non-pass DNS mechanism qualifiers, multiple SPF records, incomplete data, or lookup failures. Generated ranges can become stale as providers change infrastructure. Snapshot output is never published automatically.

Sender-context mode models one supplied SMTP client IP, MAIL FROM identity, HELO/EHLO domain, and optional receiver name against one point-in-time resolver observation. It is not an SMTP transaction and cannot reproduce a receiver's cache, local policy, or delivery decision. SPF macros can place portions of those inputs into DNS question names sent to the selected resolver.

The response-size value is an estimate for a conventional answer and can differ with owner-name compression, DNSSEC records, EDNS, resolver additions, or authoritative-server behaviour.

## Zone snippets, Record Studio, and Change Lab

The zone parser supports a practical subset of comments, quoted TXT strings, parentheses, `$ORIGIN`, `$TTL`, inherited owners, relative names, explicit TTL, IN class, and common types. It is not a complete BIND parser. Provider extensions such as ALIAS, ANAME, proprietary flattening, routing policies, health checks, and provider-side templates require provider validation.

Record Studio serialises 18 supported record types and applies the practical zone linter to a bounded local working set. It does not know provider-specific syntax, account permissions, existing authoritative records, signing policy, or the intended zone cut, and it never publishes records.

Change Lab normalisation treats ordinary RRset ordering as non-semantic and recognises selected name and numeric fields. Its risk and timing guidance is derived only from supplied or selected records. Unselected RR types, provider behaviour, application dependencies, and recursive-cache state remain outside its evidence, so it cannot assign a universal propagation-complete time.

## DMARC, DKIM, and CAA

DMARC policy mode follows the bounded RFC 9989 DNS Tree Walk, validates published policy syntax, and checks RFC 9990 and RFC 9991 external-reporting authorisation records. Alignment mode accepts an RFC5322.From domain, already-passing DKIM `d=` domains, and an SPF result with its authenticated MAIL FROM domain. It does not parse or authenticate a message; every alignment conclusion is conditional on the supplied prior authentication evidence, the selected resolver observation, and completed organisational-boundary walks. It does not apply ARC or receiver-local policy, generate reports, test report delivery, or predict enforcement.

DKIM key mode validates one supplied selector and imports supported public keys; it does not discover selectors. Message mode locally parses a bounded pasted message or byte-preserving `.eml` file and verifies at most 20 RSA-SHA256 or Ed25519-SHA256 signatures. Other algorithms, ARC, DMARC alignment, sender reputation, and delivery are outside its scope. Pasted text with reconstructed CRLF is labelled accordingly, and an `l=` signature authenticates only its signed body prefix.

CAA inspection follows a bounded parent walk and explains the first observed policy, including standardised account, validation-method, and S/MIME controls. It does not authenticate a certificate request, interpret every CA-specific parameter, or guarantee that issuance succeeds or fails.

## Client-side controls

Rate limits and input bounds protect the normal application path. They are not tamper-resistant and cannot constrain a modified client.
