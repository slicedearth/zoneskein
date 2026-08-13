# Limitations

## DNS observations

ZoneSkein queries recursive resolvers, not authoritative nameservers directly. Results are point-in-time resolver observations affected by caches, resolver policy, DNS filtering, EDNS behaviour, and network conditions. Comparing three resolvers does not establish global propagation.

When supplied, Extended DNS Errors are resolver-provided explanations rather than independently verified conclusions. Negative-cache guidance uses the lesser of the authority SOA TTL and SOA MINIMUM field; a response without the required SOA is not cached as a negative answer by ZoneSkein.

The browser must permit cross-origin DNS-over-HTTPS requests. Enterprise policy, extensions, regional resolver behaviour, or temporary CORS changes may block a resolver independently of DNS itself.

## DNSSEC

ZoneSkein starts with a bundled, reviewed IANA root trust-anchor set, verifies each root, DS, and DNSKEY RRset locally, compares DS digests, and uses authenticated NSEC or bounded NSEC3 evidence to distinguish exact insecure delegations from missing evidence. Resolver AD flags remain evidence only and never decide the local result.

The validator is intentionally narrower than a general-purpose recursive validator. It validates the delegation path, not arbitrary application RRsets, wildcard-expanded infrastructure RRsets, complete NXDOMAIN proofs, or DNAME alias targets. It supports the signing algorithms available through browser Web Crypto and bounds questions, response bytes, records, keys, signatures, digests, cryptographic attempts, NSEC3 work, and wall-clock network waits. A final authenticated conclusion requires every supporting signature and trust anchor to be current at one common instant.

NSEC3 Opt-Out proves that a covered name may or may not exist as an insecure delegation. ZoneSkein therefore stops with an explicit Opt-Out result instead of labelling it an authenticated insecure delegation. DNAME boundaries, unsupported, incomplete, insecure, not-delegated, bogus, and secure outcomes also remain distinct.

Bundled anchors are checked by a maintenance command against IANA’s detached CMS signature and a reviewed, pinned ICANN root certificate. This is a release-time update process, not RFC 5011 automated rollover. A stale build can therefore become unable to establish current trust and must be updated.

## SPF

The analyser models lookup-causing terms and follows includes and redirects within bounded depth and question budgets. It reports policy term counts separately from the DNS-over-HTTPS questions ZoneSkein made.

The snapshot flattener refuses output when correctness depends on macros, `exists`, `ptr`, cycles, unsupported syntax, non-pass DNS mechanism qualifiers, multiple SPF records, incomplete data, or lookup failures. Generated ranges can become stale as providers change infrastructure. Snapshot output is never published automatically.

The response-size value is an estimate for a conventional answer and can differ with owner-name compression, DNSSEC records, EDNS, resolver additions, or authoritative-server behaviour.

## Zone snippets and diffs

The zone parser supports a practical subset of comments, quoted TXT strings, parentheses, `$ORIGIN`, `$TTL`, inherited owners, relative names, explicit TTL, IN class, and common types. It is not a complete BIND parser. Provider extensions such as ALIAS, ANAME, proprietary flattening, routing policies, health checks, and provider-side templates require provider validation.

Diff normalisation treats ordinary RRset ordering as non-semantic and recognises selected name and numeric fields. It cannot predict every application dependency or assign a universal propagation-complete time.

## DMARC, DKIM, and CAA

DMARC inspection follows the bounded DNS Tree Walk, validates published policy syntax, and checks external reporting authorisation records. A tree walk can identify only the policy expressed in DNS; it does not inspect messages, prove SPF or DKIM alignment, test report delivery, or predict receiver enforcement.

DKIM inspection validates one supplied selector and imports supported public keys. It does not discover selectors, inspect a message, or verify a message signature.

CAA inspection follows a bounded parent walk and explains the first observed policy, including standardised account, validation-method, and S/MIME controls. It does not authenticate a certificate request, interpret every CA-specific parameter, or guarantee that issuance succeeds or fails.

## Client-side controls

Rate limits and input bounds protect the normal application path. They are not tamper-resistant and cannot constrain a modified client.
