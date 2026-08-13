# Limitations

## DNS observations

ZoneSkein queries recursive resolvers, not authoritative nameservers directly. Results are point-in-time resolver observations affected by caches, resolver policy, DNS filtering, EDNS behavior, and network conditions. Comparing three resolvers does not establish global propagation.

The browser must permit cross-origin DNS-over-HTTPS requests. Enterprise policy, extensions, regional resolver behavior, or temporary CORS changes may block a resolver independently of DNS itself.

## DNSSEC

ZoneSkein calculates DNSKEY key tags and SHA-256 or SHA-384 DS candidates, compares parent DS records to child DNSKEY records, checks RRSIG time windows, and verifies DNSKEY RRset signatures for supported Web Crypto algorithms.

It does not:

- ship and update a root trust anchor;
- independently validate every delegation from the root to the requested zone;
- cryptographically validate the returned parent DS RRset;
- verify every application RRset;
- prove NSEC or NSEC3 denial of existence;
- treat `AD=false` as proof of an unsigned delegation.

Resolver `SERVFAIL` with checking-disabled DNSSEC material is described as “likely bogus,” not an absolute conclusion.

## SPF

The analyser models lookup-causing terms and follows includes and redirects within bounded depth and question budgets. It reports policy term counts separately from the DNS-over-HTTPS questions ZoneSkein made.

The snapshot flattener refuses output when correctness depends on macros, `exists`, `ptr`, cycles, unsupported syntax, non-pass DNS mechanism qualifiers, multiple SPF records, incomplete data, or lookup failures. Generated ranges can become stale as providers change infrastructure. Snapshot output is never published automatically.

The response-size value is an estimate for a conventional answer and can differ with owner-name compression, DNSSEC records, EDNS, resolver additions, or authoritative-server behavior.

## Zone snippets and diffs

The zone parser supports a practical subset of comments, quoted TXT strings, parentheses, `$ORIGIN`, `$TTL`, inherited owners, relative names, explicit TTL, IN class, and common types. It is not a complete BIND parser. Provider extensions such as ALIAS, ANAME, proprietary flattening, routing policies, health checks, and provider-side templates require provider validation.

Diff normalization treats ordinary RRset ordering as non-semantic and recognizes selected name and numeric fields. It cannot predict every application dependency or assign a universal propagation-complete time.

## DMARC, DKIM, and CAA

DMARC inspection validates published policy syntax and external reporting authorization records. It does not inspect messages, prove SPF or DKIM alignment, test report delivery, or predict receiver enforcement.

DKIM inspection validates one supplied selector and imports supported public keys. It does not discover selectors, inspect a message, or verify a message signature.

CAA inspection follows a bounded parent walk and explains the first observed policy. It does not authenticate a certificate request, interpret every CA-specific parameter, or guarantee that issuance succeeds or fails.

## Client-side controls

Rate limits and input bounds protect the normal application path. They are not tamper-resistant and cannot constrain a modified client.
