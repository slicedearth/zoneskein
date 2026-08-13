# DNSSEC validation model

## Trust anchor and questions

ZoneSkein begins with the IANA root KeyDigest records bundled into the static build. A maintenance check downloads IANA’s current XML and detached CMS signature, validates the signer through a reviewed ICANN root certificate committed with the source, and fails when the current anchor set differs. The pinned certificate has SHA-256 fingerprint `AE:E8:99:06:D7:CC:60:C5:E1:51:F3:BB:92:3A:BF:8A:1B:28:DC:85:5D:5E:21:27:CB:52:4E:AD:4A:AD:60:3D` and expires on 18 December 2029, so its replacement must be reviewed explicitly before then. Runtime validation does not fetch trust anchors or silently update them.

For a requested name, including the root, ZoneSkein asks the selected recursive resolver for the root DNSKEY RRset and then DS and DNSKEY material for each possible delegation towards the requested name. Requests use DNS wire format with `CD=1` and `DO=1`, allowing the browser to validate returned material independently of the resolver’s AD decision.

Every response must have the expected zero ID, exactly one matching IN-class question, an untruncated body, and the requested name and type. The transport checks a declared body length before reading, streams at most 65,535 octets, and rejects malformed section counts or trailing data. The validator then isolates the exact owner, class, type, and answer-section RRset with only its own covering RRSIG records. Unrelated, wrong-class, or sibling data cannot authenticate the requested RRset.

## Local validation

At the root, each bounded candidate DNSKEY is hashed and compared with an in-date bundled IANA anchor. A matching anchor key must then authenticate the complete root DNSKEY RRset.

For each secure delegation:

1. The already trusted parent DNSKEY set verifies the exact child DS RRset.
2. ZoneSkein calculates DS digests over the canonical child owner and DNSKEY RDATA.
3. A supported authenticated DS must match a returned child DNSKEY by digest, key tag, and signing algorithm.
4. The matching child key verifies the exact child DNSKEY RRset before its eligible zone keys become trusted for the next step.

DS digest types SHA-1, SHA-256, and SHA-384 are implemented for validation. Browser cryptography supports RSA/SHA-1 algorithms 5 and 7 for legacy validation, RSA/SHA-256 algorithm 8, RSA/SHA-512 algorithm 10, ECDSA P-256/SHA-256 algorithm 13, ECDSA P-384/SHA-384 algorithm 14, and Ed25519 algorithm 15 when the browser exposes it. SHA-1 signing is deprecated for new DNSSEC deployments, but current standards still require validating resolvers to support existing signatures.

RRSIG time fields use 32-bit DNS serial arithmetic and reject zero-length, half-range, or longer ambiguous intervals. Signatures must use the exact infrastructure owner-label count, remain inside the signer’s zone, identify an eligible zone key, and canonicalise without error. Exact duplicate RRset members use DNS set semantics. NSEC Next Domain Name RDATA retains its original wire case during signature verification, as clarified by RFC 6840. Fixed external vectors cover every claimed signing algorithm, all three DS digests, mixed-case NSEC RDATA, canonical names, and time wrap-around independently of the production signing-data helper.

Each cryptographic step records when it was checked. Before returning any authenticated terminal result, ZoneSkein also requires every supporting verified signature and the selected root trust anchor to be current at one final common instant. A chain assembled from non-overlapping validity windows remains incomplete.

## Authenticated denial

An absent DS RRset is not automatically an unsigned delegation. ZoneSkein requires signatures from the already trusted parent and evaluates the denial data locally.

- An exact-owner NSEC proof establishes an insecure delegation only when its canonical bitmap has NS present and DS, SOA, CNAME, and DNAME absent.
- A signed NSEC interval can establish that an intermediate label is an empty non-terminal. Canonical ordering compares raw label octets with ASCII case folding and cannot cross a delegation or DNAME boundary.
- An exact-match NSEC3 proof applies the same delegation bitmap rules and validates canonical owner, flag, hash-length, iteration, salt, and bitmap structure.
- An NSEC3 Opt-Out proof requires authenticated records for the longest matching closest provable encloser and an Opt-Out interval covering its next-closer name with identical parameters.

Opt-Out does not authenticate that the covered name exists. It proves only that the name may or may not exist as an insecure delegation, so ZoneSkein stops with **Opt-Out: existence indeterminate**. It never upgrades that proof to an insecure delegation based on an unsigned response code or referral.

An authenticated DNAME bitmap stops with a separate alias-boundary result because this validator does not follow and validate the resulting alias chain. Malformed bitmaps, reserved flags, wrong hash lengths, out-of-zone owners or signers, contradictory DS bits, invalid signatures, and incomplete proof sets fail closed. Complete NXDOMAIN, wildcard, alias-chain, and arbitrary application NODATA validation remain outside this delegation-chain model.

## Resource and cache bounds

The application limits each run to 80 DNS questions, four concurrent requests, and eight seconds per network request. DNSSEC applies both per-operation and shared whole-run bounds: 64 records, 16 signatures, and 32 keys for one RRset; 64 authority records and 32 denial RRsets for one denial; 500 NSEC3 iterations per record; and aggregate ceilings of 4,096 record examinations, 1,024 key examinations, 512 signatures, 512 digest operations, 512 cryptographic verification attempts, and 20,000 NSEC3 hash rounds. Cancellation is checked between bounded digest and verification operations.

Authenticated cache entries expire at the earliest applicable received RR TTL, RRSIG TTL, RRSIG Original TTL, negative TTL, or signature expiry. Negative data is additionally capped at three hours, and response age is subtracted before insertion. In-flight deduplication, per-resolver token buckets, a rolling cross-tab window, cooldowns, and the ordinary question budget also apply.

These browser-side controls limit normal use but are not tamper-resistant. A modified static client can bypass them, so public resolvers still enforce their own service controls.

## Conclusions

- **Locally validated** means every actual delegation encountered from a current bundled root anchor to the requested name authenticated locally at the report’s common validation instant.
- **Insecure delegation** means exact, locally authenticated parent denial evidence establishes an unsigned child delegation.
- **Opt-Out: existence indeterminate** means authenticated NSEC3 evidence covers the name but cannot prove whether an insecure delegation exists.
- **Not a delegation** means authenticated evidence shows that the requested or intermediate name is not an unsigned zone cut.
- **DNAME boundary** means authenticated evidence reaches an alias boundary that this delegation-chain validator does not follow.
- **Bogus** means a supported authentication path was present but failed, was malformed, or contradicted the response.
- **Unsupported** means no available browser cryptographic path could evaluate the required algorithm.
- **Incomplete** means required evidence was absent, did not remain valid at one common instant, exceeded a work bound, was not safely modelled, or could not be retrieved.

The resolver remains the transport and can omit, delay, replay within cache and signature lifetimes, or block data. It cannot make an unrelated or unsigned RRset locally valid. A secure delegation path does not establish service safety, global consistency, correct application records, or successful certificate or email operation.
