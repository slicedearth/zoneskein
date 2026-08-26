# Complete-zone integrity model

## Purpose and evidence boundary

ZoneSkein can calculate and verify ZONEMD records for a supplied complete standalone zone. The mode is disabled until the visitor explicitly confirms that the input is complete. It never infers completeness from an SOA, origin, record count, or filename and does not fetch a zone transfer.

A matching digest establishes that the supplied records produce the same canonical checksum as the supplied apex publication. By itself, this is useful for detecting accidental alteration but does not authenticate the source: an attacker able to replace the zone text can also replace an unauthenticated digest. A covering RRSIG in pasted text is reported but not trusted by the file workflow. The independent live DNSSEC tool can authenticate a selected published ZONEMD RRset, but the visitor must still compare that trusted publication with the digest calculated for the intended complete zone.

## Canonical calculation

The implementation follows the SIMPLE scheme in RFC 8976 and uses an in-house TypeScript encoder rather than a zone-digest package. It:

- resolves relative owners and embedded domain names against the parsed origin;
- encodes class IN records in canonical uncompressed DNS wire form;
- lower-cases domain-name octets while preserving opaque RDATA octets;
- sorts owners by canonical DNS name order, then by numeric type and canonical RDATA;
- omits exact duplicate records while rejecting inconsistent TTLs for equivalent records;
- excludes data outside the zone, apex ZONEMD records, and apex RRSIG records covering type 63;
- includes non-apex type 63 records as ordinary data;
- treats named ZONEMD and RFC 3597 `TYPE63` forms identically;
- calculates required SHA-384 and supported SHA-512 digests with browser Web Crypto; and
- accepts a verification result when at least one valid, supported apex publication matches, while retaining mismatching or unsupported publications as evidence.

The encoder covers the practical parser profile: A, AAAA, CAA, CNAME, DNAME, DNSKEY, DS, HTTPS, MX, NAPTR, NS, NSEC, NSEC3, PTR, RRSIG, SOA, SRV, SSHFP, SVCB, TLSA, TXT, URI, ZONEMD, and RFC 3597 generic numeric RDATA. It fails closed if a record, name, timestamp, escape, class, length, or inherited TTL cannot be represented exactly.

## Bounds and interoperability

The shared parser accepts at most 262,144 input characters, 4,096 records, 8,192 logical statements, and 32,768 tokens. Canonical digest input is capped at 2 MiB, each RDATA value at 65,535 octets, and snapshots at 262,144 UTF-8 octets. An oversized report remains visible but cannot be persisted as a snapshot.

Tests reproduce the published SIMPLE and complex interoperability examples, including case folding, owner and type ordering, wildcard owners, duplicate omission, non-apex type 63 handling, and out-of-zone exclusion. Named and generic numeric forms must calculate the same digest. See [RFC 8976](https://www.rfc-editor.org/rfc/rfc8976.html) for the protocol definition.
