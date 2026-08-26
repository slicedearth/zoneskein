# Complete-zone integrity model

## Purpose and evidence boundary

ZoneSkein can calculate and verify ZONEMD records for a supplied complete standalone zone. The mode is disabled until the visitor explicitly confirms that the input is complete. It never infers completeness from an SOA, origin, record count, or filename and does not fetch a zone transfer.

A matching digest establishes that the supplied records produce the same canonical checksum as the supplied apex publication. By itself, this is useful for detecting accidental alteration but does not authenticate the source: an attacker able to replace the zone text can also replace an unauthenticated digest. A covering RRSIG in pasted text is reported but not trusted by the file workflow. The independent live DNSSEC tool can authenticate a selected published ZONEMD RRset, but the visitor must still compare that trusted publication with the digest calculated for the intended complete zone.

## Canonical calculation

The implementation follows the SIMPLE scheme in RFC 8976 and uses an in-house TypeScript encoder rather than a zone-digest package. It:

- resolves relative owners and embedded domain names against the origin active for each record, including nested relative `$ORIGIN` directives;
- splits raw master-file names only at unescaped dots, decodes character and decimal escapes to exact label octets, and retains escaped separator structure through hashing;
- encodes class IN records in canonical uncompressed DNS wire form;
- lower-cases uppercase US-ASCII octets in canonical domain names while preserving other label and opaque RDATA octets;
- sorts owners by canonical DNS name order, then by numeric type and canonical RDATA;
- omits exact duplicate records while rejecting inconsistent TTLs for equivalent records;
- excludes data outside the zone, apex ZONEMD records, and apex RRSIG records covering type 63;
- includes non-apex type 63 records as ordinary data;
- treats numeric aliases by semantic RR type, including canonical name-bearing RDATA, `TYPE63` publications, and outer `TYPE46` signatures covering type 63;
- decodes service-binding parameters in their defined two-stage presentation grammar so escaped ALPN commas remain data while unescaped commas remain list separators;
- calculates required SHA-384 and supported SHA-512 digests with browser Web Crypto; and
- accepts a verification result when at least one valid, supported apex publication matches, while retaining mismatching or unsupported publications as evidence.

The encoder covers the practical parser profile: A, AAAA, CAA, CNAME, DNAME, DNSKEY, DS, HTTPS, MX, NAPTR, NS, NSEC, NSEC3, PTR, RRSIG, SOA, SRV, SSHFP, SVCB, TLSA, TXT, URI, ZONEMD, and RFC 3597 generic numeric RDATA. Generic forms of known name-bearing types receive the same canonical transformations as their mnemonic forms; unknown numeric RDATA remains opaque. It fails closed if a record, name, timestamp, escape, class, length, origin context, or inherited TTL cannot be represented exactly.

## Bounds and interoperability

The shared parser accepts at most 262,144 input characters, 4,096 records, 8,192 logical statements, and 32,768 tokens. Canonical digest input is capped at 2 MiB, each RDATA value at 65,535 octets, and snapshots at 262,144 UTF-8 octets. An oversized report remains visible but cannot be persisted as a snapshot.

Tests reproduce the published SIMPLE and complex interoperability examples, including case folding, owner and type ordering, wildcard owners, duplicate omission, non-apex type 63 handling, and out-of-zone exclusion. Named and generic numeric forms must calculate the same digest. Additional fixed-wire vectors cover escaped label separators, active per-record origins, numeric outer signatures, generic name-bearing aliases, and service-binding list escapes. See [RFC 8976](https://www.rfc-editor.org/rfc/rfc8976.html) for the protocol definition.
