# SPF analysis and snapshot model

## Ordered parsing

SPF is tokenized before parsing. The AST preserves source order, original text, qualifier, mechanism or modifier type, argument, dual CIDR lengths, macro presence, and character offsets.

Supported mechanisms are `all`, `include`, `a`, `mx`, `ptr`, `ip4`, `ip6`, and `exists`. Supported modifiers are `redirect` and `exp`.

## Budget analysis

The DNS-causing SPF terms are `include`, `a`, `mx`, `ptr`, `exists`, and `redirect`. ZoneSkein follows include and redirect edges and reports the maximum cumulative count along a possible evaluation path. Terms after `all` are unreachable and do not contribute to that path.

Void lookups are tracked along the same path. Two voids produce a warning; more than two produce an error. The SPF term count is deliberately separate from ZoneSkein’s own DNS-over-HTTPS question count: one `a` term can require A and AAAA questions, while `mx` requires MX plus address questions.

Graph traversal is cycle-safe and depth-bounded. One user run cannot exceed 80 unique DNS questions.

## Safe pass-set extraction

Snapshot generation evaluates only finite pass-authorizing terms:

- `ip4` and `ip6` networks;
- default or explicit `+a` through observed A and AAAA answers;
- default or explicit `+mx` through observed MX targets and their A and AAAA answers;
- default or explicit `+include` through the referenced policy’s effective pass set;
- `redirect` when it becomes the effective policy;
- a terminal `all` qualifier.

An include is never replaced with the referenced policy text. Only its finite pass set is imported. A referenced `+all` is unbounded and blocks output.

Snapshot output is refused for macros, `exists`, `ptr`, cycles, multiple policies, invalid or unsupported syntax, lookup failures, unresolved expansions, incomplete traversal, or non-pass qualifiers on DNS mechanisms.

## Networks and ordering

Exact networks are deduplicated. CIDR networks are coalesced only when their union is identical to the observed authorized set. IPv4 and IPv6 remain separate. Any policy construct whose ordered behavior cannot be represented as one finite pass set blocks the snapshot.

## Output and staleness

A successful snapshot provides:

- one SPF value;
- a generic BIND TXT record;
- character-strings no longer than 255 UTF-8 octets;
- provenance for every generated network;
- generated time, earliest source expiry, and conservative recheck time;
- estimated response size and warnings near 450 characters or beyond 512 bytes;
- JSON and Markdown evidence.

Every result is labelled “Point-in-time SPF snapshot — provider address ranges may change.” Flattening can reduce receiver evaluation lookups, but transfers maintenance responsibility from the provider’s live policy to the domain operator’s snapshot.
