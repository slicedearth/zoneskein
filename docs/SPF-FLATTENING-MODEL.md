# SPF analysis and snapshot model

## Ordered parsing

SPF is tokenised before parsing. The AST preserves source order, original text, qualifier, mechanism or modifier type, argument, dual CIDR lengths, macro presence, and character offsets.

Every consumer uses the same fail-closed character grammar: a policy may contain printable ASCII and ordinary spaces only. Tabs, line breaks, non-breaking spaces, other Unicode separators, and control characters are errors rather than alternative token separators.

Supported mechanisms are `all`, `include`, `a`, `mx`, `ptr`, `ip4`, `ip6`, and `exists`. Supported modifiers are `redirect` and `exp`.

## Budget analysis

The DNS-causing SPF terms are `include`, `a`, `mx`, `ptr`, `exists`, and `redirect`. ZoneSkein follows include and redirect edges and reports the maximum cumulative count along a possible evaluation path. Terms after `all` are unreachable and do not contribute to that path.

Void lookups are tracked per DNS question and separately for IPv4 and IPv6 sender paths. The MX question and every applicable exchanger A or AAAA question therefore contribute independently. Two voids in one family produce a warning; more than two produce an error and block snapshot output. Mixed A and AAAA absences are not incorrectly added across mutually exclusive sender families. The SPF term count is deliberately separate from ZoneSkein’s own DNS-over-HTTPS question count: one `a` term can require A and AAAA questions, while `mx` requires MX plus address questions.

Graph traversal is cycle-safe and depth-bounded. It stops the complete run when an eleventh DNS-causing term is reached instead of recursively materialising an invalid path. A shared work contract also bounds dependency visits, graph edges, term expansions, response bytes, per-answer and aggregate values, retained addresses, provenance entries and provenance bytes. One answer can contribute at most 256 values, one analysis can retain at most 1,024 address values, and one user run cannot exceed 80 unique DNS questions. Crossing any bound produces an explicit incomplete analysis and no partial snapshot. Batched analysis and coalescing yield cooperatively so cancellation can be observed.

## Safe pass-set extraction

Snapshot generation evaluates only finite pass-authorising terms:

- `ip4` and `ip6` networks;
- default or explicit `+a` through observed A and AAAA answers;
- default or explicit `+mx` through observed MX targets and their A and AAAA answers;
- default or explicit `+include` through the referenced policy’s effective pass set;
- `redirect` when it becomes the effective policy;
- a terminal `all` qualifier.

An include is never replaced with the referenced policy text. Only its finite pass set is imported. A referenced `+all` is unbounded and blocks output.

Snapshot output is refused for macros, `exists`, `ptr`, cycles, multiple policies, invalid or unsupported syntax, lookup or answer-shape failures, lookup- or void-limit violations, unresolved expansions, incomplete traversal, work-bound exhaustion, or non-pass qualifiers on DNS mechanisms. Unsafe results expose blockers only: partial networks and provenance are not retained, rendered, copied, or saved.

## Networks and ordering

Exact networks are deduplicated. CIDR networks are coalesced only when their union is identical to the observed authorised set. IPv4 and IPv6 remain separate. Provenance remapping uses bounded indexed address ranges and set keys rather than nested linear searches. Any policy construct whose ordered behaviour cannot be represented as one finite pass set blocks the snapshot.

## Output and staleness

A successful snapshot provides:

- one SPF value;
- a generic BIND TXT record;
- character-strings no longer than 255 UTF-8 octets;
- bounded provenance for every generated network;
- generated time, earliest source expiry, and conservative recheck time;
- estimated response size and warnings near 450 characters or beyond 512 bytes;
- JSON and Markdown evidence.

Every result is labelled “Point-in-time SPF snapshot — provider address ranges may change.” Flattening can reduce receiver evaluation lookups, but transfers maintenance responsibility from the provider’s live policy to the domain operator’s snapshot.

Freshness is represented as an absolute expiry derived from each DNS response’s original observation time. The minimum includes every required root, include and redirect TXT policy plus MX, A and AAAA evidence. A cached response therefore contributes only its remaining lifetime; its original TTL is never restarted when the snapshot is generated. If any required response lacks an absolute expiry, aggregate freshness and the recommended recheck remain explicitly unknown. An already expired dependency blocks output.
