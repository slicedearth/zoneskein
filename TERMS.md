# Hosted service terms

Effective: 27 August 2026

These terms apply to the hosted ZoneSkein website, its automatic Quad9 compatibility relay, and its browser-initiated use of the external measurement service. They do not restrict the rights granted in ZoneSkein’s source code by the GNU Affero General Public License version 3.

## Intended use

ZoneSkein is a bounded DNS inspection, validation, authoring, and change-review workbench. It provides point-in-time technical evidence and local planning assistance. It is not an authoritative DNS service, a security certification, legal advice, or a guarantee of publication, propagation, certificate issuance, email delivery, or future behaviour.

Use the hosted service only for lawful purposes and only with DNS names, records, messages, sender details, workspace files, and other information that you are authorised to process and disclose. Prefer synthetic data when real mailbox, client-address, message, customer, employee, or internal infrastructure information is not required.

Do not use the hosted service to:

- evade its request, resource, queue, or rate limits;
- generate bulk discovery, unsolicited scanning, spam, or abusive resolver traffic;
- interfere with Netlify, Globalping, a measurement probe, a selected resolver, an authoritative DNS server, or another person’s systems;
- submit unlawful material or information obtained or disclosed without appropriate authority; or
- imply that ZoneSkein, Netlify, Google, Cloudflare, or Quad9 endorses an assessment or planned change.

The source licence permits running modified copies. These hosted-use limits govern only this deployment and relay; they do not add restrictions to copies of the software distributed under the AGPL.

## DNS and third-party services

Starting a live operation instructs the browser to send bounded DNS questions to the resolver you select. The Quad9 option starts directly; after a qualifying direct transport, timeout, or HTTP failure, automatic compatibility mode sends the question and connection metadata through Netlify before it reaches Quad9. [Google Public DNS](https://developers.google.com/speed/public-dns/terms), [Cloudflare 1.1.1.1](https://developers.cloudflare.com/1.1.1.1/terms-of-use/), [Quad9](https://quad9.net/privacy/policy/), and [Netlify](https://www.netlify.com/legal/acceptable-use-policy/) apply their own terms, privacy practices, availability limits, filtering choices, and legal obligations. ZoneSkein does not control their answers, logging, retention, or continued availability.

Delegation Lab sends an external-vantage request directly from the visitor’s browser to Globalping only after explicit consent. The request can cause up to three independently operated probes to send DNS traffic for the supplied name to the chosen recursive or authoritative server. [Globalping’s terms and policies](https://globalping.io/terms) govern that service and may impose their own target, content, rate, blocking, credit, and acceptable-use rules. Use external measurements only for bounded, interactive diagnostics of names and servers you are authorised to test. Do not automate the interface, evade its six-run-per-hour browser limit, distribute requests to avoid a service limit, or treat probe access as permission to burden a target.

## Local inputs and exports

Pasted or uploaded content is processed locally except for the DNS questions and delegated-measurement requests expressly described in `PRIVACY.md`. You remain responsible for the information you enter and for every clipboard copy, snapshot, share link, workspace export, portable configuration draft, download, backup, and recipient you choose.

Mail reports, certificates, ARC headers, BIMI material, zone bundles, and service templates can contain personal, organisational, brand, or infrastructure data even when they are handled locally. Exports may contain DNS records, raw DNS packets, hostnames, IP addresses, policy details, operational timing, or historical evidence. URL fragments, SHA-256 digests, and ordinary JSON files are not encryption. Review and protect an export before sharing it.

## Evidence and change decisions

Recursive answers are observations from selected resolvers at particular times. They do not prove authoritative state or worldwide propagation. Bounds, unsupported cases, partial evidence, stale caches, provider-specific syntax, and later DNS changes can affect a result. Verify material production changes through the relevant authoritative provider and obtain specialist advice when the consequences warrant it.

External-vantage results are a small, opportunistic sample rather than continuous monitoring or a census. Resolver or probe disagreement does not by itself establish poisoning, censorship, compromise, ownership, control, or which answer is correct. Local report, certificate, BIMI, ARC, and service-template checks cover only the fields and algorithms named by the interface; they do not reproduce a receiver, certificate authority, DNS provider, or mail operator’s complete decision process.

## Software, source, and branding

The software licence, corresponding-source offer, third-party notices, and trade-mark notice are published separately in `LICENSE`, `SOURCE.md`, `THIRD_PARTY_NOTICES.md`, and `TRADEMARKS.md`.

## Warranty and non-excludable rights

The software and hosted service are provided without warranty under the terms of the AGPL. To the maximum extent permitted by law, the operator is not responsible for decisions made solely from ZoneSkein output or for loss caused by unavailable, incomplete, delayed, filtered, or changed third-party DNS evidence. Nothing in these terms excludes, restricts, or modifies a right or remedy that applicable law does not permit to be excluded, restricted, or modified.
