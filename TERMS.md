# Hosted service terms

Effective: 16 August 2026

These terms apply to the hosted ZoneSkein website and its optional Quad9 compatibility relay. They do not restrict the rights granted in ZoneSkein’s source code by the GNU Affero General Public License version 3.

## Intended use

ZoneSkein is a bounded DNS inspection, validation, authoring, and change-review workbench. It provides point-in-time technical evidence and local planning assistance. It is not an authoritative DNS service, a security certification, legal advice, or a guarantee of publication, propagation, certificate issuance, email delivery, or future behaviour.

Use the hosted service only for lawful purposes and only with DNS names, records, messages, sender details, workspace files, and other information that you are authorised to process and disclose. Prefer synthetic data when real mailbox, client-address, message, customer, employee, or internal infrastructure information is not required.

Do not use the hosted service to:

- evade its request, resource, queue, or rate limits;
- generate bulk discovery, unsolicited scanning, spam, or abusive resolver traffic;
- interfere with Netlify, a selected resolver, an authoritative DNS server, or another person’s systems;
- submit unlawful material or information obtained or disclosed without appropriate authority; or
- imply that ZoneSkein, Netlify, Google, Cloudflare, or Quad9 endorses an assessment or planned change.

The source licence permits running modified copies. These hosted-use limits govern only this deployment and relay; they do not add restrictions to copies of the software distributed under the AGPL.

## DNS and third-party services

Starting a live operation instructs the browser to send bounded DNS questions to the resolver you select. Selecting Quad9 compatibility mode also sends the question and connection metadata through Netlify before it reaches Quad9. Those providers apply their own terms, privacy practices, availability limits, filtering choices, and legal obligations. ZoneSkein does not control their answers, logging, retention, or continued availability.

## Local inputs and exports

Pasted or uploaded content is processed locally except for the DNS questions expressly described in `PRIVACY.md`. You remain responsible for the information you enter and for every clipboard copy, snapshot, share link, workspace export, download, backup, and recipient you choose.

Exports may contain DNS records, raw DNS packets, hostnames, IP addresses, policy details, operational timing, or historical evidence. URL fragments, SHA-256 digests, and ordinary JSON files are not encryption. Review and protect an export before sharing it.

## Evidence and change decisions

Recursive answers are observations from selected resolvers at particular times. They do not prove authoritative state or worldwide propagation. Bounds, unsupported cases, partial evidence, stale caches, provider-specific syntax, and later DNS changes can affect a result. Verify material production changes through the relevant authoritative provider and obtain specialist advice when the consequences warrant it.

## Software, source, and branding

The software licence, corresponding-source offer, third-party notices, and trade-mark notice are published separately in `LICENSE`, `SOURCE.md`, `THIRD_PARTY_NOTICES.md`, and `TRADEMARKS.md`.

## Warranty and non-excludable rights

The software and hosted service are provided without warranty under the terms of the AGPL. To the maximum extent permitted by law, the operator is not responsible for decisions made solely from ZoneSkein output or for loss caused by unavailable, incomplete, delayed, filtered, or changed third-party DNS evidence. Nothing in these terms excludes, restricts, or modifies a right or remedy that applicable law does not permit to be excluded, restricted, or modified.
