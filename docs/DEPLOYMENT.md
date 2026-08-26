# Netlify deployment

## Build contract

ZoneSkein is static-first. It produces a static `dist` directory with:

- one application entry point and code-split route assets;
- `_redirects` for direct-route fallback;
- `_headers` for Netlify security headers;
- public privacy, security, source, hosted-use, third-party, and trade-mark notices;
- `zoneskein-corresponding-source.tar.gz`, its per-file manifest, and a deployed SHA-256 checksum;
- no production source maps, server-rendered routes, credentials, or environment-specific API URLs.

The deployment also contains exactly one Netlify Function source,
`netlify/functions/quad9-doh.ts`. Its exported configuration exposes the fixed
same-origin path `/api/doh/quad9` and applies Netlify's 120-request-per-minute
rate limit aggregated by source IP address and site domain. The single Quad9
option tries its first question directly and uses **Quad9 (compatibility mode)**
automatically only after a qualifying transport, timeout, or HTTP failure.
There are no Edge Functions or other server-side application components.

The committed `netlify.toml` uses:

```toml
[build]
  command = "npm run build"
  publish = "dist"
```

Node.js 24.19.0 is pinned consistently in `netlify.toml`, `.nvmrc`, and the
quality workflow. npm 12.0.2 is pinned through Netlify's `NPM_VERSION`, the
package-manager declaration, and an explicit continuous-integration setup
step. Production dependencies and build tools are locked by `package-lock.json`.

The build finishes by generating and verifying the exact corresponding-source
archive, its manifest and checksum, then checking the static output allowlist,
file and asset-size bounds, public-document copies, resolver/CSP alignment, SPA rewrite, the exactly one
allowlisted Netlify Function source and its fixed route, upstream and rate-limit
contract, and SHA-256 hashes of the entry assets. The function is deployed by
Netlify rather than copied into `dist`; the static output remains exact and
bounded. A mismatch fails the build.

Vite's development and preview servers do not execute Netlify Functions. They
can verify the direct resolver paths, while mocked browser tests verify the
relay request shape. An end-to-end `/api/doh/quad9` check requires a Netlify
local runtime or a deployed preview. Deterministic function tests exercise the
request validation and HTTP/2 boundary without contacting Quad9.

Version tags matching the exact `v<package-version>` form run the same checked
build only when the tag is annotated, resolves to the workflow revision, and
that revision is already on `main`. The unprivileged build job produces three distinct
deterministic archives. `zoneskein-static.tar.gz` contains the verified
contents of `dist`, including the corresponding-source offer. It does not place
the relay at a deployable Netlify Function path; the nested source offer still
contains the relay source.
`zoneskein-netlify-deployment.tar.gz` is the complete prebuilt Netlify deployment
artefact: it contains exactly `dist`, `netlify/functions/quad9-doh.ts`,
`netlify.toml`, package manifests, and the public legal documents.
`zoneskein-corresponding-source.tar.gz` is the machine-readable source used for
the build, including all production package source distributions and the Vite
and Rolldown package source for helpers emitted into the browser assets, and is
capped at 4 MiB. The static archive is capped at 4 MiB and the
complete deployment archive at 8 MiB. The independently checked, uncompressed
`dist` file set is capped at 5 MiB because it contains the source archive as
well as the browser assets and public documents.

The workflow also produces a bounded CycloneDX software bill of materials and a
SHA-256 checksum file covering all three archives and the SBOM. The build job
has read-only repository access and transfers an exact, short-lived artefact to
a separate attestation job. Only that second job receives identity-token and
attestation permissions; it does not check out or execute repository code, and
it independently checks the transferred file set and checksums before recording
provenance and SBOM attestations. The final files are retained for 90 days. The
exact deployment-archive commands do not use repository globs, so tests, local
files, and unrelated source cannot enter that archive. This workflow does not
deploy the site or create a release entry.

Before enabling tagged builds, repository administrators must configure both
of these remote controls, which cannot be enforced by committed workflow code:

1. protect `v*` tags with a ruleset that restricts creation, update, and deletion to authorised release maintainers;
2. protect the `release-attestation` environment with required reviewers who are independent of the tag pusher, prevent administrators from bypassing the rule, and restrict deployment branches and tags to the protected release-tag pattern.

Do not treat an attestation as authorised release approval if either remote
control is absent. Create the annotated version tag only after the version
commit has landed on `main`.

## Deploy from a repository

1. Import the repository into Netlify.
2. Confirm the build command and publish directory from `netlify.toml`.
3. Preserve the committed `netlify/functions` source directory and do not add another function or Edge Function.
4. Deploy without application environment variables or secrets.
5. Confirm `/SOURCE.md`, `/SOURCE_SHA256`, and `/zoneskein-corresponding-source.tar.gz` are reachable and that the checksum validates the archive.
6. Open `/`, `/lookup/`, `/dnssec/`, `/spf/`, `/zone-lint/`, `/studio/`, `/diff/`, `/workspace/`, `/dmarc/`, `/dkim/`, `/caa/`, `/snapshots/`, and `/about/` directly.
7. Refresh each route and confirm the application loads.
8. Run manual direct checks against Google, Cloudflare, and Quad9 from a supported browser.
9. Exercise automatic Quad9 fallback from a path that cannot complete the direct request, and confirm the result identifies **Quad9 (compatibility mode)**. Confirm a valid DNS wire POST to `/api/doh/quad9` succeeds while invalid methods, media types, query strings, oversized or malformed bodies, and unsupported question shapes are rejected. Confirm responses declare `Cache-Control: no-store`.
10. Inspect the deploy log's post-processing stage and confirm Netlify accepted the code-based rate-limit rule. Then confirm the deployed rule aggregates by source IP address and site domain, permits no more than 120 requests in 60 seconds, and does not expose a caller-selected upstream. Netlify does not necessarily fail a deploy when a code-based rule is invalid, so a successful build alone is insufficient.

## Security headers

The Netlify `_headers` file sets:

- a Content Security Policy allowing self-hosted assets, including the same-origin relay, and only the three direct DNS-over-HTTPS origins;
- `frame-ancestors 'none'` and `X-Frame-Options: DENY`;
- `Referrer-Policy: no-referrer`;
- a two-year `Strict-Transport-Security` policy covering the deployment hostname and its subdomains;
- `X-Content-Type-Options: nosniff`;
- restrictive Permissions Policy;
- same-origin opener and resource policies.

Verify deployed headers with the browser network inspector or an HTTP header client. Do not assume a successful build proves that the hosting platform applied headers.
Only host subdomains that are ready for HTTPS beneath the production hostname;
the committed HSTS `includeSubDomains` policy causes supporting browsers to
require HTTPS for them after the first secure visit. The project does not claim
preload registration.

## Production domain

The production origin is `https://www.zoneskein.com`. Configure it as follows:

1. Add both `zoneskein.com` and `www.zoneskein.com` to the Netlify site before changing DNS.
2. Set `www.zoneskein.com` as the primary domain in Netlify. Netlify then redirects the apex hostname to the canonical `www` hostname.
3. In the authoritative Cloudflare zone, point `www` to the Netlify target shown in the site’s domain settings and keep the record **DNS only**. Configure the apex with the external-DNS value shown by Netlify and keep it **DNS only** as well.
4. Remove stale or conflicting A, AAAA, and CNAME records. Do not add a second apex-to-`www` redirect in Cloudflare.
5. Wait for Netlify to provision HTTPS for both hostnames, then enable Cloudflare DNSSEC and publish the supplied DS record through the registrar.
6. If CAA records restrict certificate authorities, use the current value shown by Netlify for the site rather than a copied account identifier.

DNS-only records make Cloudflare authoritative for hostname lookups without placing its reverse proxy in the HTTP path. Netlify therefore remains responsible for TLS, canonical redirects, security headers, static caching, function routing, and source-IP rate-limit aggregation. Cloudflare proxying is outside the verified deployment boundary because it would add another TLS, redirect, caching, header, privacy, and client-address layer.

After configuration, verify both hostnames, the apex-to-`www` redirect, `/robots.txt`, `/sitemap.xml`, each route’s `https://www.zoneskein.com/.../` canonical URL, the favicon and social image, direct resolver connections, the same-origin relay, and immutable hashed assets.

## Costs and external services

ZoneSkein requires no paid resolver API, database, scheduled job, authentication provider, application secret, or environment variable. The Quad9 compatibility relay does consume Netlify Function invocations and bandwidth. Netlify plan availability, function limits, rate-limiting availability, quotas, and pricing are external and can change; review the current plan before deployment.

## Rollback

Use Netlify's previous deploy artefact to roll back both the static files and the associated function version. There is no server migration or shared application database. Visitor-created IndexedDB snapshots remain on their devices and use a versioned schema. After rollback, verify that `/api/doh/quad9` and its rate limit match the rolled-back browser interface rather than assuming a static-asset rollback covered the function.

## Relay trust and operation

The relay accepts only an RFC 8484 POST body at `/api/doh/quad9`. It has one
hard-coded upstream, `https://dns.quad9.net/dns-query`, reached with Node.js
HTTP/2. It does not accept a target or query string and does not use or forward
cookies, credentials, or an application environment override. Requests are capped at 4,096 octets and
responses at 65,535 octets; method, media type, DNS header, single-question
shape, class, supported type, work, declared response length, streamed response
length, and question binding limits fail closed. One seven-second lifecycle
deadline covers both inbound body consumption and the upstream exchange. The
HTTP/2 client disables server push, rejects reserved push streams, and applies
explicit session-memory, concurrency, and header bounds. It returns
`Cache-Control: no-store` and does not cache responses on the relay or write
question bodies to application logs. The normal bounded browser memory cache
still applies after response validation.

Netlify can observe the relayed DNS wire question and ordinary visitor
connection metadata, and Quad9 can observe the forwarded question and the
function's connection. Deployers must preserve this disclosure and must not
describe relay answers as authoritative, globally representative, or equivalent
to direct observations from the other resolvers. Successful Google and
Cloudflare results remain independent evidence when the relay fails.
