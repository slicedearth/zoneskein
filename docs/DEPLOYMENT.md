# Netlify deployment

## Build contract

ZoneSkein produces a static `dist` directory with:

- one application entry point and code-split route assets;
- `_redirects` for direct-route fallback;
- `_headers` for Netlify security headers;
- no function or edge-function bundle;
- no server endpoint, credential, or environment-specific API URL.

The committed `netlify.toml` uses:

```toml
[build]
  command = "npm run build"
  publish = "dist"
```

Node.js 24.19.0 is pinned consistently in `netlify.toml`, `.nvmrc`, and the
quality workflow. Production dependencies and build tools are locked by
`package-lock.json`.

## Deploy from a repository

1. Import the repository into Netlify.
2. Confirm the build command and publish directory from `netlify.toml`.
3. Do not configure a functions directory.
4. Deploy without application environment variables.
5. Open `/`, `/lookup/`, `/dnssec/`, `/spf/`, `/zone-lint/`, `/diff/`, `/dmarc/`, `/dkim/`, `/caa/`, `/snapshots/`, and `/about/` directly.
6. Refresh each route and confirm the application loads.
7. Run a manual resolver smoke check from a supported browser.

## Security headers

The Netlify `_headers` file sets:

- a Content Security Policy allowing self-hosted assets and only the three DNS-over-HTTPS origins;
- `frame-ancestors 'none'` and `X-Frame-Options: DENY`;
- `Referrer-Policy: no-referrer`;
- `X-Content-Type-Options: nosniff`;
- restrictive Permissions Policy;
- same-origin opener and resource policies.

Verify deployed headers with the browser network inspector or an HTTP header client. Do not assume a successful build proves that the hosting platform applied headers.

## Custom domains

Configure the custom domain in Netlify, follow its DNS and certificate instructions, and wait for HTTPS provisioning before advertising the site. ZoneSkein itself does not require a specific hostname.

If the site hostname is moved, test URL-fragment report links, direct-route fallback, favicon loading, resolver CSP connections, and immutable asset caching.

## Costs and external services

ZoneSkein requires no paid API, database, function runtime, scheduled job, authentication provider, or application secret. Netlify plan availability, quotas, and pricing are external and can change; review the current plan before deployment.

## Rollback

Use Netlify’s previous static deploy artifact to roll back. Because there is no server migration or shared application database, rollback is limited to the deployed files. Visitor-created IndexedDB snapshots remain on their devices and use a versioned schema.
