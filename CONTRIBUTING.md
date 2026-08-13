# Contributing

Contributions should preserve ZoneSkein’s static, privacy-conscious, bounded design.

## Before proposing a change

- Keep protocol and transformation logic in `src/core`; React components should orchestrate and present typed results.
- Do not add authentication, analytics, advertising, telemetry, arbitrary fetch targets, bulk discovery, subdomain generation, or a general-purpose proxy.
- Use explicit result states and conservative conclusions. Incomplete evidence must remain partial, unknown, unsupported, or failed.
- Prefer mature dependencies with permissive licences. Document every added production dependency and its transitive runtime dependencies in `THIRD_PARTY_NOTICES.md`.
- Never depend on live public DNS in deterministic tests.

## Development

```sh
npm install --global npm@12.0.2
npm --version
npm ci
npm run format:check
npm run lint
npm run check
npm test
npm run build
npm run test:e2e
```

Add focused unit tests for parsers, protocol transformations, bounds, and negative cases. Browser tests should mock DNS-over-HTTPS and cover only critical workflows. The browser gate runs those workflows in Chromium, Firefox, WebKit, and a mobile Chromium viewport.

## Protocol changes

For DNSSEC, SPF, DMARC, DKIM, CAA, wire parsing, or zone syntax changes:

1. cite the relevant standard in code review;
2. add deterministic test vectors or fixtures;
3. distinguish unsupported input from invalid input;
4. describe what evidence supports every user-facing conclusion;
5. update the current-state architecture or limitations documentation when behaviour changes.

## Commits

Keep each commit coherent and use an imperative subject that describes the completed increment. Add a detailed body explaining the user-visible outcome, important protocol or security boundaries, and why the change is safe. End with the exact verification commands or checks that passed. Do not mix unrelated formatting and protocol changes.
