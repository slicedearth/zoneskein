# Corresponding source

ZoneSkein is distributed under the GNU Affero General Public License version 3 only.

The machine-readable corresponding source for the browser application and Quad9 relay in this deployment is available at no charge:

- [Download `zoneskein-corresponding-source.tar.gz`](/zoneskein-corresponding-source.tar.gz)
- [View its SHA-256 checksum](/SOURCE_SHA256)

The archive contains the TypeScript and TSX application source, Netlify Function source, public assets, dependency lockfile, build and verification scripts, configuration, tests, documentation, licence, and third-party notices used for this build. It also includes the installed published source distributions of every production package and the Vite and Rolldown packages whose helpers are emitted into the delivered JavaScript, under `vendor/npm/`. `SOURCE_MANIFEST.sha256` inside the archive records the SHA-256 digest of every included file.

To verify and unpack it on a system with standard SHA-256 and tar tools:

```sh
sha256sum --check SOURCE_SHA256
tar -xzf zoneskein-corresponding-source.tar.gz
```

The checksum establishes transport and file consistency only. It is not a signature and does not establish who produced or authorised a deployment. Tagged release provenance, when available from the project’s source repository, should be checked separately.

General-purpose, unmodified build and test tools are not duplicated in the archive. Their exact graph is pinned by `package-lock.json` and can be installed with the npm version declared in `package.json`. Applicable dependency licence texts are reproduced in `THIRD_PARTY_NOTICES.md`.
