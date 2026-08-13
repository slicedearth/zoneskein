import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';

const boundaries = [
  {
    title: 'No application backend',
    text: 'The built site contains only static files. DNS questions travel directly from your browser to the resolver you select.',
  },
  {
    title: 'Evidence, not omniscience',
    text: 'Recursive-resolver answers are point-in-time observations. They are not authoritative answers or proof of worldwide propagation.',
  },
  {
    title: 'Persistence is opt-in',
    text: 'Queries are not stored by default. Manual snapshots use IndexedDB only after you enable the local vault.',
  },
  {
    title: 'Bounded by design',
    text: 'Every run has cancellation, an 80-question cap, depth and input limits, a four-request ceiling, and browser-side rate controls.',
  },
] as const;

export function AboutPage() {
  return (
    <div className="tool-page about-page">
      <ToolIntro eyebrow="About ZoneSkein" title="A workbench, not a scanner.">
        ZoneSkein helps domain owners and operators inspect, author, and compare the DNS records
        they already intend to work with. It does not discover subdomains, scan address space,
        publish DNS automatically, or access provider accounts.
      </ToolIntro>

      <section className="about-boundaries" aria-label="Design boundaries">
        {boundaries.map((boundary) => (
          <article key={boundary.title}>
            <h2>{boundary.title}</h2>
            <p>{boundary.text}</p>
          </article>
        ))}
      </section>

      <section className="prose-section" aria-labelledby="capabilities-title">
        <p className="eyebrow">Capabilities</p>
        <h2 id="capabilities-title">One protocol core, several focused tools</h2>
        <div className="capability-list">
          <div>
            <strong>DNS lookup</strong>
            <span>
              Wire-format DoH, 18 explicit record types, PTR, resolver comparison, exact message
              sizes, normalized fields, and exports.
            </span>
          </div>
          <div>
            <strong>DNSSEC</strong>
            <span>
              Validating/checking-disabled comparison, DNSKEY key tags, SHA-256/SHA-384 DS
              matches, RRSIG time checks, and supported local DNSKEY RRset verification.
            </span>
          </div>
          <div>
            <strong>SPF</strong>
            <span>
              Ordered AST, recursive dependency graph, path-aware lookup and void budgets,
              conservative pass-set flattening, provenance, expiry, and response sizing.
            </span>
          </div>
          <div>
            <strong>Authoring and change review</strong>
            <span>
              Recoverable zone-snippet linting, semantic DNS diffing, CAA inheritance and
              building, plus DMARC and DKIM inspection.
            </span>
          </div>
        </div>
      </section>

      <section className="prose-section" id="privacy" aria-labelledby="privacy-title">
        <p className="eyebrow">Privacy</p>
        <h2 id="privacy-title">Where data goes</h2>
        <div className="prose-columns">
          <div>
            <h3>DNS questions</h3>
            <p>
              The selected resolver receives DNS questions and your network connection
              information; that resolver’s privacy policy applies. ZoneSkein uses fixed
              allowlisted endpoints for Google Public DNS, Cloudflare 1.1.1.1, and Quad9.
              Resolver URLs cannot be supplied by a user. Cloudflare uses a wire-format POST;
              Google and Quad9 use standard base64url wire-format GET so their endpoints work
              from an ordinary browser. The resolver can read the question under either method.
            </p>
          </div>
          <div>
            <h3>Page requests</h3>
            <p>
              Netlify receives ordinary page and asset requests and may retain connection logs
              under its own policies. DNS names are never placed in those page request query
              strings.
            </p>
          </div>
          <div>
            <h3>Local and shared state</h3>
            <p>
              No cookies, analytics, telemetry, external fonts, advertising, or tracking pixels
              are used. The local snapshot preference contains no query. Manual snapshots remain
              in IndexedDB. Explicit share links put report data in the URL fragment; browser
              history and every recipient can still see it.
            </p>
          </div>
        </div>
      </section>

      <section className="prose-section" aria-labelledby="limits-title">
        <p className="eyebrow">Security and limitations</p>
        <h2 id="limits-title">Conservative conclusions</h2>
        <ul className="guidance-list">
          <li>
            Client-side rate limiting protects normal users and public resolvers from accidental
            bursts, but a modified client can bypass it. It is not an enforcement boundary.
          </li>
          <li>
            DNSSEC local checks do not independently validate the parent DS RRset to a bundled
            root trust anchor and do not verify every RRset or NSEC/NSEC3 denial.
          </li>
          <li>
            SPF snapshots are withheld for macros, exists, ptr, cycles, unresolved dependencies,
            ambiguous qualifiers, multiple policies, or incomplete data.
          </li>
          <li>
            The zone parser implements a documented practical subset, not every BIND directive
            or DNS provider extension.
          </li>
          <li>
            DMARC publication does not prove message alignment; a DKIM key does not prove
            message signatures; CAA publication does not guarantee certificate issuance.
          </li>
        </ul>
      </section>

      <section className="prose-section" id="legal" aria-labelledby="legal-title">
        <p className="eyebrow">Licence and legal notices</p>
        <h2 id="legal-title">AGPL-3.0-only</h2>
        <div className="conclusion-panel">
          <StatusBadge tone="information">Free software</StatusBadge>
          <p>
            Copyright © 2026 slicedearth. ZoneSkein’s original source is licensed under the GNU
            Affero General Public License version 3 only. You may run, study, modify, and convey
            the covered work under that licence. Network use of a modified version can require
            offering its corresponding source to users. There is no warranty. The complete,
            controlling terms are in the deployed <a href="/LICENSE">LICENSE</a> file;
            third-party packages keep their own licences as listed in{' '}
            <a href="/THIRD_PARTY_NOTICES.md">THIRD_PARTY_NOTICES.md</a>.
          </p>
        </div>
      </section>
    </div>
  );
}
