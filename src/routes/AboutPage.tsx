import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';

const boundaries = [
  {
    title: 'Static-first, bounded relay',
    text: 'DNS questions travel directly to the selected resolver by default. The only server-side component is an explicitly selected, tightly bounded Quad9 compatibility relay.',
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
              Wire-format DoH, 19 explicit record types including PTR, resolver comparison,
              exact message sizes, normalised fields, and exports.
            </span>
          </div>
          <div>
            <strong>DNSSEC</strong>
            <span>
              Independent root-to-answer validation, exact DS and DNSKEY RRsets, selected
              positive and negative application answers, wildcard and alias proofs,
              SHA-1/SHA-256/SHA-384 DS matching, explicit Opt-Out uncertainty, and replayable
              wire evidence.
            </span>
          </div>
          <div>
            <strong>SPF</strong>
            <span>
              Ordered AST, recursive dependency graph, path-aware lookup and void budgets,
              conservative pass-set flattening, sender-context evaluation, macro and DNS
              evidence, provenance, expiry, and response sizing.
            </span>
          </div>
          <div>
            <strong>Record Studio and Change Lab</strong>
            <span>
              Local authoring for 18 supported record types, bounded working-set linting,
              semantic comparison, risk findings, rollback timing, and staged rollout guidance.
              Neither tool publishes DNS.
            </span>
          </div>
          <div>
            <strong>Change Workspace</strong>
            <span>
              A bounded local file carries explicit current and intended states, structured
              analysis, rollback guidance, and historical evidence between Record Studio and
              Change Lab. Imported resolver endpoints remain inert provenance.
            </span>
          </div>
          <div>
            <strong>Email authentication</strong>
            <span>
              RFC 9989 DMARC policy discovery and conditional alignment assessment from supplied
              prior authentication evidence, plus DKIM key inspection and bounded local message
              verification.
            </span>
          </div>
          <div>
            <strong>CAA</strong>
            <span>
              Bounded inheritance analysis and record authoring for web, wildcard, and S/MIME
              issuance controls.
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
              For direct requests, the selected resolver receives DNS questions and your network
              connection information; that resolver’s privacy policy applies. ZoneSkein uses
              fixed allowlisted endpoints for Google Public DNS, Cloudflare 1.1.1.1, and Quad9.
              Resolver URLs cannot be supplied by a user. Cloudflare uses a wire-format POST;
              Google and Quad9 (direct) use standard base64url wire-format GET so their
              endpoints work from an ordinary browser. Base64url is readable encoding, not
              encryption; the resolver and local browser tooling can observe the encoded URL.
              Quad9 (direct) remains the default Quad9 path. If you explicitly select Quad9
              (compatibility mode), the browser sends a bounded wire-format POST to the
              same-origin `/api/doh/quad9` endpoint, and Netlify forwards it only to Quad9 over
              HTTP/2. Netlify sees your connection in compatibility mode, while Quad9 sees the
              relay connection; both receive the question.
            </p>
          </div>
          <div>
            <h3>Page requests</h3>
            <p>
              Netlify receives ordinary page and asset requests and may retain connection logs
              under its own policies. In explicitly selected Quad9 relay mode it also receives
              the DNS wire question and ordinary connection metadata. The fixed relay uses a
              POST body rather than a DNS-name-bearing path or query string, does not add
              cookies or credentials, and does not log or server-cache the question in
              application code.
            </p>
          </div>
          <div>
            <h3>Local and shared state</h3>
            <p>
              No cookies, analytics, telemetry, external fonts, advertising, or tracking pixels
              are used. The local snapshot preference contains no query. A bounded anonymous
              rate ledger stores only opaque request metadata, never questions or answers. Its
              request events cover a rolling one-minute window; a resolver cooldown can persist
              for at most 15 minutes. Manual snapshots remain in IndexedDB until you erase them
              or the oldest is evicted at the 100-snapshot limit. Explicit share links put
              report data in the URL fragment; browser history and every recipient can still see
              it. DNSSEC evidence bundles contain complete raw packets, decoded questions,
              resolver endpoints, and capture times, so copying, snapshotting, or sharing them
              exposes those details to the selected destination or recipient. Change Workspace
              state remains in page memory unless explicitly downloaded; imported files are read
              locally and their retained resolver endpoints are never contacted.
            </p>
          </div>
          <div>
            <h3>Email and sender inputs</h3>
            <p>
              SPF macros can place parts of a supplied mailbox, IP address, HELO/EHLO name, or
              receiver name into DNS questions visible to the selected resolver. DKIM keeps raw
              message bytes, headers, addresses, and body content in page memory and sends only
              derived selector TXT questions. Copied DKIM evidence excludes the raw message,
              filename, addresses, and body, and redacts any AUID local-part. DMARC alignment
              accepts domains and supplied prior authentication results, not a raw message. None
              of these sensitive inputs is saved or shared automatically. Use real personal,
              customer, employee, or internal information only when you are authorised to
              process it and disclose any derived DNS questions.
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
            bursts, but a modified client can bypass it. The optional Quad9 relay separately
            enforces strict request and response bounds and 120 requests per minute per source
            IP address and site domain.
          </li>
          <li>
            DNSSEC validates supported delegation, positive, NODATA, NXDOMAIN, wildcard, and
            bounded alias-continuation proof paths from bundled IANA root trust anchors. It is a
            selected-type validator, not a general recursive resolver, and NSEC3 Opt-Out cannot
            prove whether a covered delegation exists.
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
            A Change Workspace SHA-256 mismatch shows that the content no longer matches the
            included digest. A match shows internal consistency only because anyone modifying
            the file can recompute it; it provides no authenticity, authorisation, or tamper
            resistance. Unavailable and partial zone states remain explicit and cannot be
            treated as empty input.
          </li>
          <li>
            DMARC publication does not prove alignment, and alignment mode remains conditional
            on supplied prior SPF and DKIM authentication evidence. A DKIM pass authenticates
            only signed content for its signing domain; it does not establish DMARC alignment,
            reputation, or delivery. CAA publication does not guarantee certificate issuance.
          </li>
        </ul>
      </section>

      <section className="prose-section" id="legal" aria-labelledby="legal-title">
        <p className="eyebrow">Licence and legal notices</p>
        <h2 id="legal-title">Licence, source, and hosted use</h2>
        <div className="conclusion-panel">
          <StatusBadge tone="information">Free software</StatusBadge>
          <p>
            Copyright © 2026 slicedearth. ZoneSkein’s original source is licensed under the GNU
            Affero General Public License version 3 only. You may run, study, modify, and convey
            the covered work under that licence. The machine-readable{' '}
            <a href="/zoneskein-corresponding-source.tar.gz" download>
              corresponding source for this deployed build
            </a>{' '}
            is offered at no charge, with verification and unpacking directions in{' '}
            <a href="/source/">the corresponding-source guide</a>. There is no warranty, subject
            to rights that applicable law does not permit to be excluded. The complete,
            controlling terms are on the <a href="/licence/">software licence page</a>; hosted
            use is described in <a href="/terms/">the service terms</a>; third-party packages
            retain the licences listed in{' '}
            <a href="/third-party-notices/">the dependency notices</a>; and the project’s
            branding position is in <a href="/trademarks/">the trade-mark notice</a>. Each page
            also offers its controlling raw file as a download.
          </p>
        </div>
      </section>
    </div>
  );
}
