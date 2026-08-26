import { lazy, Suspense, useEffect, useRef, useState } from 'react';

import type { MailAuthenticationEvidence } from './core/mail/evidence';
import type { ActiveChangeWorkspace, ChangeWorkspace } from './core/project';
import type { ChangeLabInput } from './routes/DiffPage';

const AboutPage = lazy(() =>
  import('./routes/AboutPage').then((module) => ({ default: module.AboutPage })),
);
const CaaPage = lazy(() =>
  import('./routes/CaaPage').then((module) => ({ default: module.CaaPage })),
);
const ChangeWorkspacePage = lazy(() =>
  import('./routes/ChangeWorkspacePage').then((module) => ({
    default: module.ChangeWorkspacePage,
  })),
);
const DiffPage = lazy(() =>
  import('./routes/DiffPage').then((module) => ({ default: module.DiffPage })),
);
const DkimPage = lazy(() =>
  import('./routes/DkimPage').then((module) => ({ default: module.DkimPage })),
);
const DmarcPage = lazy(() =>
  import('./routes/DmarcPage').then((module) => ({ default: module.DmarcPage })),
);
const DnssecPage = lazy(() =>
  import('./routes/DnssecPage').then((module) => ({ default: module.DnssecPage })),
);
const LookupPage = lazy(() =>
  import('./routes/LookupPage').then((module) => ({ default: module.LookupPage })),
);
const PublicDocumentPage = lazy(() =>
  import('./routes/PublicDocumentPage').then((module) => ({
    default: module.PublicDocumentPage,
  })),
);
const SourceChecksumPage = lazy(() =>
  import('./routes/PublicDocumentPage').then((module) => ({
    default: module.SourceChecksumPage,
  })),
);
const RecordStudioPage = lazy(() =>
  import('./routes/RecordStudioPage').then((module) => ({ default: module.RecordStudioPage })),
);
const SpfPage = lazy(() =>
  import('./routes/SpfPage').then((module) => ({ default: module.SpfPage })),
);
const SnapshotsPage = lazy(() =>
  import('./routes/SnapshotsPage').then((module) => ({ default: module.SnapshotsPage })),
);
const ZoneLintPage = lazy(() =>
  import('./routes/ZoneLintPage').then((module) => ({ default: module.ZoneLintPage })),
);

type Theme = 'light' | 'dark';

interface NavigationLink {
  path: string;
  label: string;
}

const inspectLinks = [
  { path: 'lookup/', label: 'Lookup' },
  { path: 'dnssec/', label: 'DNSSEC' },
  { path: 'spf/', label: 'SPF' },
  { path: 'dmarc/', label: 'DMARC' },
  { path: 'dkim/', label: 'DKIM' },
  { path: 'caa/', label: 'CAA' },
] as const satisfies readonly NavigationLink[];

const prepareLinks = [
  { path: 'zone-lint/', label: 'Zone lint' },
  { path: 'studio/', label: 'Record Studio' },
  { path: 'diff/', label: 'Change Lab' },
  { path: 'workspace/', label: 'Change Workspace' },
] as const satisfies readonly NavigationLink[];

const directLinks = [
  { path: 'snapshots/', label: 'Snapshots' },
  { path: 'about/', label: 'About' },
] as const satisfies readonly NavigationLink[];

const routeTitles: Readonly<Record<string, string>> = {
  '': 'ZoneSkein — Untangle DNS.',
  about: 'About — ZoneSkein',
  caa: 'CAA inspection — ZoneSkein',
  diff: 'Change Lab — ZoneSkein',
  dkim: 'DKIM inspection — ZoneSkein',
  dmarc: 'DMARC analysis — ZoneSkein',
  dnssec: 'DNSSEC inspection — ZoneSkein',
  lookup: 'DNS record lookup — ZoneSkein',
  licence: 'Software licence — ZoneSkein',
  privacy: 'Privacy — ZoneSkein',
  security: 'Security — ZoneSkein',
  source: 'Corresponding source — ZoneSkein',
  'source-checksum': 'Source archive checksum — ZoneSkein',
  snapshots: 'Local snapshots — ZoneSkein',
  spf: 'SPF analysis — ZoneSkein',
  studio: 'Record Studio — ZoneSkein',
  terms: 'Hosted service terms — ZoneSkein',
  'third-party-notices': 'Third-party notices — ZoneSkein',
  trademarks: 'Trademarks — ZoneSkein',
  workspace: 'Change Workspace — ZoneSkein',
  'zone-lint': 'Zone lint — ZoneSkein',
};

function applicationPath(): string {
  return window.location.pathname.replace(/^\/+|\/+$/g, '');
}

function href(path: string): string {
  return `/${path}`;
}

function normalisePath(path: string): string {
  return path.replace(/^\/+|\/+$/g, '');
}

const tools = [
  {
    path: 'dnssec/',
    label: 'Inspect DNSSEC',
    description: 'Review resolver and chain evidence.',
  },
  {
    path: 'spf/',
    label: 'Analyse SPF',
    description: 'Map dependencies, test sender context, and build safe snapshots.',
  },
  {
    path: 'zone-lint/',
    label: 'Lint a zone snippet',
    description: 'Catch record mistakes before publishing.',
  },
  {
    path: 'diff/',
    label: 'Open Change Lab',
    description: 'Compare semantic changes and plan a bounded rollout.',
  },
] as const;

export function App() {
  const [theme, setTheme] = useState<Theme>(() =>
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: light)').matches
      ? 'light'
      : 'dark',
  );
  const [route, setRoute] = useState(() => applicationPath());
  const [openNavGroups, setOpenNavGroups] = useState({ inspect: false, prepare: false });
  const [activeWorkspace, setActiveWorkspace] = useState<ActiveChangeWorkspace | null>(null);
  const [changeLabInput, setChangeLabInput] = useState<ChangeLabInput | undefined>();
  const [mailAuthenticationEvidence, setMailAuthenticationEvidence] =
    useState<MailAuthenticationEvidence | null>(null);
  const workspaceRef = useRef<ActiveChangeWorkspace | null>(null);
  const navigationRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    document.documentElement.dataset['theme'] = theme;
    document
      .querySelector<HTMLMetaElement>('meta[name="theme-color"]')
      ?.setAttribute('content', theme === 'dark' ? '#17102f' : '#fff3dc');
  }, [theme]);

  useEffect(() => {
    document.title = routeTitles[route] ?? 'Page not found — ZoneSkein';
  }, [route]);

  useEffect(() => {
    const updateRoute = () => {
      const nextRoute = applicationPath();
      setRoute(nextRoute);
      setOpenNavGroups({ inspect: false, prepare: false });
      queueMicrotask(() => document.querySelector<HTMLElement>('#main-content')?.focus());
    };
    window.addEventListener('popstate', updateRoute);
    return () => window.removeEventListener('popstate', updateRoute);
  }, []);

  useEffect(() => {
    const closeOutside = (event: PointerEvent) => {
      if (
        navigationRef.current !== null &&
        event.target instanceof Node &&
        !navigationRef.current.contains(event.target)
      )
        setOpenNavGroups({ inspect: false, prepare: false });
    };
    document.addEventListener('pointerdown', closeOutside);
    return () => document.removeEventListener('pointerdown', closeOutside);
  }, []);

  function openRoute(path: string): void {
    window.history.pushState(null, '', href(path));
    const nextRoute = normalisePath(path);
    setRoute(nextRoute);
    setOpenNavGroups({ inspect: false, prepare: false });
    queueMicrotask(() => document.querySelector<HTMLElement>('#main-content')?.focus());
  }

  function openWorkspace(value: ChangeWorkspace): void {
    const retained = workspaceRef.current;
    const inheritedIntegrity =
      retained?.integrity.state === 'mismatch-accepted' &&
      route === 'diff' &&
      changeLabInput?.workspace === retained.workspace
        ? retained.integrity
        : { state: 'not-checked' as const };
    const active: ActiveChangeWorkspace =
      retained?.workspace === value
        ? retained
        : {
            integrity: inheritedIntegrity,
            workspace: value,
          };
    workspaceRef.current = active;
    setActiveWorkspace(active);
    openRoute('workspace/');
  }

  function openWorkspaceInChangeLab(input: ChangeLabInput): void {
    const active = workspaceRef.current;
    setChangeLabInput(
      active === null
        ? input
        : {
            current: active.workspace.current.source,
            currentIncompleteReasons: active.workspace.current.incompleteReasons,
            currentOrigin: active.workspace.current.origin,
            currentStatus: active.workspace.current.status,
            intended: active.workspace.intended.source,
            intendedIncompleteReasons: active.workspace.intended.incompleteReasons,
            intendedOrigin: active.workspace.intended.origin,
            intendedStatus: active.workspace.intended.status,
            workspace: active.workspace,
          },
    );
    openRoute('diff/');
  }

  function retainActiveWorkspace(value: ActiveChangeWorkspace): void {
    workspaceRef.current = value;
    setActiveWorkspace(value);
  }

  function openDmarcWithEvidence(value: MailAuthenticationEvidence): void {
    setMailAuthenticationEvidence(value);
    openRoute('dmarc/');
  }

  return (
    <div className="app-shell">
      <header className="site-header">
        <a
          className="brand"
          href={href('')}
          aria-current={route === '' ? 'page' : undefined}
          aria-label="ZoneSkein home"
        >
          <img src={href('logo.svg')} alt="" width="54" height="44" />
          <span className="brand-wordmark">
            <span>Zone</span>
            <span>Skein</span>
          </span>
        </a>
        <nav
          className="primary-nav"
          aria-label="Primary navigation"
          ref={navigationRef}
          onKeyDown={(event) => {
            if (event.key !== 'Escape') return;
            const summary = event.currentTarget.querySelector<HTMLElement>(
              '.nav-group[open] > summary',
            );
            if (summary === null) return;
            event.preventDefault();
            setOpenNavGroups({ inspect: false, prepare: false });
            queueMicrotask(() => summary.focus());
          }}
        >
          <details
            className="nav-group"
            onToggle={(event) => {
              const open = event.currentTarget.open;
              setOpenNavGroups((current) => ({
                ...current,
                inspect: open,
                prepare: open ? false : current.prepare,
              }));
            }}
            open={openNavGroups.inspect}
          >
            <summary>Inspect</summary>
            <div className="nav-group-links">
              {inspectLinks.map((link) => (
                <a
                  aria-current={normalisePath(link.path) === route ? 'page' : undefined}
                  href={href(link.path)}
                  key={link.path}
                >
                  {link.label}
                </a>
              ))}
            </div>
          </details>
          <details
            className="nav-group"
            onToggle={(event) => {
              const open = event.currentTarget.open;
              setOpenNavGroups((current) => ({
                ...current,
                inspect: open ? false : current.inspect,
                prepare: open,
              }));
            }}
            open={openNavGroups.prepare}
          >
            <summary>Prepare</summary>
            <div className="nav-group-links">
              {prepareLinks.map((link) => (
                <a
                  aria-current={normalisePath(link.path) === route ? 'page' : undefined}
                  href={href(link.path)}
                  key={link.path}
                >
                  {link.label}
                </a>
              ))}
            </div>
          </details>
          {directLinks.map((link) => (
            <a
              aria-current={normalisePath(link.path) === route ? 'page' : undefined}
              href={href(link.path)}
              key={link.path}
            >
              {link.label}
            </a>
          ))}
        </nav>
        <button
          className="quiet-button"
          type="button"
          onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          aria-label={`Use ${theme === 'dark' ? 'light' : 'dark'} theme`}
        >
          {theme === 'dark' ? 'Light' : 'Dark'}
        </button>
      </header>

      <main id="main-content" tabIndex={-1}>
        <Suspense
          fallback={
            <section className="page-intro" aria-live="polite">
              <p className="eyebrow">ZoneSkein</p>
              <h1>Loading tool…</h1>
            </section>
          }
        >
          {route === 'snapshots' ? (
            <SnapshotsPage />
          ) : route === 'licence' ? (
            <PublicDocumentPage documentId="licence" />
          ) : route === 'privacy' ? (
            <PublicDocumentPage documentId="privacy" />
          ) : route === 'security' ? (
            <PublicDocumentPage documentId="security" />
          ) : route === 'source' ? (
            <PublicDocumentPage documentId="source" />
          ) : route === 'source-checksum' ? (
            <SourceChecksumPage />
          ) : route === 'terms' ? (
            <PublicDocumentPage documentId="terms" />
          ) : route === 'third-party-notices' ? (
            <PublicDocumentPage documentId="third-party-notices" />
          ) : route === 'trademarks' ? (
            <PublicDocumentPage documentId="trademarks" />
          ) : route === 'about' ? (
            <AboutPage />
          ) : route === 'caa' ? (
            <CaaPage />
          ) : route === 'dkim' ? (
            <DkimPage onUseForDmarc={openDmarcWithEvidence} />
          ) : route === 'dmarc' ? (
            <DmarcPage
              {...(mailAuthenticationEvidence === null
                ? {}
                : { initialEvidence: mailAuthenticationEvidence })}
              onEvidenceChange={setMailAuthenticationEvidence}
            />
          ) : route === 'diff' ? (
            <DiffPage
              {...(changeLabInput === undefined ? {} : { initialInput: changeLabInput })}
              onCreateWorkspace={openWorkspace}
            />
          ) : route === 'studio' ? (
            <RecordStudioPage onCreateWorkspace={openWorkspace} />
          ) : route === 'workspace' ? (
            <ChangeWorkspacePage
              initialActiveWorkspace={activeWorkspace ?? undefined}
              onActiveWorkspaceChange={retainActiveWorkspace}
              onOpenChangeLab={openWorkspaceInChangeLab}
            />
          ) : route === 'zone-lint' ? (
            <ZoneLintPage />
          ) : route === 'spf' ? (
            <SpfPage onUseForDmarc={openDmarcWithEvidence} />
          ) : route === 'dnssec' ? (
            <DnssecPage />
          ) : route === 'lookup' ? (
            <LookupPage />
          ) : route === '' ? (
            <section className="hero" aria-labelledby="home-title">
              <div className="hero-copy">
                <p className="eyebrow">A browser-based DNS workbench</p>
                <h1 id="home-title">Untangle DNS.</h1>
                <p className="lede">
                  Follow every strand from question to evidence. Inspect live answers,
                  understand policy dependencies, and rehearse changes before anything gets
                  published.
                </p>
                <div className="hero-actions" aria-label="Get started">
                  <a className="primary-button" href={href('lookup/')}>
                    Start with a lookup
                  </a>
                  <a className="quiet-link" href={href('about/')}>
                    See how it works
                  </a>
                </div>
              </div>
              <div className="skein-board" aria-hidden="true">
                <span className="board-label">Messy in.</span>
                <div className="strand-field">
                  <span className="strand strand-coral" />
                  <span className="strand strand-mango" />
                  <span className="strand strand-mint" />
                  <span className="strand strand-sky" />
                </div>
                <div className="record-stack">
                  <span>
                    <b>A</b>
                    <code>192.0.2.42</code>
                  </span>
                  <span>
                    <b>MX</b>
                    <code>mail.example</code>
                  </span>
                  <span>
                    <b>TXT</b>
                    <code>v=spf1…</code>
                  </span>
                </div>
                <span className="board-label board-label-end">Evidence out.</span>
              </div>
              <div className="tool-links" aria-label="Primary tools">
                {tools.map((tool, index) => (
                  <a href={href(tool.path)} key={tool.path}>
                    <span className="tool-number">Strand 0{index + 1}</span>
                    <strong>{tool.label}</strong>
                    <span className="tool-description">{tool.description}</span>
                    <span className="tool-arrow" aria-hidden="true">
                      ↗
                    </span>
                  </a>
                ))}
              </div>
              <div className="secondary-tools" aria-label="Additional tools">
                <span>Follow another thread</span>
                <a href={href('lookup/')}>Record explorer</a>
                <a href={href('studio/')}>Record Studio</a>
                <a href={href('workspace/')}>Change Workspace</a>
                <a href={href('dmarc/')}>DMARC</a>
                <a href={href('dkim/')}>DKIM</a>
                <a href={href('caa/')}>CAA</a>
                <a href={href('snapshots/')}>Local snapshots</a>
              </div>
            </section>
          ) : (
            <section className="page-intro" aria-labelledby="route-title">
              <p className="eyebrow">ZoneSkein</p>
              <h1 id="route-title">{route.replace('/', '').replace('-', ' ')}</h1>
              <p className="lede">That page does not exist in this static build.</p>
              <a className="text-link" href={href('')}>
                Return home
              </a>
            </section>
          )}
        </Suspense>
      </main>

      <footer>
        <p>
          Static-first by design. DNS is direct by default; Quad9 (compatibility mode) is
          explicit. No warranty.
        </p>
        <div>
          <a href={href('privacy/')}>Privacy</a>
          <a href={href('source/')}>Source</a>
          <a href={href('terms/')}>Terms</a>
          <a href={href('licence/')}>Legal</a>
          <span>© 2026 slicedearth</span>
        </div>
      </footer>
    </div>
  );
}
