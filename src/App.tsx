import { lazy, Suspense, useEffect, useRef, useState } from 'react';

import type { ChangeWorkspace } from './core/project';
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
  snapshots: 'Local snapshots — ZoneSkein',
  spf: 'SPF analysis — ZoneSkein',
  studio: 'Record Studio — ZoneSkein',
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
  const [workspace, setWorkspace] = useState<ChangeWorkspace | null>(null);
  const [changeLabInput, setChangeLabInput] = useState<ChangeLabInput | undefined>();
  const workspaceRef = useRef<ChangeWorkspace | null>(null);

  useEffect(() => {
    document.documentElement.dataset['theme'] = theme;
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

  function openRoute(path: string): void {
    window.history.pushState(null, '', href(path));
    const nextRoute = normalisePath(path);
    setRoute(nextRoute);
    setOpenNavGroups({ inspect: false, prepare: false });
    queueMicrotask(() => document.querySelector<HTMLElement>('#main-content')?.focus());
  }

  function openWorkspace(value: ChangeWorkspace): void {
    workspaceRef.current = value;
    setWorkspace(value);
    openRoute('workspace/');
  }

  function openWorkspaceInChangeLab(input: ChangeLabInput): void {
    const activeWorkspace = workspaceRef.current;
    setChangeLabInput(
      activeWorkspace === null
        ? input
        : {
            current: activeWorkspace.current.source,
            currentIncompleteReasons: activeWorkspace.current.incompleteReasons,
            currentOrigin: activeWorkspace.current.origin,
            currentStatus: activeWorkspace.current.status,
            intended: activeWorkspace.intended.source,
            intendedIncompleteReasons: activeWorkspace.intended.incompleteReasons,
            intendedOrigin: activeWorkspace.intended.origin,
            intendedStatus: activeWorkspace.intended.status,
            workspace: activeWorkspace,
          },
    );
    openRoute('diff/');
  }

  function retainWorkspace(value: ChangeWorkspace): void {
    workspaceRef.current = value;
    setWorkspace(value);
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
          <img src={href('logo.svg')} alt="" width="42" height="42" />
          <span>ZoneSkein</span>
        </a>
        <nav className="primary-nav" aria-label="Primary navigation">
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
          ) : route === 'about' ? (
            <AboutPage />
          ) : route === 'caa' ? (
            <CaaPage />
          ) : route === 'dkim' ? (
            <DkimPage />
          ) : route === 'dmarc' ? (
            <DmarcPage />
          ) : route === 'diff' ? (
            <DiffPage
              {...(changeLabInput === undefined ? {} : { initialInput: changeLabInput })}
              onCreateWorkspace={openWorkspace}
            />
          ) : route === 'studio' ? (
            <RecordStudioPage onCreateWorkspace={openWorkspace} />
          ) : route === 'workspace' ? (
            <ChangeWorkspacePage
              initialWorkspace={workspace ?? undefined}
              onOpenChangeLab={openWorkspaceInChangeLab}
              onWorkspaceChange={retainWorkspace}
            />
          ) : route === 'zone-lint' ? (
            <ZoneLintPage />
          ) : route === 'spf' ? (
            <SpfPage />
          ) : route === 'dnssec' ? (
            <DnssecPage />
          ) : route === 'lookup' ? (
            <LookupPage />
          ) : route === '' ? (
            <section className="hero" aria-labelledby="home-title">
              <p className="eyebrow">Browser-based DNS workbench</p>
              <h1 id="home-title">Untangle DNS.</h1>
              <p className="lede">
                Inspect evidence, understand policy dependencies, and review records before you
                publish—without sending your work to an application backend.
              </p>
              <div className="tool-links" aria-label="Primary tools">
                {tools.map((tool, index) => (
                  <a href={href(tool.path)} key={tool.path}>
                    <span className="tool-number">0{index + 1}</span>
                    <strong>{tool.label}</strong>
                    <span>{tool.description}</span>
                  </a>
                ))}
              </div>
              <div className="secondary-tools" aria-label="Additional tools">
                <span>Also included</span>
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
          Static by design. DNS questions go directly from your browser to the resolver. No
          warranty.
        </p>
        <div>
          <a href={href('about/#privacy')}>Privacy</a>
          <a href={href('about/#legal')}>AGPL-3.0-only</a>
          <span>© 2026 slicedearth</span>
        </div>
      </footer>
    </div>
  );
}
