import { lazy, Suspense, useEffect, useState } from 'react';

const CaaPage = lazy(() =>
  import('./routes/CaaPage').then((module) => ({ default: module.CaaPage })),
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
const SpfPage = lazy(() =>
  import('./routes/SpfPage').then((module) => ({ default: module.SpfPage })),
);
const ZoneLintPage = lazy(() =>
  import('./routes/ZoneLintPage').then((module) => ({ default: module.ZoneLintPage })),
);

type Theme = 'light' | 'dark';

function applicationPath(): string {
  return window.location.pathname.replace(/^\/+|\/+$/g, '');
}

function href(path: string): string {
  return `/${path}`;
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
    description: 'Map lookup dependencies and safe snapshots.',
  },
  {
    path: 'zone-lint/',
    label: 'Lint a zone snippet',
    description: 'Catch record mistakes before publishing.',
  },
  {
    path: 'diff/',
    label: 'Compare a change',
    description: 'Separate semantic changes from formatting.',
  },
] as const;

export function App() {
  const [theme, setTheme] = useState<Theme>(() =>
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: light)').matches
      ? 'light'
      : 'dark',
  );
  const [route] = useState(() => applicationPath());

  useEffect(() => {
    document.documentElement.dataset['theme'] = theme;
  }, [theme]);

  return (
    <div className="app-shell">
      <header className="site-header">
        <a className="brand" href={href('')} aria-label="ZoneSkein home">
          <img src={href('favicon.svg')} alt="" width="34" height="34" />
          <span>ZoneSkein</span>
        </a>
        <nav aria-label="Primary navigation">
          <a href={href('lookup/')}>Lookup</a>
          <a href={href('dnssec/')}>DNSSEC</a>
          <a href={href('spf/')}>SPF</a>
          <a href={href('zone-lint/')}>Zone lint</a>
          <a href={href('diff/')}>Diff</a>
          <a href={href('dmarc/')}>DMARC</a>
          <a href={href('dkim/')}>DKIM</a>
          <a href={href('caa/')}>CAA</a>
          <a href={href('about/')}>About</a>
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

      <main id="main-content">
        <Suspense
          fallback={
            <section className="page-intro" aria-live="polite">
              <p className="eyebrow">ZoneSkein</p>
              <h1>Loading tool…</h1>
            </section>
          }
        >
          {route === 'caa' ? (
            <CaaPage />
          ) : route === 'dkim' ? (
            <DkimPage />
          ) : route === 'dmarc' ? (
            <DmarcPage />
          ) : route === 'diff' ? (
            <DiffPage />
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
            </section>
          ) : (
            <section className="page-intro" aria-labelledby="route-title">
              <p className="eyebrow">ZoneSkein</p>
              <h1 id="route-title">{route.replace('/', '').replace('-', ' ')}</h1>
              <p className="lede">This tool is being connected to the shared protocol core.</p>
              <a className="text-link" href={href('')}>
                Return home
              </a>
            </section>
          )}
        </Suspense>
      </main>

      <footer>
        <p>Static by design. DNS questions go directly from your browser to the resolver.</p>
      </footer>
    </div>
  );
}
