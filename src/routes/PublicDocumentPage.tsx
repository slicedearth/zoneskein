import { useEffect, useState, type ReactNode } from 'react';
import Markdown from 'marked-react';

import licence from '../../LICENSE?raw';
import privacy from '../../PRIVACY.md?raw';
import security from '../../SECURITY.md?raw';
import source from '../../SOURCE.md?raw';
import terms from '../../TERMS.md?raw';
import thirdPartyNotices from '../../THIRD_PARTY_NOTICES.md?raw';
import trademarks from '../../TRADEMARKS.md?raw';

export type PublicDocumentId =
  | 'licence'
  | 'privacy'
  | 'security'
  | 'source'
  | 'terms'
  | 'third-party-notices'
  | 'trademarks';

interface PublicDocument {
  readonly content: string;
  readonly eyebrow: string;
  readonly format: 'markdown' | 'text';
  readonly rawPath: string;
  readonly title: string;
}

const documents: Readonly<Record<PublicDocumentId, PublicDocument>> = {
  licence: {
    content: licence,
    eyebrow: 'Software licence',
    format: 'text',
    rawPath: '/LICENSE',
    title: 'GNU Affero General Public License',
  },
  privacy: {
    content: privacy,
    eyebrow: 'Privacy notice',
    format: 'markdown',
    rawPath: '/PRIVACY.md',
    title: 'Privacy',
  },
  security: {
    content: security,
    eyebrow: 'Security policy',
    format: 'markdown',
    rawPath: '/SECURITY.md',
    title: 'Security',
  },
  source: {
    content: source,
    eyebrow: 'Corresponding source',
    format: 'markdown',
    rawPath: '/SOURCE.md',
    title: 'Corresponding source',
  },
  terms: {
    content: terms,
    eyebrow: 'Hosted service',
    format: 'markdown',
    rawPath: '/TERMS.md',
    title: 'Hosted service terms',
  },
  'third-party-notices': {
    content: thirdPartyNotices,
    eyebrow: 'Dependency licences',
    format: 'markdown',
    rawPath: '/THIRD_PARTY_NOTICES.md',
    title: 'Third-party notices',
  },
  trademarks: {
    content: trademarks,
    eyebrow: 'Branding notice',
    format: 'markdown',
    rawPath: '/TRADEMARKS.md',
    title: 'Trademarks',
  },
};

const semanticRoutes: Readonly<Record<string, string>> = {
  LICENSE: '/licence/',
  'PRIVACY.md': '/privacy/',
  'SECURITY.md': '/security/',
  'SOURCE.md': '/source/',
  SOURCE_SHA256: '/source-checksum/',
  'TERMS.md': '/terms/',
  'THIRD_PARTY_NOTICES.md': '/third-party-notices/',
  'TRADEMARKS.md': '/trademarks/',
};

function semanticLinks(markdown: string): string {
  return Object.entries(semanticRoutes).reduce(
    (current, [rawPath, route]) =>
      current
        .replaceAll(`](${rawPath})`, `](${route})`)
        .replaceAll(`](/${rawPath})`, `](${route})`),
    markdown,
  );
}

const documentRenderer = {
  table(children: ReactNode[]) {
    return (
      <div className="table-scroll" role="region" aria-label="Document table" tabIndex={0}>
        <table>{children}</table>
      </div>
    );
  },
};

export function PublicDocumentPage({ documentId }: { readonly documentId: PublicDocumentId }) {
  const document = documents[documentId];
  return (
    <article className="public-document">
      <header className="public-document-header">
        <div>
          <p className="eyebrow">{document.eyebrow}</p>
          {document.format === 'text' ? <h1>{document.title}</h1> : null}
        </div>
        <a className="quiet-link" href={document.rawPath} download>
          Download raw {document.rawPath.replace('/', '')}
        </a>
      </header>
      {document.format === 'text' ? (
        <pre className="public-document-plain">{document.content}</pre>
      ) : (
        <div className="public-document-markdown">
          <Markdown
            gfm
            openLinksInNewTab={false}
            renderer={documentRenderer}
            value={semanticLinks(document.content)}
          />
        </div>
      )}
    </article>
  );
}

export function SourceChecksumPage() {
  const [checksum, setChecksum] = useState<
    | { readonly state: 'loading' }
    | { readonly state: 'ready'; readonly value: string }
    | { readonly state: 'unavailable' }
  >({ state: 'loading' });

  useEffect(() => {
    const controller = new AbortController();
    void fetch('/SOURCE_SHA256', {
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
    })
      .then((response) => {
        if (!response.ok) throw new Error('Checksum response failed.');
        return response.text();
      })
      .then((value) => setChecksum({ state: 'ready', value: value.trim() }))
      .catch(() => {
        if (!controller.signal.aborted) setChecksum({ state: 'unavailable' });
      });
    return () => controller.abort();
  }, []);

  return (
    <article className="public-document">
      <header className="public-document-header">
        <div>
          <p className="eyebrow">Corresponding source integrity</p>
          <h1>Source archive checksum</h1>
        </div>
        <a className="quiet-link" href="/SOURCE_SHA256" download>
          Download raw SOURCE_SHA256
        </a>
      </header>
      <div className="public-document-markdown">
        <p>
          Compare this build-specific SHA-256 value with the downloaded corresponding-source
          archive. The checksum establishes file consistency only; it is not a signature or an
          authorship claim.
        </p>
        <pre className="public-document-code" aria-live="polite">
          {checksum.state === 'loading'
            ? 'Loading checksum…'
            : checksum.state === 'ready'
              ? checksum.value
              : 'The checksum could not be loaded. Use the raw download link above.'}
        </pre>
        <p>
          <a href="/zoneskein-corresponding-source.tar.gz" download>
            Download the corresponding-source archive
          </a>{' '}
          or read the <a href="/source/">verification and unpacking directions</a>.
        </p>
      </div>
    </article>
  );
}
