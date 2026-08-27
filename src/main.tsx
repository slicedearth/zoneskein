import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import '@fontsource-variable/atkinson-hyperlegible-next/wght.css';
import '@fontsource-variable/bricolage-grotesque/wght.css';

import { App } from './App';
import { DomainThreadProvider } from './components/DomainThreadProvider';
import './styles/app.css';

const root = document.querySelector<HTMLDivElement>('#root');

if (root === null) {
  throw new Error('Application root was not found.');
}

createRoot(root).render(
  <StrictMode>
    <DomainThreadProvider>
      <App />
    </DomainThreadProvider>
  </StrictMode>,
);
