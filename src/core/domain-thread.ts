import { createContext, useContext } from 'react';

import type { ValidatedDnsName } from './dns/types';

export interface DomainThreadValue {
  readonly clearDomain: () => void;
  readonly domain: ValidatedDnsName | null;
  readonly setDomain: (value: ValidatedDnsName) => void;
}

export const DomainThreadContext = createContext<DomainThreadValue>({
  clearDomain: () => undefined,
  domain: null,
  setDomain: () => undefined,
});

export function useDomainThread(): DomainThreadValue {
  return useContext(DomainThreadContext);
}
