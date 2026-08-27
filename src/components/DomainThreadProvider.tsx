import { useMemo, useState } from 'react';

import { DomainThreadContext, type DomainThreadValue } from '../core/domain-thread';
import type { ValidatedDnsName } from '../core/dns/types';

export function DomainThreadProvider({ children }: { readonly children: React.ReactNode }) {
  const [domain, setDomain] = useState<ValidatedDnsName | null>(null);
  const value = useMemo<DomainThreadValue>(
    () => ({ clearDomain: () => setDomain(null), domain, setDomain }),
    [domain],
  );
  return <DomainThreadContext value={value}>{children}</DomainThreadContext>;
}
