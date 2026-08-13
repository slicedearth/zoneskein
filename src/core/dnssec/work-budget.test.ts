import { describe, expect, it } from 'vitest';

import { DnssecWorkBudget } from './work-budget';

describe('aggregate DNSSEC work budget', () => {
  it('shares category limits across a complete run', () => {
    const budget = new DnssecWorkBudget({ limits: { digestOperations: 2 } });

    expect(budget.consume('digestOperations')).toBe(true);
    expect(budget.consume('digestOperations')).toBe(true);
    expect(budget.consume('digestOperations')).toBe(false);
    expect(budget.exhausted).toBe(true);
    expect(budget.explanation).toMatch(/digest-operation/iu);
  });

  it('stops new work as soon as the run is cancelled', () => {
    const controller = new AbortController();
    const budget = new DnssecWorkBudget({ signal: controller.signal });
    controller.abort();

    expect(budget.consume('cryptographicVerifications')).toBe(false);
    expect(budget.cancelled).toBe(true);
    expect(budget.explanation).toMatch(/cancelled/iu);
  });
});
