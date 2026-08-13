import { describe, expect, it } from 'vitest';

import { QueryBudget } from './query-budget';

describe('per-run query budget', () => {
  it('deduplicates questions and rejects question 81', () => {
    const budget = new QueryBudget();
    budget.consume('same');
    budget.consume('same');
    expect(budget.used).toBe(1);

    for (let index = 1; index < 80; index += 1) budget.consume(`question-${String(index)}`);
    expect(budget.used).toBe(80);
    expect(() => budget.consume('too-many')).toThrow(/80-question/);
  });
});
