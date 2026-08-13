import type { DnsQueryOptions, DnsQuestion, DnsResolver, DnsResponse } from '../dns/types';
import { QueryBudget } from './query-budget';

export class DnsQueryRun {
  readonly #budget = new QueryBudget();
  readonly #controller = new AbortController();

  get cancelled(): boolean {
    return this.#controller.signal.aborted;
  }

  get questionsUsed(): number {
    return this.#budget.used;
  }

  cancel(): void {
    this.#controller.abort();
  }

  query(
    resolver: DnsResolver,
    question: DnsQuestion,
    options: Omit<DnsQueryOptions, 'signal'>,
  ): Promise<DnsResponse> {
    const key = [
      resolver.definition.id,
      question.name.absolute,
      question.type,
      options.checkingDisabled ? 'cd1' : 'cd0',
      options.dnssecOk ? 'do1' : 'do0',
    ].join('|');
    this.#budget.consume(key);
    return resolver.query(question, { ...options, signal: this.#controller.signal });
  }
}
