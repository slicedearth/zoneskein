import { DnsQueryError } from '../dns/types';

const MAX_UNIQUE_QUESTIONS = 80;

export class QueryBudget {
  readonly #questions = new Set<string>();

  get limit(): number {
    return MAX_UNIQUE_QUESTIONS;
  }

  get used(): number {
    return this.#questions.size;
  }

  consume(key: string): void {
    if (this.#questions.has(key)) return;
    if (this.#questions.size >= MAX_UNIQUE_QUESTIONS) {
      throw new DnsQueryError(
        'budget-exhausted',
        `This run reached its ${String(MAX_UNIQUE_QUESTIONS)}-question DNS budget.`,
      );
    }
    this.#questions.add(key);
  }
}
