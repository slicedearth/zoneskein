export type DnssecWorkKind =
  | 'cryptographicVerifications'
  | 'digestOperations'
  | 'ed448Verifications'
  | 'keys'
  | 'nsec3HashRounds'
  | 'records'
  | 'signatures';

const DEFAULT_LIMITS: Readonly<Record<DnssecWorkKind, number>> = {
  cryptographicVerifications: 512,
  digestOperations: 512,
  ed448Verifications: 64,
  keys: 1024,
  nsec3HashRounds: 20_000,
  records: 4096,
  signatures: 512,
};

const WORK_KIND_LABELS: Readonly<Record<DnssecWorkKind, string>> = {
  cryptographicVerifications: 'cryptographic-verification',
  digestOperations: 'digest-operation',
  ed448Verifications: 'Ed448-verification',
  keys: 'key',
  nsec3HashRounds: 'NSEC3 hash-round',
  records: 'record',
  signatures: 'signature',
};

export interface DnssecWorkBudgetOptions {
  readonly limits?: Partial<Readonly<Record<DnssecWorkKind, number>>>;
  readonly signal?: AbortSignal;
}

export class DnssecWorkBudget {
  readonly #limits: Readonly<Record<DnssecWorkKind, number>>;
  readonly #signal: AbortSignal | undefined;
  readonly #used: Record<DnssecWorkKind, number> = {
    cryptographicVerifications: 0,
    digestOperations: 0,
    ed448Verifications: 0,
    keys: 0,
    nsec3HashRounds: 0,
    records: 0,
    signatures: 0,
  };
  #exhaustedKind?: DnssecWorkKind;

  constructor(options: DnssecWorkBudgetOptions = {}) {
    this.#limits = { ...DEFAULT_LIMITS, ...options.limits };
    this.#signal = options.signal;
  }

  get cancelled(): boolean {
    return this.#signal?.aborted === true;
  }

  get exhausted(): boolean {
    return this.cancelled || this.#exhaustedKind !== undefined;
  }

  get explanation(): string {
    if (this.cancelled) return 'The DNSSEC validation run was cancelled.';
    return this.#exhaustedKind === undefined
      ? 'The DNSSEC work budget remains available.'
      : `The DNSSEC validation run exceeded its aggregate ${WORK_KIND_LABELS[this.#exhaustedKind]} work bound.`;
  }

  consume(kind: DnssecWorkKind, amount = 1): boolean {
    if (this.cancelled || this.#exhaustedKind !== undefined) return false;
    if (!Number.isSafeInteger(amount) || amount < 0) {
      this.#exhaustedKind = kind;
      return false;
    }
    const next = this.#used[kind] + amount;
    if (next > this.#limits[kind]) {
      this.#exhaustedKind = kind;
      return false;
    }
    this.#used[kind] = next;
    return true;
  }
}
