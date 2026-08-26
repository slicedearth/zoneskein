import {
  DnsQueryError,
  type DnsQueryOptions,
  type DnsQuestion,
  type DnsResolver,
  type DnsResponse,
  type ResolverDefinition,
} from '../dns/types';
import { WireDnsResolver, type WireResolverDependencies } from './wire-resolver';

type Quad9Path = 'direct' | 'relay' | 'undecided';

function permitsCompatibilityFallback(error: DnsQueryError): boolean {
  return (
    error.code === 'http-error' || error.code === 'timeout' || error.code === 'transport-error'
  );
}

function asDnsQueryError(cause: unknown): DnsQueryError {
  return cause instanceof DnsQueryError
    ? cause
    : new DnsQueryError(
        'transport-error',
        cause instanceof Error ? cause.message : 'The DNS query failed.',
      );
}

/**
 * Selects one stable Quad9 path for a resolver instance. The first question is
 * the capability probe and also supplies real evidence: a valid direct answer
 * locks the run to direct mode, while an eligible transport failure locks it
 * to the bounded compatibility relay. Concurrent questions wait for that
 * decision so one unavailable direct path cannot create a retry burst.
 */
export class Quad9AutoResolver implements DnsResolver {
  readonly #direct: WireDnsResolver;
  #path: Quad9Path = 'undecided';
  #probe: Promise<void> | null = null;
  readonly #relay: WireDnsResolver;

  constructor(
    direct: ResolverDefinition,
    relay: ResolverDefinition,
    dependencies: WireResolverDependencies = {},
  ) {
    if (direct.id !== 'quad9' || relay.id !== 'quad9-relay') {
      throw new Error(
        'The automatic Quad9 resolver requires the fixed direct and relay paths.',
      );
    }
    this.#direct = new WireDnsResolver(direct, dependencies);
    this.#relay = new WireDnsResolver(relay, dependencies);
  }

  get definition(): ResolverDefinition {
    return this.#path === 'relay' ? this.#relay.definition : this.#direct.definition;
  }

  async query(question: DnsQuestion, options: DnsQueryOptions): Promise<DnsResponse> {
    if (this.#path === 'direct') return this.#direct.query(question, options);
    if (this.#path === 'relay') return this.#relay.query(question, options);

    if (this.#probe !== null) {
      await this.#probe;
      return this.#activeResolver().query(question, options);
    }

    const first = this.#probePath(question, options);
    this.#probe = first.then(
      () => undefined,
      () => undefined,
    );
    return first;
  }

  #activeResolver(): WireDnsResolver {
    return this.#path === 'relay' ? this.#relay : this.#direct;
  }

  async #probePath(question: DnsQuestion, options: DnsQueryOptions): Promise<DnsResponse> {
    try {
      const response = await this.#direct.query(question, options);
      this.#path = 'direct';
      return response;
    } catch (cause) {
      const directError = asDnsQueryError(cause);
      if (!permitsCompatibilityFallback(directError) || options.signal?.aborted === true) {
        this.#path = 'direct';
        throw directError;
      }

      this.#path = 'relay';
      try {
        return await this.#relay.query(question, options);
      } catch (relayCause) {
        const relayError = asDnsQueryError(relayCause);
        throw new DnsQueryError(
          relayError.code,
          `Quad9 direct failed: ${directError.message} Automatic compatibility mode also failed: ${relayError.message}`,
          relayError.retryAfterMs,
        );
      }
    }
  }
}
