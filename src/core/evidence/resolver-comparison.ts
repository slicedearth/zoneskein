import type { DnsRecord, DnsResponse } from '../dns/types';
import type { DnsGraphObservation } from './dns-graph';

export type ResolverDifferenceKind =
  | 'answer-data'
  | 'authority-data'
  | 'dnssec-signal'
  | 'extended-error'
  | 'response-code'
  | 'ttl';

export interface ResolverDifference {
  readonly explanation: string;
  readonly kind: ResolverDifferenceKind;
  readonly label: string;
}

export interface ResolverObservationSummary {
  readonly answerCount: number | null;
  readonly authenticatedData: boolean | null;
  readonly error: string | null;
  readonly extendedErrors: readonly string[];
  readonly resolver: string;
  readonly responseCode: string | null;
}

export interface ResolverQuestionComparison {
  readonly differences: readonly ResolverDifference[];
  readonly observations: readonly ResolverObservationSummary[];
  readonly questionName: string;
  readonly questionType: string;
  readonly state: 'agreement' | 'disagreement' | 'incomplete' | 'unavailable';
}

function hex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function recordIdentity(record: DnsRecord): string {
  return [
    record.owner.toLowerCase(),
    record.class,
    String(record.typeCode),
    hex(record.rawRdata),
  ].join('|');
}

function answerSet(response: DnsResponse): string {
  return response.message.answers.map(recordIdentity).sort().join('\n');
}

function authoritySet(response: DnsResponse): string {
  return response.message.authorities.map(recordIdentity).sort().join('\n');
}

function ttlSet(response: DnsResponse): string {
  return [...response.message.answers, ...response.message.authorities]
    .map((record) => `${record.section}|${recordIdentity(record)}|${String(record.ttl)}`)
    .sort()
    .join('\n');
}

function edeSet(response: DnsResponse): string {
  return (response.message.edns?.extendedErrors ?? [])
    .map((error) => `${String(error.code)}|${error.name}|${error.text ?? ''}`)
    .sort()
    .join('\n');
}

function distinct(values: readonly string[]): boolean {
  return new Set(values).size > 1;
}

function resolverName(observation: DnsGraphObservation, index: number): string {
  return (
    observation.response?.resolver.label ??
    observation.resolverLabel ??
    `Resolver observation ${String(index + 1)}`
  );
}

function differences(responses: readonly DnsResponse[]): readonly ResolverDifference[] {
  const output: ResolverDifference[] = [];
  if (distinct(responses.map((response) => response.message.responseCode)))
    output.push({
      explanation:
        'Response codes differ. This can reflect cache timing, DNSSEC or filtering policy, delegation state, or a transient resolver path; the answers alone do not identify which cause applies.',
      kind: 'response-code',
      label: 'Different response codes',
    });
  const answerSets = responses.map(answerSet);
  const authoritySets = responses.map(authoritySet);
  if (distinct(answerSets))
    output.push({
      explanation:
        'The answer RDATA differs after ignoring TTL and order. Check aliases, authoritative servers, propagation timing, resolver policy, and any accompanying extended error before acting.',
      kind: 'answer-data',
      label: 'Different answer data',
    });
  if (distinct(authoritySets))
    output.push({
      explanation:
        'Authority-section evidence differs. For empty or negative answers this can change the denial proof, negative-cache lifetime, or observed zone authority even when the answer section is identical.',
      kind: 'authority-data',
      label: 'Different authority data',
    });
  if (!distinct(answerSets) && !distinct(authoritySets) && distinct(responses.map(ttlSet)))
    output.push({
      explanation:
        'Answer data agrees, but observed TTLs differ. Ordinary cache age can cause this; it is not evidence that the underlying records differ.',
      kind: 'ttl',
      label: 'TTL-only difference',
    });
  if (distinct(responses.map((response) => String(response.message.flags.authenticatedData))))
    output.push({
      explanation:
        'Authenticated Data flags differ. AD is a resolver assertion under the query’s checking settings, not local validation; compare DNSSEC evidence separately.',
      kind: 'dnssec-signal',
      label: 'Different AD signals',
    });
  if (distinct(responses.map(edeSet)))
    output.push({
      explanation:
        'Extended DNS Error details differ. Where present, the resolver-supplied code can explain policy or validation handling, but absence of an EDE is not proof that no policy was applied.',
      kind: 'extended-error',
      label: 'Different extended errors',
    });
  return output;
}

export function compareDnsGraphObservations(
  observations: readonly DnsGraphObservation[],
): readonly ResolverQuestionComparison[] {
  const groups = new Map<string, DnsGraphObservation[]>();
  for (const observation of observations) {
    const key = `${observation.questionName.toLowerCase()}|${observation.questionType.toUpperCase()}`;
    const group = groups.get(key) ?? [];
    group.push(observation);
    groups.set(key, group);
  }
  return [...groups.values()]
    .map((group): ResolverQuestionComparison => {
      const responses = group.flatMap((item) => item.response ?? []);
      const failures = group.length - responses.length;
      const foundDifferences = responses.length > 1 ? differences(responses) : [];
      return {
        differences: foundDifferences,
        observations: group.map((observation, index) => ({
          answerCount: observation.response?.message.answers.length ?? null,
          authenticatedData: observation.response?.message.flags.authenticatedData ?? null,
          error:
            observation.response === undefined ? (observation.error ?? 'Unavailable') : null,
          extendedErrors: (observation.response?.message.edns?.extendedErrors ?? []).map(
            (error) =>
              `${String(error.code)} ${error.name}${error.text === undefined ? '' : `: ${error.text}`}`,
          ),
          resolver: resolverName(observation, index),
          responseCode: observation.response?.message.responseCode ?? null,
        })),
        questionName: group[0]?.questionName ?? '',
        questionType: group[0]?.questionType ?? '',
        state:
          responses.length === 0
            ? 'unavailable'
            : failures > 0 || responses.length < 2
              ? 'incomplete'
              : foundDifferences.length === 0
                ? 'agreement'
                : 'disagreement',
      };
    })
    .sort((left, right) => left.questionType.localeCompare(right.questionType));
}
