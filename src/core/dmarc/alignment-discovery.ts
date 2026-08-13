import {
  dmarcAlignmentModes,
  evaluateDmarcAlignment,
  type DmarcAlignmentEvaluation,
  type DmarcAlignmentResult,
  type DmarcBoundaryStatus,
  type DmarcSpfAuthentication,
} from './alignment';
import {
  DmarcDiscoverySession,
  type DmarcCancellationCheck,
  type DmarcDiscoveryResult,
  type DmarcTxtLookup,
} from './discovery';
import type { DmarcPolicy } from './types';

export interface DmarcAlignmentDiscoveryInput {
  readonly dkimDomains: readonly string[];
  readonly fromDomain: string;
  readonly spf: DmarcSpfAuthentication;
}

export interface DmarcIdentifierDiscovery {
  readonly domain: string;
  readonly discovery: DmarcDiscoveryResult;
}

export interface DmarcAlignmentDiscoveryResult {
  readonly evaluation?: DmarcAlignmentEvaluation;
  readonly identifierDiscoveries: readonly DmarcIdentifierDiscovery[];
  readonly policy?: DmarcPolicy;
  readonly policyDiscovery: DmarcDiscoveryResult;
  readonly policyDomain?: string;
  readonly questionsUsed: number;
  readonly reason: string;
  readonly result: DmarcAlignmentResult;
}

function discoveryFailureResult(status: DmarcDiscoveryResult['status']): DmarcAlignmentResult {
  if (status === 'temperror' || status === 'permerror') return status;
  return 'indeterminate';
}

function boundaryStatus(status: DmarcDiscoveryResult['status']): DmarcBoundaryStatus {
  if (status === 'complete') return 'complete';
  if (status === 'temperror' || status === 'permerror') return status;
  return 'indeterminate';
}

/** Discover every boundary required by one DMARC alignment decision, then evaluate it locally. */
export async function discoverAndEvaluateDmarcAlignment(
  input: DmarcAlignmentDiscoveryInput,
  lookup: DmarcTxtLookup,
  maximumQuestions?: number,
  isCancelled?: DmarcCancellationCheck,
): Promise<DmarcAlignmentDiscoveryResult> {
  const session = new DmarcDiscoverySession(lookup, maximumQuestions, isCancelled);
  const policyDiscovery = await session.discover(input.fromDomain);
  const cancelled = () => isCancelled?.() === true;
  if (cancelled())
    return {
      identifierDiscoveries: [],
      policyDiscovery,
      questionsUsed: session.questionsUsed,
      reason: 'DMARC alignment discovery was cancelled before a complete result was available.',
      result: 'temperror',
    };
  if (policyDiscovery.status !== 'complete')
    return {
      identifierDiscoveries: [],
      policyDiscovery,
      questionsUsed: session.questionsUsed,
      reason: `DMARC alignment cannot be evaluated safely. ${policyDiscovery.reason}`,
      result: discoveryFailureResult(policyDiscovery.status),
    };

  const selected = policyDiscovery.selected;
  const organizationalDomain = policyDiscovery.organizationalDomain;
  if (selected === undefined || organizationalDomain === undefined)
    return {
      identifierDiscoveries: [],
      policyDiscovery,
      questionsUsed: session.questionsUsed,
      reason:
        'No applicable DMARC policy was discovered for the RFC5322.From domain, so an alignment result is not asserted.',
      result: 'indeterminate',
    };

  const policy = selected.policy;
  if (!policy.applicable)
    return {
      identifierDiscoveries: [],
      policy,
      policyDiscovery,
      policyDomain: selected.domain,
      questionsUsed: session.questionsUsed,
      reason: 'The selected DMARC record is not applicable, so alignment fails closed.',
      result: 'permerror',
    };

  const modes = dmarcAlignmentModes(policy);
  const preliminary = evaluateDmarcAlignment({
    ...modes,
    dkimDomains: input.dkimDomains,
    fromDomain: input.fromDomain,
    organizationalDomain,
    organizationalDomainStatus: 'complete',
    spf: input.spf,
  });
  const neededDomains = [
    ...new Set(
      preliminary.evidence.flatMap((item) =>
        item.status === 'indeterminate' && item.domain !== undefined ? [item.domain] : [],
      ),
    ),
  ];
  const identifierDiscoveries: DmarcIdentifierDiscovery[] = [];
  const boundaries: Record<string, string> = {};
  const statuses: Record<string, DmarcBoundaryStatus> = {};
  for (const domain of neededDomains) {
    if (cancelled())
      return {
        identifierDiscoveries,
        policy,
        policyDiscovery,
        policyDomain: selected.domain,
        questionsUsed: session.questionsUsed,
        reason: 'DMARC alignment discovery was cancelled before every boundary was completed.',
        result: 'temperror',
      };
    const discovery = await session.discoverBoundary(domain);
    identifierDiscoveries.push({ discovery, domain });
    if (cancelled())
      return {
        identifierDiscoveries,
        policy,
        policyDiscovery,
        policyDomain: selected.domain,
        questionsUsed: session.questionsUsed,
        reason: 'DMARC alignment discovery was cancelled before every boundary was completed.',
        result: 'temperror',
      };
    statuses[domain] = boundaryStatus(discovery.status);
    if (discovery.status === 'complete' && discovery.organizationalDomain !== undefined)
      boundaries[domain] = discovery.organizationalDomain;
  }

  const evaluation =
    neededDomains.length === 0
      ? preliminary
      : evaluateDmarcAlignment({
          ...modes,
          authenticatedOrganizationalDomains: boundaries,
          authenticatedOrganizationalDomainStatuses: statuses,
          dkimDomains: input.dkimDomains,
          fromDomain: input.fromDomain,
          organizationalDomain,
          organizationalDomainStatus: 'complete',
          spf: input.spf,
        });
  return {
    evaluation,
    identifierDiscoveries,
    policy,
    policyDiscovery,
    policyDomain: selected.domain,
    questionsUsed: session.questionsUsed,
    reason: evaluation.reason,
    result: evaluation.result,
  };
}
