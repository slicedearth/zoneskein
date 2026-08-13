import {
  DmarcDiscoverySession,
  type DmarcCancellationCheck,
  type DmarcDiscoveryResult,
  type DmarcTxtLookup,
} from './discovery';
import {
  dmarcReportAuthorizationName,
  dmarcReportDestinationHost,
  evaluateDmarcReportAuthorization,
  type DmarcReportAuthorization,
  type DmarcReportAuthorizationTag,
} from './report-authorization';

export type DmarcReportingCheckStatus =
  'internal' | 'authorized' | 'unauthorized' | 'temperror' | 'permerror' | 'indeterminate';

export interface DmarcReportingCheck {
  readonly authorization?: DmarcReportAuthorization;
  readonly authorizationName?: string;
  readonly destinationHost?: string;
  readonly destinationUri: string;
  readonly discovery?: DmarcDiscoveryResult;
  readonly reason: string;
  readonly selectedUris: readonly string[];
  readonly status: DmarcReportingCheckStatus;
}

function discoveryFailureStatus(
  status: DmarcDiscoveryResult['status'],
): Extract<DmarcReportingCheckStatus, 'temperror' | 'permerror' | 'indeterminate'> {
  if (status === 'temperror' || status === 'permerror') return status;
  return 'indeterminate';
}

/**
 * Prove a reporting destination internal by independent tree walk, or require
 * and parse its RFC 9990/9991 external authorisation record.
 */
export async function discoverDmarcReportingAuthorization(
  policyDomain: string,
  policyOrganizationalDomain: string,
  destinationUri: string,
  lookupOrSession: DmarcTxtLookup | DmarcDiscoverySession,
  authorizationTag: DmarcReportAuthorizationTag = 'rua',
  maximumQuestions?: number,
  isCancelled?: DmarcCancellationCheck,
): Promise<DmarcReportingCheck> {
  const destinationHost = dmarcReportDestinationHost(destinationUri);
  if (destinationHost === null)
    return {
      destinationUri,
      reason: 'The reporting URI has no valid destination host.',
      selectedUris: [],
      status: 'permerror',
    };

  const session =
    lookupOrSession instanceof DmarcDiscoverySession
      ? lookupOrSession
      : new DmarcDiscoverySession(lookupOrSession, maximumQuestions, isCancelled);
  const discovery = await session.discoverBoundary(destinationHost);
  if (discovery.status !== 'complete' || discovery.organizationalDomain === undefined)
    return {
      destinationHost,
      destinationUri,
      discovery,
      reason: `The destination organisational boundary could not be completed. ${discovery.reason}`,
      selectedUris: [],
      status: discoveryFailureStatus(discovery.status),
    };

  if (discovery.organizationalDomain === policyOrganizationalDomain)
    return {
      destinationHost,
      destinationUri,
      discovery,
      reason: `The independently selected destination boundary ${discovery.organizationalDomain} matches the policy boundary.`,
      selectedUris: [destinationUri],
      status: 'internal',
    };

  const authorizationName = dmarcReportAuthorizationName(policyDomain, destinationUri);
  if (authorizationName === null)
    return {
      destinationHost,
      destinationUri,
      discovery,
      reason: 'The external authorisation DNS owner name exceeds protocol bounds.',
      selectedUris: [],
      status: 'permerror',
    };
  const authorizationLookup = await session.lookup(authorizationName);
  if (
    authorizationLookup.status === 'temperror' ||
    authorizationLookup.status === 'permerror' ||
    authorizationLookup.status === 'limit'
  )
    return {
      authorizationName,
      destinationHost,
      destinationUri,
      discovery,
      reason:
        authorizationLookup.error ??
        'The external authorisation TXT query did not complete safely.',
      selectedUris: [],
      status:
        authorizationLookup.status === 'limit' ? 'indeterminate' : authorizationLookup.status,
    };

  const authorization = evaluateDmarcReportAuthorization(
    destinationUri,
    authorizationLookup.values,
    authorizationTag,
  );
  return {
    authorization,
    authorizationName,
    destinationHost,
    destinationUri,
    discovery,
    reason: authorization.reason,
    selectedUris: authorization.selectedUris,
    status: authorization.status,
  };
}
