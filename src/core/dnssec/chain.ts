import type { DnsExtendedError, DnsRecordType, DnsResponse } from '../dns/types';
import {
  canEstablishDsTrustPath,
  canValidateDsDigestType,
  isDeprecatedSha1DnssecAlgorithm,
} from './algorithm-policy';
import {
  validateApplicationRrset,
  type DnssecApplicationResult,
  type DnssecApplicationType,
} from './application';
import { compareDsToDnskeys } from './digest';
import { validateDsDenial, type DsDenialResult } from './denial';
import { parseDnskey, parseDs, signatureTimeState } from './records';
import {
  matchRootTrustAnchors,
  ROOT_TRUST_ANCHOR_SOURCE,
  type RootTrustAnchorMatch,
} from './trust-anchors';
import type { DnskeyInfo, DsInfo, DsMatch, SignatureVerification } from './types';
import { verifyRrset } from './verify';
import { boundDenialRecords, boundRrset, wireQuestionMatches } from './wire-evidence';
import { DnssecWorkBudget } from './work-budget';

export type DnssecChainState =
  | 'secure'
  | 'insecure'
  | 'not-delegated'
  | 'alias-boundary'
  | 'opt-out'
  | 'bogus'
  | 'unsupported'
  | 'incomplete';

export interface DnssecChainEvidence {
  readonly authenticatedData?: boolean;
  readonly cache?: DnsResponse['cache'];
  readonly error?: string;
  readonly extendedErrors?: readonly DnsExtendedError[];
  readonly name: string;
  readonly decodedQuestion?: DnsResponse['message']['questions'][number];
  readonly rawDnsBase64?: string;
  readonly receivedAt?: string;
  readonly resolver?: string;
  readonly resolverEndpoint?: string;
  readonly resolverId?: string;
  readonly responseCode?: string;
  readonly type: DnsRecordType;
}

export interface DnssecChainStep {
  readonly denial?: DsDenialResult;
  readonly dnskeys: readonly DnskeyInfo[];
  readonly dnskeyVerifications: readonly SignatureVerification[];
  readonly ds: readonly DsInfo[];
  readonly dsMatches: readonly DsMatch[];
  readonly dsVerifications: readonly SignatureVerification[];
  readonly explanation: string;
  readonly state: DnssecChainState;
  readonly trustAnchors?: readonly RootTrustAnchorMatch[];
  readonly validatedAt: string;
  readonly zone: string;
}

export interface DnssecChainReport {
  readonly application?: DnssecApplicationResult;
  readonly evidence: readonly DnssecChainEvidence[];
  readonly explanation: string;
  readonly state: DnssecChainState;
  readonly steps: readonly DnssecChainStep[];
  readonly target: string;
  readonly trustAnchorSource: typeof ROOT_TRUST_ANCHOR_SOURCE;
  readonly validatedAt: string;
  readonly validatorVersion: 2;
}

export type DnssecChainQuery = (
  absoluteName: string,
  type: DnsRecordType,
) => Promise<DnsResponse>;

export interface DnssecChainOptions {
  readonly clock?: () => number;
  readonly matchTrustAnchors?: typeof matchRootTrustAnchors;
  readonly now?: number;
  readonly rrsetType?: DnssecApplicationType;
  readonly signal?: AbortSignal;
}

const MAX_CHAIN_QUESTIONS = 80;
const MAX_CHAIN_RRSET_RECORDS = 64;

function absolute(name: string): string {
  const normalized = name.toLowerCase().replace(/\.$/u, '');
  return normalized === '' ? '.' : `${normalized}.`;
}

function base64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function errorMessage(cause: unknown): string {
  return cause instanceof Error ? cause.message : 'The DNSSEC question failed.';
}

function eligibleKeys(keys: readonly DnskeyInfo[]): readonly DnskeyInfo[] {
  return keys.filter(
    (key) => key.protocol === 3 && key.zoneKey && !key.revoked && (key.flags & ~0x0181) === 0,
  );
}

function boundResponse(response: DnsResponse, name: string, type: DnsRecordType): boolean {
  const decoded = response.message.questions[0];
  return (
    response.message.id === 0 &&
    !response.message.flags.truncated &&
    wireQuestionMatches(response, name, type) &&
    response.message.questions.length === 1 &&
    decoded?.class.toUpperCase() === 'IN' &&
    absolute(decoded.name) === absolute(name) &&
    decoded.type === type &&
    absolute(response.question.name.absolute) === absolute(name) &&
    response.question.type === type
  );
}

function failureState(verifications: readonly SignatureVerification[]): DnssecChainState {
  if (verifications.some((verification) => verification.status === 'resource-limit'))
    return 'incomplete';
  return verifications.length > 0 &&
    verifications.every((verification) => verification.status === 'unsupported')
    ? 'unsupported'
    : 'bogus';
}

function anchorIsCurrent(match: RootTrustAnchorMatch, now: number): boolean {
  return (
    Date.parse(match.anchor.validFrom) <= now &&
    (match.anchor.validUntil === undefined || Date.parse(match.anchor.validUntil) > now)
  );
}

function verificationIsCurrent(verification: SignatureVerification, now: number): boolean {
  return (
    verification.status === 'verified' &&
    verification.inception !== undefined &&
    verification.expiration !== undefined &&
    signatureTimeState(verification.inception, verification.expiration, now) === 'current'
  );
}

function failureExplanation(type: 'DS' | 'DNSKEY', state: DnssecChainState): string {
  if (state === 'incomplete')
    return `The ${type} RRset exceeds the local cryptographic work bound.`;
  return state === 'unsupported'
    ? `The ${type} RRset uses a signature algorithm unavailable to this browser validator.`
    : `No current ${type} signature verified with the already trusted keys.`;
}

export async function validateDnssecChain(
  requestedName: string,
  query: DnssecChainQuery,
  options: DnssecChainOptions = {},
): Promise<DnssecChainReport> {
  const fixedNow = options.now;
  const clock = options.clock ?? Date.now;
  const currentTime = () => fixedNow ?? clock();
  const budget = new DnssecWorkBudget(
    options.signal === undefined ? {} : { signal: options.signal },
  );
  const target = absolute(requestedName);
  const labels = target === '.' ? [] : target.slice(0, -1).split('.');
  const evidence: DnssecChainEvidence[] = [];
  const steps: DnssecChainStep[] = [];
  const authenticatedGroups: (readonly SignatureVerification[])[] = [];
  let rootAnchorMatches: readonly RootTrustAnchorMatch[] = [];
  let application: DnssecApplicationResult | undefined;
  let questionsUsed = 0;

  const ask = async (name: string, type: DnsRecordType): Promise<DnsResponse | undefined> => {
    if (questionsUsed >= MAX_CHAIN_QUESTIONS) {
      evidence.push({
        error: `The DNSSEC run reached its ${String(MAX_CHAIN_QUESTIONS)}-question bound.`,
        name,
        type,
      });
      return undefined;
    }
    questionsUsed += 1;
    try {
      const response = await query(name, type);
      const item: DnssecChainEvidence = {
        authenticatedData: response.message.flags.authenticatedData,
        cache: response.cache,
        ...(response.message.questions[0] === undefined
          ? {}
          : { decodedQuestion: response.message.questions[0] }),
        ...(response.message.edns?.extendedErrors === undefined
          ? {}
          : { extendedErrors: response.message.edns.extendedErrors }),
        name,
        rawDnsBase64: base64(response.message.raw),
        receivedAt: response.receivedAt,
        resolver: response.resolver.label,
        resolverEndpoint: response.resolver.endpoint,
        resolverId: response.resolver.id,
        responseCode: response.message.responseCode,
        type,
      };
      if (!boundResponse(response, name, type)) {
        evidence.push({
          ...item,
          error: 'The decoded DNS response does not match the requested question.',
        });
        return undefined;
      }
      evidence.push(item);
      return response;
    } catch (cause) {
      evidence.push({ error: errorMessage(cause), name, type });
      return undefined;
    }
  };

  const finishAt = (
    state: DnssecChainState,
    explanation: string,
    validationTime: number,
  ): DnssecChainReport => ({
    ...(application === undefined ? {} : { application }),
    evidence,
    explanation,
    state,
    steps,
    target,
    trustAnchorSource: ROOT_TRUST_ANCHOR_SOURCE,
    validatedAt: new Date(validationTime).toISOString(),
    validatorVersion: 2,
  });
  const finish = (state: DnssecChainState, explanation: string): DnssecChainReport =>
    finishAt(state, explanation, currentTime());
  const finishAuthenticated = (
    state: DnssecChainState,
    explanation: string,
  ): DnssecChainReport => {
    const validationTime = currentTime();
    const serialTime = Math.floor(validationTime / 1000);
    const rootGroup = authenticatedGroups[0];
    const rootIsCurrent =
      rootGroup?.some(
        (verification) =>
          verificationIsCurrent(verification, serialTime) &&
          rootAnchorMatches.some(
            (match) =>
              match.key.keyTag === verification.keyTag &&
              match.key.algorithm === verification.algorithm &&
              anchorIsCurrent(match, validationTime),
          ),
      ) === true;
    const everyLaterGroupIsCurrent = authenticatedGroups
      .slice(1)
      .every((group) =>
        group.some((verification) => verificationIsCurrent(verification, serialTime)),
      );
    if (!rootIsCurrent || !everyLaterGroupIsCurrent) {
      return finishAt(
        'incomplete',
        'The authenticated links did not remain valid at one common validation time.',
        validationTime,
      );
    }
    return finishAt(state, explanation, validationTime);
  };
  const finishApplicationResponse = async (
    response: DnsResponse,
    keys: readonly DnskeyInfo[],
    type: DnssecApplicationType,
    responseQuestionType: DnsRecordType = type,
  ): Promise<DnssecChainReport> => {
    application = await validateApplicationRrset(
      response,
      target,
      type,
      keys,
      Math.floor(currentTime() / 1000),
      budget,
      responseQuestionType,
    );
    if (application.verifications.some((verification) => verification.status === 'verified'))
      authenticatedGroups.push(application.verifications);
    return finishAuthenticated(application.state, application.explanation);
  };
  const finishWithApplication = async (
    keys: readonly DnskeyInfo[],
    chainExplanation: string,
  ): Promise<DnssecChainReport> => {
    const type = options.rrsetType;
    if (type === undefined) return finishAuthenticated('secure', chainExplanation);
    const response = await ask(target, type);
    if (response === undefined)
      return finish('incomplete', `The ${type} RRset for ${target} could not be retrieved.`);
    return finishApplicationResponse(response, keys, type);
  };

  const rootResponse = await ask('.', 'DNSKEY');
  if (rootResponse === undefined)
    return finish('incomplete', 'The root DNSKEY RRset could not be retrieved.');
  if (rootResponse.message.responseCode !== 'NOERROR')
    return finish(
      'incomplete',
      `The root DNSKEY question returned ${rootResponse.message.responseCode}.`,
    );
  const rootRecords = boundRrset(rootResponse, 'answer', '.', 'DNSKEY');
  if (rootRecords === null)
    return finish(
      'incomplete',
      'The root DNSKEY response could not be bound to its wire RRset.',
    );
  if (
    rootRecords.length > MAX_CHAIN_RRSET_RECORDS ||
    !budget.consume('records', rootRecords.length)
  )
    return finish('incomplete', 'The root DNSKEY RRset exceeds the local work bound.');
  const rootDnskeyRecords = rootRecords.filter((record) => record.type === 'DNSKEY');
  const rootKeys = rootRecords.flatMap((record) => {
    const key = parseDnskey(record);
    return key === null ? [] : [key];
  });
  if (rootKeys.length !== rootDnskeyRecords.length)
    return finish('bogus', 'The root DNSKEY RRset contains malformed DNSKEY RDATA.');
  const anchorMatches = await (options.matchTrustAnchors ?? matchRootTrustAnchors)(
    rootKeys,
    currentTime(),
    budget,
  );
  rootAnchorMatches = anchorMatches;
  if (anchorMatches.length === 0) {
    const state: DnssecChainState = budget.exhausted ? 'incomplete' : 'bogus';
    const explanation = budget.exhausted
      ? budget.explanation
      : 'No returned root DNSKEY matches a current bundled IANA trust anchor.';
    steps.push({
      dnskeys: rootKeys,
      dnskeyVerifications: [],
      ds: [],
      dsMatches: [],
      dsVerifications: [],
      explanation,
      state,
      trustAnchors: [],
      validatedAt: new Date(currentTime()).toISOString(),
      zone: '.',
    });
    return finish(state, explanation);
  }
  const rootVerifications = await verifyRrset(
    rootRecords,
    'DNSKEY',
    anchorMatches.map((match) => match.key),
    Math.floor(currentTime() / 1000),
    budget,
  );
  if (!rootVerifications.some((verification) => verification.status === 'verified')) {
    const state = failureState(rootVerifications);
    steps.push({
      dnskeys: rootKeys,
      dnskeyVerifications: rootVerifications,
      ds: [],
      dsMatches: [],
      dsVerifications: [],
      explanation: failureExplanation('DNSKEY', state),
      state,
      trustAnchors: anchorMatches,
      validatedAt: new Date(currentTime()).toISOString(),
      zone: '.',
    });
    return finish(
      state,
      'The root DNSKEY RRset was not validated from a bundled trust anchor.',
    );
  }
  authenticatedGroups.push(rootVerifications);

  let trustedKeys = eligibleKeys(rootKeys);
  if (trustedKeys.length === 0)
    return finish('bogus', 'The authenticated root DNSKEY RRset has no eligible zone keys.');
  steps.push({
    dnskeys: rootKeys,
    dnskeyVerifications: rootVerifications,
    ds: [],
    dsMatches: [],
    dsVerifications: [],
    explanation: 'A bundled IANA trust anchor validated the root DNSKEY RRset locally.',
    state: 'secure',
    trustAnchors: anchorMatches,
    validatedAt: new Date(currentTime()).toISOString(),
    zone: '.',
  });
  if (labels.length === 0)
    return finishWithApplication(trustedKeys, 'The root DNSKEY RRset validated locally.');

  const zones = Array.from({ length: labels.length }, (_, index) =>
    absolute(labels.slice(labels.length - 1 - index).join('.')),
  );
  for (const zone of zones) {
    const dsResponse = await ask(zone, 'DS');
    if (dsResponse === undefined)
      return finish('incomplete', `The DS RRset for ${zone} could not be retrieved.`);
    if (
      dsResponse.message.responseCode !== 'NOERROR' &&
      dsResponse.message.responseCode !== 'NXDOMAIN'
    )
      return finish(
        'incomplete',
        `The DS question for ${zone} returned ${dsResponse.message.responseCode}.`,
      );
    const dsRrset = boundRrset(dsResponse, 'answer', zone, 'DS');
    if (dsRrset === null)
      return finish(
        'incomplete',
        `The DS response for ${zone} could not be bound to its wire RRset.`,
      );
    if (dsRrset.length > MAX_CHAIN_RRSET_RECORDS || !budget.consume('records', dsRrset.length))
      return finish('incomplete', `The DS RRset for ${zone} exceeds the local work bound.`);
    const typedDsRecords = dsRrset.filter((record) => record.type === 'DS');
    const dsRecords = dsRrset.flatMap((record) => {
      const ds = parseDs(record);
      return ds === null || absolute(record.owner) !== zone ? [] : [ds];
    });
    if (dsRecords.length !== typedDsRecords.length)
      return finish('bogus', `The DS RRset for ${zone} contains malformed DS RDATA.`);
    if (dsRecords.length === 0) {
      if (
        zone === target &&
        options.rrsetType === 'CNAME' &&
        dsResponse.message.responseCode === 'NOERROR' &&
        dsResponse.message.answers.some(
          (record) =>
            record.class.toUpperCase() === 'IN' &&
            absolute(record.owner) === target &&
            record.type === 'CNAME',
        )
      )
        return finishApplicationResponse(dsResponse, trustedKeys, 'CNAME', 'DS');
      const alias = dsResponse.message.answers.find(
        (record) =>
          record.class.toUpperCase() === 'IN' &&
          (record.type === 'CNAME' || record.type === 'DNAME'),
      );
      if (alias !== undefined)
        return finish(
          'incomplete',
          `The delegation probe crossed a ${alias.type} alias; every alias step and the final target must be authenticated before this result can be completed.`,
        );
      if (dsResponse.message.responseCode === 'NXDOMAIN') {
        const explanation =
          'The parent returned NXDOMAIN; this chain validator does not treat an exact-owner NODATA proof as authenticated non-existence.';
        steps.push({
          dnskeys: [],
          dnskeyVerifications: [],
          ds: [],
          dsMatches: [],
          dsVerifications: [],
          explanation,
          state: 'incomplete',
          validatedAt: new Date(currentTime()).toISOString(),
          zone,
        });
        return finish('incomplete', explanation);
      }
      const denialRecords = boundDenialRecords(dsResponse);
      if (denialRecords === null)
        return finish(
          'incomplete',
          `The denial response for ${zone} could not be bound to lossless wire names.`,
        );
      const denial = await validateDsDenial(
        zone,
        denialRecords,
        trustedKeys,
        Math.floor(currentTime() / 1000),
        budget,
      );
      steps.push({
        denial,
        dnskeys: [],
        dnskeyVerifications: [],
        ds: [],
        dsMatches: [],
        dsVerifications: denial.verifications,
        explanation: denial.explanation,
        state: denial.state,
        validatedAt: new Date(currentTime()).toISOString(),
        zone,
      });
      if (
        denial.state === 'insecure' ||
        denial.state === 'not-delegated' ||
        denial.state === 'alias-boundary' ||
        denial.state === 'opt-out'
      ) {
        if (denial.proofVerifications === undefined || denial.proofVerifications.length === 0)
          return finish(
            'incomplete',
            'The authenticated denial result did not retain its verification groups.',
          );
        authenticatedGroups.push(...denial.proofVerifications);
        if (denial.state === 'not-delegated' && zone !== target) continue;
        if (denial.state === 'not-delegated')
          return finishWithApplication(
            trustedKeys,
            `The authenticated containing-zone keys are available for ${target}.`,
          );
        return finishAuthenticated(denial.state, denial.explanation);
      }
      return finish(denial.state, denial.explanation);
    }
    if (dsResponse.message.responseCode !== 'NOERROR')
      return finish(
        'bogus',
        `The DS response for ${zone} contains records despite ${dsResponse.message.responseCode}.`,
      );

    const dsVerifications = await verifyRrset(
      dsRrset,
      'DS',
      trustedKeys,
      Math.floor(currentTime() / 1000),
      budget,
    );
    if (!dsVerifications.some((verification) => verification.status === 'verified')) {
      const state = failureState(dsVerifications);
      const explanation = failureExplanation('DS', state);
      steps.push({
        dnskeys: [],
        dnskeyVerifications: [],
        ds: dsRecords,
        dsMatches: [],
        dsVerifications,
        explanation,
        state,
        validatedAt: new Date(currentTime()).toISOString(),
        zone,
      });
      return finish(state, explanation);
    }
    authenticatedGroups.push(dsVerifications);

    const acceptableDsRecords = dsRecords.filter((ds) => canEstablishDsTrustPath(ds.algorithm));
    if (
      acceptableDsRecords.length === 0 &&
      dsRecords.every((ds) => isDeprecatedSha1DnssecAlgorithm(ds.algorithm))
    ) {
      const explanation = `The authenticated DS RRset for ${zone} contains only RSA/SHA-1 algorithms 5 or 7, which RFC 9905 requires validators to treat as an insecure delegation.`;
      steps.push({
        dnskeys: [],
        dnskeyVerifications: [],
        ds: dsRecords,
        dsMatches: [],
        dsVerifications,
        explanation,
        state: 'insecure',
        validatedAt: new Date(currentTime()).toISOString(),
        zone,
      });
      return finishAuthenticated('insecure', explanation);
    }

    const keyResponse = await ask(zone, 'DNSKEY');
    if (keyResponse === undefined)
      return finish('incomplete', `The DNSKEY RRset for ${zone} could not be retrieved.`);
    if (keyResponse.message.responseCode !== 'NOERROR')
      return finish(
        'bogus',
        `The signed delegation exists, but its DNSKEY question returned ${keyResponse.message.responseCode}.`,
      );
    const keyRecords = boundRrset(keyResponse, 'answer', zone, 'DNSKEY');
    if (keyRecords === null)
      return finish(
        'incomplete',
        `The DNSKEY response for ${zone} could not be bound to its wire RRset.`,
      );
    if (
      keyRecords.length > MAX_CHAIN_RRSET_RECORDS ||
      !budget.consume('records', keyRecords.length)
    )
      return finish('incomplete', `The DNSKEY RRset for ${zone} exceeds the local work bound.`);
    const typedKeyRecords = keyRecords.filter((record) => record.type === 'DNSKEY');
    const dnskeys = keyRecords.flatMap((record) => {
      const key = parseDnskey(record);
      return key === null || absolute(record.owner) !== zone ? [] : [key];
    });
    if (dnskeys.length !== typedKeyRecords.length)
      return finish('bogus', `The DNSKEY RRset for ${zone} contains malformed DNSKEY RDATA.`);
    const matches = await compareDsToDnskeys(zone, acceptableDsRecords, dnskeys, budget);
    const matchingKeys = matches
      .filter((match) => match.matches)
      .map((match) => match.dnskey)
      .filter((key, index, values) => values.indexOf(key) === index);
    if (matchingKeys.length === 0) {
      if (budget.exhausted) return finish('incomplete', budget.explanation);
      const supportedPath = acceptableDsRecords.some((ds) =>
        canValidateDsDigestType(ds.digestType),
      );
      const state: DnssecChainState = supportedPath ? 'bogus' : 'unsupported';
      const explanation = supportedPath
        ? 'No child DNSKEY matches any acceptable, locally authenticated parent DS record.'
        : 'The authenticated DS RRset has no acceptable signing-algorithm and digest combination available to this browser validator.';
      steps.push({
        dnskeys,
        dnskeyVerifications: [],
        ds: dsRecords,
        dsMatches: matches,
        dsVerifications,
        explanation,
        state,
        validatedAt: new Date(currentTime()).toISOString(),
        zone,
      });
      return finish(state, explanation);
    }
    const dnskeyVerifications = await verifyRrset(
      keyRecords,
      'DNSKEY',
      matchingKeys,
      Math.floor(currentTime() / 1000),
      budget,
    );
    if (!dnskeyVerifications.some((verification) => verification.status === 'verified')) {
      const state = failureState(dnskeyVerifications);
      const explanation = failureExplanation('DNSKEY', state);
      steps.push({
        dnskeys,
        dnskeyVerifications,
        ds: dsRecords,
        dsMatches: matches,
        dsVerifications,
        explanation,
        state,
        validatedAt: new Date(currentTime()).toISOString(),
        zone,
      });
      return finish(state, explanation);
    }
    authenticatedGroups.push(dnskeyVerifications);
    trustedKeys = eligibleKeys(dnskeys);
    if (trustedKeys.length === 0) {
      const explanation = 'The authenticated child DNSKEY RRset has no eligible zone keys.';
      steps.push({
        dnskeys,
        dnskeyVerifications,
        ds: dsRecords,
        dsMatches: matches,
        dsVerifications,
        explanation,
        state: 'bogus',
        validatedAt: new Date(currentTime()).toISOString(),
        zone,
      });
      return finish('bogus', explanation);
    }
    steps.push({
      dnskeys,
      dnskeyVerifications,
      ds: dsRecords,
      dsMatches: matches,
      dsVerifications,
      explanation: 'The parent DS and child DNSKEY RRsets validated locally.',
      state: 'secure',
      validatedAt: new Date(currentTime()).toISOString(),
      zone,
    });
  }
  return finishWithApplication(
    trustedKeys,
    `Every delegation from the IANA root trust anchor to ${target} validated locally.`,
  );
}
