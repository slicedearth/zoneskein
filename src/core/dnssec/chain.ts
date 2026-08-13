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
import {
  ancestorDnameTransition,
  classifyServiceBindingRrset,
  DnssecAliasPath,
  exactCnameTransition,
  type DnssecAliasTransition,
} from './alias';
import { compareDsToDnskeys } from './digest';
import { validateDsDenial, type DsDenialResult } from './denial';
import { parseDnskey, parseDs, parseRrsig, signatureTimeState } from './records';
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
  readonly validatorVersion: 3;
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

type AuthenticatedAliasResult =
  | { readonly kind: 'none' }
  | { readonly kind: 'follow'; readonly transition: DnssecAliasTransition }
  | {
      readonly explanation: string;
      readonly kind: 'failure';
      readonly state: DnssecChainState;
    };

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

function nameLabels(name: string): readonly string[] {
  const canonical = absolute(name);
  return canonical === '.' ? [] : canonical.slice(0, -1).split('.');
}

function isStrictAncestorName(owner: string, name: string): boolean {
  const ownerLabels = nameLabels(owner);
  const childLabels = nameLabels(name);
  return (
    ownerLabels.length < childLabels.length &&
    ownerLabels.every(
      (label, index) => childLabels[childLabels.length - ownerLabels.length + index] === label,
    )
  );
}

function aliasVerificationExplanation(
  type: 'CNAME' | 'DNAME',
  state: DnssecChainState,
): string {
  if (state === 'incomplete')
    return `The ${type} RRset exceeds the local cryptographic work bound.`;
  return state === 'unsupported'
    ? `The ${type} RRset uses a signature algorithm unavailable to this browser validator.`
    : `No current ${type} signature verified with the authenticated owner-zone keys.`;
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
    validatorVersion: 3,
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
  const validateApplicationResponse = async (
    response: DnsResponse,
    owner: string,
    keys: readonly DnskeyInfo[],
    type: DnssecApplicationType,
    responseQuestionType: DnsRecordType = type,
  ): Promise<DnssecApplicationResult> => {
    application = await validateApplicationRrset(
      response,
      owner,
      type,
      keys,
      Math.floor(currentTime() / 1000),
      budget,
      responseQuestionType,
    );
    authenticatedGroups.push(...application.verificationGroups);
    return application;
  };
  const authenticateAlias = async (
    response: DnsResponse,
    responseName: string,
    currentName: string,
    currentType: DnsRecordType,
    keys: readonly DnskeyInfo[],
    allowCname: boolean,
  ): Promise<AuthenticatedAliasResult> => {
    const dnameOwners = [
      ...new Set(
        response.message.answers
          .filter(
            (record) =>
              record.class.toUpperCase() === 'IN' &&
              record.type === 'DNAME' &&
              isStrictAncestorName(record.owner, currentName),
          )
          .map((record) => absolute(record.owner)),
      ),
    ];
    if (dnameOwners.length > 1)
      return {
        explanation:
          'The answer contains ambiguous DNAME owners for one authenticated alias transition.',
        kind: 'failure',
        state: 'bogus',
      };
    const dnameOwner = dnameOwners[0];
    if (dnameOwner !== undefined) {
      if (response.message.responseCode !== 'NOERROR')
        return {
          explanation: 'The response contains a DNAME alias while claiming a DNS error.',
          kind: 'failure',
          state: 'bogus',
        };
      const rrset = boundRrset(response, 'answer', dnameOwner, 'DNAME');
      if (rrset === null)
        return {
          explanation: 'The DNAME answer could not be bound to its lossless wire RRset.',
          kind: 'failure',
          state: 'incomplete',
        };
      if (rrset.length > MAX_CHAIN_RRSET_RECORDS || !budget.consume('records', rrset.length))
        return {
          explanation: 'The DNAME RRset exceeds the local work bound.',
          kind: 'failure',
          state: 'incomplete',
        };
      const records = rrset.filter((record) => record.type === 'DNAME');
      if (records.length === 0)
        return {
          explanation: 'The authenticated DNAME answer does not contain a DNAME record.',
          kind: 'failure',
          state: 'bogus',
        };
      const verifications = await verifyRrset(
        rrset,
        'DNAME',
        keys,
        Math.floor(currentTime() / 1000),
        budget,
      );
      if (!verifications.some((verification) => verification.status === 'verified')) {
        const state = failureState(verifications);
        return {
          explanation: aliasVerificationExplanation('DNAME', state),
          kind: 'failure',
          state,
        };
      }
      const dnameLabels = nameLabels(dnameOwner).length;
      const dnameSignatures = rrset.flatMap((record) => {
        const signature = parseRrsig(record, Math.floor(currentTime() / 1000));
        return signature?.typeCovered === 'DNAME' ? [signature] : [];
      });
      if (
        !dnameSignatures.some(
          (signature, index) =>
            signature.labels === dnameLabels && verifications[index]?.status === 'verified',
        )
      )
        return {
          explanation:
            'A wildcard-expanded DNAME cannot be used for subtree substitution without a dedicated wildcard-DNAME proof model.',
          kind: 'failure',
          state: 'incomplete',
        };
      const cnameRrset = boundRrset(response, 'answer', currentName, 'CNAME');
      if (cnameRrset === null)
        return {
          explanation: 'The synthesised CNAME could not be bound to the original DNS response.',
          kind: 'failure',
          state: 'incomplete',
        };
      const synthesisedCnames = cnameRrset.filter((record) => record.type === 'CNAME');
      const parsed = ancestorDnameTransition(
        currentName,
        currentType,
        records,
        responseName === currentName ? synthesisedCnames : [],
      );
      if (!parsed.ok)
        return {
          explanation: `The authenticated DNAME transition is invalid: ${parsed.error.message}`,
          kind: 'failure',
          state: 'bogus',
        };
      authenticatedGroups.push(verifications);
      return { kind: 'follow', transition: parsed.value };
    }

    if (!allowCname || responseName !== currentName) return { kind: 'none' };
    const hasExactCname = response.message.answers.some(
      (record) =>
        record.class.toUpperCase() === 'IN' &&
        record.type === 'CNAME' &&
        absolute(record.owner) === currentName,
    );
    if (!hasExactCname) return { kind: 'none' };
    if (response.message.responseCode !== 'NOERROR')
      return {
        explanation: 'The response contains a CNAME alias while claiming a DNS error.',
        kind: 'failure',
        state: 'bogus',
      };
    const cnameResult = await validateApplicationRrset(
      response,
      currentName,
      'CNAME',
      keys,
      Math.floor(currentTime() / 1000),
      budget,
      response.question.type,
    );
    if (cnameResult.state !== 'secure')
      return {
        explanation: cnameResult.explanation,
        kind: 'failure',
        state: cnameResult.state,
      };
    const parsed = exactCnameTransition(currentName, currentType, cnameResult.records);
    if (!parsed.ok)
      return {
        explanation: `The authenticated CNAME transition is invalid: ${parsed.error.message}`,
        kind: 'failure',
        state: 'bogus',
      };
    authenticatedGroups.push(...cnameResult.verificationGroups);
    return { kind: 'follow', transition: parsed.value };
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

  const rootTrustedKeys = eligibleKeys(rootKeys);
  if (rootTrustedKeys.length === 0)
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
  const pathResult = DnssecAliasPath.start(target, options.rrsetType ?? 'DS');
  if (!pathResult.ok)
    return finish('incomplete', `The DNSSEC target is invalid: ${pathResult.error.message}`);
  const aliasPath = pathResult.value;
  const authenticatedZoneKeys = new Map<string, readonly DnskeyInfo[]>([
    ['.', rootTrustedKeys],
  ]);

  aliasLoop: for (;;) {
    const position = aliasPath.position;
    const currentName = position.name;
    const labels = currentName === '.' ? [] : currentName.slice(0, -1).split('.');
    let trustedKeys = rootTrustedKeys;
    let finalBoundary: DsDenialResult | undefined;
    const zones = Array.from({ length: labels.length }, (_, index) =>
      absolute(labels.slice(labels.length - 1 - index).join('.')),
    );
    for (const zone of zones) {
      const cachedKeys = authenticatedZoneKeys.get(zone);
      if (cachedKeys !== undefined) {
        trustedKeys = cachedKeys;
        continue;
      }
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
      if (
        dsRrset.length > MAX_CHAIN_RRSET_RECORDS ||
        !budget.consume('records', dsRrset.length)
      )
        return finish('incomplete', `The DS RRset for ${zone} exceeds the local work bound.`);
      const typedDsRecords = dsRrset.filter((record) => record.type === 'DS');
      const dsRecords = dsRrset.flatMap((record) => {
        const ds = parseDs(record);
        return ds === null || absolute(record.owner) !== zone ? [] : [ds];
      });
      if (dsRecords.length !== typedDsRecords.length)
        return finish('bogus', `The DS RRset for ${zone} contains malformed DS RDATA.`);
      if (
        dsRecords.length > 0 &&
        dsResponse.message.answers.some(
          (record) =>
            record.class.toUpperCase() === 'IN' &&
            ((record.type === 'CNAME' && absolute(record.owner) === zone) ||
              (record.type === 'DNAME' && isStrictAncestorName(record.owner, currentName))),
        )
      )
        return finish(
          'bogus',
          `The DS response for ${zone} contains both a delegation and an alias transition.`,
        );
      if (dsRecords.length === 0) {
        const alias = await authenticateAlias(
          dsResponse,
          zone,
          currentName,
          position.type,
          trustedKeys,
          options.rrsetType !== 'CNAME',
        );
        if (alias.kind === 'failure') return finish(alias.state, alias.explanation);
        if (alias.kind === 'follow') {
          const followed = aliasPath.follow(alias.transition);
          if (!followed.ok) {
            const explanation =
              followed.error.code === 'loop'
                ? 'The authenticated DNS alias path contains an alias loop.'
                : followed.error.message;
            return finish('incomplete', explanation);
          }
          application = undefined;
          continue aliasLoop;
        }
        if (
          zone === currentName &&
          options.rrsetType === 'CNAME' &&
          dsResponse.message.responseCode === 'NOERROR' &&
          dsResponse.message.answers.some(
            (record) =>
              record.class.toUpperCase() === 'IN' &&
              absolute(record.owner) === currentName &&
              record.type === 'CNAME',
          )
        ) {
          const result = await validateApplicationResponse(
            dsResponse,
            currentName,
            trustedKeys,
            'CNAME',
            'DS',
          );
          return finishAuthenticated(result.state, result.explanation);
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
          if (
            (denial.state === 'not-delegated' || denial.state === 'alias-boundary') &&
            zone !== currentName
          )
            continue;
          if (denial.state === 'not-delegated') {
            finalBoundary = denial;
            break;
          }
          if (denial.state === 'alias-boundary' && options.rrsetType !== undefined) {
            finalBoundary = denial;
            break;
          }
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

      const acceptableDsRecords = dsRecords.filter((ds) =>
        canEstablishDsTrustPath(ds.algorithm),
      );
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
        return finish(
          'incomplete',
          `The DNSKEY RRset for ${zone} exceeds the local work bound.`,
        );
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
      authenticatedZoneKeys.set(zone, trustedKeys);
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
    if (options.rrsetType === undefined) {
      const explanation =
        finalBoundary?.explanation ??
        (currentName === '.'
          ? 'The root DNSKEY RRset validated locally.'
          : `Every delegation from the IANA root trust anchor to ${currentName} validated locally.`);
      return finishAuthenticated('secure', explanation);
    }

    const response = await ask(currentName, position.type);
    if (response === undefined)
      return finish(
        'incomplete',
        `The ${position.type} RRset for ${currentName} could not be retrieved.`,
      );
    const alias = await authenticateAlias(
      response,
      currentName,
      currentName,
      position.type,
      trustedKeys,
      position.type !== 'CNAME',
    );
    if (alias.kind === 'failure') return finish(alias.state, alias.explanation);
    if (alias.kind === 'follow') {
      const directRrset = boundRrset(response, 'answer', currentName, position.type);
      if (directRrset?.some((record) => record.type === position.type) === true)
        return finish(
          'bogus',
          `The answer contains both an alias and an exact ${position.type} RRset for ${currentName}.`,
        );
      const followed = aliasPath.follow(alias.transition);
      if (!followed.ok) {
        const explanation =
          followed.error.code === 'loop'
            ? 'The authenticated DNS alias path contains an alias loop.'
            : followed.error.message;
        return finish('incomplete', explanation);
      }
      application = undefined;
      continue aliasLoop;
    }

    const result = await validateApplicationResponse(
      response,
      currentName,
      trustedKeys,
      options.rrsetType,
    );
    if (result.state !== 'secure') return finishAuthenticated(result.state, result.explanation);
    if (position.type !== 'SVCB' && position.type !== 'HTTPS')
      return finishAuthenticated('secure', result.explanation);

    const serviceBinding = classifyServiceBindingRrset(
      currentName,
      position.type,
      result.records,
    );
    if (!serviceBinding.ok) {
      return finishAuthenticated(
        'incomplete',
        `The ${position.type} RRset authenticated, but its service-binding continuation cannot be processed safely: ${serviceBinding.error.message}`,
      );
    }
    if (serviceBinding.value.kind === 'alias-choices')
      return finishAuthenticated(
        'incomplete',
        `The ${position.type} RRset authenticated, but its ${String(serviceBinding.value.targetNames.length)} AliasMode targets require bounded branch validation before an end-to-end result can be reported.`,
      );
    if (serviceBinding.value.kind !== 'alias')
      return finishAuthenticated('secure', result.explanation);
    const followed = aliasPath.follow(serviceBinding.value.transition);
    if (!followed.ok) {
      application = undefined;
      const explanation =
        followed.error.code === 'loop'
          ? 'The authenticated DNS alias path contains an alias loop.'
          : followed.error.message;
      return finish('incomplete', explanation);
    }
    application = undefined;
  }
}
