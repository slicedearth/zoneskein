import { validateDnsName } from '../dns/names';

import {
  assessDmarcPolicy,
  dmarcDiscoveryNames,
  isDmarcRecord,
  parseDmarcRecord,
  selectDmarcPolicy,
} from './parser';
import type {
  DmarcDiscoveryObservation,
  DmarcPolicy,
  DmarcPolicyAssessment,
  DmarcSelection,
} from './types';

const MAX_DISCOVERY_QUESTIONS = 80;
const MAX_TXT_RECORDS_PER_QUESTION = 64;
const MAX_TXT_RECORD_CHARACTERS = 8_192;
const MAX_TXT_CHARACTERS_PER_QUESTION = 65_535;

export type DmarcTxtLookupStatus =
  'answer' | 'nodata' | 'nxdomain' | 'temperror' | 'permerror' | 'limit';

export type DmarcDiscoveryStatus = 'complete' | 'temperror' | 'permerror' | 'indeterminate';

export interface DmarcTxtLookupResult {
  readonly error?: string;
  readonly status: DmarcTxtLookupStatus;
  readonly ttl?: number;
  readonly values: readonly string[];
}

export type DmarcTxtLookup = (name: string) => Promise<DmarcTxtLookupResult>;
export type DmarcCancellationCheck = () => boolean;

export interface DmarcDiscoveryQuestion {
  readonly detail: string;
  readonly dmarcRecords: number;
  readonly name: string;
  readonly purpose: 'policy-discovery' | 'domain-existence';
  readonly status: DmarcTxtLookupStatus;
  readonly txtRecords: number;
}

export interface DmarcSelectedPolicy {
  readonly assessment: DmarcPolicyAssessment;
  readonly domain: string;
  readonly policy: DmarcPolicy;
  readonly queryName: string;
  readonly record: string;
  readonly ttl?: number;
}

export type DmarcRejectedPolicy = Omit<DmarcSelectedPolicy, 'assessment'>;

export interface DmarcDiscoveryResult {
  readonly authorDomainExistence?: 'existing' | 'non-existent';
  readonly domain?: string;
  readonly observations: readonly DmarcDiscoveryObservation[];
  readonly organizationalDomain?: string;
  readonly questions: readonly DmarcDiscoveryQuestion[];
  readonly reason: string;
  readonly rejected?: DmarcRejectedPolicy;
  readonly selected?: DmarcSelectedPolicy;
  readonly selection: DmarcSelection;
  readonly status: DmarcDiscoveryStatus;
}

function emptySelection(): DmarcSelection {
  return { source: 'none' };
}

function normaliseDomain(value: string): string | null {
  if (value !== value.trim() || value.includes('://')) return null;
  const parsed = validateDnsName(value);
  if (!parsed.ok || parsed.value.ascii === '') return null;
  if (
    parsed.value.ascii
      .split('.')
      .some((label) => !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))
  )
    return null;
  return parsed.value.ascii;
}

function failureStatus(status: DmarcTxtLookupStatus): DmarcDiscoveryStatus | null {
  if (status === 'temperror') return 'temperror';
  if (status === 'permerror') return 'permerror';
  if (status === 'limit') return 'indeterminate';
  return null;
}

function boundedValues(values: readonly string[]): string | null {
  if (values.length > MAX_TXT_RECORDS_PER_QUESTION)
    return `The response exceeds the ${String(MAX_TXT_RECORDS_PER_QUESTION)}-record TXT limit.`;
  let total = 0;
  for (const value of values) {
    if (value.length > MAX_TXT_RECORD_CHARACTERS)
      return `A TXT record exceeds the ${String(MAX_TXT_RECORD_CHARACTERS)}-character limit.`;
    total += value.length;
    if (total > MAX_TXT_CHARACTERS_PER_QUESTION)
      return `The response exceeds the ${String(MAX_TXT_CHARACTERS_PER_QUESTION)}-character TXT limit.`;
  }
  return null;
}

function selectedPolicy(
  selection: DmarcSelection,
  records: ReadonlyMap<
    string,
    {
      readonly policy: DmarcPolicy;
      readonly queryName: string;
      readonly record: string;
      readonly ttl?: number;
    }
  >,
  organizationalDomain: string,
  context: DmarcPolicyAssessment['context'],
): DmarcSelectedPolicy | undefined {
  const selected = selection.selected;
  if (selected === undefined) return undefined;
  const record = records.get(selected.domain);
  if (record === undefined) return undefined;
  const policy = parseDmarcRecord(record.record, selected.domain, organizationalDomain);
  const assessment = assessDmarcPolicy(policy, context);
  if (assessment === undefined) return undefined;
  return {
    assessment,
    domain: selected.domain,
    policy,
    queryName: record.queryName,
    record: record.record,
    ...(record.ttl === undefined ? {} : { ttl: record.ttl }),
  };
}

/** Perform one standards-bounded DMARC DNS Tree Walk through a supplied TXT lookup. */
export async function discoverDmarc(
  suppliedDomain: string,
  lookup: DmarcTxtLookup,
  mode: 'policy' | 'boundary' = 'policy',
): Promise<DmarcDiscoveryResult> {
  const domain = normaliseDomain(suppliedDomain);
  if (domain === null)
    return {
      observations: [],
      questions: [],
      reason: 'The domain is malformed, so DMARC discovery cannot start.',
      selection: emptySelection(),
      status: 'permerror',
    };

  const observations: DmarcDiscoveryObservation[] = [];
  const questions: DmarcDiscoveryQuestion[] = [];
  const records = new Map<
    string,
    {
      readonly policy: DmarcPolicy;
      readonly queryName: string;
      readonly record: string;
      readonly ttl?: number;
    }
  >();

  for (const name of dmarcDiscoveryNames(domain)) {
    let answer: DmarcTxtLookupResult;
    try {
      answer = await lookup(name);
    } catch (cause) {
      const detail = cause instanceof Error ? cause.message : 'The TXT lookup failed.';
      questions.push({
        detail,
        dmarcRecords: 0,
        name,
        purpose: 'policy-discovery',
        status: 'temperror',
        txtRecords: 0,
      });
      return {
        domain,
        observations,
        questions,
        reason: `${name}: ${detail} The organisational-domain boundary is incomplete.`,
        selection: emptySelection(),
        status: 'temperror',
      };
    }

    const failed = failureStatus(answer.status);
    if (failed !== null) {
      const detail =
        answer.error ??
        (answer.status === 'limit'
          ? 'The bounded DMARC DNS question limit was reached.'
          : 'The TXT lookup did not complete safely.');
      questions.push({
        detail,
        dmarcRecords: 0,
        name,
        purpose: 'policy-discovery',
        status: answer.status,
        txtRecords: 0,
      });
      return {
        domain,
        observations,
        questions,
        reason: `${name}: ${detail} The organisational-domain boundary is incomplete.`,
        selection: emptySelection(),
        status: failed,
      };
    }

    const boundError = boundedValues(answer.values);
    if (boundError !== null) {
      questions.push({
        detail: boundError,
        dmarcRecords: 0,
        name,
        purpose: 'policy-discovery',
        status: 'limit',
        txtRecords: answer.values.length,
      });
      return {
        domain,
        observations,
        questions,
        reason: `${name}: ${boundError} The result is indeterminate.`,
        selection: emptySelection(),
        status: 'indeterminate',
      };
    }

    const policyDomain = name.slice('_dmarc.'.length);
    const policies = answer.values.filter(isDmarcRecord);
    if (policies.length > 1) {
      const detail = 'Multiple DMARC records were discarded at this tree-walk node.';
      questions.push({
        detail,
        dmarcRecords: policies.length,
        name,
        purpose: 'policy-discovery',
        status: answer.status,
        txtRecords: answer.values.length,
      });
      observations.push({ domain: policyDomain });
      continue;
    }

    const record = policies[0];
    if (record === undefined) {
      const detail =
        answer.status === 'nxdomain'
          ? 'The name does not exist.'
          : 'No DMARC policy record was observed.';
      questions.push({
        detail,
        dmarcRecords: 0,
        name,
        purpose: 'policy-discovery',
        status: answer.status,
        txtRecords: answer.values.length,
      });
      observations.push({ domain: policyDomain });
      continue;
    }

    const policy = parseDmarcRecord(record, policyDomain);
    questions.push({
      detail: policy.applicable
        ? 'One applicable DMARC policy record was observed.'
        : 'The DMARC-looking record is not applicable.',
      dmarcRecords: 1,
      name,
      purpose: 'policy-discovery',
      status: answer.status,
      txtRecords: answer.values.length,
    });
    observations.push({ domain: policyDomain, policy });
    records.set(policyDomain, {
      policy,
      queryName: name,
      record,
      ...(answer.ttl === undefined ? {} : { ttl: answer.ttl }),
    });
    if (policy.assessmentPolicyInvalid && !policy.applicable)
      return {
        domain,
        observations,
        questions,
        reason: `${name}: the record contains an invalid p, sp, or np tag and no syntactically valid rua destination, so DMARC processing does not apply and no parent policy is inherited.`,
        rejected: {
          domain: policyDomain,
          policy,
          queryName: name,
          record,
          ...(answer.ttl === undefined ? {} : { ttl: answer.ttl }),
        },
        selection: emptySelection(),
        status: 'complete',
      };
    if (policy.applicable && (policy.psd === 'n' || policy.psd === 'y')) break;
  }

  const selection = selectDmarcPolicy(domain, observations);
  const organizationalDomain = selection.organizationalDomain ?? domain;
  const selectedObservation = selection.selected;
  let authorDomainExistence: DmarcDiscoveryResult['authorDomainExistence'];
  let context: DmarcPolicyAssessment['context'] = 'direct-author-domain';

  if (mode === 'policy' && selectedObservation !== undefined && selection.source !== 'direct') {
    let existenceAnswer: DmarcTxtLookupResult;
    try {
      existenceAnswer = await lookup(domain);
    } catch (cause) {
      const detail =
        cause instanceof Error ? cause.message : 'The domain-existence lookup failed.';
      questions.push({
        detail,
        dmarcRecords: 0,
        name: domain,
        purpose: 'domain-existence',
        status: 'temperror',
        txtRecords: 0,
      });
      return {
        domain,
        observations,
        organizationalDomain,
        questions,
        reason: `${domain}: ${detail} The inherited assessment policy cannot be selected safely.`,
        selection: { ...selection, organizationalDomain },
        status: 'temperror',
      };
    }
    const failed = failureStatus(existenceAnswer.status);
    const detail =
      existenceAnswer.status === 'nxdomain'
        ? 'NXDOMAIN proves that the Author Domain does not exist.'
        : existenceAnswer.status === 'answer' || existenceAnswer.status === 'nodata'
          ? 'NOERROR proves that the Author Domain exists; no particular record type is required.'
          : (existenceAnswer.error ?? 'The Author Domain existence result is unresolved.');
    questions.push({
      detail,
      dmarcRecords: 0,
      name: domain,
      purpose: 'domain-existence',
      status: existenceAnswer.status,
      txtRecords: existenceAnswer.values.length,
    });
    if (failed !== null)
      return {
        domain,
        observations,
        organizationalDomain,
        questions,
        reason: `${domain}: ${detail} The inherited assessment policy cannot be selected safely.`,
        selection: { ...selection, organizationalDomain },
        status: failed,
      };
    authorDomainExistence = existenceAnswer.status === 'nxdomain' ? 'non-existent' : 'existing';
    context =
      authorDomainExistence === 'non-existent'
        ? 'non-existent-inherited-subdomain'
        : 'existing-inherited-subdomain';
  }

  const selected =
    selectedObservation === undefined || mode === 'boundary'
      ? undefined
      : selectedPolicy(selection, records, organizationalDomain, context);
  return {
    ...(authorDomainExistence === undefined ? {} : { authorDomainExistence }),
    domain,
    observations,
    organizationalDomain,
    questions,
    reason:
      selectedObservation !== undefined && mode === 'boundary'
        ? `The bounded tree walk selected the organisational boundary ${organizationalDomain}; no message assessment policy was requested for this boundary-only walk.`
        : selected === undefined
          ? `The bounded tree walk completed without an applicable DMARC policy; ${organizationalDomain} is the selected organisational boundary for this walk.`
          : `The bounded tree walk selected the policy at ${selected.domain} and the organisational boundary ${organizationalDomain}. ${selected.assessment.reason}`,
    ...(selected === undefined ? {} : { selected }),
    selection: {
      ...selection,
      organizationalDomain,
    },
    status: 'complete',
  };
}

/** Share and cap TXT questions across related author, identifier, and reporting walks. */
export class DmarcDiscoverySession {
  readonly #cache = new Map<string, Promise<DmarcTxtLookupResult>>();
  readonly #isCancelled: DmarcCancellationCheck;
  readonly #lookup: DmarcTxtLookup;
  readonly #maximumQuestions: number;

  constructor(
    lookup: DmarcTxtLookup,
    maximumQuestions = MAX_DISCOVERY_QUESTIONS,
    isCancelled: DmarcCancellationCheck = () => false,
  ) {
    this.#lookup = lookup;
    this.#maximumQuestions = Number.isSafeInteger(maximumQuestions)
      ? Math.max(1, Math.min(MAX_DISCOVERY_QUESTIONS, maximumQuestions))
      : 1;
    this.#isCancelled = isCancelled;
  }

  get questionsUsed(): number {
    return this.#cache.size;
  }

  discover(domain: string): Promise<DmarcDiscoveryResult> {
    return discoverDmarc(domain, (name) => this.lookup(name));
  }

  discoverBoundary(domain: string): Promise<DmarcDiscoveryResult> {
    return discoverDmarc(domain, (name) => this.lookup(name), 'boundary');
  }

  lookup(name: string): Promise<DmarcTxtLookupResult> {
    if (this.#isCancelled()) return Promise.resolve(cancelledLookup());
    const existing = this.#cache.get(name);
    if (existing !== undefined) return existing;
    if (this.#cache.size >= this.#maximumQuestions)
      return Promise.resolve({
        error: `This run reached its ${String(this.#maximumQuestions)}-question DMARC DNS limit.`,
        status: 'limit',
        values: [],
      });
    const pending = Promise.resolve()
      .then(() => (this.#isCancelled() ? cancelledLookup() : this.#lookup(name)))
      .then((result) => (this.#isCancelled() ? cancelledLookup() : result))
      .catch((cause: unknown): DmarcTxtLookupResult =>
        this.#isCancelled()
          ? cancelledLookup()
          : {
              error: cause instanceof Error ? cause.message : 'The TXT lookup failed.',
              status: 'temperror',
              values: [],
            },
      );
    this.#cache.set(name, pending);
    return pending;
  }
}

function cancelledLookup(): DmarcTxtLookupResult {
  return {
    error: 'The DMARC DNS run was cancelled.',
    status: 'temperror',
    values: [],
  };
}
