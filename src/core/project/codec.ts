import { failure, success, type Result } from '../result';
import { canonicalJson } from './canonical-json';
import { CHANGE_WORKSPACE_LIMITS } from './limits';
import {
  CHANGE_WORKSPACE_FORMAT,
  type ChangeWorkspace,
  type ChangeWorkspaceAnalysis,
  type ChangeWorkspaceAnalysedChange,
  type ChangeWorkspaceCodecError,
  type ChangeWorkspaceEnvelope,
  type ChangeWorkspaceEvidence,
  type ChangeWorkspaceFinding,
  type ChangeWorkspaceObservationRun,
  type ChangeWorkspaceQuestionObservation,
  type ChangeWorkspaceQuestionStatus,
  type ChangeWorkspaceResolverObservation,
  type ChangeWorkspaceRolloutPhase,
  type ChangeWorkspaceTiming,
  type ChangeWorkspaceZoneState,
  type DecodedChangeWorkspace,
} from './types';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/u;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const RECORD_TYPE_PATTERN = /^(?:[A-Z][A-Z0-9-]{0,31}|TYPE(?:0|[1-9]\d{0,4}))$/u;
const LOCAL_FAILURE_STATUSES = new Set<ChangeWorkspaceQuestionStatus>([
  'cancelled',
  'malformed-response',
  'network-error',
  'timeout',
]);
const DEFINITIVE_QUESTION_STATUSES = new Set<ChangeWorkspaceQuestionStatus>([
  'answer',
  'name-error',
  'no-data',
]);
const RISKS = ['information', 'low', 'moderate', 'high', 'critical'] as const;
const CHANGE_CATEGORIES = [
  'added',
  'removed',
  'value-changed',
  'priority-changed',
  'ttl-only',
  'formatting-only',
] as const;
const QUESTION_STATUSES = [
  'answer',
  'no-data',
  'name-error',
  'refused',
  'server-failure',
  'timeout',
  'network-error',
  'malformed-response',
  'cancelled',
] as const;
const RESOLVER_IDS = ['cloudflare', 'google', 'quad9', 'custom'] as const;
const ANALYSIS_STATUSES = ['not-run', 'complete', 'partial'] as const;
const EVIDENCE_STATUSES = ['none', 'complete', 'partial'] as const;
const COMPLETENESS = ['complete', 'partial'] as const;
const ZONE_STATUSES = ['unavailable', 'complete', 'partial'] as const;
const PHASE_IDS = ['prepare', 'wait', 'publish', 'verify', 'observe', 'restore'] as const;

function isRecordType(value: string): boolean {
  if (!RECORD_TYPE_PATTERN.test(value)) return false;
  return !value.startsWith('TYPE') || Number(value.slice(4)) <= 65_535;
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const following = value.charCodeAt(index + 1);
      if (!(following >= 0xdc00 && following <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

interface EvidenceBudget {
  octets: number;
  questions: number;
  records: number;
  readonly questionIds: Set<string>;
  readonly resolverIds: Set<string>;
  readonly runIds: Set<string>;
}

function codecFailure(
  code: ChangeWorkspaceCodecError['code'],
  message: string,
  path?: string,
): Result<never, ChangeWorkspaceCodecError> {
  return failure({ code, message, ...(path === undefined ? {} : { path }) });
}

function schemaFailure(
  message: string,
  path: string,
): Result<never, ChangeWorkspaceCodecError> {
  return codecFailure('invalid-schema', message, path);
}

function resourceFailure(
  message: string,
  path: string,
): Result<never, ChangeWorkspaceCodecError> {
  return codecFailure('resource-limit', message, path);
}

function asRecord(
  value: unknown,
  keys: readonly string[],
  path: string,
): Result<Record<string, unknown>, ChangeWorkspaceCodecError> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return schemaFailure('Expected a JSON object.', path);
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    return schemaFailure('Expected a plain JSON object.', path);
  }
  const actual = Reflect.ownKeys(value);
  if (
    actual.length !== keys.length ||
    actual.some((key) => typeof key !== 'string') ||
    keys.some((key) => !actual.includes(key))
  ) {
    return schemaFailure(`Object keys must be exactly: ${keys.join(', ')}.`, path);
  }
  const inert: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor)) {
      return schemaFailure('Expected enumerable JSON data properties without accessors.', path);
    }
    inert[key] = descriptor.value as unknown;
  }
  return success(inert);
}

function asArray(
  value: unknown,
  limit: number,
  path: string,
): Result<readonly unknown[], ChangeWorkspaceCodecError> {
  if (!Array.isArray(value)) return schemaFailure('Expected a JSON array.', path);
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    return schemaFailure('Expected an ordinary JSON array.', path);
  }
  if (value.length > limit) {
    return resourceFailure(`Collection exceeds its ${String(limit)}-item safety limit.`, path);
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== value.length + 1 ||
    keys.some(
      (key) => typeof key !== 'string' || (key !== 'length' && !/^(?:0|[1-9]\d*)$/u.test(key)),
    )
  ) {
    return schemaFailure(
      'Expected a dense JSON array without named or symbol properties.',
      path,
    );
  }
  const inert: unknown[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !('value' in descriptor)) {
      return schemaFailure('Expected JSON array data entries without accessors.', path);
    }
    inert.push(descriptor.value as unknown);
  }
  return success(inert);
}

function asEnum<const Values extends readonly string[]>(
  value: unknown,
  values: Values,
  path: string,
): Result<Values[number], ChangeWorkspaceCodecError> {
  if (typeof value !== 'string' || !values.includes(value)) {
    return schemaFailure(`Expected one of: ${values.join(', ')}.`, path);
  }
  return success(value as Values[number]);
}

function asString(
  value: unknown,
  maximumOctets: number,
  path: string,
  options: { readonly allowEmpty?: boolean; readonly trim?: boolean } = {},
): Result<string, ChangeWorkspaceCodecError> {
  if (typeof value !== 'string') return schemaFailure('Expected a string.', path);
  if (hasUnpairedSurrogate(value)) {
    return schemaFailure('String must not contain unpaired UTF-16 surrogates.', path);
  }
  if (options.allowEmpty !== true && value.length === 0) {
    return schemaFailure('String must not be empty.', path);
  }
  if (options.trim === true && value.trim() !== value) {
    return schemaFailure('String must not have leading or trailing whitespace.', path);
  }
  if (encoder.encode(value).length > maximumOctets) {
    return resourceFailure(
      `String exceeds its ${String(maximumOctets)}-octet safety limit.`,
      path,
    );
  }
  return success(value);
}

function asNullableString(
  value: unknown,
  maximumOctets: number,
  path: string,
  options: { readonly trim?: boolean } = {},
): Result<string | null, ChangeWorkspaceCodecError> {
  return value === null ? success(null) : asString(value, maximumOctets, path, options);
}

function asBooleanOrNull(
  value: unknown,
  path: string,
): Result<boolean | null, ChangeWorkspaceCodecError> {
  return value === null || typeof value === 'boolean'
    ? success(value)
    : schemaFailure('Expected a boolean or null.', path);
}

function asIntegerOrNull(
  value: unknown,
  minimum: number,
  maximum: number,
  path: string,
): Result<number | null, ChangeWorkspaceCodecError> {
  if (value === null) return success(null);
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < minimum ||
    value > maximum
  ) {
    return schemaFailure(
      `Expected null or a safe integer from ${String(minimum)} to ${String(maximum)}.`,
      path,
    );
  }
  return success(value);
}

function asUuid(value: unknown, path: string): Result<string, ChangeWorkspaceCodecError> {
  return typeof value === 'string' && UUID_PATTERN.test(value)
    ? success(value)
    : schemaFailure('Expected a canonical lower-case UUID version 4.', path);
}

function asTimestamp(value: unknown, path: string): Result<string, ChangeWorkspaceCodecError> {
  if (typeof value !== 'string' || !TIMESTAMP_PATTERN.test(value)) {
    return schemaFailure(
      'Expected a canonical UTC timestamp with millisecond precision.',
      path,
    );
  }
  try {
    return new Date(value).toISOString() === value
      ? success(value)
      : schemaFailure('Expected a real canonical UTC timestamp.', path);
  } catch {
    return schemaFailure('Expected a real canonical UTC timestamp.', path);
  }
}

function asNullableTimestamp(
  value: unknown,
  path: string,
): Result<string | null, ChangeWorkspaceCodecError> {
  return value === null ? success(null) : asTimestamp(value, path);
}

function asStringList(
  value: unknown,
  limit: number,
  maximumOctets: number,
  path: string,
  requireUnique = true,
): Result<readonly string[], ChangeWorkspaceCodecError> {
  const array = asArray(value, limit, path);
  if (!array.ok) return array;
  const parsed: string[] = [];
  const uniqueValues = new Set<string>();
  for (let index = 0; index < array.value.length; index += 1) {
    const item = asString(array.value[index], maximumOctets, `${path}[${String(index)}]`, {
      trim: true,
    });
    if (!item.ok) return item;
    if (requireUnique && uniqueValues.has(item.value)) {
      return schemaFailure(
        'Duplicate list values are not permitted.',
        `${path}[${String(index)}]`,
      );
    }
    uniqueValues.add(item.value);
    parsed.push(item.value);
  }
  return success(parsed);
}

function parseZoneState(
  value: unknown,
  path: string,
): Result<ChangeWorkspaceZoneState, ChangeWorkspaceCodecError> {
  const object = asRecord(
    value,
    ['format', 'incompleteReasons', 'origin', 'source', 'status'],
    path,
  );
  if (!object.ok) return object;
  if (object.value['format'] !== 'bind-zone-text') {
    return schemaFailure('Zone state format must be bind-zone-text.', `${path}.format`);
  }
  const incompleteReasons = asStringList(
    object.value['incompleteReasons'],
    CHANGE_WORKSPACE_LIMITS.incompleteReasons,
    CHANGE_WORKSPACE_LIMITS.messageOctets,
    `${path}.incompleteReasons`,
  );
  if (!incompleteReasons.ok) return incompleteReasons;
  const origin = asNullableString(
    object.value['origin'],
    CHANGE_WORKSPACE_LIMITS.shortStringOctets,
    `${path}.origin`,
    { trim: true },
  );
  if (!origin.ok) return origin;
  const sourceValue = object.value['source'];
  if (typeof sourceValue !== 'string')
    return schemaFailure('Expected a string.', `${path}.source`);
  if (sourceValue.length > CHANGE_WORKSPACE_LIMITS.zoneCharacters) {
    return resourceFailure(
      `Zone source exceeds the ${String(CHANGE_WORKSPACE_LIMITS.zoneCharacters)}-character safety limit.`,
      `${path}.source`,
    );
  }
  const source = asString(sourceValue, CHANGE_WORKSPACE_LIMITS.zoneOctets, `${path}.source`, {
    allowEmpty: true,
  });
  if (!source.ok) return source;
  const status = asEnum(object.value['status'], ZONE_STATUSES, `${path}.status`);
  if (!status.ok) return status;
  if (status.value === 'complete' && incompleteReasons.value.length !== 0) {
    return schemaFailure('A complete zone state must not contain incomplete reasons.', path);
  }
  if (status.value === 'partial' && incompleteReasons.value.length === 0) {
    return schemaFailure('A partial zone state requires an incomplete reason.', path);
  }
  if (
    status.value === 'unavailable' &&
    (source.value !== '' || origin.value !== null || incompleteReasons.value.length === 0)
  ) {
    return schemaFailure(
      'An unavailable zone state requires a reason and must not contain an origin or source.',
      path,
    );
  }
  return success({
    format: 'bind-zone-text',
    incompleteReasons: incompleteReasons.value,
    origin: origin.value,
    source: source.value,
    status: status.value,
  });
}

function parseChange(
  value: unknown,
  path: string,
): Result<ChangeWorkspaceAnalysedChange, ChangeWorkspaceCodecError> {
  const object = asRecord(
    value,
    [
      'after',
      'before',
      'category',
      'disruptive',
      'explanation',
      'owner',
      'reasons',
      'risk',
      'rollback',
      'type',
    ],
    path,
  );
  if (!object.ok) return object;
  const after = asNullableString(
    object.value['after'],
    CHANGE_WORKSPACE_LIMITS.recordOctets,
    `${path}.after`,
  );
  if (!after.ok) return after;
  const before = asNullableString(
    object.value['before'],
    CHANGE_WORKSPACE_LIMITS.recordOctets,
    `${path}.before`,
  );
  if (!before.ok) return before;
  const category = asEnum(object.value['category'], CHANGE_CATEGORIES, `${path}.category`);
  if (!category.ok) return category;
  if (typeof object.value['disruptive'] !== 'boolean') {
    return schemaFailure('Expected a boolean.', `${path}.disruptive`);
  }
  const explanation = asString(
    object.value['explanation'],
    CHANGE_WORKSPACE_LIMITS.messageOctets,
    `${path}.explanation`,
    { trim: true },
  );
  if (!explanation.ok) return explanation;
  const owner = asString(
    object.value['owner'],
    CHANGE_WORKSPACE_LIMITS.shortStringOctets,
    `${path}.owner`,
    { trim: true },
  );
  if (!owner.ok) return owner;
  const reasons = asStringList(
    object.value['reasons'],
    CHANGE_WORKSPACE_LIMITS.guidanceItems,
    CHANGE_WORKSPACE_LIMITS.messageOctets,
    `${path}.reasons`,
  );
  if (!reasons.ok) return reasons;
  if (reasons.value.length === 0) {
    return schemaFailure(
      'An analysed change requires at least one impact reason.',
      `${path}.reasons`,
    );
  }
  const risk = asEnum(object.value['risk'], RISKS, `${path}.risk`);
  if (!risk.ok) return risk;
  const rollback = asString(
    object.value['rollback'],
    CHANGE_WORKSPACE_LIMITS.messageOctets,
    `${path}.rollback`,
    { trim: true },
  );
  if (!rollback.ok) return rollback;
  const type = asString(object.value['type'], 32, `${path}.type`, { trim: true });
  if (!type.ok) return type;
  if (!isRecordType(type.value)) {
    return schemaFailure(
      'Record type must use an upper-case mnemonic or TYPE number.',
      `${path}.type`,
    );
  }
  if (category.value === 'added' && (before.value !== null || after.value === null)) {
    return schemaFailure('An added change requires only an after value.', path);
  }
  if (category.value === 'removed' && (before.value === null || after.value !== null)) {
    return schemaFailure('A removed change requires only a before value.', path);
  }
  if (
    category.value !== 'added' &&
    category.value !== 'removed' &&
    (before.value === null || after.value === null)
  ) {
    return schemaFailure('A changed value requires both before and after values.', path);
  }
  return success({
    after: after.value,
    before: before.value,
    category: category.value,
    disruptive: object.value['disruptive'],
    explanation: explanation.value,
    owner: owner.value,
    reasons: reasons.value,
    risk: risk.value,
    rollback: rollback.value,
    type: type.value,
  });
}

function parseFinding(
  value: unknown,
  path: string,
): Result<ChangeWorkspaceFinding, ChangeWorkspaceCodecError> {
  const object = asRecord(value, ['code', 'message', 'risk'], path);
  if (!object.ok) return object;
  const code = asString(object.value['code'], 128, `${path}.code`, { trim: true });
  if (!code.ok) return code;
  if (!/^[a-z][a-z0-9-]*$/u.test(code.value)) {
    return schemaFailure(
      'Finding code must be a lower-case kebab-case identifier.',
      `${path}.code`,
    );
  }
  const message = asString(
    object.value['message'],
    CHANGE_WORKSPACE_LIMITS.messageOctets,
    `${path}.message`,
    { trim: true },
  );
  if (!message.ok) return message;
  const risk = asEnum(object.value['risk'], RISKS, `${path}.risk`);
  if (!risk.ok) return risk;
  return success({ code: code.value, message: message.value, risk: risk.value });
}

function parseTiming(
  value: unknown,
  path: string,
): Result<ChangeWorkspaceTiming, ChangeWorkspaceCodecError> {
  const object = asRecord(
    value,
    [
      'plannedAt',
      'preparationDeadline',
      'previousTtlSeconds',
      'rollbackCacheHorizon',
      'safeChangeAtIfLoweredNow',
    ],
    path,
  );
  if (!object.ok) return object;
  const plannedAt = asNullableTimestamp(object.value['plannedAt'], `${path}.plannedAt`);
  if (!plannedAt.ok) return plannedAt;
  const preparationDeadline = asNullableTimestamp(
    object.value['preparationDeadline'],
    `${path}.preparationDeadline`,
  );
  if (!preparationDeadline.ok) return preparationDeadline;
  const previousTtlSeconds = asIntegerOrNull(
    object.value['previousTtlSeconds'],
    0,
    2_147_483_647,
    `${path}.previousTtlSeconds`,
  );
  if (!previousTtlSeconds.ok) return previousTtlSeconds;
  const rollbackCacheHorizon = asNullableTimestamp(
    object.value['rollbackCacheHorizon'],
    `${path}.rollbackCacheHorizon`,
  );
  if (!rollbackCacheHorizon.ok) return rollbackCacheHorizon;
  const safeChangeAtIfLoweredNow = asNullableTimestamp(
    object.value['safeChangeAtIfLoweredNow'],
    `${path}.safeChangeAtIfLoweredNow`,
  );
  if (!safeChangeAtIfLoweredNow.ok) return safeChangeAtIfLoweredNow;
  if (plannedAt.value === null && preparationDeadline.value !== null) {
    return schemaFailure('A preparation deadline requires plannedAt.', path);
  }
  if (
    previousTtlSeconds.value === null &&
    (preparationDeadline.value !== null || safeChangeAtIfLoweredNow.value !== null)
  ) {
    return schemaFailure('TTL preparation timing requires previousTtlSeconds.', path);
  }
  if (
    plannedAt.value !== null &&
    preparationDeadline.value !== null &&
    preparationDeadline.value > plannedAt.value
  ) {
    return schemaFailure('The preparation deadline must not follow plannedAt.', path);
  }
  if (
    plannedAt.value !== null &&
    preparationDeadline.value !== null &&
    previousTtlSeconds.value !== null &&
    new Date(plannedAt.value).getTime() - new Date(preparationDeadline.value).getTime() !==
      previousTtlSeconds.value * 1_000
  ) {
    return schemaFailure(
      'The preparation deadline must be exactly one previous TTL before plannedAt.',
      path,
    );
  }
  if (
    plannedAt.value !== null &&
    rollbackCacheHorizon.value !== null &&
    rollbackCacheHorizon.value < plannedAt.value
  ) {
    return schemaFailure('The rollback cache horizon must not precede plannedAt.', path);
  }
  return success({
    plannedAt: plannedAt.value,
    preparationDeadline: preparationDeadline.value,
    previousTtlSeconds: previousTtlSeconds.value,
    rollbackCacheHorizon: rollbackCacheHorizon.value,
    safeChangeAtIfLoweredNow: safeChangeAtIfLoweredNow.value,
  });
}

function parsePhase(
  value: unknown,
  path: string,
): Result<ChangeWorkspaceRolloutPhase, ChangeWorkspaceCodecError> {
  const object = asRecord(value, ['actions', 'id', 'title'], path);
  if (!object.ok) return object;
  const actions = asStringList(
    object.value['actions'],
    CHANGE_WORKSPACE_LIMITS.actionsPerPhase,
    CHANGE_WORKSPACE_LIMITS.messageOctets,
    `${path}.actions`,
  );
  if (!actions.ok) return actions;
  if (actions.value.length === 0) {
    return schemaFailure('A rollout phase requires at least one action.', `${path}.actions`);
  }
  const id = asEnum(object.value['id'], PHASE_IDS, `${path}.id`);
  if (!id.ok) return id;
  const title = asString(
    object.value['title'],
    CHANGE_WORKSPACE_LIMITS.shortStringOctets,
    `${path}.title`,
    { trim: true },
  );
  if (!title.ok) return title;
  return success({ actions: actions.value, id: id.value, title: title.value });
}

function parseAnalysis(
  value: unknown,
  path: string,
): Result<ChangeWorkspaceAnalysis, ChangeWorkspaceCodecError> {
  const object = asRecord(
    value,
    [
      'analysedAt',
      'changes',
      'findings',
      'guidance',
      'incompleteReasons',
      'phases',
      'risk',
      'status',
      'timing',
    ],
    path,
  );
  if (!object.ok) return object;
  const analysedAt = asNullableTimestamp(object.value['analysedAt'], `${path}.analysedAt`);
  if (!analysedAt.ok) return analysedAt;
  const changes = asArray(
    object.value['changes'],
    CHANGE_WORKSPACE_LIMITS.analysisChanges,
    `${path}.changes`,
  );
  if (!changes.ok) return changes;
  const parsedChanges: ChangeWorkspaceAnalysedChange[] = [];
  for (let index = 0; index < changes.value.length; index += 1) {
    const change = parseChange(changes.value[index], `${path}.changes[${String(index)}]`);
    if (!change.ok) return change;
    parsedChanges.push(change.value);
  }
  const findings = asArray(
    object.value['findings'],
    CHANGE_WORKSPACE_LIMITS.analysisFindings,
    `${path}.findings`,
  );
  if (!findings.ok) return findings;
  const parsedFindings: ChangeWorkspaceFinding[] = [];
  for (let index = 0; index < findings.value.length; index += 1) {
    const finding = parseFinding(findings.value[index], `${path}.findings[${String(index)}]`);
    if (!finding.ok) return finding;
    parsedFindings.push(finding.value);
  }
  const guidance = asStringList(
    object.value['guidance'],
    CHANGE_WORKSPACE_LIMITS.guidanceItems,
    CHANGE_WORKSPACE_LIMITS.messageOctets,
    `${path}.guidance`,
  );
  if (!guidance.ok) return guidance;
  const incompleteReasons = asStringList(
    object.value['incompleteReasons'],
    CHANGE_WORKSPACE_LIMITS.incompleteReasons,
    CHANGE_WORKSPACE_LIMITS.messageOctets,
    `${path}.incompleteReasons`,
  );
  if (!incompleteReasons.ok) return incompleteReasons;
  const phases = asArray(
    object.value['phases'],
    CHANGE_WORKSPACE_LIMITS.analysisPhases,
    `${path}.phases`,
  );
  if (!phases.ok) return phases;
  const parsedPhases: ChangeWorkspaceRolloutPhase[] = [];
  const phaseIds = new Set<string>();
  for (let index = 0; index < phases.value.length; index += 1) {
    const phase = parsePhase(phases.value[index], `${path}.phases[${String(index)}]`);
    if (!phase.ok) return phase;
    if (phaseIds.has(phase.value.id)) {
      return schemaFailure(
        'Rollout phase IDs must be unique.',
        `${path}.phases[${String(index)}].id`,
      );
    }
    phaseIds.add(phase.value.id);
    parsedPhases.push(phase.value);
  }
  const risk =
    object.value['risk'] === null
      ? success(null)
      : asEnum(object.value['risk'], RISKS, `${path}.risk`);
  if (!risk.ok) return risk;
  const status = asEnum(object.value['status'], ANALYSIS_STATUSES, `${path}.status`);
  if (!status.ok) return status;
  const timing = parseTiming(object.value['timing'], `${path}.timing`);
  if (!timing.ok) return timing;
  const hasTiming = Object.values(timing.value).some((item) => item !== null);
  if (
    status.value === 'not-run' &&
    (analysedAt.value !== null ||
      parsedChanges.length !== 0 ||
      parsedFindings.length !== 0 ||
      guidance.value.length !== 0 ||
      incompleteReasons.value.length !== 0 ||
      parsedPhases.length !== 0 ||
      risk.value !== null ||
      hasTiming)
  ) {
    return schemaFailure('A not-run analysis must not contain derived results.', path);
  }
  if (status.value !== 'not-run' && analysedAt.value === null) {
    return schemaFailure(
      'A completed or partial analysis requires analysedAt.',
      `${path}.analysedAt`,
    );
  }
  if (status.value === 'complete' && incompleteReasons.value.length !== 0) {
    return schemaFailure('A complete analysis must not contain incomplete reasons.', path);
  }
  if (status.value === 'partial' && incompleteReasons.value.length === 0) {
    return schemaFailure('A partial analysis requires at least one incomplete reason.', path);
  }
  if (status.value === 'complete' && risk.value === null) {
    return schemaFailure('A complete analysis requires an overall risk.', `${path}.risk`);
  }
  if (status.value === 'partial' && risk.value !== null) {
    return schemaFailure(
      'A partial analysis must not claim an overall risk; per-change and finding risks remain scoped.',
      `${path}.risk`,
    );
  }
  return success({
    analysedAt: analysedAt.value,
    changes: parsedChanges,
    findings: parsedFindings,
    guidance: guidance.value,
    incompleteReasons: incompleteReasons.value,
    phases: parsedPhases,
    risk: risk.value,
    status: status.value,
    timing: timing.value,
  });
}

function consumeEvidenceOctets(
  budget: EvidenceBudget,
  value: string,
  path: string,
): Result<true, ChangeWorkspaceCodecError> {
  budget.octets += encoder.encode(value).length;
  if (budget.octets > CHANGE_WORKSPACE_LIMITS.evidenceOctets) {
    return resourceFailure(
      `Resolver evidence exceeds the ${String(CHANGE_WORKSPACE_LIMITS.evidenceOctets)}-octet safety limit.`,
      path,
    );
  }
  return success(true);
}

function consumeEvidenceStrings(
  budget: EvidenceBudget,
  values: readonly string[],
  path: string,
): Result<true, ChangeWorkspaceCodecError> {
  for (let index = 0; index < values.length; index += 1) {
    const consumed = consumeEvidenceOctets(
      budget,
      values[index] ?? '',
      `${path}[${String(index)}]`,
    );
    if (!consumed.ok) return consumed;
  }
  return success(true);
}

function parseQuestion(
  value: unknown,
  path: string,
  budget: EvidenceBudget,
): Result<ChangeWorkspaceQuestionObservation, ChangeWorkspaceCodecError> {
  budget.questions += 1;
  if (budget.questions > CHANGE_WORKSPACE_LIMITS.evidenceQuestions) {
    return resourceFailure(
      `Resolver evidence exceeds the ${String(CHANGE_WORKSPACE_LIMITS.evidenceQuestions)}-question safety limit.`,
      path,
    );
  }
  const object = asRecord(
    value,
    [
      'authenticatedData',
      'className',
      'error',
      'id',
      'name',
      'observedAt',
      'records',
      'responseCode',
      'status',
      'type',
    ],
    path,
  );
  if (!object.ok) return object;
  const authenticatedData = asBooleanOrNull(
    object.value['authenticatedData'],
    `${path}.authenticatedData`,
  );
  if (!authenticatedData.ok) return authenticatedData;
  if (object.value['className'] !== 'IN') {
    return schemaFailure('Question className must be IN.', `${path}.className`);
  }
  const error = asNullableString(
    object.value['error'],
    CHANGE_WORKSPACE_LIMITS.messageOctets,
    `${path}.error`,
    { trim: true },
  );
  if (!error.ok) return error;
  const id = asUuid(object.value['id'], `${path}.id`);
  if (!id.ok) return id;
  if (budget.questionIds.has(id.value)) {
    return schemaFailure('Question evidence IDs must be unique.', `${path}.id`);
  }
  budget.questionIds.add(id.value);
  const name = asString(
    object.value['name'],
    CHANGE_WORKSPACE_LIMITS.shortStringOctets,
    `${path}.name`,
    { trim: true },
  );
  if (!name.ok) return name;
  const observedAt = asTimestamp(object.value['observedAt'], `${path}.observedAt`);
  if (!observedAt.ok) return observedAt;
  const records = asStringList(
    object.value['records'],
    CHANGE_WORKSPACE_LIMITS.recordsPerQuestion,
    CHANGE_WORKSPACE_LIMITS.recordOctets,
    `${path}.records`,
    false,
  );
  if (!records.ok) return records;
  budget.records += records.value.length;
  if (budget.records > CHANGE_WORKSPACE_LIMITS.evidenceRecords) {
    return resourceFailure(
      `Resolver evidence exceeds the ${String(CHANGE_WORKSPACE_LIMITS.evidenceRecords)}-record safety limit.`,
      `${path}.records`,
    );
  }
  const responseCode = asIntegerOrNull(
    object.value['responseCode'],
    0,
    15,
    `${path}.responseCode`,
  );
  if (!responseCode.ok) return responseCode;
  const status = asEnum(object.value['status'], QUESTION_STATUSES, `${path}.status`);
  if (!status.ok) return status;
  const type = asString(object.value['type'], 32, `${path}.type`, { trim: true });
  if (!type.ok) return type;
  if (!isRecordType(type.value)) {
    return schemaFailure(
      'Question type must use an upper-case mnemonic or TYPE number.',
      `${path}.type`,
    );
  }
  const localFailure = LOCAL_FAILURE_STATUSES.has(status.value);
  if (
    localFailure &&
    (responseCode.value !== null ||
      authenticatedData.value !== null ||
      records.value.length !== 0 ||
      error.value === null)
  ) {
    return schemaFailure(
      'A local question failure requires an error and must not claim a DNS response or records.',
      path,
    );
  }
  if (
    !localFailure &&
    (responseCode.value === null || authenticatedData.value === null || error.value !== null)
  ) {
    return schemaFailure(
      'A DNS response requires responseCode and authenticatedData and must not contain a local error.',
      path,
    );
  }
  const expectedResponseCode =
    status.value === 'answer' || status.value === 'no-data'
      ? 0
      : status.value === 'server-failure'
        ? 2
        : status.value === 'name-error'
          ? 3
          : status.value === 'refused'
            ? 5
            : null;
  if (!localFailure && responseCode.value !== expectedResponseCode) {
    return schemaFailure('Question status does not match responseCode.', path);
  }
  if (status.value === 'answer' && records.value.length === 0) {
    return schemaFailure(
      'An answer observation requires at least one record.',
      `${path}.records`,
    );
  }
  const evidenceStrings = [
    id.value,
    name.value,
    observedAt.value,
    type.value,
    ...(error.value === null ? [] : [error.value]),
    ...records.value,
  ];
  const consumed = consumeEvidenceStrings(budget, evidenceStrings, path);
  if (!consumed.ok) return consumed;
  return success({
    authenticatedData: authenticatedData.value,
    className: 'IN',
    error: error.value,
    id: id.value,
    name: name.value,
    observedAt: observedAt.value,
    records: records.value,
    responseCode: responseCode.value,
    status: status.value,
    type: type.value,
  });
}

function parseResolver(
  value: unknown,
  path: string,
  budget: EvidenceBudget,
): Result<ChangeWorkspaceResolverObservation, ChangeWorkspaceCodecError> {
  const object = asRecord(
    value,
    ['endpoint', 'id', 'incompleteReasons', 'label', 'questions', 'resolverId', 'status'],
    path,
  );
  if (!object.ok) return object;
  const endpoint = asString(
    object.value['endpoint'],
    CHANGE_WORKSPACE_LIMITS.shortStringOctets,
    `${path}.endpoint`,
    { trim: true },
  );
  if (!endpoint.ok) return endpoint;
  if (!/^https:\/\/[^\s#@]+$/u.test(endpoint.value)) {
    return schemaFailure(
      'Resolver endpoint must be an inert HTTPS string without credentials, whitespace, or a fragment.',
      `${path}.endpoint`,
    );
  }
  const id = asUuid(object.value['id'], `${path}.id`);
  if (!id.ok) return id;
  if (budget.resolverIds.has(id.value)) {
    return schemaFailure('Resolver observation IDs must be unique.', `${path}.id`);
  }
  budget.resolverIds.add(id.value);
  const incompleteReasons = asStringList(
    object.value['incompleteReasons'],
    CHANGE_WORKSPACE_LIMITS.incompleteReasons,
    CHANGE_WORKSPACE_LIMITS.messageOctets,
    `${path}.incompleteReasons`,
  );
  if (!incompleteReasons.ok) return incompleteReasons;
  const label = asString(
    object.value['label'],
    CHANGE_WORKSPACE_LIMITS.shortStringOctets,
    `${path}.label`,
    { trim: true },
  );
  if (!label.ok) return label;
  const questions = asArray(
    object.value['questions'],
    CHANGE_WORKSPACE_LIMITS.questionsPerResolver,
    `${path}.questions`,
  );
  if (!questions.ok) return questions;
  const parsedQuestions: ChangeWorkspaceQuestionObservation[] = [];
  const questionKeys = new Set<string>();
  for (let index = 0; index < questions.value.length; index += 1) {
    const question = parseQuestion(
      questions.value[index],
      `${path}.questions[${String(index)}]`,
      budget,
    );
    if (!question.ok) return question;
    const questionKey = `${question.value.name.toLowerCase()}\u0000${question.value.type}\u0000${question.value.className}`;
    if (questionKeys.has(questionKey)) {
      return schemaFailure(
        'A resolver observation must not repeat the same DNS question.',
        `${path}.questions[${String(index)}]`,
      );
    }
    questionKeys.add(questionKey);
    parsedQuestions.push(question.value);
  }
  const resolverId = asEnum(object.value['resolverId'], RESOLVER_IDS, `${path}.resolverId`);
  if (!resolverId.ok) return resolverId;
  const status = asEnum(object.value['status'], COMPLETENESS, `${path}.status`);
  if (!status.ok) return status;
  if (status.value === 'complete' && incompleteReasons.value.length !== 0) {
    return schemaFailure(
      'A complete resolver observation must not contain incomplete reasons.',
      path,
    );
  }
  if (status.value === 'complete' && parsedQuestions.length === 0) {
    return schemaFailure(
      'A complete resolver observation requires at least one question.',
      path,
    );
  }
  if (
    status.value === 'complete' &&
    parsedQuestions.some((question) => !DEFINITIVE_QUESTION_STATUSES.has(question.status))
  ) {
    return schemaFailure(
      'A complete resolver observation requires every question to have a definitive answer, no-data, or name-error outcome.',
      path,
    );
  }
  if (status.value === 'partial' && incompleteReasons.value.length === 0) {
    return schemaFailure('A partial resolver observation requires an incomplete reason.', path);
  }
  const consumed = consumeEvidenceStrings(
    budget,
    [endpoint.value, id.value, label.value, ...incompleteReasons.value],
    path,
  );
  if (!consumed.ok) return consumed;
  return success({
    endpoint: endpoint.value,
    id: id.value,
    incompleteReasons: incompleteReasons.value,
    label: label.value,
    questions: parsedQuestions,
    resolverId: resolverId.value,
    status: status.value,
  });
}

function parseRun(
  value: unknown,
  path: string,
  budget: EvidenceBudget,
): Result<ChangeWorkspaceObservationRun, ChangeWorkspaceCodecError> {
  const object = asRecord(
    value,
    ['completedAt', 'id', 'incompleteReasons', 'resolvers', 'startedAt', 'status'],
    path,
  );
  if (!object.ok) return object;
  const completedAt = asTimestamp(object.value['completedAt'], `${path}.completedAt`);
  if (!completedAt.ok) return completedAt;
  const id = asUuid(object.value['id'], `${path}.id`);
  if (!id.ok) return id;
  if (budget.runIds.has(id.value))
    return schemaFailure('Evidence run IDs must be unique.', `${path}.id`);
  budget.runIds.add(id.value);
  const incompleteReasons = asStringList(
    object.value['incompleteReasons'],
    CHANGE_WORKSPACE_LIMITS.incompleteReasons,
    CHANGE_WORKSPACE_LIMITS.messageOctets,
    `${path}.incompleteReasons`,
  );
  if (!incompleteReasons.ok) return incompleteReasons;
  const resolvers = asArray(
    object.value['resolvers'],
    CHANGE_WORKSPACE_LIMITS.resolversPerRun,
    `${path}.resolvers`,
  );
  if (!resolvers.ok) return resolvers;
  const parsedResolvers: ChangeWorkspaceResolverObservation[] = [];
  const resolverKeys = new Set<string>();
  for (let index = 0; index < resolvers.value.length; index += 1) {
    const resolver = parseResolver(
      resolvers.value[index],
      `${path}.resolvers[${String(index)}]`,
      budget,
    );
    if (!resolver.ok) return resolver;
    const resolverKey = `${resolver.value.resolverId}\u0000${resolver.value.endpoint}`;
    if (resolverKeys.has(resolverKey)) {
      return schemaFailure(
        'An evidence run must not repeat the same resolver endpoint.',
        `${path}.resolvers[${String(index)}]`,
      );
    }
    resolverKeys.add(resolverKey);
    parsedResolvers.push(resolver.value);
  }
  const startedAt = asTimestamp(object.value['startedAt'], `${path}.startedAt`);
  if (!startedAt.ok) return startedAt;
  if (completedAt.value < startedAt.value) {
    return schemaFailure('Evidence completedAt must not precede startedAt.', path);
  }
  for (let resolverIndex = 0; resolverIndex < parsedResolvers.length; resolverIndex += 1) {
    const resolver = parsedResolvers[resolverIndex];
    if (resolver === undefined) continue;
    for (let questionIndex = 0; questionIndex < resolver.questions.length; questionIndex += 1) {
      const question = resolver.questions[questionIndex];
      if (question === undefined) continue;
      if (question.observedAt < startedAt.value || question.observedAt > completedAt.value) {
        return schemaFailure(
          'Question observedAt must fall within its evidence run interval.',
          `${path}.resolvers[${String(resolverIndex)}].questions[${String(questionIndex)}].observedAt`,
        );
      }
    }
  }
  const status = asEnum(object.value['status'], COMPLETENESS, `${path}.status`);
  if (!status.ok) return status;
  if (status.value === 'complete' && incompleteReasons.value.length !== 0) {
    return schemaFailure('A complete evidence run must not contain incomplete reasons.', path);
  }
  if (status.value === 'complete' && parsedResolvers.length === 0) {
    return schemaFailure(
      'A complete evidence run requires at least one resolver observation.',
      path,
    );
  }
  if (
    status.value === 'complete' &&
    parsedResolvers.some((resolver) => resolver.status !== 'complete')
  ) {
    return schemaFailure(
      'A complete evidence run cannot contain a partial resolver observation.',
      path,
    );
  }
  if (status.value === 'partial' && incompleteReasons.value.length === 0) {
    return schemaFailure('A partial evidence run requires an incomplete reason.', path);
  }
  const consumed = consumeEvidenceStrings(
    budget,
    [completedAt.value, id.value, startedAt.value, ...incompleteReasons.value],
    path,
  );
  if (!consumed.ok) return consumed;
  return success({
    completedAt: completedAt.value,
    id: id.value,
    incompleteReasons: incompleteReasons.value,
    resolvers: parsedResolvers,
    startedAt: startedAt.value,
    status: status.value,
  });
}

function parseEvidence(
  value: unknown,
  path: string,
): Result<ChangeWorkspaceEvidence, ChangeWorkspaceCodecError> {
  const object = asRecord(value, ['incompleteReasons', 'runs', 'status'], path);
  if (!object.ok) return object;
  const incompleteReasons = asStringList(
    object.value['incompleteReasons'],
    CHANGE_WORKSPACE_LIMITS.incompleteReasons,
    CHANGE_WORKSPACE_LIMITS.messageOctets,
    `${path}.incompleteReasons`,
  );
  if (!incompleteReasons.ok) return incompleteReasons;
  const runs = asArray(
    object.value['runs'],
    CHANGE_WORKSPACE_LIMITS.evidenceRuns,
    `${path}.runs`,
  );
  if (!runs.ok) return runs;
  const budget: EvidenceBudget = {
    octets: 0,
    questionIds: new Set(),
    questions: 0,
    records: 0,
    resolverIds: new Set(),
    runIds: new Set(),
  };
  const parsedRuns: ChangeWorkspaceObservationRun[] = [];
  for (let index = 0; index < runs.value.length; index += 1) {
    const run = parseRun(runs.value[index], `${path}.runs[${String(index)}]`, budget);
    if (!run.ok) return run;
    parsedRuns.push(run.value);
  }
  const status = asEnum(object.value['status'], EVIDENCE_STATUSES, `${path}.status`);
  if (!status.ok) return status;
  if (
    status.value === 'none' &&
    (parsedRuns.length !== 0 || incompleteReasons.value.length !== 0)
  ) {
    return schemaFailure(
      'Evidence with status none must not contain runs or incomplete reasons.',
      path,
    );
  }
  if (status.value === 'complete' && incompleteReasons.value.length !== 0) {
    return schemaFailure('Complete evidence must not contain incomplete reasons.', path);
  }
  if (status.value === 'complete' && parsedRuns.length === 0) {
    return schemaFailure('Complete evidence requires at least one observation run.', path);
  }
  if (status.value === 'complete' && parsedRuns.some((run) => run.status !== 'complete')) {
    return schemaFailure('Complete evidence cannot contain a partial observation run.', path);
  }
  if (status.value === 'partial' && incompleteReasons.value.length === 0) {
    return schemaFailure('Partial evidence requires at least one incomplete reason.', path);
  }
  const consumed = consumeEvidenceStrings(
    budget,
    incompleteReasons.value,
    `${path}.incompleteReasons`,
  );
  if (!consumed.ok) return consumed;
  return success({
    incompleteReasons: incompleteReasons.value,
    runs: parsedRuns,
    status: status.value,
  });
}

export function parseChangeWorkspace(
  value: unknown,
): Result<ChangeWorkspace, ChangeWorkspaceCodecError> {
  const object = asRecord(
    value,
    ['analysis', 'createdAt', 'current', 'evidence', 'id', 'intended', 'title', 'updatedAt'],
    '$.workspace',
  );
  if (!object.ok) return object;
  const analysis = parseAnalysis(object.value['analysis'], '$.workspace.analysis');
  if (!analysis.ok) return analysis;
  const createdAt = asTimestamp(object.value['createdAt'], '$.workspace.createdAt');
  if (!createdAt.ok) return createdAt;
  const current = parseZoneState(object.value['current'], '$.workspace.current');
  if (!current.ok) return current;
  const evidence = parseEvidence(object.value['evidence'], '$.workspace.evidence');
  if (!evidence.ok) return evidence;
  const id = asUuid(object.value['id'], '$.workspace.id');
  if (!id.ok) return id;
  const intended = parseZoneState(object.value['intended'], '$.workspace.intended');
  if (!intended.ok) return intended;
  const title = asString(
    object.value['title'],
    CHANGE_WORKSPACE_LIMITS.shortStringOctets,
    '$.workspace.title',
    {
      trim: true,
    },
  );
  if (!title.ok) return title;
  if (Array.from(title.value).length > CHANGE_WORKSPACE_LIMITS.titleCharacters) {
    return resourceFailure(
      `Workspace title exceeds the ${String(CHANGE_WORKSPACE_LIMITS.titleCharacters)}-character safety limit.`,
      '$.workspace.title',
    );
  }
  const updatedAt = asTimestamp(object.value['updatedAt'], '$.workspace.updatedAt');
  if (!updatedAt.ok) return updatedAt;
  if (updatedAt.value < createdAt.value) {
    return schemaFailure('Workspace updatedAt must not precede createdAt.', '$.workspace');
  }
  const zoneStatuses = [current.value.status, intended.value.status] as const;
  if (
    analysis.value.status === 'complete' &&
    zoneStatuses.some((status) => status !== 'complete')
  ) {
    return schemaFailure(
      'A complete analysis requires complete current and intended zone states.',
      '$.workspace.analysis',
    );
  }
  if (zoneStatuses.includes('unavailable') && analysis.value.status !== 'not-run') {
    return schemaFailure(
      'An unavailable zone state requires analysis status not-run without derived conclusions.',
      '$.workspace.analysis',
    );
  }
  if (
    !zoneStatuses.includes('unavailable') &&
    zoneStatuses.includes('partial') &&
    analysis.value.status !== 'partial'
  ) {
    return schemaFailure(
      'A partial zone state requires analysis status partial.',
      '$.workspace.analysis',
    );
  }
  return success({
    analysis: analysis.value,
    createdAt: createdAt.value,
    current: current.value,
    evidence: evidence.value,
    id: id.value,
    intended: intended.value,
    title: title.value,
    updatedAt: updatedAt.value,
  });
}

function digestMaterial(workspace: ChangeWorkspace): Result<string, ChangeWorkspaceCodecError> {
  return canonicalJson({ format: CHANGE_WORKSPACE_FORMAT, workspace });
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}

async function sha256(value: string): Promise<Result<string, ChangeWorkspaceCodecError>> {
  try {
    const digest = new Uint8Array(
      await crypto.subtle.digest('SHA-256', asArrayBuffer(encoder.encode(value))),
    );
    return success([...digest].map((octet) => octet.toString(16).padStart(2, '0')).join(''));
  } catch {
    return codecFailure(
      'crypto-unavailable',
      'The browser could not calculate the workspace SHA-256 integrity digest.',
    );
  }
}

function duplicateJsonKey(text: string): Result<true, ChangeWorkspaceCodecError> {
  let offset = 0;

  function skipWhitespace(): void {
    while (offset < text.length && /[\t\n\r ]/u.test(text[offset] ?? '')) offset += 1;
  }

  function stringToken(): Result<string, ChangeWorkspaceCodecError> {
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const character = text[offset];
      if (character === '"') {
        offset += 1;
        try {
          return success(JSON.parse(text.slice(start, offset)) as string);
        } catch {
          return codecFailure('invalid-json', 'Workspace file contains malformed JSON.');
        }
      }
      if (character === '\\') {
        offset += 1;
        if (text[offset] === 'u') offset += 5;
        else offset += 1;
      } else offset += 1;
    }
    return codecFailure('invalid-json', 'Workspace file contains malformed JSON.');
  }

  function value(path: string, depth: number): Result<true, ChangeWorkspaceCodecError> {
    if (depth > CHANGE_WORKSPACE_LIMITS.jsonDepth + 1) {
      return resourceFailure(
        `JSON input exceeds the ${String(CHANGE_WORKSPACE_LIMITS.jsonDepth)}-level depth safety limit.`,
        path,
      );
    }
    skipWhitespace();
    const character = text[offset];
    if (character === '{') {
      offset += 1;
      skipWhitespace();
      const keys = new Set<string>();
      if (text[offset] === '}') {
        offset += 1;
        return success(true);
      }
      while (offset < text.length) {
        if (text[offset] !== '"')
          return codecFailure('invalid-json', 'Workspace file contains malformed JSON.');
        const key = stringToken();
        if (!key.ok) return key;
        if (keys.has(key.value)) {
          return codecFailure(
            'duplicate-key',
            'Workspace JSON object keys must be unique.',
            path,
          );
        }
        keys.add(key.value);
        skipWhitespace();
        if (text[offset] !== ':')
          return codecFailure('invalid-json', 'Workspace file contains malformed JSON.');
        offset += 1;
        const nested = value(`${path}.${key.value}`, depth + 1);
        if (!nested.ok) return nested;
        skipWhitespace();
        if (text[offset] === '}') {
          offset += 1;
          return success(true);
        }
        if (text[offset] !== ',')
          return codecFailure('invalid-json', 'Workspace file contains malformed JSON.');
        offset += 1;
        skipWhitespace();
      }
      return codecFailure('invalid-json', 'Workspace file contains malformed JSON.');
    }
    if (character === '[') {
      offset += 1;
      skipWhitespace();
      if (text[offset] === ']') {
        offset += 1;
        return success(true);
      }
      let index = 0;
      while (offset < text.length) {
        const nested = value(`${path}[${String(index)}]`, depth + 1);
        if (!nested.ok) return nested;
        index += 1;
        skipWhitespace();
        if (text[offset] === ']') {
          offset += 1;
          return success(true);
        }
        if (text[offset] !== ',')
          return codecFailure('invalid-json', 'Workspace file contains malformed JSON.');
        offset += 1;
      }
      return codecFailure('invalid-json', 'Workspace file contains malformed JSON.');
    }
    if (character === '"') {
      const parsed = stringToken();
      return parsed.ok ? success(true) : parsed;
    }
    const remaining = text.slice(offset);
    const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(
      remaining,
    )?.[0];
    if (token === undefined)
      return codecFailure('invalid-json', 'Workspace file contains malformed JSON.');
    offset += token.length;
    return success(true);
  }

  const parsed = value('$', 0);
  if (!parsed.ok) return parsed;
  skipWhitespace();
  return offset === text.length
    ? success(true)
    : codecFailure('invalid-json', 'Workspace file contains trailing JSON content.');
}

export async function encodeChangeWorkspace(
  value: unknown,
): Promise<Result<string, ChangeWorkspaceCodecError>> {
  const inertInput = canonicalJson(value);
  if (!inertInput.ok) return inertInput;
  const parsed = parseChangeWorkspace(JSON.parse(inertInput.value) as unknown);
  if (!parsed.ok) return parsed;
  const material = digestMaterial(parsed.value);
  if (!material.ok) return material;
  const digest = await sha256(material.value);
  if (!digest.ok) return digest;
  const envelope: ChangeWorkspaceEnvelope = {
    format: CHANGE_WORKSPACE_FORMAT,
    integrity: { algorithm: 'SHA-256', authenticity: 'none', digest: digest.value },
    workspace: parsed.value,
  };
  const pretty = `${JSON.stringify(envelope, null, 2)}\n`;
  if (encoder.encode(pretty).length > CHANGE_WORKSPACE_LIMITS.fileOctets) {
    return codecFailure(
      'file-too-large',
      `Workspace file exceeds the ${String(CHANGE_WORKSPACE_LIMITS.fileOctets)}-octet safety limit.`,
    );
  }
  return success(pretty);
}

export async function decodeChangeWorkspace(
  bytes: Uint8Array,
): Promise<Result<DecodedChangeWorkspace, ChangeWorkspaceCodecError>> {
  if (bytes.byteLength > CHANGE_WORKSPACE_LIMITS.fileOctets) {
    return codecFailure(
      'file-too-large',
      `Workspace file exceeds the ${String(CHANGE_WORKSPACE_LIMITS.fileOctets)}-octet safety limit.`,
    );
  }
  let text: string;
  try {
    text = decoder.decode(bytes);
  } catch {
    return codecFailure('invalid-utf8', 'Workspace file is not valid UTF-8.');
  }
  const duplicateCheck = duplicateJsonKey(text);
  if (!duplicateCheck.ok) return duplicateCheck;
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    return codecFailure('invalid-json', 'Workspace file contains malformed JSON.');
  }
  const safeJson = canonicalJson(raw);
  if (!safeJson.ok) return safeJson;
  const inert = JSON.parse(safeJson.value) as unknown;
  const envelope = asRecord(inert, ['format', 'integrity', 'workspace'], '$');
  if (!envelope.ok) return envelope;
  if (envelope.value['format'] !== CHANGE_WORKSPACE_FORMAT) {
    return schemaFailure(`Workspace format must be ${CHANGE_WORKSPACE_FORMAT}.`, '$.format');
  }
  const integrity = asRecord(
    envelope.value['integrity'],
    ['algorithm', 'authenticity', 'digest'],
    '$.integrity',
  );
  if (!integrity.ok) return integrity;
  if (integrity.value['algorithm'] !== 'SHA-256') {
    return schemaFailure('Integrity algorithm must be SHA-256.', '$.integrity.algorithm');
  }
  if (integrity.value['authenticity'] !== 'none') {
    return schemaFailure(
      'Portable workspaces do not claim cryptographic authenticity.',
      '$.integrity.authenticity',
    );
  }
  if (
    typeof integrity.value['digest'] !== 'string' ||
    !DIGEST_PATTERN.test(integrity.value['digest'])
  ) {
    return schemaFailure(
      'Integrity digest must be 64 lower-case hexadecimal characters.',
      '$.integrity.digest',
    );
  }
  const workspace = parseChangeWorkspace(envelope.value['workspace']);
  if (!workspace.ok) return workspace;
  const material = digestMaterial(workspace.value);
  if (!material.ok) return material;
  const calculated = await sha256(material.value);
  if (!calculated.ok) return calculated;
  const claimed = integrity.value['digest'];
  return success({
    format: CHANGE_WORKSPACE_FORMAT,
    integrity:
      claimed === calculated.value
        ? {
            algorithm: 'SHA-256',
            authenticity: 'none',
            digest: claimed,
            status: 'match',
          }
        : {
            algorithm: 'SHA-256',
            authenticity: 'none',
            calculatedDigest: calculated.value,
            claimedDigest: claimed,
            status: 'mismatch',
          },
    workspace: workspace.value,
  });
}
