import { processStrictIpAddress, type ProcessedIpAddress } from '../dns/ip';
import { validateDnsName } from '../dns/names';
import { DnsQueryError } from '../dns/types';
import { parseSpfRecord } from './parser';
import { validateMailFromLocalPart } from './sender-input';
import type {
  SpfDnsClient,
  SpfLookupResult,
  SpfLookupStatus,
  SpfLookupType,
  SpfMechanism,
  SpfPolicy,
  SpfQualifier,
} from './types';

const DNS_TERM_LIMIT = 10;
const VOID_LOOKUP_LIMIT = 2;
const MAX_RECURSION_DEPTH = 20;
const MAX_MX_RECORDS = 10;
const MAX_PTR_TARGETS = 10;
const MAX_DNS_QUERIES = 128;
const MAX_DNS_VALUES = 256;
const MAX_DNS_VALUE_CHARACTERS = 8192;
const MAX_DNS_MESSAGE_BYTES = 65_535;
const MAX_TRACE_ENTRIES = 512;
const MAX_TRACE_VALUES = 12;
const MAX_MACRO_OUTPUT_OCTETS = 4096;
const MAX_EXPLANATION_CHARACTERS = 512;
const textEncoder = new TextEncoder();

type IpAddress = ProcessedIpAddress;
type FaultResult = 'permerror' | 'temperror';

export type SpfSenderResult =
  'none' | 'neutral' | 'pass' | 'fail' | 'softfail' | 'temperror' | 'permerror';

export type SpfSenderTraceStage =
  'input' | 'policy' | 'mechanism' | 'lookup' | 'macro' | 'limit' | 'explanation' | 'result';

export type SpfSenderQueryType = SpfLookupType | 'PTR';

export interface SpfSenderDnsClient extends SpfDnsClient {
  lookupPtr(ip: string): Promise<SpfLookupResult>;
}

export interface SpfSenderContext {
  readonly heloDomain: string;
  readonly ip: string;
  readonly localPart: string;
  readonly mailFromDomain: string;
  readonly receiver: string;
  readonly signal?: AbortSignal;
  readonly timestamp: Date;
}

export interface SpfSenderTraceQuery {
  readonly error?: string;
  readonly messageBytes: number;
  readonly name: string;
  readonly status: SpfLookupStatus | 'threw';
  readonly type: SpfSenderQueryType;
  readonly valueCount: number;
  readonly values: readonly string[];
}

export interface SpfSenderTraceEntry {
  readonly depth: number;
  readonly domain?: string;
  readonly message: string;
  readonly outcome?: SpfSenderResult | 'match' | 'no-match';
  readonly query?: SpfSenderTraceQuery;
  readonly record?: string;
  readonly sequence: number;
  readonly stage: SpfSenderTraceStage;
  readonly term?: string;
}

export interface SpfSenderMechanismMatch {
  readonly domain: string;
  readonly index: number;
  readonly qualifier: SpfQualifier;
  readonly term: string;
}

export interface SpfSenderEvaluation {
  readonly capturedAt?: string;
  readonly dnsQueries: number;
  readonly dnsTerms: number;
  readonly domain: string;
  readonly explanation?: string;
  readonly identity: string;
  readonly identitySource: 'helo' | 'mail-from';
  readonly ip: string;
  readonly match?: SpfSenderMechanismMatch;
  readonly reason: string;
  readonly responseBytes: number;
  readonly result: SpfSenderResult;
  readonly trace: readonly SpfSenderTraceEntry[];
  readonly voidLookups: number;
}

interface NormalisedContext {
  readonly heloDomain: string;
  readonly ip: IpAddress;
  readonly ipText: string;
  readonly identitySource: 'helo' | 'mail-from';
  readonly localPart: string;
  readonly originDomain: string;
  readonly receiver: string;
  readonly sender: string;
  readonly signal?: AbortSignal;
  readonly timestampSeconds: number;
}

interface EvaluationState {
  readonly context: NormalisedContext;
  readonly dns: SpfSenderDnsClient;
  dnsQueries: number;
  dnsTerms: number;
  responseBytes: number;
  readonly trace: SpfSenderTraceEntry[];
  traceTruncated: boolean;
  validatedNames: readonly string[] | null;
  voidLookups: number;
}

interface DomainEvaluation {
  readonly explanationDomain?: string;
  readonly explanationSpec?: string;
  readonly match?: SpfSenderMechanismMatch;
  readonly reason: string;
  readonly result: Exclude<SpfSenderResult, FaultResult>;
}

interface ParsedMechanism {
  readonly ipv4Prefix?: number;
  readonly ipv6Prefix?: number;
  readonly name: SpfMechanism['name'];
  readonly network?: string;
  readonly targetSpec?: string;
}

interface LookupOptions {
  readonly countVoid: boolean;
  readonly depth: number;
  readonly domain: string;
  readonly errors: 'fail' | 'ignore';
  readonly term?: string;
}

class EvaluationFault extends Error {
  readonly result: FaultResult;

  constructor(result: FaultResult, message: string) {
    super(message);
    this.name = 'EvaluationFault';
    this.result = result;
  }
}

class MacroSyntaxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MacroSyntaxError';
  }
}

function addTrace(state: EvaluationState, entry: Omit<SpfSenderTraceEntry, 'sequence'>): void {
  if (state.trace.length < MAX_TRACE_ENTRIES) {
    state.trace.push({ ...entry, sequence: state.trace.length + 1 });
    return;
  }
  if (state.traceTruncated) return;
  state.traceTruncated = true;
  state.trace[MAX_TRACE_ENTRIES - 1] = {
    depth: 0,
    message: `Trace evidence was truncated at ${String(MAX_TRACE_ENTRIES)} entries.`,
    sequence: MAX_TRACE_ENTRIES,
    stage: 'limit',
  };
}

function fail(
  state: EvaluationState,
  result: FaultResult,
  message: string,
  depth: number,
  domain?: string,
  term?: string,
): never {
  addTrace(state, {
    depth,
    ...(domain === undefined ? {} : { domain }),
    message,
    outcome: result,
    stage: 'limit',
    ...(term === undefined ? {} : { term }),
  });
  throw new EvaluationFault(result, message);
}

function safeText(value: string, maximum = 512): string {
  return value.length <= maximum ? value : `${value.slice(0, maximum)}…`;
}

function normaliseDomain(value: string, requireMultipleLabels: boolean): string | null {
  if (value !== value.trim() || value.includes('://')) return null;
  const parsed = validateDnsName(value);
  if (!parsed.ok || parsed.value.ascii === '') return null;
  if (requireMultipleLabels && !parsed.value.ascii.includes('.')) return null;
  return parsed.value.ascii;
}

function normaliseIp(value: string): IpAddress | null {
  return processStrictIpAddress(value);
}

function capturedAt(timestamp: Date): string | undefined {
  return timestamp instanceof Date && Number.isFinite(timestamp.getTime())
    ? timestamp.toISOString()
    : undefined;
}

function earlyEvaluation(
  context: SpfSenderContext,
  result: 'none' | 'permerror',
  reason: string,
): SpfSenderEvaluation {
  const domain = context.mailFromDomain === '' ? context.heloDomain : context.mailFromDomain;
  const evaluationTime = capturedAt(context.timestamp);
  const localPart =
    context.mailFromDomain === '' || context.localPart === ''
      ? 'postmaster'
      : context.localPart;
  return {
    ...(evaluationTime === undefined ? {} : { capturedAt: evaluationTime }),
    dnsQueries: 0,
    dnsTerms: 0,
    domain,
    identity: `${localPart}@${domain}`,
    identitySource: context.mailFromDomain === '' ? 'helo' : 'mail-from',
    ip: context.ip,
    reason,
    responseBytes: 0,
    result,
    trace: [
      {
        depth: 0,
        domain,
        message: reason,
        outcome: result,
        sequence: 1,
        stage: 'input',
      },
    ],
    voidLookups: 0,
  };
}

function normaliseContext(context: SpfSenderContext): NormalisedContext | SpfSenderEvaluation {
  const heloDomain = normaliseDomain(context.heloDomain, true);
  if (context.mailFromDomain === '' && heloDomain === null) {
    return earlyEvaluation(
      context,
      'none',
      'No well-formed multi-label HELO identity was available for the null reverse path.',
    );
  }
  const sourceDomain =
    context.mailFromDomain === '' ? (heloDomain ?? '') : context.mailFromDomain;
  const originDomain = normaliseDomain(sourceDomain, true);
  if (originDomain === null) {
    return earlyEvaluation(
      context,
      'none',
      'No well-formed multi-label MAIL FROM domain was available for SPF evaluation.',
    );
  }
  const ip = normaliseIp(context.ip);
  if (ip === null) {
    return earlyEvaluation(context, 'permerror', 'The supplied SMTP client IP is malformed.');
  }
  const localPart =
    context.mailFromDomain === '' || context.localPart === ''
      ? 'postmaster'
      : context.localPart;
  const localPartError = validateMailFromLocalPart(localPart);
  if (localPartError !== null) {
    return earlyEvaluation(context, 'permerror', localPartError);
  }
  if (!(context.timestamp instanceof Date) || !Number.isFinite(context.timestamp.getTime())) {
    return earlyEvaluation(
      context,
      'permerror',
      'The supplied evaluation timestamp is invalid.',
    );
  }
  const receiver = normaliseDomain(context.receiver, false) ?? 'unknown';
  const ipText = ip.toString();
  return {
    heloDomain: heloDomain ?? context.heloDomain.trim(),
    identitySource: context.mailFromDomain === '' ? 'helo' : 'mail-from',
    ip,
    ipText,
    localPart,
    originDomain,
    receiver,
    sender: `${localPart}@${originDomain}`,
    ...(context.signal === undefined ? {} : { signal: context.signal }),
    timestampSeconds: Math.floor(context.timestamp.getTime() / 1000),
  };
}

function isEvaluation(
  value: NormalisedContext | SpfSenderEvaluation,
): value is SpfSenderEvaluation {
  return 'result' in value;
}

function checkCancellation(state: EvaluationState, depth: number, domain: string): void {
  if (state.context.signal?.aborted === true) {
    fail(state, 'temperror', 'SPF evaluation was cancelled.', depth, domain);
  }
}

function consumeDnsTerm(
  state: EvaluationState,
  depth: number,
  domain: string,
  term: string,
): void {
  state.dnsTerms += 1;
  addTrace(state, {
    depth,
    domain,
    message: `DNS-causing SPF term ${String(state.dnsTerms)} of ${String(DNS_TERM_LIMIT)} was entered.`,
    stage: 'limit',
    term,
  });
  if (state.dnsTerms > DNS_TERM_LIMIT) {
    fail(
      state,
      'permerror',
      `SPF evaluation exceeded the global ${String(DNS_TERM_LIMIT)} DNS-term limit.`,
      depth,
      domain,
      term,
    );
  }
}

function lookupShapeError(result: SpfLookupResult): string | null {
  if (
    !Number.isInteger(result.messageBytes) ||
    result.messageBytes < 0 ||
    result.messageBytes > MAX_DNS_MESSAGE_BYTES
  ) {
    return 'The resolver reported an invalid DNS message size.';
  }
  if (result.values.length > MAX_DNS_VALUES) {
    return `The resolver returned more than ${String(MAX_DNS_VALUES)} values in one answer.`;
  }
  if (
    result.values.some(
      (value) => typeof value !== 'string' || value.length > MAX_DNS_VALUE_CHARACTERS,
    )
  ) {
    return 'The resolver returned an invalid or overlong DNS value.';
  }
  if (result.status !== 'answer' && result.values.length > 0) {
    return 'The resolver returned answer values with a non-answer status.';
  }
  return null;
}

function isVoid(result: SpfLookupResult): boolean {
  return (
    result.status === 'nxdomain' ||
    result.status === 'nodata' ||
    (result.status === 'answer' && result.values.length === 0)
  );
}

function distinctMxRecords(result: SpfLookupResult): readonly { exchange: string }[] | null {
  if (result.mxRecords === undefined) return null;
  const records = new Map<string, { exchange: string }>();
  for (const record of result.mxRecords) {
    const key = `${String(record.preference)}\u0000${record.exchange}`;
    if (!records.has(key)) records.set(key, { exchange: record.exchange });
  }
  return [...records.values()];
}

async function performLookup(
  state: EvaluationState,
  name: string,
  type: SpfSenderQueryType,
  options: LookupOptions,
): Promise<SpfLookupResult | null> {
  checkCancellation(state, options.depth, options.domain);
  state.dnsQueries += 1;
  if (state.dnsQueries > MAX_DNS_QUERIES) {
    if (options.errors === 'ignore') {
      addTrace(state, {
        depth: options.depth,
        domain: options.domain,
        message: `The ${String(MAX_DNS_QUERIES)}-query aggregate safety bound prevented an optional lookup.`,
        stage: 'limit',
        ...(options.term === undefined ? {} : { term: options.term }),
      });
      return null;
    }
    fail(
      state,
      'permerror',
      `SPF evaluation exceeded the ${String(MAX_DNS_QUERIES)}-query aggregate safety bound.`,
      options.depth,
      options.domain,
      options.term,
    );
  }

  let result: SpfLookupResult;
  try {
    result =
      type === 'PTR' ? await state.dns.lookupPtr(name) : await state.dns.lookup(name, type);
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : 'The DNS client threw an error.';
    addTrace(state, {
      depth: options.depth,
      domain: options.domain,
      message: `${type} lookup for ${name} threw: ${safeText(message)}`,
      query: {
        error: safeText(message),
        messageBytes: 0,
        name,
        status: 'threw',
        type,
        valueCount: 0,
        values: [],
      },
      stage: 'lookup',
      ...(options.term === undefined ? {} : { term: options.term }),
    });
    if (
      cause instanceof DnsQueryError &&
      (cause.code === 'aborted' || cause.code === 'budget-exhausted')
    ) {
      fail(
        state,
        'temperror',
        `${type} lookup for ${name} could not complete within this run.`,
        options.depth,
        options.domain,
        options.term,
      );
    }
    if (options.errors === 'ignore') return null;
    fail(
      state,
      'temperror',
      `${type} lookup for ${name} failed.`,
      options.depth,
      options.domain,
      options.term,
    );
  }

  const shapeError = lookupShapeError(result);
  addTrace(state, {
    depth: options.depth,
    domain: options.domain,
    message:
      shapeError === null
        ? `${type} lookup for ${name} returned ${result.status}.`
        : `${type} lookup for ${name} returned unusable evidence: ${shapeError}`,
    query: {
      ...(result.error === undefined ? {} : { error: safeText(result.error) }),
      messageBytes: result.messageBytes,
      name,
      status: result.status,
      type,
      valueCount: result.values.length,
      values: result.values.slice(0, MAX_TRACE_VALUES).map((value) => safeText(value)),
    },
    stage: 'lookup',
    ...(options.term === undefined ? {} : { term: options.term }),
  });
  if (shapeError !== null) {
    if (options.errors === 'ignore') return null;
    fail(state, 'permerror', shapeError, options.depth, options.domain, options.term);
  }

  state.responseBytes += result.messageBytes;
  if (result.status === 'error' || result.status === 'servfail') {
    if (options.errors === 'ignore') return null;
    fail(
      state,
      'temperror',
      `${type} lookup for ${name} returned ${result.status}${result.error === undefined ? '.' : `: ${safeText(result.error)}`}`,
      options.depth,
      options.domain,
      options.term,
    );
  }

  if (options.countVoid && isVoid(result)) {
    state.voidLookups += 1;
    addTrace(state, {
      depth: options.depth,
      domain: options.domain,
      message: `Void lookup ${String(state.voidLookups)} of ${String(VOID_LOOKUP_LIMIT)} was observed.`,
      stage: 'limit',
      ...(options.term === undefined ? {} : { term: options.term }),
    });
    if (state.voidLookups > VOID_LOOKUP_LIMIT) {
      fail(
        state,
        'permerror',
        `SPF evaluation exceeded the ${String(VOID_LOOKUP_LIMIT)}-void-lookup limit.`,
        options.depth,
        options.domain,
        options.term,
      );
    }
  }
  return result;
}

function exactSpfRecords(result: SpfLookupResult): readonly string[] {
  return result.values.filter((value) => /^v=spf1(?: |$)/iu.test(value));
}

function topLevelSlash(value: string): number {
  let inMacro = false;
  for (let index = 0; index < value.length; index += 1) {
    if (!inMacro && value[index] === '%' && value[index + 1] === '{') {
      inMacro = true;
      index += 1;
      continue;
    }
    if (inMacro && value[index] === '}') {
      inMacro = false;
      continue;
    }
    if (!inMacro && value[index] === '/') return index;
  }
  return -1;
}

function parsePrefix(value: string, maximum: number): number | null {
  if (!/^(?:0|[1-9][0-9]{0,2})$/u.test(value)) return null;
  const parsed = Number(value);
  return parsed <= maximum ? parsed : null;
}

function parseTargetAndCidr(
  tail: string,
): Pick<ParsedMechanism, 'targetSpec' | 'ipv4Prefix' | 'ipv6Prefix'> | null {
  const slash = topLevelSlash(tail);
  const targetPart = slash < 0 ? tail : tail.slice(0, slash);
  const cidrPart = slash < 0 ? '' : tail.slice(slash);
  if (targetPart !== '' && !targetPart.startsWith(':')) return null;
  const targetSpec = targetPart === '' ? undefined : targetPart.slice(1);
  if (targetSpec === '') return null;

  let ipv4Prefix: number | undefined;
  let ipv6Prefix: number | undefined;
  if (cidrPart !== '') {
    const dual = /^\/([0-9]+)\/\/([0-9]+)$/u.exec(cidrPart);
    const ipv4Only = /^\/([0-9]+)$/u.exec(cidrPart);
    const ipv6Only = /^\/\/([0-9]+)$/u.exec(cidrPart);
    if (dual !== null) {
      const first = dual[1];
      const second = dual[2];
      if (first === undefined || second === undefined) return null;
      ipv4Prefix = parsePrefix(first, 32) ?? undefined;
      ipv6Prefix = parsePrefix(second, 128) ?? undefined;
      if (ipv4Prefix === undefined || ipv6Prefix === undefined) return null;
    } else if (ipv4Only !== null) {
      const first = ipv4Only[1];
      if (first === undefined) return null;
      ipv4Prefix = parsePrefix(first, 32) ?? undefined;
      if (ipv4Prefix === undefined) return null;
    } else if (ipv6Only !== null) {
      const second = ipv6Only[1];
      if (second === undefined) return null;
      ipv6Prefix = parsePrefix(second, 128) ?? undefined;
      if (ipv6Prefix === undefined) return null;
    } else return null;
  }
  return {
    ...(targetSpec === undefined ? {} : { targetSpec }),
    ...(ipv4Prefix === undefined ? {} : { ipv4Prefix }),
    ...(ipv6Prefix === undefined ? {} : { ipv6Prefix }),
  };
}

function parseNetworkMechanism(name: 'ip4' | 'ip6', tail: string): ParsedMechanism | null {
  if (!tail.startsWith(':')) return null;
  const value = tail.slice(1);
  const slash = value.lastIndexOf('/');
  const network = slash < 0 ? value : value.slice(0, slash);
  const prefixText = slash < 0 ? undefined : value.slice(slash + 1);
  if (network === '' || network.includes('%')) return null;
  const maximum = name === 'ip4' ? 32 : 128;
  const prefix = prefixText === undefined ? maximum : parsePrefix(prefixText, maximum);
  if (prefix === null) return null;
  const parsed = normaliseIp(network);
  if (parsed?.kind() !== (name === 'ip4' ? 'ipv4' : 'ipv6')) return null;
  return {
    ...(name === 'ip4' ? { ipv4Prefix: prefix } : { ipv6Prefix: prefix }),
    name,
    network,
  };
}

function parseRawMechanism(mechanism: SpfMechanism): ParsedMechanism | null {
  const original = /^[+\-~?]/u.test(mechanism.original)
    ? mechanism.original.slice(1)
    : mechanism.original;
  const match = /^([A-Za-z0-9]+)(.*)$/u.exec(original);
  if (match === null) return null;
  const name = match[1]?.toLowerCase();
  const tail = match[2];
  if (tail === undefined || name !== mechanism.name) return null;

  if (name === 'all') return tail === '' ? { name: 'all' } : null;
  if (name === 'ip4' || name === 'ip6') return parseNetworkMechanism(name, tail);
  if (name === 'include' || name === 'exists') {
    return tail.startsWith(':') && tail.length > 1 ? { name, targetSpec: tail.slice(1) } : null;
  }
  if (name === 'ptr') {
    if (tail === '') return { name };
    return tail.startsWith(':') && tail.length > 1 ? { name, targetSpec: tail.slice(1) } : null;
  }
  const parsed = parseTargetAndCidr(tail);
  return parsed === null ? null : { name, ...parsed };
}

function macroExpressionParts(expression: string): {
  readonly count?: number;
  readonly delimiters: string;
  readonly letter: string;
  readonly reverse: boolean;
  readonly urlEscape: boolean;
} {
  const match = /^([A-Za-z])([0-9]*)(r?)([.\-+,/_=]*)$/u.exec(expression);
  if (match === null) throw new MacroSyntaxError(`Malformed SPF macro %{${expression}}.`);
  const sourceLetter = match[1];
  const digits = match[2] ?? '';
  if (sourceLetter === undefined) throw new MacroSyntaxError('SPF macro letter is missing.');
  if (digits === '0') throw new MacroSyntaxError('An SPF macro transformer cannot be zero.');
  const parsedCount = digits === '' ? undefined : Number(digits);
  if (parsedCount !== undefined && (!Number.isFinite(parsedCount) || parsedCount < 1)) {
    throw new MacroSyntaxError('SPF macro transformer is invalid.');
  }
  return {
    ...(parsedCount === undefined ? {} : { count: Math.min(parsedCount, 4096) }),
    delimiters: match[4] === '' || match[4] === undefined ? '.' : match[4],
    letter: sourceLetter.toLowerCase(),
    reverse: match[3] === 'r',
    urlEscape: sourceLetter !== sourceLetter.toLowerCase(),
  };
}

function inspectMacroSyntax(value: string, explanation: boolean): void {
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== '%') continue;
    const next = value[index + 1];
    if (next === '%' || next === '_' || next === '-') {
      index += 1;
      continue;
    }
    if (next !== '{') throw new MacroSyntaxError('A percent sign begins an invalid SPF macro.');
    const end = value.indexOf('}', index + 2);
    if (end < 0) throw new MacroSyntaxError('An SPF macro is missing its closing brace.');
    const expression = value.slice(index + 2, end);
    const parts = macroExpressionParts(expression);
    const allowed = explanation ? 'slodipvhcrt' : 'slodipvh';
    if (!allowed.includes(parts.letter)) {
      throw new MacroSyntaxError(`SPF macro letter “${parts.letter}” is not valid here.`);
    }
    index = end;
  }
}

function validatePolicy(policy: SpfPolicy): string | null {
  if (
    policy.record.length > 4096 ||
    /[^\x20-\x7e]/u.test(policy.record) ||
    !/^v=spf1(?: |$)/iu.test(policy.record) ||
    !policy.validVersion
  ) {
    return 'The selected SPF policy has invalid version, character, or length syntax.';
  }
  const parserError = policy.diagnostics.find((item) => item.severity === 'error');
  if (parserError !== undefined) return parserError.message;
  const modifiers = new Set<string>();
  try {
    for (const term of policy.terms) {
      if (term.kind === 'unknown') {
        return `Unsupported or malformed SPF term: ${term.original}.`;
      }
      if (term.kind === 'unknown-modifier') continue;
      if (term.kind === 'mechanism') {
        const parsed = parseRawMechanism(term);
        if (parsed === null) return `Malformed SPF mechanism: ${term.original}.`;
        if (parsed.targetSpec !== undefined) inspectMacroSyntax(parsed.targetSpec, false);
        continue;
      }
      const expected = `${term.name}=`;
      if (!term.original.toLowerCase().startsWith(expected) || term.value === '') {
        return `Malformed SPF modifier: ${term.original}.`;
      }
      if (modifiers.has(term.name)) {
        return `The ${term.name} modifier appears more than once.`;
      }
      modifiers.add(term.name);
      inspectMacroSyntax(term.value, false);
    }
  } catch (cause) {
    return cause instanceof Error ? cause.message : 'The SPF policy contains an invalid macro.';
  }
  return null;
}

function escapeRegexCharacterClass(value: string): string {
  return value.replace(/[\\\]\-^]/gu, '\\$&');
}

function transformMacroValue(
  value: string,
  parts: ReturnType<typeof macroExpressionParts>,
): string {
  let tokens = value.split(new RegExp(`[${escapeRegexCharacterClass(parts.delimiters)}]`, 'u'));
  if (parts.reverse) tokens = [...tokens].reverse();
  if (parts.count !== undefined && tokens.length > parts.count) {
    tokens = tokens.slice(tokens.length - parts.count);
  }
  const transformed = tokens.join('.');
  return parts.urlEscape ? rfc3986Encode(transformed) : transformed;
}

function rfc3986Encode(value: string): string {
  let result = '';
  for (const byte of textEncoder.encode(value)) {
    const character = String.fromCharCode(byte);
    result += /^[A-Za-z0-9._~-]$/u.test(character)
      ? character
      : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return result;
}

function ipv6Macro(ip: IpAddress): string {
  return ip
    .toByteArray()
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .split('')
    .join('.');
}

function domainContains(candidate: string, domain: string): boolean {
  return candidate === domain || candidate.endsWith(`.${domain}`);
}

function selectValidatedName(names: readonly string[], domain: string): string {
  const ordered = [...names].sort((left, right) => left.localeCompare(right));
  return (
    ordered.find((candidate) => candidate === domain) ??
    ordered.find((candidate) => domainContains(candidate, domain)) ??
    ordered[0] ??
    'unknown'
  );
}

async function macroBaseValue(
  state: EvaluationState,
  letter: string,
  domain: string,
  depth: number,
): Promise<string> {
  const context = state.context;
  if (letter === 's') return context.sender;
  if (letter === 'l') return context.localPart;
  if (letter === 'o') return context.originDomain;
  if (letter === 'd') return domain;
  if (letter === 'i')
    return context.ip.kind() === 'ipv4' ? context.ipText : ipv6Macro(context.ip);
  if (letter === 'v') return context.ip.kind() === 'ipv4' ? 'in-addr' : 'ip6';
  if (letter === 'h') return context.heloDomain;
  if (letter === 'c') return context.ipText;
  if (letter === 'r') return context.receiver;
  if (letter === 't') return String(context.timestampSeconds);
  if (letter === 'p') {
    consumeDnsTerm(state, depth, domain, '%{p} macro');
    const names = await validatedPtrNames(state, depth, domain, '%{p} macro');
    return selectValidatedName(names, domain);
  }
  throw new MacroSyntaxError(`Unsupported SPF macro letter “${letter}”.`);
}

async function expandMacroString(
  state: EvaluationState,
  value: string,
  domain: string,
  depth: number,
  explanation: boolean,
): Promise<string> {
  inspectMacroSyntax(value, explanation);
  let output = '';
  for (let index = 0; index < value.length; index += 1) {
    const character = value.charAt(index);
    if (character !== '%') {
      output += character;
    } else {
      const next = value[index + 1];
      if (next === '%') output += '%';
      else if (next === '_') output += ' ';
      else if (next === '-') output += '%20';
      else if (next === '{') {
        const end = value.indexOf('}', index + 2);
        if (end < 0) throw new MacroSyntaxError('An SPF macro is missing its closing brace.');
        const parts = macroExpressionParts(value.slice(index + 2, end));
        const base = await macroBaseValue(state, parts.letter, domain, depth);
        output += transformMacroValue(base, parts);
        index = end;
        if (textEncoder.encode(output).length > MAX_MACRO_OUTPUT_OCTETS) {
          throw new MacroSyntaxError('SPF macro expansion exceeded the bounded output size.');
        }
        continue;
      }
      index += 1;
    }
    if (textEncoder.encode(output).length > MAX_MACRO_OUTPUT_OCTETS) {
      throw new MacroSyntaxError('SPF macro expansion exceeded the bounded output size.');
    }
  }
  addTrace(state, {
    depth,
    domain,
    message: `Expanded SPF macro input to “${safeText(output, 253)}”.`,
    stage: 'macro',
  });
  return output;
}

function truncateDomain(value: string): string {
  const source = value.endsWith('.') ? value.slice(0, -1) : value;
  const labels = source.split('.');
  while (labels.length > 1 && textEncoder.encode(labels.join('.')).length > 253) labels.shift();
  return labels.join('.');
}

async function expandDomainSpec(
  state: EvaluationState,
  value: string,
  domain: string,
  depth: number,
): Promise<string> {
  let expanded: string;
  try {
    expanded = await expandMacroString(state, value, domain, depth, false);
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : 'SPF macro expansion failed.';
    fail(state, 'permerror', message, depth, domain, value);
  }
  const truncated = truncateDomain(expanded);
  const normalised = normaliseDomain(truncated, true);
  if (normalised === null) {
    fail(
      state,
      'permerror',
      `SPF domain specification expanded to an invalid DNS name: ${safeText(expanded, 253)}.`,
      depth,
      domain,
      value,
    );
  }
  return normalised;
}

function parsedAddress(value: string, expectedKind: 'ipv4' | 'ipv6'): IpAddress | null {
  const parsed = normaliseIp(value);
  if (parsed?.kind() !== expectedKind) return null;
  return parsed;
}

function prefixMatches(left: IpAddress, right: IpAddress, prefix: number): boolean {
  if (left.kind() !== right.kind()) return false;
  const leftBytes = left.toByteArray();
  const rightBytes = right.toByteArray();
  const completeBytes = Math.floor(prefix / 8);
  const remainingBits = prefix % 8;
  for (let index = 0; index < completeBytes; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) return false;
  }
  if (remainingBits === 0) return true;
  const mask = (0xff << (8 - remainingBits)) & 0xff;
  return ((leftBytes[completeBytes] ?? 0) & mask) === ((rightBytes[completeBytes] ?? 0) & mask);
}

function validateAddressValues(
  state: EvaluationState,
  values: readonly string[],
  kind: 'ipv4' | 'ipv6',
  depth: number,
  domain: string,
  term: string,
): readonly IpAddress[] {
  const parsed: IpAddress[] = [];
  for (const value of values) {
    const address = parsedAddress(value, kind);
    if (address === null) {
      fail(
        state,
        'permerror',
        `The resolver returned malformed ${kind === 'ipv4' ? 'A' : 'AAAA'} address data.`,
        depth,
        domain,
        term,
      );
    }
    parsed.push(address);
  }
  return parsed;
}

async function validatedPtrNames(
  state: EvaluationState,
  depth: number,
  domain: string,
  term: string,
): Promise<readonly string[]> {
  if (state.validatedNames !== null) return state.validatedNames;
  if (typeof state.dns.lookupPtr !== 'function') {
    fail(
      state,
      'permerror',
      'The configured DNS client cannot perform the PTR lookup required by this policy.',
      depth,
      domain,
      term,
    );
  }
  const reverse = await performLookup(state, state.context.ipText, 'PTR', {
    countVoid: true,
    depth,
    domain,
    errors: 'ignore',
    term,
  });
  if (reverse === null) {
    state.validatedNames = [];
    return state.validatedNames;
  }
  const candidates = reverse.values.slice(0, MAX_PTR_TARGETS);
  if (reverse.values.length > MAX_PTR_TARGETS) {
    addTrace(state, {
      depth,
      domain,
      message: `PTR validation ignored names after the first ${String(MAX_PTR_TARGETS)} targets.`,
      stage: 'limit',
      term,
    });
  }
  const type: SpfLookupType = state.context.ip.kind() === 'ipv4' ? 'A' : 'AAAA';
  const kind = state.context.ip.kind();
  const validated: string[] = [];
  for (const candidate of candidates) {
    const name = normaliseDomain(candidate, true);
    if (name === null) continue;
    const forward = await performLookup(state, name, type, {
      countVoid: true,
      depth,
      domain,
      errors: 'ignore',
      term,
    });
    if (forward === null) continue;
    const addresses = forward.values.flatMap((value) => {
      const parsed = parsedAddress(value, kind);
      return parsed === null ? [] : [parsed];
    });
    if (
      addresses.some((address) =>
        prefixMatches(state.context.ip, address, kind === 'ipv4' ? 32 : 128),
      )
    ) {
      validated.push(name);
    }
  }
  state.validatedNames = [...new Set(validated)];
  return state.validatedNames;
}

function qualifierResult(qualifier: SpfQualifier): 'pass' | 'fail' | 'softfail' | 'neutral' {
  if (qualifier === '-') return 'fail';
  if (qualifier === '~') return 'softfail';
  if (qualifier === '?') return 'neutral';
  return 'pass';
}

async function targetDomain(
  state: EvaluationState,
  parsed: ParsedMechanism,
  currentDomain: string,
  depth: number,
): Promise<string> {
  return parsed.targetSpec === undefined
    ? currentDomain
    : await expandDomainSpec(state, parsed.targetSpec, currentDomain, depth);
}

async function addressMechanismMatches(
  state: EvaluationState,
  parsed: ParsedMechanism,
  domain: string,
  depth: number,
  term: string,
): Promise<boolean> {
  const target = await targetDomain(state, parsed, domain, depth);
  const ipv4 = state.context.ip.kind() === 'ipv4';
  const type: SpfLookupType = ipv4 ? 'A' : 'AAAA';
  const result = await performLookup(state, target, type, {
    countVoid: true,
    depth,
    domain,
    errors: 'fail',
    term,
  });
  if (result === null) return false;
  const addresses = validateAddressValues(
    state,
    result.values,
    ipv4 ? 'ipv4' : 'ipv6',
    depth,
    domain,
    term,
  );
  const prefix = ipv4 ? (parsed.ipv4Prefix ?? 32) : (parsed.ipv6Prefix ?? 128);
  return addresses.some((address) => prefixMatches(state.context.ip, address, prefix));
}

async function mxMechanismMatches(
  state: EvaluationState,
  parsed: ParsedMechanism,
  domain: string,
  depth: number,
  term: string,
): Promise<boolean> {
  const target = await targetDomain(state, parsed, domain, depth);
  const mx = await performLookup(state, target, 'MX', {
    countVoid: true,
    depth,
    domain,
    errors: 'fail',
    term,
  });
  if (mx === null) return false;
  const mxRecords = distinctMxRecords(mx);
  const recordsOrValues = mxRecords?.map((record) => record.exchange) ?? [
    ...new Set(mx.values),
  ];
  const recordCount = mxRecords?.length ?? recordsOrValues.length;
  if (recordCount > MAX_MX_RECORDS) {
    fail(
      state,
      'permerror',
      `The mx mechanism returned more than ${String(MAX_MX_RECORDS)} MX records.`,
      depth,
      domain,
      term,
    );
  }
  const ipv4 = state.context.ip.kind() === 'ipv4';
  const type: SpfLookupType = ipv4 ? 'A' : 'AAAA';
  const kind = ipv4 ? 'ipv4' : 'ipv6';
  const prefix = ipv4 ? (parsed.ipv4Prefix ?? 32) : (parsed.ipv6Prefix ?? 128);
  const targets = [
    ...new Set(
      recordsOrValues
        .filter((value) => value !== '.')
        .map((value) => normaliseDomain(value, true)),
    ),
  ];
  if (targets.some((value) => value === null)) {
    fail(
      state,
      'permerror',
      'The MX answer contained a malformed target name.',
      depth,
      domain,
      term,
    );
  }
  for (const host of targets) {
    if (host === null) continue;
    const answer = await performLookup(state, host, type, {
      countVoid: true,
      depth,
      domain,
      errors: 'fail',
      term,
    });
    if (answer === null) continue;
    const addresses = validateAddressValues(state, answer.values, kind, depth, domain, term);
    if (addresses.some((address) => prefixMatches(state.context.ip, address, prefix)))
      return true;
  }
  return false;
}

async function mechanismMatches(
  state: EvaluationState,
  mechanism: SpfMechanism,
  parsed: ParsedMechanism,
  domain: string,
  depth: number,
  path: readonly string[],
): Promise<boolean> {
  const term = mechanism.original;
  if (parsed.name === 'all') return true;
  if (parsed.name === 'ip4' || parsed.name === 'ip6') {
    const expectedKind = parsed.name === 'ip4' ? 'ipv4' : 'ipv6';
    if (state.context.ip.kind() !== expectedKind || parsed.network === undefined) return false;
    const network = parsedAddress(parsed.network, expectedKind);
    if (network === null) {
      fail(state, 'permerror', `Malformed ${parsed.name} network.`, depth, domain, term);
    }
    const prefix =
      parsed.name === 'ip4' ? (parsed.ipv4Prefix ?? 32) : (parsed.ipv6Prefix ?? 128);
    return prefixMatches(state.context.ip, network, prefix);
  }

  consumeDnsTerm(state, depth, domain, term);
  if (parsed.name === 'include') {
    const target = await targetDomain(state, parsed, domain, depth);
    const nested = await evaluateDomain(state, target, depth + 1, [...path, target]);
    if (nested.result === 'none') {
      fail(
        state,
        'permerror',
        `The include target ${target} did not publish an SPF policy.`,
        depth,
        domain,
        term,
      );
    }
    return nested.result === 'pass';
  }
  if (parsed.name === 'a')
    return await addressMechanismMatches(state, parsed, domain, depth, term);
  if (parsed.name === 'mx') return await mxMechanismMatches(state, parsed, domain, depth, term);
  if (parsed.name === 'exists') {
    const target = await targetDomain(state, parsed, domain, depth);
    const answer = await performLookup(state, target, 'A', {
      countVoid: true,
      depth,
      domain,
      errors: 'fail',
      term,
    });
    if (answer === null) return false;
    validateAddressValues(state, answer.values, 'ipv4', depth, domain, term);
    return answer.values.length > 0;
  }
  const target = await targetDomain(state, parsed, domain, depth);
  const names = await validatedPtrNames(state, depth, domain, term);
  return names.some((candidate) => domainContains(candidate, target));
}

function explanationModifier(policy: SpfPolicy): string | undefined {
  const modifier = policy.terms.find((term) => term.kind === 'modifier' && term.name === 'exp');
  return modifier?.kind === 'modifier' ? modifier.value : undefined;
}

async function evaluateDomain(
  state: EvaluationState,
  domain: string,
  depth: number,
  path: readonly string[],
): Promise<DomainEvaluation> {
  checkCancellation(state, depth, domain);
  if (depth > MAX_RECURSION_DEPTH) {
    fail(
      state,
      'permerror',
      `SPF recursion exceeded the ${String(MAX_RECURSION_DEPTH)}-level safety bound.`,
      depth,
      domain,
    );
  }
  if (path.slice(0, -1).includes(domain)) {
    fail(
      state,
      'permerror',
      `SPF dependency cycle detected: ${path.join(' → ')}.`,
      depth,
      domain,
    );
  }
  const txt = await performLookup(state, domain, 'TXT', {
    countVoid: depth > 0,
    depth,
    domain,
    errors: 'fail',
  });
  if (txt === null) {
    return { reason: `No SPF policy was found at ${domain}.`, result: 'none' };
  }
  const records = exactSpfRecords(txt);
  if (records.length === 0) {
    addTrace(state, {
      depth,
      domain,
      message: `No SPF policy was selected at ${domain}.`,
      outcome: 'none',
      stage: 'policy',
    });
    return { reason: `No SPF policy was found at ${domain}.`, result: 'none' };
  }
  if (records.length > 1) {
    fail(state, 'permerror', `${domain} publishes more than one SPF policy.`, depth, domain);
  }
  const record = records[0];
  if (record === undefined) throw new Error('SPF policy selection failed.');
  const policy = parseSpfRecord(record, domain);
  const policyError = validatePolicy(policy);
  addTrace(state, {
    depth,
    domain,
    message:
      policyError === null
        ? `Selected one syntactically supported SPF policy at ${domain}.`
        : `The selected SPF policy is unusable: ${policyError}`,
    record: safeText(record, 4096),
    stage: 'policy',
  });
  if (policyError !== null) fail(state, 'permerror', policyError, depth, domain);

  for (const [index, term] of policy.terms.entries()) {
    if (term.kind !== 'mechanism') continue;
    const parsed = parseRawMechanism(term);
    if (parsed === null)
      fail(
        state,
        'permerror',
        `Malformed SPF mechanism: ${term.original}.`,
        depth,
        domain,
        term.original,
      );
    const matches = await mechanismMatches(state, term, parsed, domain, depth, path);
    addTrace(state, {
      depth,
      domain,
      message: `${term.original} ${matches ? 'matched' : 'did not match'} the supplied sender context.`,
      outcome: matches ? 'match' : 'no-match',
      stage: 'mechanism',
      term: term.original,
    });
    if (!matches) continue;
    const result = qualifierResult(term.qualifier);
    const exp = explanationModifier(policy);
    return {
      ...(result === 'fail' && exp !== undefined
        ? { explanationDomain: domain, explanationSpec: exp }
        : {}),
      match: { domain, index, qualifier: term.qualifier, term: term.original },
      reason: `${term.original} matched at ${domain}.`,
      result,
    };
  }

  const redirect = policy.terms.find(
    (term) => term.kind === 'modifier' && term.name === 'redirect',
  );
  if (redirect?.kind === 'modifier') {
    consumeDnsTerm(state, depth, domain, redirect.original);
    const target = await expandDomainSpec(state, redirect.value, domain, depth);
    const nested = await evaluateDomain(state, target, depth + 1, [...path, target]);
    if (nested.result === 'none') {
      fail(
        state,
        'permerror',
        `The redirect target ${target} did not publish an SPF policy.`,
        depth,
        domain,
        redirect.original,
      );
    }
    return nested;
  }
  return {
    reason: `No mechanism matched at ${domain}; the implicit result is neutral.`,
    result: 'neutral',
  };
}

async function loadExplanation(
  state: EvaluationState,
  evaluation: DomainEvaluation,
): Promise<string | undefined> {
  if (
    evaluation.result !== 'fail' ||
    evaluation.explanationDomain === undefined ||
    evaluation.explanationSpec === undefined
  ) {
    return undefined;
  }
  const domain = evaluation.explanationDomain;
  try {
    const target = await expandDomainSpec(state, evaluation.explanationSpec, domain, 0);
    const txt = await performLookup(state, target, 'TXT', {
      countVoid: false,
      depth: 0,
      domain,
      errors: 'ignore',
      term: `exp=${evaluation.explanationSpec}`,
    });
    if (txt?.status !== 'answer' || txt.values.length !== 1) {
      addTrace(state, {
        depth: 0,
        domain,
        message: 'The optional SPF explanation was unavailable or ambiguous and was omitted.',
        stage: 'explanation',
      });
      return undefined;
    }
    const source = txt.values[0];
    if (source === undefined) return undefined;
    const expanded = await expandMacroString(state, source, domain, 0, true);
    if (!/^[\x20-\x7e]*$/u.test(expanded)) {
      addTrace(state, {
        depth: 0,
        domain,
        message: 'The optional SPF explanation was not US-ASCII and was omitted.',
        stage: 'explanation',
      });
      return undefined;
    }
    const explanation = expanded.slice(0, MAX_EXPLANATION_CHARACTERS);
    addTrace(state, {
      depth: 0,
      domain,
      message:
        expanded.length > MAX_EXPLANATION_CHARACTERS
          ? `The publisher explanation was truncated to ${String(MAX_EXPLANATION_CHARACTERS)} characters.`
          : 'The publisher explanation was expanded successfully.',
      stage: 'explanation',
    });
    return explanation;
  } catch (cause) {
    addTrace(state, {
      depth: 0,
      domain,
      message: `The optional SPF explanation was omitted: ${cause instanceof Error ? safeText(cause.message) : 'expansion failed'}.`,
      stage: 'explanation',
    });
    return undefined;
  }
}

function finalEvaluation(
  state: EvaluationState,
  evaluation: {
    readonly match?: SpfSenderMechanismMatch;
    readonly reason: string;
    readonly result: SpfSenderResult;
  },
  explanation?: string,
): SpfSenderEvaluation {
  addTrace(state, {
    depth: 0,
    domain: state.context.originDomain,
    message: evaluation.reason,
    outcome: evaluation.result,
    stage: 'result',
  });
  return {
    capturedAt: new Date(state.context.timestampSeconds * 1000).toISOString(),
    dnsQueries: state.dnsQueries,
    dnsTerms: state.dnsTerms,
    domain: state.context.originDomain,
    ...(explanation === undefined ? {} : { explanation }),
    identity: state.context.sender,
    identitySource: state.context.identitySource,
    ip: state.context.ipText,
    ...(evaluation.match === undefined ? {} : { match: evaluation.match }),
    reason: evaluation.reason,
    responseBytes: state.responseBytes,
    result: evaluation.result,
    trace: state.trace,
    voidLookups: state.voidLookups,
  };
}

export async function evaluateSpfSender(
  context: SpfSenderContext,
  dns: SpfSenderDnsClient,
): Promise<SpfSenderEvaluation> {
  const normalised = normaliseContext(context);
  if (isEvaluation(normalised)) return normalised;
  const state: EvaluationState = {
    context: normalised,
    dns,
    dnsQueries: 0,
    dnsTerms: 0,
    responseBytes: 0,
    trace: [],
    traceTruncated: false,
    validatedNames: null,
    voidLookups: 0,
  };
  addTrace(state, {
    depth: 0,
    domain: normalised.originDomain,
    message: `Evaluating ${normalised.sender} from ${normalised.ipText}.`,
    stage: 'input',
  });
  try {
    const evaluation = await evaluateDomain(state, normalised.originDomain, 0, [
      normalised.originDomain,
    ]);
    const explanation = await loadExplanation(state, evaluation);
    checkCancellation(state, 0, normalised.originDomain);
    return finalEvaluation(state, evaluation, explanation);
  } catch (cause) {
    if (cause instanceof EvaluationFault) {
      return finalEvaluation(state, { reason: cause.message, result: cause.result });
    }
    const reason =
      cause instanceof Error
        ? `Unexpected SPF evaluation failure: ${safeText(cause.message)}.`
        : 'Unexpected SPF evaluation failure.';
    return finalEvaluation(state, { reason, result: 'temperror' });
  }
}
