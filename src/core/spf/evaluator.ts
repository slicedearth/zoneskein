import { validateDnsName } from '../dns/names';
import { DnsQueryError } from '../dns/types';
import { spfLookupShapeError, SPF_WORK_LIMITS } from './limits';
import { parseSpfRecord } from './parser';
import type {
  SpfAnalysis,
  SpfDiagnostic,
  SpfDnsClient,
  SpfGraphEdge,
  SpfGraphNode,
  SpfLookupResult,
  SpfMechanism,
  SpfResolution,
} from './types';

const MAX_DEPTH = 20;
const LOOKUP_LIMIT = 10;
const MAX_MX_RECORDS = 10;
const encoder = new TextEncoder();

interface WalkResult {
  readonly lookups: number;
  readonly voids: VoidCounts;
}

interface VoidCounts {
  readonly ipv4: number;
  readonly ipv6: number;
}

interface EvaluationState {
  answerValues: number;
  complete: boolean;
  dependencyVisits: number;
  readonly diagnostics: SpfDiagnostic[];
  readonly diagnosticKeys: Set<string>;
  readonly dns: SpfDnsClient;
  readonly edges: SpfGraphEdge[];
  halted: boolean;
  maximumDepth: number;
  maximumLookups: number;
  maximumVoids: VoidCounts;
  networkValues: number;
  readonly nodePromises: Map<string, Promise<SpfGraphNode>>;
  readonly nodes: Map<string, SpfGraphNode>;
  readonly signal?: AbortSignal;
  termExpansions: number;
  totalResponseBytes: number;
}

function addDiagnostic(state: EvaluationState, diagnostic: SpfDiagnostic): void {
  const key = `${diagnostic.sourceDomain ?? ''}|${diagnostic.code}|${String(diagnostic.location?.start ?? -1)}|${diagnostic.message}`;
  if (state.diagnosticKeys.has(key)) return;
  state.diagnosticKeys.add(key);
  state.diagnostics.push(diagnostic);
}

function withDomain(diagnostic: SpfDiagnostic, sourceDomain: string): SpfDiagnostic {
  return { ...diagnostic, sourceDomain };
}

function checkCancellation(state: EvaluationState): void {
  if (state.signal?.aborted === true)
    throw new DOMException('SPF analysis aborted.', 'AbortError');
}

async function cooperativeCheckpoint(state: EvaluationState, count: number): Promise<void> {
  if (count === 0 || count % 64 !== 0) return;
  await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 0));
  checkCancellation(state);
}

function analysisHasStopped(state: EvaluationState): boolean {
  return state.halted;
}

function stopIncomplete(state: EvaluationState, diagnostic: SpfDiagnostic): void {
  addDiagnostic(state, diagnostic);
  state.complete = false;
  state.halted = true;
}

function incompleteLookupResult(message: string, messageBytes = 0): SpfLookupResult {
  return { error: message, messageBytes, status: 'error', values: [] };
}

function policyRecords(result: SpfLookupResult): readonly string[] {
  return result.values.filter((value) => /^v=spf1(?: |$)/iu.test(value));
}

function isVoidLookup(result: SpfLookupResult): boolean {
  return (
    result.status === 'nodata' ||
    result.status === 'nxdomain' ||
    (result.status === 'answer' && result.values.length === 0)
  );
}

function voidLookupCount(result: SpfLookupResult): number {
  return result.status === 'error' || result.status === 'servfail' || !isVoidLookup(result)
    ? 0
    : 1;
}

async function lookup(
  state: EvaluationState,
  domain: string,
  type: 'TXT' | 'A' | 'AAAA' | 'MX',
): Promise<SpfLookupResult> {
  checkCancellation(state);
  if (state.halted) return incompleteLookupResult('SPF analysis stopped at its work bound.');
  let result: SpfLookupResult;
  try {
    result = await state.dns.lookup(domain, type);
  } catch (cause) {
    if (
      state.signal?.aborted === true ||
      (cause instanceof DnsQueryError && cause.code === 'aborted') ||
      (cause instanceof DOMException && cause.name === 'AbortError')
    ) {
      throw cause;
    }
    const message = cause instanceof Error ? cause.message : 'The DNS client threw an error.';
    if (cause instanceof DnsQueryError && cause.code === 'budget-exhausted') {
      stopIncomplete(state, {
        code: 'analysis-work-limit',
        message: `${type} lookup for ${domain} reached the aggregate DNS-question bound: ${message}`,
        severity: 'error',
        sourceDomain: domain,
      });
    } else {
      state.complete = false;
      addDiagnostic(state, {
        code: 'lookup-failed',
        message: `${type} lookup for ${domain} threw: ${message}`,
        severity: 'error',
        sourceDomain: domain,
      });
    }
    return incompleteLookupResult(message);
  }
  const shapeError = spfLookupShapeError(result);
  if (shapeError !== null) {
    state.complete = false;
    addDiagnostic(state, {
      code: 'invalid-lookup-shape',
      message: `${type} lookup for ${domain} returned unusable evidence: ${shapeError}`,
      severity: 'error',
      sourceDomain: domain,
    });
    return incompleteLookupResult(
      shapeError,
      Number.isInteger(result.messageBytes) ? result.messageBytes : 0,
    );
  }
  state.totalResponseBytes += result.messageBytes;
  state.answerValues += result.values.length + (result.mxRecords?.length ?? 0);
  if (
    state.totalResponseBytes > SPF_WORK_LIMITS.responseBytes ||
    state.answerValues > SPF_WORK_LIMITS.aggregateAnswerValues
  ) {
    const reason =
      state.totalResponseBytes > SPF_WORK_LIMITS.responseBytes
        ? `SPF analysis exceeded the ${String(SPF_WORK_LIMITS.responseBytes)}-byte aggregate DNS-response bound.`
        : `SPF analysis exceeded the ${String(SPF_WORK_LIMITS.aggregateAnswerValues)}-value aggregate DNS-answer bound.`;
    stopIncomplete(state, {
      code: 'analysis-work-limit',
      message: reason,
      severity: 'error',
      sourceDomain: domain,
    });
    return incompleteLookupResult(reason, result.messageBytes);
  }
  if (result.status === 'error' || result.status === 'servfail') {
    state.complete = false;
    const detail = result.error === undefined ? '' : `: ${result.error}`;
    addDiagnostic(state, {
      code: 'lookup-failed',
      message: `${type} lookup for ${domain} failed${detail}. Concrete evaluation returns temperror.`,
      severity: 'error',
      sourceDomain: domain,
    });
  }
  return result;
}

function targetDomain(mechanism: SpfMechanism, sourceDomain: string): string | null {
  if (mechanism.macro) return null;
  const target = mechanism.argument ?? sourceDomain;
  const parsed = validateDnsName(target);
  return parsed.ok ? parsed.value.ascii : null;
}

function minimumExpiry(results: readonly SpfLookupResult[]): string | undefined {
  const expiries: string[] = [];
  for (const result of results) {
    if (result.expiresAt === undefined) return undefined;
    expiries.push(result.expiresAt);
  }
  return expiries.length === 0
    ? undefined
    : expiries.reduce((earliest, value) =>
        Date.parse(value) < Date.parse(earliest) ? value : earliest,
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

function retainNetworks(
  state: EvaluationState,
  values: readonly string[],
  sourceDomain: string,
): readonly string[] {
  if (state.halted) return [];
  if (state.networkValues + values.length > SPF_WORK_LIMITS.analysisNetworkValues) {
    stopIncomplete(state, {
      code: 'analysis-network-limit',
      message: `SPF analysis exceeds the ${String(SPF_WORK_LIMITS.analysisNetworkValues)}-address aggregate safety bound.`,
      severity: 'error',
      sourceDomain,
    });
    return [];
  }
  state.networkValues += values.length;
  return values;
}

function consumeTermExpansion(state: EvaluationState, sourceDomain: string): boolean {
  state.termExpansions += 1;
  if (state.termExpansions <= SPF_WORK_LIMITS.termExpansions) return true;
  stopIncomplete(state, {
    code: 'analysis-work-limit',
    message: `SPF analysis exceeds the ${String(SPF_WORK_LIMITS.termExpansions)}-term aggregate safety bound.`,
    severity: 'error',
    sourceDomain,
  });
  return false;
}

async function resolveMechanism(
  state: EvaluationState,
  mechanism: SpfMechanism,
  sourceDomain: string,
  termIndex: number,
): Promise<SpfResolution | null> {
  if (mechanism.name !== 'a' && mechanism.name !== 'mx' && mechanism.name !== 'exists') {
    return null;
  }
  const domain = targetDomain(mechanism, sourceDomain);
  if (domain === null) {
    if (!mechanism.macro) {
      addDiagnostic(state, {
        code: 'invalid-domain-spec',
        location: mechanism.location,
        message: `${mechanism.argument ?? sourceDomain} is not a valid DNS domain specification.`,
        severity: 'error',
        sourceDomain,
      });
    }
    return {
      domain: mechanism.argument ?? sourceDomain,
      kind: mechanism.name,
      networks: [],
      targets: [],
      termIndex,
      voidLookups: { ipv4: 0, ipv6: 0 },
    };
  }

  if (mechanism.name === 'exists') {
    const answer = await lookup(state, domain, 'A');
    const voids = voidLookupCount(answer);
    return {
      domain,
      ...(answer.expiresAt === undefined ? {} : { expiresAt: answer.expiresAt }),
      kind: 'exists',
      networks: [],
      targets: [],
      termIndex,
      ...(answer.ttl === undefined ? {} : { ttl: answer.ttl }),
      voidLookups: { ipv4: voids, ipv6: voids },
    };
  }
  if (mechanism.name === 'a') {
    const [ipv4, ipv6] = await Promise.all([
      lookup(state, domain, 'A'),
      lookup(state, domain, 'AAAA'),
    ]);
    const networks = retainNetworks(state, [...ipv4.values, ...ipv6.values], sourceDomain);
    const ttlValues = [ipv4.ttl, ipv6.ttl].filter(
      (value): value is number => value !== undefined,
    );
    const ttl = ttlValues.length === 2 ? Math.min(...ttlValues) : undefined;
    const expiresAt = minimumExpiry([ipv4, ipv6]);
    return {
      domain,
      ...(expiresAt === undefined ? {} : { expiresAt }),
      kind: 'a',
      networks,
      targets: [domain],
      termIndex,
      ...(ttl === undefined ? {} : { ttl }),
      voidLookups: {
        ipv4: voidLookupCount(ipv4),
        ipv6: voidLookupCount(ipv6),
      },
    };
  }

  const mx = await lookup(state, domain, 'MX');
  const mxRecords = distinctMxRecords(mx);
  const recordsOrValues = mxRecords?.map((record) => record.exchange) ?? [
    ...new Set(mx.values),
  ];
  const targets = [
    ...new Set(recordsOrValues.slice(0, MAX_MX_RECORDS).filter((target) => target !== '.')),
  ];
  const recordCount = mxRecords?.length ?? recordsOrValues.length;
  if (recordCount > MAX_MX_RECORDS) {
    addDiagnostic(state, {
      code: 'mx-target-limit',
      location: mechanism.location,
      message: `MX expansion for ${domain} returned more than ${String(MAX_MX_RECORDS)} records.`,
      severity: 'error',
      sourceDomain,
    });
  }
  const addressAnswers: SpfLookupResult[] = [];
  const networks: string[] = [];
  let ipv4Voids = voidLookupCount(mx);
  let ipv6Voids = voidLookupCount(mx);
  for (const target of targets) {
    if (state.halted) break;
    const ipv4 = await lookup(state, target, 'A');
    const ipv6 = await lookup(state, target, 'AAAA');
    addressAnswers.push(ipv4, ipv6);
    ipv4Voids += voidLookupCount(ipv4);
    ipv6Voids += voidLookupCount(ipv6);
    const retained = retainNetworks(state, [...ipv4.values, ...ipv6.values], sourceDomain);
    networks.push(...retained);
  }
  const expiryInputs = [mx, ...addressAnswers];
  const expiresAt = state.halted ? undefined : minimumExpiry(expiryInputs);
  const ttlValues = expiryInputs.map((answer) => answer.ttl);
  const ttl =
    state.halted || ttlValues.some((value) => value === undefined)
      ? undefined
      : Math.min(...(ttlValues as number[]));
  return {
    domain,
    ...(expiresAt === undefined ? {} : { expiresAt }),
    kind: 'mx',
    networks,
    targets,
    termIndex,
    ...(ttl === undefined ? {} : { ttl }),
    voidLookups: { ipv4: ipv4Voids, ipv6: ipv6Voids },
  };
}

async function loadNode(state: EvaluationState, domain: string): Promise<SpfGraphNode> {
  const loaded = state.nodes.get(domain);
  if (loaded !== undefined) return loaded;
  const existing = state.nodePromises.get(domain);
  if (existing !== undefined) return existing;
  const promise = (async () => {
    const txt = await lookup(state, domain, 'TXT');
    const policies = policyRecords(txt);
    if (policies.length === 0) {
      addDiagnostic(state, {
        code: 'no-spf-policy',
        message: `No SPF policy was found at ${domain}.`,
        severity: 'error',
        sourceDomain: domain,
      });
      return {
        domain,
        ...(txt.expiresAt === undefined ? {} : { expiresAt: txt.expiresAt }),
        messageBytes: txt.messageBytes,
        resolutions: [],
        status: txt.status,
        ...(txt.ttl === undefined ? {} : { ttl: txt.ttl }),
        txtOctets: 0,
      } satisfies SpfGraphNode;
    }
    if (policies.length > 1) {
      addDiagnostic(state, {
        code: 'multiple-spf-policies',
        message: `${domain} publishes ${String(policies.length)} SPF policies; SPF permits exactly one.`,
        severity: 'error',
        sourceDomain: domain,
      });
      return {
        domain,
        ...(txt.expiresAt === undefined ? {} : { expiresAt: txt.expiresAt }),
        messageBytes: txt.messageBytes,
        resolutions: [],
        status: 'multiple-policy',
        ...(txt.ttl === undefined ? {} : { ttl: txt.ttl }),
        txtOctets: policies.reduce((sum, value) => sum + encoder.encode(value).length, 0),
      } satisfies SpfGraphNode;
    }
    const record = policies[0];
    if (record === undefined) throw new Error('SPF policy selection failed.');
    const policy = parseSpfRecord(record, domain);
    for (const item of policy.diagnostics) addDiagnostic(state, withDomain(item, domain));
    return {
      domain,
      ...(txt.expiresAt === undefined ? {} : { expiresAt: txt.expiresAt }),
      messageBytes: txt.messageBytes,
      policy,
      resolutions: [],
      status: txt.status,
      ...(txt.ttl === undefined ? {} : { ttl: txt.ttl }),
      txtOctets: encoder.encode(record).length,
    } satisfies SpfGraphNode;
  })();
  state.nodePromises.set(domain, promise);
  const node = await promise;
  state.nodes.set(domain, node);
  return node;
}

function isLookupMechanism(mechanism: SpfMechanism): boolean {
  return (
    mechanism.name === 'include' ||
    mechanism.name === 'a' ||
    mechanism.name === 'mx' ||
    mechanism.name === 'ptr' ||
    mechanism.name === 'exists'
  );
}

async function resolutionForTerm(
  state: EvaluationState,
  node: SpfGraphNode,
  mechanism: SpfMechanism,
  termIndex: number,
): Promise<SpfResolution | null> {
  const current = state.nodes.get(node.domain) ?? node;
  const existing = current.resolutions.find((item) => item.termIndex === termIndex);
  if (existing !== undefined) return existing;
  const resolution = await resolveMechanism(state, mechanism, node.domain, termIndex);
  if (resolution === null) return null;
  const latest = state.nodes.get(node.domain) ?? current;
  state.nodes.set(node.domain, {
    ...latest,
    resolutions: [...latest.resolutions, resolution].sort(
      (left, right) => left.termIndex - right.termIndex,
    ),
  });
  return resolution;
}

function addVoidCounts(left: VoidCounts, right: VoidCounts): VoidCounts {
  return { ipv4: left.ipv4 + right.ipv4, ipv6: left.ipv6 + right.ipv6 };
}

function updateVoidEvidence(
  state: EvaluationState,
  voids: VoidCounts,
  sourceDomain: string,
  term?: SpfMechanism | { readonly location: SpfMechanism['location'] },
): void {
  state.maximumVoids = {
    ipv4: Math.max(state.maximumVoids.ipv4, voids.ipv4),
    ipv6: Math.max(state.maximumVoids.ipv6, voids.ipv6),
  };
  const over = [...(voids.ipv4 > 2 ? ['IPv4'] : []), ...(voids.ipv6 > 2 ? ['IPv6'] : [])];
  const warning = [
    ...(voids.ipv4 === 2 ? ['IPv4'] : []),
    ...(voids.ipv6 === 2 ? ['IPv6'] : []),
  ];
  if (over.length > 0) {
    addDiagnostic(state, {
      code: 'void-limit',
      ...(term === undefined ? {} : { location: term.location }),
      message: `The worst-case ${over.join(' and ')} path exceeds the two-void-lookup limit.`,
      severity: 'error',
      sourceDomain,
    });
  } else if (warning.length > 0) {
    addDiagnostic(state, {
      code: 'void-warning',
      ...(term === undefined ? {} : { location: term.location }),
      message: `The worst-case ${warning.join(' and ')} path reaches two void lookups; another applicable void result can cause permerror.`,
      severity: 'warning',
      sourceDomain,
    });
  }
}

async function walk(
  state: EvaluationState,
  domain: string,
  path: readonly string[],
  startingLookups: number,
  startingVoids: VoidCounts,
): Promise<WalkResult> {
  checkCancellation(state);
  state.dependencyVisits += 1;
  if (state.dependencyVisits > SPF_WORK_LIMITS.dependencyVisits) {
    stopIncomplete(state, {
      code: 'analysis-work-limit',
      message: `SPF analysis exceeds the ${String(SPF_WORK_LIMITS.dependencyVisits)}-visit dependency safety bound.`,
      severity: 'error',
      sourceDomain: domain,
    });
    return { lookups: startingLookups, voids: startingVoids };
  }
  const depth = path.length;
  state.maximumDepth = Math.max(state.maximumDepth, depth);
  if (depth > MAX_DEPTH) {
    addDiagnostic(state, {
      code: 'maximum-depth',
      message: `SPF dependency depth exceeds the ${String(MAX_DEPTH)}-level safety bound.`,
      severity: 'error',
      sourceDomain: domain,
    });
    return { lookups: startingLookups, voids: startingVoids };
  }
  if (path.slice(0, -1).includes(domain)) {
    addDiagnostic(state, {
      code: 'include-cycle',
      message: `SPF dependency cycle: ${path.join(' → ')}.`,
      severity: 'error',
      sourceDomain: domain,
    });
    return { lookups: startingLookups, voids: startingVoids };
  }
  const node = await loadNode(state, domain);
  if (state.halted) return { lookups: startingLookups, voids: startingVoids };
  if (node.policy === undefined) {
    const voids =
      depth > 1 && (node.status === 'nodata' || node.status === 'nxdomain')
        ? addVoidCounts(startingVoids, { ipv4: 1, ipv6: 1 })
        : startingVoids;
    updateVoidEvidence(state, voids, domain);
    return { lookups: startingLookups, voids };
  }
  if (node.policy.diagnostics.some((item) => item.severity === 'error')) {
    return { lookups: startingLookups, voids: startingVoids };
  }

  let lookups = startingLookups;
  let voids = startingVoids;
  let terminalSeen = false;
  const hasAll = node.policy.terms.some(
    (term) => term.kind === 'mechanism' && term.name === 'all',
  );
  for (const [index, term] of node.policy.terms.entries()) {
    checkCancellation(state);
    if (analysisHasStopped(state) || !consumeTermExpansion(state, domain)) break;
    await cooperativeCheckpoint(state, state.termExpansions);
    if (terminalSeen) continue;
    if (term.kind === 'mechanism' && term.name === 'all') terminalSeen = true;
    const effectiveRedirect = term.kind === 'modifier' && term.name === 'redirect' && !hasAll;
    if (term.kind === 'mechanism' && isLookupMechanism(term)) {
      lookups += 1;
    } else if (effectiveRedirect) lookups += 1;
    state.maximumLookups = Math.max(state.maximumLookups, lookups);
    if (lookups > LOOKUP_LIMIT) {
      stopIncomplete(state, {
        code: 'lookup-limit',
        location: term.location,
        message: `The worst-case evaluation path exceeds SPF's ${String(LOOKUP_LIMIT)} lookup-term limit; traversal stopped without constructing a partial snapshot.`,
        severity: 'error',
        sourceDomain: domain,
      });
      return { lookups, voids };
    }

    if (term.kind === 'mechanism') {
      const resolution = await resolutionForTerm(state, node, term, index);
      if (resolution !== null) {
        voids = addVoidCounts(voids, resolution.voidLookups);
        updateVoidEvidence(state, voids, domain, term);
      }
    }

    const dependency =
      term.kind === 'mechanism' && term.name === 'include'
        ? { kind: 'include' as const, target: term.argument }
        : effectiveRedirect
          ? { kind: 'redirect' as const, target: term.value }
          : null;
    if (dependency?.target !== undefined && !dependency.target.includes('%')) {
      const parsed = validateDnsName(dependency.target);
      if (!parsed.ok) {
        addDiagnostic(state, {
          code: 'invalid-domain-spec',
          location: term.location,
          message: `${dependency.target} is not a valid dependency domain.`,
          severity: 'error',
          sourceDomain: domain,
        });
      } else {
        const target = parsed.value.ascii;
        const duplicateEdge = state.edges.some(
          (edge) => edge.from === domain && edge.to === target && edge.kind === dependency.kind,
        );
        if (!duplicateEdge) {
          if (state.edges.length >= SPF_WORK_LIMITS.graphEdges) {
            stopIncomplete(state, {
              code: 'analysis-work-limit',
              location: term.location,
              message: `SPF analysis exceeds the ${String(SPF_WORK_LIMITS.graphEdges)}-edge graph safety bound.`,
              severity: 'error',
              sourceDomain: domain,
            });
            return { lookups, voids };
          }
          state.edges.push({ from: domain, kind: dependency.kind, to: target });
        }
        const nested = await walk(state, target, [...path, target], lookups, voids);
        lookups = Math.max(lookups, nested.lookups);
        voids = {
          ipv4: Math.max(voids.ipv4, nested.voids.ipv4),
          ipv6: Math.max(voids.ipv6, nested.voids.ipv6),
        };
      }
    }
  }
  return { lookups, voids };
}

export async function analyseSpf(
  rootDomain: string,
  dns: SpfDnsClient,
  signal?: AbortSignal,
): Promise<SpfAnalysis> {
  const parsed = validateDnsName(rootDomain);
  if (!parsed.ok) throw new Error(parsed.error.message);
  const root = parsed.value.ascii;
  const state: EvaluationState = {
    answerValues: 0,
    complete: true,
    dependencyVisits: 0,
    diagnosticKeys: new Set(),
    diagnostics: [],
    dns,
    edges: [],
    halted: false,
    maximumDepth: 0,
    maximumLookups: 0,
    maximumVoids: { ipv4: 0, ipv6: 0 },
    networkValues: 0,
    nodePromises: new Map(),
    nodes: new Map(),
    ...(signal === undefined ? {} : { signal }),
    termExpansions: 0,
    totalResponseBytes: 0,
  };
  await walk(state, root, [root], 0, { ipv4: 0, ipv6: 0 });
  return {
    completion: state.complete && !state.halted ? 'complete' : 'incomplete',
    diagnostics: state.diagnostics,
    edges: state.edges,
    maximumDepth: state.maximumDepth,
    maximumLookupTerms: state.maximumLookups,
    maximumVoidLookups: Math.max(state.maximumVoids.ipv4, state.maximumVoids.ipv6),
    maximumVoidLookupsByFamily: state.maximumVoids,
    nodes: [...state.nodes.values()],
    rootDomain: root,
    totalResponseBytes: state.totalResponseBytes,
    work: {
      answerValues: state.answerValues,
      dependencyVisits: state.dependencyVisits,
      networkValues: state.networkValues,
      termExpansions: state.termExpansions,
    },
  };
}
