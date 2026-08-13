import { validateDnsName } from '../dns/names';
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
const MAX_MX_TARGETS = 10;
const encoder = new TextEncoder();

interface WalkResult {
  readonly lookups: number;
  readonly voids: number;
}

interface EvaluationState {
  readonly diagnostics: SpfDiagnostic[];
  readonly diagnosticKeys: Set<string>;
  readonly dns: SpfDnsClient;
  readonly edges: SpfGraphEdge[];
  maximumDepth: number;
  maximumLookups: number;
  maximumVoids: number;
  readonly nodePromises: Map<string, Promise<SpfGraphNode>>;
  readonly nodes: Map<string, SpfGraphNode>;
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

function policyRecords(result: SpfLookupResult): readonly string[] {
  return result.values.filter((value) => value.trimStart().toLowerCase().startsWith('v=spf1'));
}

async function lookup(
  state: EvaluationState,
  domain: string,
  type: 'TXT' | 'A' | 'AAAA' | 'MX',
): Promise<SpfLookupResult> {
  const result = await state.dns.lookup(domain, type);
  state.totalResponseBytes += result.messageBytes;
  if (result.status === 'error' || result.status === 'servfail') {
    addDiagnostic(state, {
      code: 'lookup-failed',
      message: `${type} lookup for ${domain} failed${result.error === undefined ? '.' : `: ${result.error}`}`,
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

function minimumTtl(results: readonly SpfLookupResult[]): number | undefined {
  const values = results.flatMap((result) => (result.ttl === undefined ? [] : [result.ttl]));
  return values.length === 0 ? undefined : Math.min(...values);
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
      void: false,
    };
  }

  if (mechanism.name === 'exists') {
    const answer = await lookup(state, domain, 'A');
    return {
      domain,
      kind: 'exists',
      networks: [],
      targets: [],
      termIndex,
      ...(answer.ttl === undefined ? {} : { ttl: answer.ttl }),
      void: answer.values.length === 0 && answer.status !== 'error',
    };
  }
  if (mechanism.name === 'a') {
    const [ipv4, ipv6] = await Promise.all([
      lookup(state, domain, 'A'),
      lookup(state, domain, 'AAAA'),
    ]);
    const networks = [...ipv4.values, ...ipv6.values];
    const ttl = minimumTtl([ipv4, ipv6]);
    return {
      domain,
      kind: 'a',
      networks,
      targets: [domain],
      termIndex,
      ...(ttl === undefined ? {} : { ttl }),
      void: networks.length === 0 && ipv4.status !== 'error' && ipv6.status !== 'error',
    };
  }

  const mx = await lookup(state, domain, 'MX');
  const targets = mx.values.slice(0, MAX_MX_TARGETS);
  if (mx.values.length > MAX_MX_TARGETS) {
    addDiagnostic(state, {
      code: 'mx-target-limit',
      location: mechanism.location,
      message: `MX expansion for ${domain} returned more than ${String(MAX_MX_TARGETS)} targets.`,
      severity: 'error',
      sourceDomain,
    });
  }
  const addressAnswers = await Promise.all(
    targets.flatMap((target) => [lookup(state, target, 'A'), lookup(state, target, 'AAAA')]),
  );
  const networks = addressAnswers.flatMap((answer) => answer.values);
  const ttl = minimumTtl([mx, ...addressAnswers]);
  return {
    domain,
    kind: 'mx',
    networks,
    targets,
    termIndex,
    ...(ttl === undefined ? {} : { ttl }),
    void: targets.length === 0 || networks.length === 0,
  };
}

async function loadNode(state: EvaluationState, domain: string): Promise<SpfGraphNode> {
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
    let terminalSeen = false;
    const resolutionPromises = policy.terms.map((term, index) => {
      if (terminalSeen) return Promise.resolve(null);
      if (term.kind === 'mechanism' && term.name === 'all') terminalSeen = true;
      return term.kind === 'mechanism'
        ? resolveMechanism(state, term, domain, index)
        : Promise.resolve(null);
    });
    const resolutions = (await Promise.all(resolutionPromises)).filter(
      (item): item is SpfResolution => item !== null,
    );
    return {
      domain,
      messageBytes: txt.messageBytes,
      policy,
      resolutions,
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

async function walk(
  state: EvaluationState,
  domain: string,
  path: readonly string[],
  startingLookups: number,
  startingVoids: number,
): Promise<WalkResult> {
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
  if (node.policy === undefined) return { lookups: startingLookups, voids: startingVoids + 1 };

  let lookups = startingLookups;
  let voids = startingVoids;
  let terminalSeen = false;
  for (const [index, term] of node.policy.terms.entries()) {
    if (terminalSeen) continue;
    if (term.kind === 'mechanism' && term.name === 'all') terminalSeen = true;
    if (term.kind === 'mechanism' && isLookupMechanism(term)) {
      lookups += 1;
      const resolution = node.resolutions.find((item) => item.termIndex === index);
      if (resolution?.void === true) voids += 1;
    }
    if (term.kind === 'modifier' && term.name === 'redirect') lookups += 1;
    state.maximumLookups = Math.max(state.maximumLookups, lookups);
    state.maximumVoids = Math.max(state.maximumVoids, voids);
    if (lookups > LOOKUP_LIMIT) {
      addDiagnostic(state, {
        code: 'lookup-limit',
        location: term.location,
        message: `The worst-case evaluation path exceeds SPF's ${String(LOOKUP_LIMIT)} lookup-term limit.`,
        severity: 'error',
        sourceDomain: domain,
      });
    }
    if (voids >= 2) {
      addDiagnostic(state, {
        code: voids > 2 ? 'void-limit' : 'void-warning',
        location: term.location,
        message:
          voids > 2
            ? 'The worst-case path exceeds the two-void-lookup limit.'
            : 'The worst-case path reaches two void lookups; another void result can cause permerror.',
        severity: voids > 2 ? 'error' : 'warning',
        sourceDomain: domain,
      });
    }

    const dependency =
      term.kind === 'mechanism' && term.name === 'include'
        ? { kind: 'include' as const, target: term.argument }
        : term.kind === 'modifier' && term.name === 'redirect'
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
        if (
          !state.edges.some(
            (edge) =>
              edge.from === domain && edge.to === target && edge.kind === dependency.kind,
          )
        ) {
          state.edges.push({ from: domain, kind: dependency.kind, to: target });
        }
        const nested = await walk(state, target, [...path, target], lookups, voids);
        lookups = Math.max(lookups, nested.lookups);
        voids = Math.max(voids, nested.voids);
      }
    }
  }
  return { lookups, voids };
}

export async function analyseSpf(rootDomain: string, dns: SpfDnsClient): Promise<SpfAnalysis> {
  const parsed = validateDnsName(rootDomain);
  if (!parsed.ok) throw new Error(parsed.error.message);
  const root = parsed.value.ascii;
  const state: EvaluationState = {
    diagnosticKeys: new Set(),
    diagnostics: [],
    dns,
    edges: [],
    maximumDepth: 0,
    maximumLookups: 0,
    maximumVoids: 0,
    nodePromises: new Map(),
    nodes: new Map(),
    totalResponseBytes: 0,
  };
  await walk(state, root, [root], 0, 0);
  return {
    diagnostics: state.diagnostics,
    edges: state.edges,
    maximumDepth: state.maximumDepth,
    maximumLookupTerms: state.maximumLookups,
    maximumVoidLookups: state.maximumVoids,
    nodes: [...state.nodes.values()],
    rootDomain: root,
    totalResponseBytes: state.totalResponseBytes,
  };
}
