import { mergeCidr, normalizeCidr, parseCidr } from 'cidr-tools';

import { parseStrictIpAddress } from '../dns/ip';
import { analyseSpf } from './evaluator';
import { MAX_SPF_DNS_MESSAGE_BYTES, SPF_WORK_LIMITS } from './limits';
import type {
  SpfAnalysis,
  SpfDnsClient,
  SpfMechanism,
  SpfProvenance,
  SpfSnapshot,
} from './types';

interface FlattenResult {
  readonly terminal: string | null;
}

type DependencyExpiry = string | null | undefined;

interface FlattenBudget {
  dependencyVisits: number;
  provenanceEntries: number;
  provenanceOctets: number;
  termExpansions: number;
}

interface FreshnessState {
  earliest?: string;
  sources: number;
  unknown: boolean;
}

interface MergedRange {
  readonly end: bigint;
  readonly network: string;
  readonly start: bigint;
}

const encoder = new TextEncoder();

function includeExpiry(current: DependencyExpiry, next: string | undefined): string | null {
  if (current === null || next === undefined) return null;
  return current === undefined || Date.parse(next) < Date.parse(current) ? next : current;
}

function recordExpiry(state: FreshnessState, value: string | undefined): void {
  state.sources += 1;
  if (value === undefined) {
    state.unknown = true;
    return;
  }
  if (state.earliest === undefined || Date.parse(value) < Date.parse(state.earliest)) {
    state.earliest = value;
  }
}

function checkCancellation(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) throw new DOMException('SPF flattening aborted.', 'AbortError');
}

async function cooperativeCheckpoint(
  count: number,
  signal: AbortSignal | undefined,
): Promise<void> {
  if (count === 0 || count % 64 !== 0) return;
  await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 0));
  checkCancellation(signal);
}

function prefixFor(mechanism: SpfMechanism, address: string): number {
  const family = parseStrictIpAddress(address.split('/')[0] ?? address)?.kind();
  if (family === undefined) throw new Error('Address is not a strict IP literal.');
  return family === 'ipv4' ? (mechanism.cidr?.ipv4 ?? 32) : (mechanism.cidr?.ipv6 ?? 128);
}

function normalizedNetwork(address: string, mechanism: SpfMechanism): string {
  const bare = address.split('/')[0] ?? address;
  const parsed = parseStrictIpAddress(bare);
  if (parsed === null) throw new Error('Address is not a strict IP literal.');
  return normalizeCidr(`${parsed.toNormalizedString()}/${String(prefixFor(mechanism, bare))}`);
}

function chunkSpf(value: string): readonly string[] {
  const chunks: string[] = [];
  let current = '';
  for (const token of value.split(' ')) {
    if (encoder.encode(token).length > 255) throw new Error('An SPF token exceeds 255 octets.');
    const candidate = current === '' ? token : `${current} ${token}`;
    if (encoder.encode(candidate).length <= 255) current = candidate;
    else {
      chunks.push(current);
      current = token;
    }
  }
  if (current !== '') chunks.push(current);
  return chunks;
}

function wireNameLength(name: string): number {
  return name.split('.').reduce((length, label) => length + 1 + label.length, 1);
}

export function estimateSpfResponseBytes(domain: string, chunks: readonly string[]): number {
  const rdata = chunks.reduce(
    (length, chunk) => length + 1 + new TextEncoder().encode(chunk).length,
    0,
  );
  return 12 + wireNameLength(domain) + 4 + 2 + 10 + rdata + 11;
}

async function coalesce(
  networks: readonly string[],
  provenance: readonly SpfProvenance[],
  signal?: AbortSignal,
): Promise<{ networks: string[]; provenance: SpfProvenance[] }> {
  checkCancellation(signal);
  const merged = mergeCidr([...new Set(networks)]);
  const ranges = new Map<number, MergedRange[]>([
    [4, []],
    [6, []],
  ]);
  for (const [index, network] of merged.entries()) {
    await cooperativeCheckpoint(index + 1, signal);
    const parsed = parseCidr(network);
    ranges.get(parsed.version)?.push({ end: parsed.end, network, start: parsed.start });
  }
  for (const family of ranges.values()) {
    family.sort((left, right) =>
      left.start < right.start ? -1 : left.start > right.start ? 1 : 0,
    );
  }

  const containingNetwork = (network: string): string | undefined => {
    const parsed = parseCidr(network);
    const candidates = ranges.get(parsed.version) ?? [];
    let lower = 0;
    let upper = candidates.length - 1;
    let selected: MergedRange | undefined;
    while (lower <= upper) {
      const middle = Math.floor((lower + upper) / 2);
      const candidate = candidates[middle];
      if (candidate === undefined) break;
      if (candidate.start <= parsed.start) {
        selected = candidate;
        lower = middle + 1;
      } else upper = middle - 1;
    }
    return selected !== undefined && selected.end >= parsed.end ? selected.network : undefined;
  };

  const unique: SpfProvenance[] = [];
  const seen = new Set<string>();
  for (const [index, item] of provenance.entries()) {
    await cooperativeCheckpoint(index + 1, signal);
    checkCancellation(signal);
    const network = containingNetwork(item.network);
    if (network === undefined) continue;
    const mapped = { ...item, network };
    const key = JSON.stringify([
      mapped.network,
      mapped.mechanism,
      mapped.path,
      mapped.sourceRecord,
      mapped.sourceExpiresAt ?? null,
    ]);
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(mapped);
  }
  const sorted = merged.sort((left, right) => {
    const parsedLeft = parseCidr(left);
    const parsedRight = parseCidr(right);
    if (parsedLeft.version !== parsedRight.version)
      return parsedLeft.version - parsedRight.version;
    return parsedLeft.start < parsedRight.start
      ? -1
      : parsedLeft.start > parsedRight.start
        ? 1
        : 0;
  });
  return { networks: sorted, provenance: unique };
}

export async function flattenSpf(
  rootDomain: string,
  dns: SpfDnsClient,
  now = new Date(),
  signal?: AbortSignal,
): Promise<{ analysis: SpfAnalysis; snapshot: SpfSnapshot }> {
  const analysis = await analyseSpf(rootDomain, dns, signal);
  const blockers = new Set<string>();
  const warnings = new Set<string>();
  for (const item of analysis.diagnostics) {
    if (item.severity === 'error')
      blockers.add(`${item.sourceDomain ?? rootDomain}: ${item.message}`);
    else if (item.code === 'macro-present' || item.code === 'ptr-discouraged')
      blockers.add(`${item.sourceDomain ?? rootDomain}: ${item.message}`);
    else warnings.add(`${item.sourceDomain ?? rootDomain}: ${item.message}`);
  }
  if (analysis.completion === 'incomplete') {
    blockers.add(
      'SPF analysis stopped at a declared protocol or work bound; no partial snapshot can be published.',
    );
  }

  const budget: FlattenBudget = {
    dependencyVisits: 0,
    provenanceEntries: 0,
    provenanceOctets: 0,
    termExpansions: 0,
  };
  const freshness: FreshnessState = { sources: 0, unknown: false };
  const networks: string[] = [];
  const provenance: SpfProvenance[] = [];
  const nodes = new Map(analysis.nodes.map((node) => [node.domain, node]));
  let budgetExceeded = false;

  const stopAtFlattenBound = (message: string): void => {
    blockers.add(message);
    budgetExceeded = true;
  };

  const appendEvidence = (
    network: string,
    mechanism: string,
    path: readonly string[],
    sourceRecord: string,
    sourceExpiresAt: DependencyExpiry,
  ): void => {
    if (budgetExceeded) return;
    const item: SpfProvenance = {
      mechanism,
      network,
      path,
      sourceRecord,
      ...(sourceExpiresAt === null || sourceExpiresAt === undefined ? {} : { sourceExpiresAt }),
    };
    const octets = encoder.encode(JSON.stringify(item)).length;
    if (
      budget.provenanceEntries >= SPF_WORK_LIMITS.provenanceEntries ||
      budget.provenanceOctets + octets > SPF_WORK_LIMITS.provenanceOctets
    ) {
      stopAtFlattenBound(
        `SPF flattening exceeds the ${String(SPF_WORK_LIMITS.provenanceEntries)}-entry or ${String(SPF_WORK_LIMITS.provenanceOctets)}-octet provenance safety bound.`,
      );
      return;
    }
    budget.provenanceEntries += 1;
    budget.provenanceOctets += octets;
    networks.push(network);
    provenance.push(item);
  };

  const flattenDomain = async (
    domain: string,
    path: readonly string[],
    visiting: ReadonlySet<string>,
    inheritedExpiry: DependencyExpiry,
  ): Promise<FlattenResult> => {
    checkCancellation(signal);
    budget.dependencyVisits += 1;
    if (budget.dependencyVisits > SPF_WORK_LIMITS.dependencyVisits) {
      stopAtFlattenBound(
        `SPF flattening exceeds the ${String(SPF_WORK_LIMITS.dependencyVisits)}-visit dependency safety bound.`,
      );
      return { terminal: null };
    }
    if (visiting.has(domain)) {
      blockers.add(
        `Dependency cycle prevents a safe snapshot: ${[...path, domain].join(' → ')}.`,
      );
      return { terminal: null };
    }
    const node = nodes.get(domain);
    if (node?.policy === undefined) {
      blockers.add(`${domain}: a single complete SPF policy is required.`);
      return { terminal: null };
    }
    recordExpiry(freshness, node.expiresAt);
    const policyExpiry = includeExpiry(inheritedExpiry, node.expiresAt);
    const nextVisiting = new Set(visiting).add(domain);
    let terminal: string | null = null;
    let redirect: string | null = null;

    for (const [index, term] of node.policy.terms.entries()) {
      checkCancellation(signal);
      budget.termExpansions += 1;
      if (budget.termExpansions > SPF_WORK_LIMITS.termExpansions) {
        stopAtFlattenBound(
          `SPF flattening exceeds the ${String(SPF_WORK_LIMITS.termExpansions)}-term aggregate safety bound.`,
        );
        return { terminal: null };
      }
      await cooperativeCheckpoint(budget.termExpansions, signal);
      if (term.kind === 'unknown') {
        blockers.add(`${domain}: unsupported term ${term.original}.`);
        continue;
      }
      if (term.kind === 'unknown-modifier') continue;
      if (term.kind === 'modifier') {
        if (term.name === 'redirect') {
          if (term.macro) blockers.add(`${domain}: redirect uses sender-dependent macros.`);
          else redirect = term.value;
        } else {
          warnings.add(`${domain}: exp affects explanations and is omitted from the snapshot.`);
        }
        continue;
      }
      if (terminal !== null) continue;
      if (term.name === 'all') {
        terminal = `${term.qualifier}all`;
        continue;
      }
      if (term.qualifier !== '+') {
        blockers.add(
          `${domain}: ${term.original} has a non-pass qualifier with ordered semantics.`,
        );
        continue;
      }
      if (term.macro || term.name === 'exists' || term.name === 'ptr') {
        blockers.add(`${domain}: ${term.original} depends on dynamic sender context.`);
        continue;
      }
      if (term.name === 'ip4' || term.name === 'ip6') {
        if (term.argument === undefined) continue;
        try {
          const network = normalizedNetwork(term.argument, term);
          const family = parseCidr(network).version;
          if ((term.name === 'ip4' && family !== 4) || (term.name === 'ip6' && family !== 6)) {
            throw new Error('Address family mismatch.');
          }
          appendEvidence(network, term.original, path, node.policy.record, policyExpiry);
        } catch {
          blockers.add(`${domain}: ${term.original} is not a valid network.`);
        }
        continue;
      }
      if (term.name === 'a' || term.name === 'mx') {
        const resolution = node.resolutions.find((item) => item.termIndex === index);
        if (resolution === undefined || resolution.networks.length === 0) {
          blockers.add(
            `${domain}: ${term.original} did not resolve to a complete address set.`,
          );
          continue;
        }
        recordExpiry(freshness, resolution.expiresAt);
        const resolutionExpiry = includeExpiry(policyExpiry, resolution.expiresAt);
        for (const address of resolution.networks) {
          try {
            const network = normalizedNetwork(address, term);
            appendEvidence(network, term.original, path, node.policy.record, resolutionExpiry);
          } catch {
            blockers.add(`${domain}: ${term.original} returned a malformed address value.`);
          }
          if (budgetExceeded) return { terminal: null };
        }
        continue;
      }
      if (term.argument !== undefined) {
        const nested = await flattenDomain(
          term.argument.toLowerCase().replace(/\.$/u, ''),
          [...path, term.argument],
          nextVisiting,
          policyExpiry,
        );
        if (nested.terminal === '+all') {
          blockers.add(`${domain}: ${term.original} authorises an unbounded pass set.`);
        }
      }
    }

    if (terminal === null && redirect !== null) {
      const nested = await flattenDomain(
        redirect.toLowerCase().replace(/\.$/u, ''),
        [...path, redirect],
        nextVisiting,
        policyExpiry,
      );
      terminal = nested.terminal;
    }
    if (terminal === null)
      blockers.add(`${domain}: no effective terminal all mechanism was found.`);
    return { terminal };
  };

  const generatedAt = now.toISOString();
  const unsafeSnapshot = (): SpfSnapshot => ({
    blockers: [...blockers],
    chunks: [],
    generatedAt,
    networks: [],
    provenance: [],
    safe: false,
    warnings: [...warnings],
  });

  if (blockers.size > 0) return { analysis, snapshot: unsafeSnapshot() };

  const flattened = await flattenDomain(
    analysis.rootDomain,
    [analysis.rootDomain],
    new Set(),
    undefined,
  );
  if (blockers.size > 0 || flattened.terminal === null) {
    return { analysis, snapshot: unsafeSnapshot() };
  }

  const merged = await coalesce(networks, provenance, signal);
  if (
    merged.networks.length > SPF_WORK_LIMITS.provenanceEntries ||
    merged.provenance.length > SPF_WORK_LIMITS.provenanceEntries
  ) {
    blockers.add('SPF coalescing exceeded its retained network or provenance safety bound.');
    return { analysis, snapshot: unsafeSnapshot() };
  }

  const terms = merged.networks.map(
    (network) => `${parseCidr(network).version === 4 ? 'ip4' : 'ip6'}:${network}`,
  );
  const value = ['v=spf1', ...terms, flattened.terminal].join(' ');
  if (encoder.encode(value).length > SPF_WORK_LIMITS.outputOctets) {
    blockers.add(
      `The generated SPF value exceeds the ${String(SPF_WORK_LIMITS.outputOctets)}-octet output safety bound.`,
    );
    return { analysis, snapshot: unsafeSnapshot() };
  }
  const chunks = chunkSpf(value);
  const estimatedResponseBytes = estimateSpfResponseBytes(analysis.rootDomain, chunks);
  if (estimatedResponseBytes > MAX_SPF_DNS_MESSAGE_BYTES) {
    blockers.add(
      `The generated TXT response exceeds the ${String(MAX_SPF_DNS_MESSAGE_BYTES)}-octet DNS message bound.`,
    );
    return { analysis, snapshot: unsafeSnapshot() };
  }
  if (value.length >= 450)
    warnings.add(
      'The generated SPF value is at least 450 characters and has little room for growth.',
    );
  if (estimatedResponseBytes > 512)
    warnings.add(
      'The estimated DNS response exceeds 512 bytes and may depend on EDNS or TCP fallback.',
    );

  const earliestSourceExpiry =
    freshness.sources > 0 && !freshness.unknown ? freshness.earliest : undefined;
  let recommendedRecheck: string | undefined;
  if (earliestSourceExpiry === undefined) {
    warnings.add(
      'At least one required policy or address response had no absolute expiry, so aggregate freshness is unknown.',
    );
  } else {
    const remaining = Date.parse(earliestSourceExpiry) - now.getTime();
    if (remaining <= 0) {
      blockers.add('Required SPF evidence had already expired before snapshot generation.');
      return { analysis, snapshot: unsafeSnapshot() };
    }
    const delay = Math.min(3_600_000, Math.max(1_000, Math.floor(remaining / 2)));
    recommendedRecheck = new Date(now.getTime() + Math.min(delay, remaining)).toISOString();
  }

  const bindRecord = `${analysis.rootDomain}. IN TXT (${chunks.map((chunk) => `"${chunk}"`).join(' ')})`;
  if (encoder.encode(bindRecord).length > SPF_WORK_LIMITS.outputOctets) {
    blockers.add(
      `The generated master-file record exceeds the ${String(SPF_WORK_LIMITS.outputOctets)}-octet output safety bound.`,
    );
    return { analysis, snapshot: unsafeSnapshot() };
  }
  const markdown = [
    '# Point-in-time SPF snapshot',
    '',
    `Generated: ${generatedAt}`,
    '',
    `\`${value}\``,
    '',
    '> Point-in-time SPF snapshot — provider address ranges may change.',
    '',
    '| Network | Original mechanism | Dependency path | Source expiry |',
    '| --- | --- | --- | --- |',
    ...merged.provenance.map(
      (item) =>
        `| ${item.network} | ${item.mechanism} | ${item.path.join(' → ')} | ${item.sourceExpiresAt ?? 'unknown'} |`,
    ),
  ].join('\n');
  if (encoder.encode(markdown).length > SPF_WORK_LIMITS.provenanceOctets) {
    blockers.add(
      `The generated provenance Markdown exceeds the ${String(SPF_WORK_LIMITS.provenanceOctets)}-octet export safety bound.`,
    );
    return { analysis, snapshot: unsafeSnapshot() };
  }

  return {
    analysis,
    snapshot: {
      bindRecord,
      blockers: [],
      chunks,
      ...(earliestSourceExpiry === undefined ? {} : { earliestSourceExpiry }),
      estimatedResponseBytes,
      generatedAt,
      markdown,
      networks: merged.networks,
      provenance: merged.provenance,
      ...(recommendedRecheck === undefined ? {} : { recommendedRecheck }),
      safe: true,
      terminal: flattened.terminal,
      value,
      warnings: [...warnings],
    },
  };
}
