import { containsCidr, mergeCidr, normalizeCidr, parseCidr } from 'cidr-tools';

import { parseStrictIpAddress } from '../dns/ip';
import { analyseSpf } from './evaluator';
import type {
  SpfAnalysis,
  SpfDnsClient,
  SpfGraphNode,
  SpfMechanism,
  SpfProvenance,
  SpfSnapshot,
} from './types';

interface FlattenResult {
  readonly networks: string[];
  readonly provenance: SpfProvenance[];
  readonly terminal: string | null;
}

type DependencyTtl = number | null | undefined;

function includeTtl(current: DependencyTtl, next: number | undefined): number | null {
  if (current === null || next === undefined) return null;
  return current === undefined ? next : Math.min(current, next);
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
  const encoder = new TextEncoder();
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

function nodeByDomain(analysis: SpfAnalysis, domain: string): SpfGraphNode | null {
  return analysis.nodes.find((node) => node.domain === domain) ?? null;
}

function coalesce(
  networks: readonly string[],
  provenance: readonly SpfProvenance[],
): { networks: string[]; provenance: SpfProvenance[] } {
  const merged = mergeCidr([...new Set(networks)]);
  const mapped = provenance.flatMap((item) => {
    const network = merged.find((candidate) => containsCidr(candidate, item.network));
    return network === undefined ? [] : [{ ...item, network }];
  });
  const unique = mapped.filter(
    (item, index) =>
      mapped.findIndex(
        (candidate) =>
          candidate.network === item.network &&
          candidate.mechanism === item.mechanism &&
          candidate.path.join('|') === item.path.join('|') &&
          candidate.sourceRecord === item.sourceRecord,
      ) === index,
  );
  return { networks: merged, provenance: unique };
}

export async function flattenSpf(
  rootDomain: string,
  dns: SpfDnsClient,
  now = new Date(),
): Promise<{ analysis: SpfAnalysis; snapshot: SpfSnapshot }> {
  const analysis = await analyseSpf(rootDomain, dns);
  const blockers = new Set<string>();
  const warnings = new Set<string>();
  const snapshotRemediates = new Set(['lookup-limit', 'void-limit', 'void-warning']);
  for (const item of analysis.diagnostics) {
    if (item.severity === 'error' && !snapshotRemediates.has(item.code))
      blockers.add(`${item.sourceDomain ?? rootDomain}: ${item.message}`);
    else if (item.code === 'macro-present' || item.code === 'ptr-discouraged')
      blockers.add(`${item.sourceDomain ?? rootDomain}: ${item.message}`);
    else warnings.add(`${item.sourceDomain ?? rootDomain}: ${item.message}`);
  }

  const flattenDomain = (
    domain: string,
    path: readonly string[],
    visiting: ReadonlySet<string>,
    inheritedTtl: DependencyTtl,
  ): FlattenResult => {
    if (visiting.has(domain)) {
      blockers.add(
        `Dependency cycle prevents a safe snapshot: ${[...path, domain].join(' → ')}.`,
      );
      return { networks: [], provenance: [], terminal: null };
    }
    const node = nodeByDomain(analysis, domain);
    if (node?.policy === undefined) {
      blockers.add(`${domain}: a single complete SPF policy is required.`);
      return { networks: [], provenance: [], terminal: null };
    }
    const policyTtl = includeTtl(inheritedTtl, node.ttl);
    const nextVisiting = new Set(visiting).add(domain);
    const networks: string[] = [];
    const provenance: SpfProvenance[] = [];
    let terminal: string | null = null;
    let redirect: string | null = null;

    for (const [index, term] of node.policy.terms.entries()) {
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
          networks.push(network);
          provenance.push({
            mechanism: term.original,
            network,
            path,
            sourceRecord: node.policy.record,
            ...(policyTtl === null ? {} : { sourceTtl: policyTtl }),
          });
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
        const resolutionTtl = includeTtl(policyTtl, resolution.ttl);
        for (const address of resolution.networks) {
          const network = normalizedNetwork(address, term);
          networks.push(network);
          provenance.push({
            mechanism: term.original,
            network,
            path,
            sourceRecord: node.policy.record,
            ...(resolutionTtl === null ? {} : { sourceTtl: resolutionTtl }),
          });
        }
        continue;
      }
      if (term.argument !== undefined) {
        const nested = flattenDomain(
          term.argument.toLowerCase().replace(/\.$/u, ''),
          [...path, term.argument],
          nextVisiting,
          policyTtl,
        );
        if (nested.terminal === '+all') {
          blockers.add(`${domain}: ${term.original} authorises an unbounded pass set.`);
        }
        networks.push(...nested.networks);
        provenance.push(...nested.provenance);
      }
    }

    if (terminal === null && redirect !== null) {
      const nested = flattenDomain(
        redirect.toLowerCase().replace(/\.$/u, ''),
        [...path, redirect],
        nextVisiting,
        policyTtl,
      );
      networks.push(...nested.networks);
      provenance.push(...nested.provenance);
      terminal = nested.terminal;
    }
    if (terminal === null)
      blockers.add(`${domain}: no effective terminal all mechanism was found.`);
    return { networks, provenance, terminal };
  };

  const flattened = flattenDomain(
    analysis.rootDomain,
    [analysis.rootDomain],
    new Set(),
    undefined,
  );
  const merged = coalesce(flattened.networks, flattened.provenance);
  const generatedAt = now.toISOString();
  if (blockers.size > 0 || flattened.terminal === null) {
    return {
      analysis,
      snapshot: {
        blockers: [...blockers],
        chunks: [],
        generatedAt,
        networks: merged.networks,
        provenance: merged.provenance,
        safe: false,
        warnings: [...warnings],
      },
    };
  }

  const terms = merged.networks.map(
    (network) => `${parseCidr(network).version === 4 ? 'ip4' : 'ip6'}:${network}`,
  );
  const value = ['v=spf1', ...terms, flattened.terminal].join(' ');
  const chunks = chunkSpf(value);
  const estimatedResponseBytes = estimateSpfResponseBytes(analysis.rootDomain, chunks);
  if (value.length >= 450)
    warnings.add(
      'The generated SPF value is at least 450 characters and has little room for growth.',
    );
  if (estimatedResponseBytes > 512)
    warnings.add(
      'The estimated DNS response exceeds 512 bytes and may depend on EDNS or TCP fallback.',
    );
  const knownTtls = merged.provenance.flatMap((item) =>
    item.sourceTtl === undefined ? [] : [item.sourceTtl],
  );
  const ttlsKnown =
    merged.provenance.length > 0 && knownTtls.length === merged.provenance.length;
  const minimumTtl = ttlsKnown ? Math.min(...knownTtls) : null;
  const earliestSourceExpiry =
    minimumTtl === null ? undefined : new Date(now.getTime() + minimumTtl * 1000).toISOString();
  const recommendedRecheck =
    minimumTtl === null
      ? undefined
      : new Date(
          now.getTime() +
            Math.min(minimumTtl, Math.max(1, Math.min(3600, Math.floor(minimumTtl / 2)))) *
              1000,
        ).toISOString();
  const bindRecord = `${analysis.rootDomain}. IN TXT (${chunks.map((chunk) => `"${chunk}"`).join(' ')})`;
  const markdown = [
    '# Point-in-time SPF snapshot',
    '',
    `Generated: ${generatedAt}`,
    '',
    `\`${value}\``,
    '',
    '> Point-in-time SPF snapshot — provider address ranges may change.',
    '',
    '| Network | Original mechanism | Dependency path | Source TTL |',
    '| --- | --- | --- | ---: |',
    ...merged.provenance.map(
      (item) =>
        `| ${item.network} | ${item.mechanism} | ${item.path.join(' → ')} | ${item.sourceTtl === undefined ? 'unknown' : String(item.sourceTtl)} |`,
    ),
  ].join('\n');

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
