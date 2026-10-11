import { parseRecordView } from '../dns/records';
import { dnsRecordIdentity } from '../dns/record-identity';
import type { DnsRecord, DnsResponse } from '../dns/types';
import { canonicalMasterName } from '../zone/master-name';
import {
  EVIDENCE_BUNDLE_SCHEMA,
  type EvidenceBundle,
  type EvidenceLink,
  type EvidenceNode,
  type EvidenceNodeKind,
} from './types';

export interface DnsGraphObservation {
  readonly error?: string;
  readonly questionName: string;
  readonly questionType: string;
  readonly resolverLabel?: string;
  readonly response?: DnsResponse;
}

const MAX_GRAPH_NODES = 160;
const MAX_GRAPH_LINKS = 320;
const MAX_DEPENDENCIES_PER_RECORD = 20;

function normaliseName(value: string): string {
  return canonicalMasterName(value, '.')?.absolute ?? value;
}

function identifier(kind: EvidenceNodeKind, value: string): string {
  return JSON.stringify([kind, value]);
}

function objectValue(value: unknown): Readonly<Record<string, unknown>> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Readonly<Record<string, unknown>>)
    : null;
}

function stringField(value: unknown, key: string): string | null {
  const object = objectValue(value);
  const field = object?.[key];
  return typeof field === 'string' ? field : null;
}

function txtText(record: DnsRecord): string {
  const view = parseRecordView(record);
  return view.txtChunks?.map((chunk) => chunk.text ?? '').join('') ?? view.text;
}

function dependencyNames(record: DnsRecord): readonly string[] {
  const direct =
    record.type === 'CNAME' ||
    record.type === 'DNAME' ||
    record.type === 'NS' ||
    record.type === 'PTR'
      ? typeof record.data === 'string'
        ? record.data
        : null
      : record.type === 'MX'
        ? stringField(record.data, 'exchange')
        : record.type === 'SRV'
          ? stringField(record.data, 'target')
          : null;
  if (direct !== null) return [normaliseName(direct)];

  if (record.type === 'SVCB' || record.type === 'HTTPS') {
    const target = parseRecordView(record).fields.find(
      (field) => field.label === 'Target',
    )?.value;
    return target === undefined || target === '.' ? [] : [normaliseName(target)];
  }

  if (record.type !== 'TXT') return [];
  const value = txtText(record);
  const dependencies: string[] = [];
  for (const match of value.matchAll(/(?:^|\s)(?:include:|redirect=)([^\s;]+)/giu)) {
    const target = match[1];
    if (target !== undefined && !target.includes('%')) dependencies.push(normaliseName(target));
    if (dependencies.length >= MAX_DEPENDENCIES_PER_RECORD) break;
  }
  for (const match of value.matchAll(/(?:^|[,;])\s*(?:mailto:)?[^@\s,;]+@([^\s,;!]+)/giu)) {
    const target = match[1];
    if (target !== undefined) dependencies.push(normaliseName(target));
    if (dependencies.length >= MAX_DEPENDENCIES_PER_RECORD) break;
  }
  return [...new Set(dependencies)].slice(0, MAX_DEPENDENCIES_PER_RECORD);
}

function recordKey(record: DnsRecord, resolverId: string): string {
  return JSON.stringify([resolverId, record.section, dnsRecordIdentity(record)]);
}

function sectionKind(record: DnsRecord): EvidenceNodeKind {
  return record.section === 'authority' ? 'authority' : 'record';
}

export function buildDnsEvidenceBundle(
  subject: string,
  observations: readonly DnsGraphObservation[],
  capturedAt = new Date().toISOString(),
): EvidenceBundle {
  const canonicalSubject = normaliseName(subject);
  const nodes = new Map<string, EvidenceNode>();
  const links = new Map<string, EvidenceLink>();
  const incompleteReasons: string[] = [];

  const addNode = (node: EvidenceNode): boolean => {
    const existing = nodes.get(node.id);
    if (existing !== undefined) {
      // Equivalent observations retain a deterministic display representative.
      if (JSON.stringify(node) < JSON.stringify(existing)) nodes.set(node.id, node);
      return true;
    }
    if (nodes.size >= MAX_GRAPH_NODES) return false;
    nodes.set(node.id, node);
    return true;
  };
  const addLink = (link: EvidenceLink): void => {
    if (!nodes.has(link.source) || !nodes.has(link.target)) return;
    if (links.size >= MAX_GRAPH_LINKS) {
      incompleteReasons.push('The evidence graph reached its bounded relationship limit.');
      return;
    }
    links.set(JSON.stringify([link.source, link.target, link.kind, link.label]), link);
  };

  const subjectId = identifier('subject', canonicalSubject);
  addNode({
    detail: 'The DNS name supplied for this bounded evidence run.',
    id: subjectId,
    kind: 'subject',
    label: canonicalSubject,
    status: 'observed',
  });

  for (const observation of observations) {
    if (observation.response === undefined) {
      const reason = `${observation.questionType}: ${observation.error ?? 'No response was retained.'}`;
      incompleteReasons.push(reason);
      const uncertaintyId = identifier(
        'uncertainty',
        JSON.stringify([
          normaliseName(observation.questionName),
          observation.questionType.toUpperCase(),
          reason,
        ]),
      );
      if (
        addNode({
          detail: reason,
          id: uncertaintyId,
          kind: 'uncertainty',
          label: `${observation.questionType} unavailable`,
          status: 'error',
          uncertainty: 'No DNS conclusion can be drawn for this question.',
        })
      ) {
        addLink({
          kind: 'qualifies',
          label: 'limits',
          source: uncertaintyId,
          target: subjectId,
        });
      }
      continue;
    }

    const { response } = observation;
    const resolverId = identifier('resolver', response.resolver.id);
    addNode({
      detail: `${response.resolver.label} via RFC 8484 ${response.resolver.httpMethod}.`,
      id: resolverId,
      kind: 'resolver',
      label: response.resolver.label,
      observedAt: response.receivedAt,
      source: response.resolver.endpoint,
      status: 'observed',
      uncertainty:
        'This is a recursive-resolver observation, not an authoritative or global view.',
    });
    addLink({
      kind: 'observed-by',
      label: observation.questionType,
      source: subjectId,
      target: resolverId,
    });

    if (response.message.responseCode !== 'NOERROR') {
      incompleteReasons.push(
        `${observation.questionType}: resolver returned ${response.message.responseCode}.`,
      );
    }

    const records = [
      ...response.message.answers,
      ...response.message.authorities,
      ...response.message.additionals,
    ];
    for (const record of records) {
      const key = recordKey(record, response.resolver.id);
      const kind = sectionKind(record);
      const nodeId = identifier(kind, key);
      if (
        !addNode({
          detail: `${record.owner} ${String(record.ttl)} IN ${record.type} ${parseRecordView(record).text}`,
          id: nodeId,
          kind,
          label: `${record.type} · ${parseRecordView(record).text}`,
          observedAt: response.receivedAt,
          source: response.resolver.label,
          status: 'observed',
          ttlSeconds: record.ttl,
          uncertainty: response.message.flags.authenticatedData
            ? 'The resolver set AD; local DNSSEC validation is a separate operation.'
            : 'The record was observed but is not locally authenticated by this graph.',
        })
      ) {
        incompleteReasons.push('The evidence graph reached its bounded node limit.');
        break;
      }
      addLink({
        kind: record.section === 'authority' ? 'served-by' : 'publishes',
        label: record.section,
        source: subjectId,
        target: nodeId,
      });

      for (const dependency of dependencyNames(record)) {
        const targetId = identifier('target', dependency);
        if (
          !addNode({
            detail: `A dependency named by the ${record.type} record. It was not automatically resolved by this graph.`,
            id: targetId,
            kind: 'target',
            label: dependency,
            status: 'unknown',
            uncertainty:
              'Named dependency only; presence, ownership and reachability are not implied.',
          })
        ) {
          incompleteReasons.push('The evidence graph reached its bounded node limit.');
          break;
        }
        addLink({
          kind: 'points-to',
          label: record.type,
          source: nodeId,
          target: targetId,
        });
      }
    }
  }

  const reasons = [...new Set(incompleteReasons)].sort();
  return {
    capturedAt,
    incompleteReasons: reasons,
    links: [...links.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, link]) => link),
    nodes: [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id)),
    schema: EVIDENCE_BUNDLE_SCHEMA,
    status: reasons.length === 0 ? 'complete' : nodes.size > 1 ? 'partial' : 'unavailable',
    subject: canonicalSubject,
  };
}
