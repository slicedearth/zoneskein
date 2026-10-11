import {
  EVIDENCE_BUNDLE_SCHEMA,
  type EvidenceBundle,
  type EvidenceLink,
  type EvidenceNode,
} from '../evidence/types';
import type { GlobalpingDnsMeasurement } from './globalping';

const MAX_GRAPH_NODES = 160;
const MAX_GRAPH_LINKS = 320;

function id(kind: string, value: string): string {
  return `${kind}:${value.toLowerCase()}`;
}

export function globalpingEvidenceBundle(
  measurement: GlobalpingDnsMeasurement,
): EvidenceBundle {
  const nodes = new Map<string, EvidenceNode>();
  const links: EvidenceLink[] = [];
  const incompleteReasons: string[] = [];
  const graphState: { truncated: boolean } = { truncated: false };
  const addNode = (node: EvidenceNode): boolean => {
    if (nodes.has(node.id)) return true;
    if (nodes.size >= MAX_GRAPH_NODES) {
      graphState.truncated = true;
      return false;
    }
    nodes.set(node.id, node);
    return true;
  };
  const addLink = (link: EvidenceLink): void => {
    if (links.length >= MAX_GRAPH_LINKS || !nodes.has(link.source) || !nodes.has(link.target)) {
      graphState.truncated = true;
      return;
    }
    links.push(link);
  };
  const subjectId = id('subject', measurement.target);
  addNode({
    detail: 'Public DNS target supplied for this user-triggered measurement.',
    id: subjectId,
    kind: 'subject',
    label: measurement.target,
    observedAt: measurement.completedAt,
    source: `Globalping measurement ${measurement.id}`,
    status: 'observed',
  });
  measurement.results.forEach((result, resultIndex) => {
    const location = [result.probe.city, result.probe.country].filter(Boolean).join(', ');
    const probeId = id(
      'resolver',
      `${measurement.id}|${String(resultIndex)}|${location}|${result.probe.network}`,
    );
    if (
      !addNode({
        detail: `${result.probe.network}${result.probe.asn === null ? '' : ` (AS${String(result.probe.asn)})`}.`,
        id: probeId,
        kind: 'resolver',
        label: location || result.probe.network,
        observedAt: measurement.completedAt,
        source: 'Globalping probe',
        status: result.status === 'finished' ? 'observed' : 'error',
        uncertainty:
          'A probe is one network vantage point, not a globally representative sample.',
      })
    )
      return;
    addLink({
      kind: 'observed-by',
      label: result.status,
      source: subjectId,
      target: probeId,
    });
    if (result.status !== 'finished')
      incompleteReasons.push(`${location || 'Probe'} returned ${result.status}.`);
    result.hops.forEach((hop, hopIndex) => {
      const authorityId = id(
        'authority',
        `${String(resultIndex)}|${String(hopIndex)}|${hop.resolver}`,
      );
      if (
        !addNode({
          detail: `Delegation hop ${String(hopIndex + 1)} answered by ${hop.resolver}.`,
          id: authorityId,
          kind: 'authority',
          label: hop.resolver,
          observedAt: measurement.completedAt,
          source: location,
          status: 'observed',
        })
      )
        return;
      addLink({
        kind: 'served-by',
        label: `hop ${String(hopIndex + 1)}`,
        source: probeId,
        target: authorityId,
      });
      hop.answers.forEach((answer, answerIndex) => {
        const recordId = id(
          'record',
          `${String(resultIndex)}|${String(hopIndex)}|${String(answerIndex)}|${answer.name}|${answer.type}|${answer.value}`,
        );
        if (
          !addNode({
            detail: `${answer.name} ${String(answer.ttl)} ${answer.className} ${answer.type} ${answer.value}`,
            id: recordId,
            kind: 'record',
            label: `${answer.type} · ${answer.value}`,
            observedAt: measurement.completedAt,
            source: hop.resolver,
            status: 'observed',
            ttlSeconds: answer.ttl,
            uncertainty:
              'Measurement output is transport evidence; DNSSEC authenticity requires separate validation.',
          })
        )
          return;
        addLink({
          kind: 'publishes',
          label: answer.type,
          source: authorityId,
          target: recordId,
        });
      });
    });
  });
  if (measurement.results.length === 0) incompleteReasons.push('No probe result was returned.');
  if (graphState.truncated)
    incompleteReasons.push('The evidence graph reached its bounded display limit.');
  return {
    capturedAt: measurement.completedAt,
    incompleteReasons,
    links,
    nodes: [...nodes.values()],
    schema: EVIDENCE_BUNDLE_SCHEMA,
    status:
      incompleteReasons.length === 0 ? 'complete' : nodes.size > 1 ? 'partial' : 'unavailable',
    subject: measurement.target,
  };
}
