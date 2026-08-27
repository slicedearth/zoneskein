import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceRadial,
  forceSimulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from 'd3-force';
import { drag, type D3DragEvent } from 'd3-drag';
import { select } from 'd3-selection';
import { zoom, zoomIdentity, type D3ZoomEvent, type ZoomBehavior } from 'd3-zoom';
import { useEffect, useMemo, useRef, useState } from 'react';

import type { EvidenceBundle, EvidenceNode } from '../core/evidence/types';

interface LayoutNode extends SimulationNodeDatum {
  readonly evidence: EvidenceNode;
  readonly id: string;
  readonly orbitRadius: number;
}

interface LayoutLink extends SimulationLinkDatum<LayoutNode> {
  readonly label: string;
}

const WIDTH = 1_100;
const HEIGHT = 700;

function nodeRadius(node: EvidenceNode): number {
  if (node.kind === 'subject') return 24;
  if (node.kind === 'resolver') return 19;
  if (node.kind === 'uncertainty') return 18;
  return 15;
}

function clippedLabel(value: string, maximum: number): string {
  return value.length > maximum ? `${value.slice(0, maximum - 1)}…` : value;
}

function graphLabel(node: EvidenceNode): string {
  if (node.kind !== 'record' && node.kind !== 'authority') return clippedLabel(node.label, 25);
  const separator = node.label.indexOf(' · ');
  if (separator < 0) return clippedLabel(node.label, 22);
  const type = node.label.slice(0, separator);
  const detail = node.label.slice(separator + 3);
  if (type === 'OPT') return type;
  if (type === 'RRSIG') return `${type} · ${detail.trim().split(/\s+/u).at(-1) ?? 'record'}`;
  return `${type} · ${clippedLabel(detail, 17)}`;
}

function layout(bundle: EvidenceBundle): {
  readonly links: readonly LayoutLink[];
  readonly nodes: readonly LayoutNode[];
} {
  let recordIndex = 0;
  const orbitAssignments = bundle.nodes.map((evidence) => {
    if (evidence.kind === 'subject') return 0;
    if (evidence.kind === 'resolver') return 90;
    if (evidence.kind === 'record' || evidence.kind === 'authority') {
      const orbit = recordIndex % 2 === 0 ? 185 : 265;
      recordIndex += 1;
      return orbit;
    }
    return 305;
  });
  const orbitCounts = new Map<number, number>();
  for (const orbit of orbitAssignments)
    orbitCounts.set(orbit, (orbitCounts.get(orbit) ?? 0) + 1);
  const orbitIndices = new Map<number, number>();
  const nodes: LayoutNode[] = bundle.nodes.map((evidence, index) => {
    const orbitRadius = orbitAssignments[index] ?? 0;
    const orbitIndex = orbitIndices.get(orbitRadius) ?? 0;
    const orbitCount = orbitCounts.get(orbitRadius) ?? 1;
    orbitIndices.set(orbitRadius, orbitIndex + 1);
    const phase = orbitRadius === 265 || orbitRadius === 305 ? Math.PI / orbitCount : 0;
    const angle = (orbitIndex / orbitCount) * Math.PI * 2 - Math.PI / 2 + phase;
    return {
      evidence,
      id: evidence.id,
      orbitRadius,
      x: WIDTH / 2 + Math.cos(angle) * orbitRadius,
      y: HEIGHT / 2 + Math.sin(angle) * orbitRadius,
    };
  });
  const links: LayoutLink[] = bundle.links.map((link) => ({
    label: link.label,
    source: link.source,
    target: link.target,
  }));
  const simulation = forceSimulation(nodes)
    .randomSource(() => 0.5)
    .force(
      'link',
      forceLink<LayoutNode, LayoutLink>(links)
        .id((node) => node.id)
        .distance((link) =>
          link.label === 'answer' || link.label === 'authority' || link.label === 'additional'
            ? 245
            : 140,
        )
        .strength(0.2),
    )
    .force('charge', forceManyBody().strength(-280).distanceMax(360))
    .force(
      'collide',
      forceCollide<LayoutNode>()
        .radius((node) => nodeRadius(node.evidence) + 29)
        .strength(0.92),
    )
    .force(
      'orbit',
      forceRadial<LayoutNode>((node) => node.orbitRadius, WIDTH / 2, HEIGHT / 2).strength(
        (node) => (node.evidence.kind === 'subject' ? 1 : 0.94),
      ),
    )
    .force('centre', forceCenter(WIDTH / 2, HEIGHT / 2))
    .stop();
  for (let tick = 0; tick < 320; tick += 1) simulation.tick();
  for (const node of nodes) {
    const radius = nodeRadius(node.evidence);
    node.x = Math.max(radius + 12, Math.min(WIDTH - radius - 12, node.x ?? WIDTH / 2));
    node.y = Math.max(radius + 12, Math.min(HEIGHT - radius - 12, node.y ?? HEIGHT / 2));
  }
  return { links, nodes };
}

function endpoint(value: string | number | LayoutNode): LayoutNode | null {
  return typeof value === 'object' ? value : null;
}

function defaultView(svg: SVGSVGElement) {
  if (svg.clientWidth >= 640) return zoomIdentity;
  const scale = 1.65;
  return zoomIdentity
    .translate(WIDTH / 2, HEIGHT / 2)
    .scale(scale)
    .translate(-WIDTH / 2, -HEIGHT / 2);
}

export function EvidenceGraph({ bundle }: { readonly bundle: EvidenceBundle }) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const viewportRef = useRef<SVGGElement | null>(null);
  const zoomRef = useRef<ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const [selectedId, setSelectedId] = useState(bundle.nodes[0]?.id ?? '');
  const graph = useMemo(() => layout(bundle), [bundle]);
  const selected = bundle.nodes.find((node) => node.id === selectedId) ?? bundle.nodes[0];

  useEffect(() => {
    const svg = svgRef.current;
    const viewport = viewportRef.current;
    if (svg === null || viewport === null) return;
    const behaviour = zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.45, 3.2])
      .on('zoom', (event: D3ZoomEvent<SVGSVGElement, unknown>) => {
        select(viewport).attr('transform', event.transform.toString());
      });
    zoomRef.current = behaviour;
    const selection = select(svg);
    selection.call(behaviour);
    behaviour.transform(selection, defaultView(svg));
    return () => {
      select(svg).on('.zoom', null);
      zoomRef.current = null;
    };
  }, [graph]);

  useEffect(() => {
    const svg = svgRef.current;
    if (svg === null) return;
    const links = select(svg)
      .selectAll<SVGLineElement, LayoutLink>('.evidence-links line')
      .data(graph.links);
    const redrawLinks = () => {
      links
        .attr('x1', (link) => endpoint(link.source)?.x ?? 0)
        .attr('y1', (link) => endpoint(link.source)?.y ?? 0)
        .attr('x2', (link) => endpoint(link.target)?.x ?? 0)
        .attr('y2', (link) => endpoint(link.target)?.y ?? 0);
    };
    const nodes = select(svg).selectAll<SVGGElement, LayoutNode>('.evidence-node');
    nodes.call(
      drag<SVGGElement, LayoutNode>()
        .on('start', function () {
          select(this).classed('is-dragging', true);
        })
        .on('drag', function (event: D3DragEvent<SVGGElement, LayoutNode, LayoutNode>, node) {
          node.x = Math.max(18, Math.min(WIDTH - 18, event.x));
          node.y = Math.max(18, Math.min(HEIGHT - 18, event.y));
          select(this).attr('transform', `translate(${String(node.x)},${String(node.y)})`);
          redrawLinks();
        })
        .on('end', function () {
          select(this).classed('is-dragging', false);
        }),
    );
  }, [graph]);

  function resetView(): void {
    const svg = svgRef.current;
    const behaviour = zoomRef.current;
    if (svg !== null && behaviour !== null) {
      const selection = select(svg);
      behaviour.transform(selection, defaultView(svg));
    }
  }

  return (
    <div className="evidence-graph-shell">
      <div className="graph-toolbar">
        <p>
          Drag nodes to tease strands apart. Scroll or pinch to zoom; drag empty space to move
          the map.
        </p>
        <button className="quiet-button" type="button" onClick={resetView}>
          Reset view
        </button>
      </div>
      <div className="evidence-graph-frame">
        <svg
          aria-labelledby="evidence-graph-title evidence-graph-description"
          className="evidence-graph"
          ref={svgRef}
          role="group"
          viewBox={`0 0 ${String(WIDTH)} ${String(HEIGHT)}`}
        >
          <title id="evidence-graph-title">Evidence relationships for {bundle.subject}</title>
          <desc id="evidence-graph-description">
            An interactive graph backed by the complete accessible evidence table below.
          </desc>
          <defs>
            <marker
              id="evidence-arrow"
              markerHeight="7"
              markerWidth="7"
              orient="auto"
              refX="24"
              refY="3.5"
            >
              <path d="M0,0 L7,3.5 L0,7 Z" />
            </marker>
          </defs>
          <g ref={viewportRef}>
            <g className="evidence-links" aria-hidden="true">
              {graph.links.map((link, index) => {
                const source = endpoint(link.source);
                const target = endpoint(link.target);
                return source === null || target === null ? null : (
                  <line
                    key={`${source.id}-${target.id}-${String(index)}`}
                    x1={source.x}
                    y1={source.y}
                    x2={target.x}
                    y2={target.y}
                  />
                );
              })}
            </g>
            <g className="evidence-nodes">
              {graph.nodes.map((node) => (
                <g
                  aria-label={`${node.evidence.kind}: ${node.evidence.label}`}
                  aria-pressed={selected?.id === node.id}
                  className={`evidence-node evidence-node-${node.evidence.kind}${selected?.id === node.id ? ' is-selected' : ''}`}
                  key={node.id}
                  onClick={() => setSelectedId(node.id)}
                  onKeyDown={(event) => {
                    if (event.key !== 'Enter' && event.key !== ' ') return;
                    event.preventDefault();
                    setSelectedId(node.id);
                  }}
                  role="button"
                  tabIndex={0}
                  transform={`translate(${String(node.x)},${String(node.y)})`}
                >
                  <title>{node.evidence.label}</title>
                  <circle r={nodeRadius(node.evidence)} />
                  <text dy={nodeRadius(node.evidence) + 16} textAnchor="middle">
                    {graphLabel(node.evidence)}
                  </text>
                </g>
              ))}
            </g>
          </g>
        </svg>
      </div>
      <ul className="graph-legend" aria-label="Evidence graph legend">
        {(['subject', 'record', 'target', 'resolver', 'authority', 'uncertainty'] as const).map(
          (kind) => (
            <li key={kind}>
              <span className={`legend-dot evidence-node-${kind}`} aria-hidden="true" />
              {kind}
            </li>
          ),
        )}
      </ul>
      {selected === undefined ? null : (
        <article className="graph-selection" aria-live="polite">
          <p className="eyebrow">Selected strand</p>
          <h3>{selected.label}</h3>
          <p>{selected.detail}</p>
          <dl className="metadata-grid">
            <div>
              <dt>Kind</dt>
              <dd>{selected.kind}</dd>
            </div>
            <div>
              <dt>State</dt>
              <dd>{selected.status}</dd>
            </div>
            <div>
              <dt>Source</dt>
              <dd>{selected.source ?? 'Local interpretation'}</dd>
            </div>
            <div>
              <dt>TTL</dt>
              <dd>
                {selected.ttlSeconds === undefined
                  ? 'Not applicable'
                  : `${String(selected.ttlSeconds)} seconds`}
              </dd>
            </div>
          </dl>
          {selected.uncertainty === undefined ? null : (
            <p className="detail-note">{selected.uncertainty}</p>
          )}
        </article>
      )}
      <details className="graph-data-fallback">
        <summary>
          Accessible evidence tables ({bundle.nodes.length} nodes, {bundle.links.length}{' '}
          relationships)
        </summary>
        <h3>Evidence nodes</h3>
        <div
          className="table-scroll"
          tabIndex={0}
          role="region"
          aria-label="Evidence graph data"
        >
          <table>
            <thead>
              <tr>
                <th>Kind</th>
                <th>Label</th>
                <th>State</th>
                <th>Source</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {bundle.nodes.map((node) => (
                <tr key={node.id}>
                  <td>{node.kind}</td>
                  <td>
                    <bdi className="technical-value" dir="ltr">
                      {node.label}
                    </bdi>
                  </td>
                  <td>{node.status}</td>
                  <td>{node.source ?? 'Local interpretation'}</td>
                  <td>{node.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <h3>Evidence relationships</h3>
        <div
          className="table-scroll"
          tabIndex={0}
          role="region"
          aria-label="Evidence graph relationships"
        >
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Relationship</th>
                <th>Target</th>
                <th>Label</th>
              </tr>
            </thead>
            <tbody>
              {bundle.links.map((link, index) => (
                <tr key={`${link.source}-${link.target}-${link.kind}-${String(index)}`}>
                  <td>
                    {bundle.nodes.find((node) => node.id === link.source)?.label ?? link.source}
                  </td>
                  <td>{link.kind}</td>
                  <td>
                    {bundle.nodes.find((node) => node.id === link.target)?.label ?? link.target}
                  </td>
                  <td>{link.label}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
