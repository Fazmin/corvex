import { useMemo } from "react";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import type {
  AssetEndpoint,
  AssetFinding,
  AssetOverview,
  AssetRelated,
  AssetService,
  AssetTech,
} from "../../api";
import { useAssetNav } from "../../asset_nav";
import { severityColor } from "./panelStyles";

interface Props {
  overview: AssetOverview;
  services: AssetService[];
  techs: AssetTech[];
  endpoints: AssetEndpoint[];
  findings: AssetFinding[];
  related: AssetRelated;
}

// Maximum nodes per ring — anything above gets folded into a "+ N more"
// node that links to the corresponding panel. Keeps the graph readable
// on a 1280-wide window without horizontal scroll on the default zoom.
const NODE_CAP_PER_RING = 12;

// Radial layout for the ecosystem. Center node = the asset; rings
// radiate outward by entity kind. Coordinates are deterministic — no
// force simulation in v1, easier to demo and reason about.
export function AssetGraph({
  overview,
  services,
  techs,
  endpoints,
  findings,
  related,
}: Props) {
  const { open } = useAssetNav();

  const { nodes, edges } = useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];

    nodes.push({
      id: "host:center",
      position: { x: 0, y: 0 },
      data: {
        label: (
          <div style={{ textAlign: "center" }}>
            <div style={{ fontWeight: 700 }}>{overview.host}</div>
            <div style={{ fontSize: "0.75em", color: "var(--muted)" }}>
              {overview.ips[0] ?? "no IP"}
            </div>
          </div>
        ),
      },
      style: {
        background: "var(--accent)",
        color: "var(--accent-fg)",
        border: "2px solid var(--accent-border)",
        borderRadius: 16,
        padding: 12,
        width: 220,
        boxShadow: "var(--shadow-strong)",
      },
    });

    placeRing({
      label: "Services",
      items: services.slice(0, NODE_CAP_PER_RING),
      ring: 220,
      angleStart: -Math.PI / 2,
      angleEnd: -Math.PI / 4,
      idFor: (s) => `svc:${s.port}`,
      nodeFor: (s) => ({
        label: (
          <div>
            <div style={{ fontWeight: 600 }}>:{s.port}</div>
            <div style={{ fontSize: "0.7em", color: "var(--muted)" }}>
              {s.product ?? s.service ?? "?"}
            </div>
          </div>
        ),
        bg: "var(--panel-alt)",
        border: "var(--border-strong)",
      }),
      onClick: undefined,
      overflow:
        services.length > NODE_CAP_PER_RING
          ? services.length - NODE_CAP_PER_RING
          : 0,
      nodes,
      edges,
    });

    placeRing({
      label: "Stack",
      items: techs.slice(0, NODE_CAP_PER_RING),
      ring: 220,
      angleStart: -Math.PI / 4,
      angleEnd: Math.PI / 4,
      idFor: (t) => `tech:${t.name}-${t.version ?? ""}`,
      nodeFor: (t) => ({
        label: (
          <div>
            <div style={{ fontWeight: 600 }}>{t.name}</div>
            {t.version && (
              <div style={{ fontSize: "0.7em", color: "var(--muted)" }}>
                {t.version}
              </div>
            )}
          </div>
        ),
        bg: "var(--accent-soft)",
        border: "var(--accent-border)",
      }),
      onClick: undefined,
      overflow:
        techs.length > NODE_CAP_PER_RING ? techs.length - NODE_CAP_PER_RING : 0,
      nodes,
      edges,
    });

    placeRing({
      label: "Endpoints",
      items: endpoints.slice(0, NODE_CAP_PER_RING),
      ring: 280,
      angleStart: Math.PI / 4,
      angleEnd: (3 * Math.PI) / 4,
      idFor: (e) => `ep:${e.port}-${e.method}-${e.path}`,
      nodeFor: (e) => ({
        label: (
          <div>
            <div style={{ fontWeight: 600 }}>
              {e.method}{" "}
              {e.path.length > 22 ? `${e.path.slice(0, 22)}…` : e.path}
            </div>
            <div style={{ fontSize: "0.7em", color: "var(--muted)" }}>
              {e.exchange_count} exch · {e.finding_count} find
            </div>
          </div>
        ),
        bg: "var(--panel)",
        border: "var(--border-strong)",
      }),
      onClick: undefined,
      overflow:
        endpoints.length > NODE_CAP_PER_RING
          ? endpoints.length - NODE_CAP_PER_RING
          : 0,
      nodes,
      edges,
    });

    placeRing({
      label: "Findings",
      items: findings.slice(0, NODE_CAP_PER_RING),
      ring: 280,
      angleStart: (3 * Math.PI) / 4,
      angleEnd: (5 * Math.PI) / 4,
      idFor: (f) =>
        `find:${f.check_id}-${f.example_path}-${f.port}`,
      nodeFor: (f) => ({
        label: (
          <div>
            <div style={{ fontWeight: 600 }}>{f.title}</div>
            <div style={{ fontSize: "0.7em", color: "var(--muted)" }}>
              {f.severity}
            </div>
          </div>
        ),
        bg: "var(--panel-alt)",
        border: severityColor(f.severity),
      }),
      onClick: undefined,
      overflow:
        findings.length > NODE_CAP_PER_RING
          ? findings.length - NODE_CAP_PER_RING
          : 0,
      nodes,
      edges,
    });

    const relatedHosts: { host: string; tag: string }[] = [
      ...related.same_jarm.map((r) => ({ host: r.host, tag: "JARM" })),
      ...related.same_root_domain.map((h) => ({ host: h, tag: "domain" })),
      ...related.same_cidr_24.map((h) => ({ host: h, tag: "/24" })),
    ].slice(0, NODE_CAP_PER_RING);
    placeRing({
      label: "Related",
      items: relatedHosts,
      ring: 320,
      angleStart: (5 * Math.PI) / 4,
      angleEnd: (7 * Math.PI) / 4,
      idFor: (r) => `host:${r.host}`,
      nodeFor: (r) => ({
        label: (
          <div>
            <div style={{ fontWeight: 600 }}>{r.host}</div>
            <div style={{ fontSize: "0.7em", color: "var(--muted)" }}>
              {r.tag}
            </div>
          </div>
        ),
        bg: "var(--accent-soft)",
        border: "var(--accent-border)",
      }),
      onClick: (r) => open({ host: r.host }),
      overflow: 0,
      nodes,
      edges,
    });

    return { nodes, edges };
  }, [overview, services, techs, endpoints, findings, related, open]);

  if (services.length === 0 && endpoints.length === 0 && findings.length === 0) {
    return (
      <div
        style={{
          height: 520,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "var(--muted)",
          background: "var(--panel)",
          border: "1px dashed var(--border)",
          borderRadius: "var(--radius)",
        }}
      >
        Probe this host or browse it through the proxy to populate the graph.
      </div>
    );
  }

  return (
    <div
      style={{
        height: 560,
        background: "var(--panel)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        overflow: "hidden",
      }}
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        nodesDraggable
        nodesConnectable={false}
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={20} color="var(--border)" />
        <MiniMap pannable zoomable nodeColor={() => "var(--accent)"} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

interface RingArgs<T> {
  label: string;
  items: T[];
  ring: number;
  angleStart: number;
  angleEnd: number;
  idFor: (item: T) => string;
  nodeFor: (item: T) => { label: React.ReactNode; bg: string; border: string };
  onClick?: ((item: T) => void) | undefined;
  overflow: number;
  nodes: Node[];
  edges: Edge[];
}

function placeRing<T>({
  label,
  items,
  ring,
  angleStart,
  angleEnd,
  idFor,
  nodeFor,
  onClick,
  overflow,
  nodes,
  edges,
}: RingArgs<T>) {
  if (items.length === 0 && overflow === 0) return;
  const span = angleEnd - angleStart;
  const step = items.length > 1 ? span / (items.length - 1) : 0;
  items.forEach((item, i) => {
    const angle =
      items.length === 1 ? (angleStart + angleEnd) / 2 : angleStart + step * i;
    const x = Math.cos(angle) * ring;
    const y = Math.sin(angle) * ring;
    const id = idFor(item);
    const n = nodeFor(item);
    nodes.push({
      id,
      position: { x, y },
      data: { label: n.label },
      style: {
        background: n.bg,
        border: `1px solid ${n.border}`,
        borderRadius: 10,
        padding: 8,
        minWidth: 130,
        cursor: onClick ? "pointer" : "default",
      },
      ...(onClick
        ? {
            // React-flow attaches the click via Node interactions; the
            // wrapper passes through to onClick when invoked.
          }
        : {}),
    });
    edges.push({
      id: `e-${id}`,
      source: "host:center",
      target: id,
      style: { stroke: "var(--border-strong)" },
    });
    if (onClick) {
      const lastIdx = nodes.length - 1;
      const node = nodes[lastIdx];
      // React-flow doesn't support onClick on the node spec directly in
      // its public types; we wrap the rendered label in a button-ish div.
      node.data = {
        label: (
          <div
            onClick={(ev: React.MouseEvent) => {
              ev.stopPropagation();
              onClick(item);
            }}
            role="button"
            style={{ width: "100%" }}
          >
            {n.label}
          </div>
        ),
      };
    }
  });
  if (overflow > 0) {
    const angle = (angleStart + angleEnd) / 2;
    const x = Math.cos(angle) * (ring + 60);
    const y = Math.sin(angle) * (ring + 60);
    const id = `more:${label}`;
    nodes.push({
      id,
      position: { x, y },
      data: {
        label: (
          <div style={{ fontSize: "0.75em" }}>
            +{overflow} more
            <div style={{ color: "var(--muted)", fontSize: "0.85em" }}>
              {label}
            </div>
          </div>
        ),
      },
      style: {
        background: "var(--panel)",
        border: "1px dashed var(--border-strong)",
        borderRadius: 999,
        padding: 6,
      },
    });
    edges.push({
      id: `e-${id}`,
      source: "host:center",
      target: id,
      animated: true,
      style: { stroke: "var(--border-strong)", strokeDasharray: "4 4" },
    });
  }
}
