import type { AssetTimelineEvent } from "../../api";
import { InfoTip } from "../InfoTip";
import {
  emptyStateStyle,
  fmtUnix,
  panelHeaderStyle,
  panelStyle,
  panelTitleStyle,
} from "./panelStyles";

interface Props {
  events: AssetTimelineEvent[];
}

function kindColor(kind: string): string {
  switch (kind) {
    case "finding":
      return "var(--danger)";
    case "exchange":
      return "var(--accent)";
    case "probe":
      return "var(--accent-2)";
    case "recon":
      return "var(--success)";
    case "scan":
      return "var(--warning)";
    default:
      return "var(--muted)";
  }
}

function kindLabel(kind: string): string {
  switch (kind) {
    case "finding":
      return "FIND";
    case "exchange":
      return "EXCH";
    case "probe":
      return "PROBE";
    case "recon":
      return "RECON";
    case "scan":
      return "SCAN";
    default:
      return kind.toUpperCase().slice(0, 5);
  }
}

export function TimelinePanel({ events }: Props) {
  return (
    <section style={panelStyle}>
      <header style={panelHeaderStyle}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          <h3 style={panelTitleStyle}>Timeline</h3>
          <InfoTip label="What is the Timeline panel?">
            <p>
              <strong>Everything that happened to this asset, in order.</strong>{" "}
              Probe runs, proxy exchanges, findings, recon discoveries,
              and scan rows interleaved by timestamp — newest first.
            </p>
            <p>
              <strong>Color key:</strong>{" "}
              <span style={{ color: "var(--danger)" }}>FIND</span> findings ·{" "}
              <span style={{ color: "var(--accent)" }}>EXCH</span> proxy
              exchanges ·{" "}
              <span style={{ color: "var(--accent-2)" }}>PROBE</span> probe
              runs ·{" "}
              <span style={{ color: "var(--success)" }}>RECON</span> DNS
              discoveries ·{" "}
              <span style={{ color: "var(--warning)" }}>SCAN</span> web
              scans.
            </p>
            <p>
              Useful for "what changed since last week?" and tracing a
              finding back to the request that produced it.
            </p>
          </InfoTip>
        </span>
        <span style={{ color: "var(--muted)", fontSize: "0.82em" }}>
          last {events.length}
        </span>
      </header>
      {events.length === 0 ? (
        <div style={emptyStateStyle}>No activity recorded for this asset.</div>
      ) : (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 6,
            maxHeight: 360,
            overflowY: "auto",
          }}
        >
          {events.slice(0, 200).map((e, i) => (
            <div
              key={`${e.ts_unix}-${i}`}
              style={{
                display: "grid",
                gridTemplateColumns: "70px 60px 1fr",
                gap: 8,
                padding: "6px 8px",
                borderLeft: `3px solid ${kindColor(e.kind)}`,
                borderRadius: 4,
                background: "var(--panel-alt)",
                alignItems: "baseline",
              }}
            >
              <span
                style={{
                  fontSize: "0.7em",
                  fontWeight: 700,
                  color: kindColor(e.kind),
                  fontFamily: "var(--mono)",
                  letterSpacing: 0.5,
                }}
              >
                {kindLabel(e.kind)}
              </span>
              <span
                style={{
                  fontSize: "0.78em",
                  color: "var(--muted)",
                  fontFamily: "var(--mono)",
                  whiteSpace: "nowrap",
                }}
                title={fmtUnix(e.ts_unix)}
              >
                {new Date(e.ts_unix * 1000).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                })}
              </span>
              <span
                style={{
                  fontSize: "0.85em",
                  fontFamily: "var(--mono)",
                  wordBreak: "break-word",
                }}
              >
                {e.summary}
              </span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
