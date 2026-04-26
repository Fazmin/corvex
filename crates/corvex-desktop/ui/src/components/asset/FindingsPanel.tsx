import { useState } from "react";
import type { AssetFinding } from "../../api";
import { InfoTip } from "../InfoTip";
import {
  emptyStateStyle,
  fmtRelative,
  panelHeaderStyle,
  panelStyle,
  panelTitleStyle,
  severityColor,
  tableCell,
  tableHeadCell,
  tableStyle,
} from "./panelStyles";

interface Props {
  findings: AssetFinding[];
  /** Span two grid columns when the parent uses an auto-fit panel grid. */
  wide?: boolean;
}

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
type SevFilter = "all" | (typeof SEVERITIES)[number];

export function FindingsPanel({ findings, wide = false }: Props) {
  const [sev, setSev] = useState<SevFilter>("all");
  const counts = SEVERITIES.reduce<Record<string, number>>((acc, s) => {
    acc[s] = findings.filter((f) => f.severity.toUpperCase() === s).length;
    return acc;
  }, {});
  const visible =
    sev === "all"
      ? findings
      : findings.filter((f) => f.severity.toUpperCase() === sev);

  return (
    <section style={{ ...panelStyle, ...(wide ? { gridColumn: "span 2" } : null) }}>
      <header style={panelHeaderStyle}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          <h3 style={panelTitleStyle}>Findings</h3>
          <InfoTip label="What is the Findings panel?">
            <p>
              <strong>Vulnerabilities tied to this asset</strong>,
              deduplicated across every engine (passive checks, active
              checks, SCA, banner-CVE, Nuclei templates).
            </p>
            <p>
              <strong>Dedup key:</strong> <code>(check_id, port, path)</code>.
              The <em>Count</em> column shows how many raw observations
              collapsed into the row — useful for spotting
              repeat-offender endpoints.
            </p>
            <p>
              Use the severity chips to filter. Sorted CRITICAL → INFO,
              then most recent first.
            </p>
          </InfoTip>
        </span>
        <span style={{ color: "var(--muted)", fontSize: "0.82em" }}>
          {findings.length} unique
        </span>
      </header>

      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        <FilterChip
          label={`All ${findings.length}`}
          active={sev === "all"}
          color="var(--accent)"
          onClick={() => setSev("all")}
        />
        {SEVERITIES.map((s) => (
          <FilterChip
            key={s}
            label={`${s} ${counts[s] ?? 0}`}
            active={sev === s}
            color={severityColor(s)}
            onClick={() => setSev(s)}
          />
        ))}
      </div>

      {visible.length === 0 ? (
        <div style={emptyStateStyle}>
          {findings.length === 0
            ? "No findings yet. Run passive checks (auto on every exchange) or active checks from Proxy → Checks."
            : "No findings at this severity."}
        </div>
      ) : (
        <div style={{ overflowX: "auto", overflowY: "auto", maxHeight: 360 }}>
          <table style={tableStyle}>
            <thead
              style={{
                position: "sticky",
                top: 0,
                background: "var(--panel)",
                zIndex: 1,
              }}
            >
              <tr>
                <th style={tableHeadCell}>Severity</th>
                <th style={tableHeadCell}>Title</th>
                <th style={tableHeadCell}>Path</th>
                <th style={{ ...tableHeadCell, textAlign: "right" }}>Count</th>
                <th style={tableHeadCell}>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {visible.slice(0, 300).map((f) => (
                <tr key={`${f.check_id}-${f.example_path}-${f.port}`}>
                  <td style={tableCell}>
                    <span
                      style={{
                        color: severityColor(f.severity),
                        fontWeight: 600,
                      }}
                    >
                      {f.severity.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ ...tableCell, fontFamily: "var(--sans)" }}>
                    {f.title}
                    <div
                      style={{
                        color: "var(--muted)",
                        fontSize: "0.78em",
                        marginTop: 2,
                      }}
                    >
                      {f.check_id}
                    </div>
                  </td>
                  <td style={{ ...tableCell, wordBreak: "break-all" }}>
                    <span style={{ color: "var(--muted)" }}>:{f.port}</span>
                    {f.example_path}
                  </td>
                  <td
                    style={{
                      ...tableCell,
                      textAlign: "right",
                      color: "var(--fg-strong)",
                    }}
                  >
                    {f.occurrence_count}
                  </td>
                  <td style={{ ...tableCell, color: "var(--muted)" }}>
                    {fmtRelative(f.last_seen_unix)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function FilterChip({
  label,
  active,
  color,
  onClick,
}: {
  label: string;
  active: boolean;
  color: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        padding: "3px 10px",
        borderRadius: 999,
        border: `1px solid ${active ? color : "var(--border)"}`,
        background: active ? "var(--accent-soft)" : "transparent",
        color: active ? color : "var(--muted)",
        fontSize: "0.8em",
        cursor: "pointer",
        fontFamily: "var(--mono)",
      }}
    >
      {label}
    </button>
  );
}
