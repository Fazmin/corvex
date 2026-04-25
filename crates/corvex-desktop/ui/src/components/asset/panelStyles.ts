// Shared style atoms for the asset detail panels. Keeps the panels
// visually coherent without inventing a new CSS file — every panel uses
// the same surface, header treatment, and table cell rhythm.

import type { CSSProperties } from "react";

export const panelStyle: CSSProperties = {
  background: "var(--panel)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  padding: "16px 18px",
  boxShadow: "var(--shadow)",
  display: "flex",
  flexDirection: "column",
  gap: 12,
  minHeight: 140,
};

export const panelHeaderStyle: CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 10,
};

export const panelTitleStyle: CSSProperties = {
  margin: 0,
  fontSize: "0.92em",
  fontWeight: 600,
  textTransform: "uppercase",
  letterSpacing: 0.6,
  color: "var(--muted-strong)",
};

export const tableStyle: CSSProperties = {
  width: "100%",
  borderCollapse: "collapse",
  fontSize: "0.92em",
};

export const tableHeadCell: CSSProperties = {
  textAlign: "left",
  padding: "6px 8px",
  fontWeight: 500,
  color: "var(--muted)",
  borderBottom: "1px solid var(--border)",
  fontSize: "0.82em",
  textTransform: "uppercase",
  letterSpacing: 0.4,
};

export const tableCell: CSSProperties = {
  padding: "8px",
  borderBottom: "1px solid var(--border-soft)",
  fontFamily: "var(--mono)",
  verticalAlign: "top",
};

export const monoChipStyle: CSSProperties = {
  display: "inline-block",
  padding: "2px 8px",
  borderRadius: 6,
  background: "var(--panel-alt)",
  border: "1px solid var(--border)",
  fontFamily: "var(--mono)",
  fontSize: "0.85em",
  color: "var(--fg)",
};

export const accentChipStyle: CSSProperties = {
  ...monoChipStyle,
  background: "var(--accent-soft)",
  borderColor: "var(--accent-border)",
  color: "var(--accent)",
};

export const emptyStateStyle: CSSProperties = {
  color: "var(--muted)",
  fontSize: "0.9em",
  padding: "12px 0",
};

export function severityColor(sev: string): string {
  const s = sev.toUpperCase();
  if (s === "CRITICAL") return "var(--danger)";
  if (s === "HIGH") return "var(--danger)";
  if (s === "MEDIUM") return "var(--warning)";
  if (s === "LOW") return "var(--accent-2)";
  if (s === "INFO") return "var(--muted)";
  return "var(--muted)";
}

export function fmtUnix(ts: number | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleString();
}

export function fmtRelative(ts: number | null | undefined): string {
  if (!ts) return "—";
  const now = Date.now() / 1000;
  const delta = Math.max(0, now - ts);
  if (delta < 60) return `${Math.round(delta)}s ago`;
  if (delta < 3600) return `${Math.round(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.round(delta / 3600)}h ago`;
  return `${Math.round(delta / 86400)}d ago`;
}
