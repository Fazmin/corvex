import { useMemo } from "react";
import type { FindingPayload, SeverityLevel } from "../api";

const SEVERITY_COLORS: Record<SeverityLevel, string> = {
  CRITICAL: "#e53935",
  HIGH: "#fb8c00",
  MEDIUM: "#fdd835",
  LOW: "#42a5f5",
  INFO: "#78909c",
};

const ORDER: SeverityLevel[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

interface Props {
  findings: FindingPayload[];
}

export function SeverityBreakdown({ findings }: Props) {
  const counts = useMemo(() => {
    const m: Record<SeverityLevel, number> = {
      CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
    };
    for (const f of findings) m[f.severity] = (m[f.severity] ?? 0) + 1;
    return m;
  }, [findings]);

  const total = findings.length;
  const empty = total === 0;

  return (
    <div className="panel severity-breakdown">
      <div className="severity-breakdown-header">
        <span className="label">Severity mix</span>
        <span className="muted">{total} finding{total === 1 ? "" : "s"}</span>
      </div>
      <div className="severity-bar" role="img" aria-label="Severity distribution">
        {empty ? (
          <div className="severity-bar-empty">No findings yet</div>
        ) : (
          ORDER.map((s) => {
            const n = counts[s];
            if (n === 0) return null;
            const pct = (n / total) * 100;
            return (
              <div
                key={s}
                className="severity-bar-segment"
                style={{
                  width: `${pct}%`,
                  backgroundColor: SEVERITY_COLORS[s],
                  color: s === "MEDIUM" ? "#333" : "#fff",
                }}
                title={`${s}: ${n} (${pct.toFixed(1)}%)`}
              >
                {pct >= 8 ? `${s[0]} ${n}` : ""}
              </div>
            );
          })
        )}
      </div>
      <div className="severity-legend">
        {ORDER.map((s) => (
          <span key={s} className="severity-legend-item">
            <span
              className="dot"
              style={{ backgroundColor: SEVERITY_COLORS[s] }}
              aria-hidden
            />
            {s} <strong>{counts[s]}</strong>
          </span>
        ))}
      </div>
    </div>
  );
}
