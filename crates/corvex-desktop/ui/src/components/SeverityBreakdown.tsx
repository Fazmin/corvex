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

export type SeverityFilter = "all" | SeverityLevel;

interface Props {
  findings: FindingPayload[];
  /** Currently selected severity filter. `all` means no filter. */
  value?: SeverityFilter;
  /** Clicking a chip invokes this with the chosen filter. Clicking an
   *  already-active chip invokes it with `"all"` to clear. */
  onChange?: (f: SeverityFilter) => void;
}

/**
 * Minimal severity strip that doubles as the severity filter control.
 * Each chip is a clickable toggle: click an inactive chip to filter by
 * that severity; click the active chip (or "All") to clear.
 */
export function SeverityBreakdown({ findings, value = "all", onChange }: Props) {
  const counts = useMemo(() => {
    const m: Record<SeverityLevel, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    for (const f of findings) m[f.severity] = (m[f.severity] ?? 0) + 1;
    return m;
  }, [findings]);

  const clickable = Boolean(onChange);

  const handle = (next: SeverityFilter) => {
    if (!onChange) return;
    onChange(value === next ? "all" : next);
  };

  return (
    <div
      className={`severity-strip${clickable ? " is-filter" : ""}`}
      role={clickable ? "toolbar" : "group"}
      aria-label="Severity mix"
    >
      {clickable && (
        <button
          type="button"
          className={`severity-strip-chip severity-strip-all${
            value === "all" ? " active" : ""
          }`}
          onClick={() => onChange!("all")}
          title="Show all severities"
          aria-pressed={value === "all"}
        >
          All
        </button>
      )}
      {ORDER.map((s) => {
        const active = value === s;
        const chipClass = `severity-strip-chip${active ? " active" : ""}`;
        const activeStyle = active
          ? {
              backgroundColor: SEVERITY_COLORS[s],
              borderColor: SEVERITY_COLORS[s],
              color: s === "MEDIUM" ? "#333" : "#fff",
            }
          : undefined;

        if (clickable) {
          return (
            <button
              key={s}
              type="button"
              className={chipClass}
              onClick={() => handle(s)}
              title={`${active ? "Clear filter" : "Filter by"} ${s.toLowerCase()}`}
              aria-pressed={active}
              style={activeStyle}
            >
              <span
                className="severity-strip-dot"
                style={{
                  backgroundColor: active ? "transparent" : SEVERITY_COLORS[s],
                  borderColor: active
                    ? "rgba(255,255,255,0.7)"
                    : SEVERITY_COLORS[s],
                }}
                aria-hidden
              />
              <span className="severity-strip-label">{s}</span>
              <strong className="severity-strip-count">{counts[s]}</strong>
            </button>
          );
        }
        return (
          <span
            key={s}
            className={chipClass}
            title={`${s}: ${counts[s]}`}
          >
            <span
              className="severity-strip-dot"
              style={{ backgroundColor: SEVERITY_COLORS[s] }}
              aria-hidden
            />
            <span className="severity-strip-label">{s}</span>
            <strong className="severity-strip-count">{counts[s]}</strong>
          </span>
        );
      })}
    </div>
  );
}
