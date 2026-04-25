import type { AssetTech } from "../../api";
import {
  emptyStateStyle,
  monoChipStyle,
  panelHeaderStyle,
  panelStyle,
  panelTitleStyle,
} from "./panelStyles";

interface Props {
  techs: AssetTech[];
}

// One chip per (technology, version) pair. Chips are colour-keyed by
// the first listed Wappalyzer category — matching the convention used
// in the Traffic view stack tags so muscle memory carries over.
export function StackPanel({ techs }: Props) {
  return (
    <section style={panelStyle}>
      <header style={panelHeaderStyle}>
        <h3 style={panelTitleStyle}>Stack</h3>
        <span style={{ color: "var(--muted)", fontSize: "0.82em" }}>
          {techs.length} technolog{techs.length === 1 ? "y" : "ies"}
        </span>
      </header>
      {techs.length === 0 ? (
        <div style={emptyStateStyle}>
          No stack fingerprints yet. The Stack Fingerprint check runs on
          every captured proxy exchange — browse the host through the
          proxy to populate this panel.
        </div>
      ) : (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          {techs.map((t, i) => (
            <span
              key={`${t.name}-${t.version ?? ""}-${i}`}
              style={{
                ...monoChipStyle,
                background: "var(--accent-soft)",
                borderColor: "var(--accent-border)",
                color: "var(--fg)",
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
              }}
              title={
                t.categories.length > 0
                  ? `Categories: ${t.categories.join(", ")} · seen on ${t.observed_on_paths.length} path${
                      t.observed_on_paths.length === 1 ? "" : "s"
                    }`
                  : `Seen on ${t.observed_on_paths.length} path${
                      t.observed_on_paths.length === 1 ? "" : "s"
                    }`
              }
            >
              <strong style={{ color: "var(--accent)" }}>{t.name}</strong>
              {t.version && (
                <span style={{ color: "var(--muted-strong)" }}>{t.version}</span>
              )}
              {t.categories.length > 0 && (
                <span
                  style={{
                    color: "var(--muted)",
                    fontSize: "0.8em",
                    paddingLeft: 6,
                    borderLeft: "1px solid var(--border)",
                  }}
                >
                  {t.categories[0]}
                </span>
              )}
            </span>
          ))}
        </div>
      )}
    </section>
  );
}
