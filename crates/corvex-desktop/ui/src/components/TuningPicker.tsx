import { useMemo } from "react";
import { InfoTip } from "./InfoTip";

// Engine-facing category codes. The legacy Nikto convention is
// 0–9 + a–f; users see them as the named labels below, never the
// raw codes. The order in this array drives the rendered layout.
const CATEGORIES: {
  code: string;
  label: string;
  hint: string;
  /** Marked unsafe → shown with a ⚠ glyph and skipped by the
   *  "Safe (skip DoS)" preset. */
  unsafe?: boolean;
}[] = [
  { code: "0", label: "File upload",        hint: "Tests for unrestricted file-upload endpoints." },
  { code: "1", label: "Interesting files",  hint: "Leftover or suspicious files commonly seen in logs." },
  { code: "2", label: "Misconfig / default", hint: "Default installs, sample content, exposed admin endpoints." },
  { code: "3", label: "Info disclosure",    hint: "Sensitive data leaked through headers, errors, or debug pages." },
  { code: "4", label: "XSS / injection",    hint: "Cross-site scripting / HTML injection probes." },
  { code: "5", label: "Web-root RFR",       hint: "Remote file retrieval rooted inside the web root." },
  { code: "6", label: "DoS",                hint: "Tests that may cause denial of service — use with caution.", unsafe: true },
  { code: "7", label: "Server-wide RFR",    hint: "Traversal / LFI tests outside the web root." },
  { code: "8", label: "Command exec",       hint: "Remote command execution / shell payloads." },
  { code: "9", label: "SQL injection",      hint: "SQLi probes against known parameters." },
  { code: "a", label: "Auth bypass",        hint: "Unauthenticated access to protected resources." },
  { code: "b", label: "Software ID",        hint: "Fingerprinting of server / framework versions." },
  { code: "c", label: "Remote source inclusion", hint: "Remote source-inclusion vectors." },
  { code: "d", label: "Web services",       hint: "SOAP / WSDL / REST-service specific checks." },
  { code: "e", label: "Admin consoles",     hint: "Exposed administrative consoles and dashboards." },
  { code: "f", label: "XML injection",      hint: "XML parsing / external-entity injection vectors." },
];

const ALL_CODES = CATEGORIES.map((c) => c.code);

interface Props {
  value: string;
  onChange: (next: string) => void;
}

/**
 * Parse a tuning string into a per-category enabled/disabled map.
 * Mirrors the engine's `TuningFilter::parse` + `allows` logic so a
 * round-trip through this component yields the same effective filter.
 *
 * Rules (from `crates/corvex-core/src/tuning.rs`):
 *   - empty string                  → all categories enabled.
 *   - chars before any `x`          → include set (only these enabled).
 *   - chars after first `x`         → exclude set (always disabled).
 *   - if include is non-empty, a category is enabled iff it's in the
 *     include set AND not in the exclude set.
 *   - if include is empty, a category is enabled iff it's not in the
 *     exclude set.
 */
function parseTuning(value: string): { include: string[] | null; exclude: string[] } {
  let include: string[] | null = null;
  const exclude: string[] = [];
  let inverted = false;
  for (const ch of value) {
    if (ch === "x" || ch === "X") {
      inverted = true;
      continue;
    }
    if (inverted) {
      exclude.push(ch);
    } else {
      if (include === null) include = [];
      include.push(ch);
    }
  }
  return { include, exclude };
}

function buildEnabledMap(value: string): Record<string, boolean> {
  const { include, exclude } = parseTuning(value);
  const out: Record<string, boolean> = {};
  for (const code of ALL_CODES) {
    if (include === null) {
      out[code] = !exclude.includes(code);
    } else {
      out[code] = include.includes(code) && !exclude.includes(code);
    }
  }
  return out;
}

/**
 * Pick the shortest engine-equivalent string for a given enabled map.
 * Same engine behaviour either way; we prefer the shorter form so
 * saved presets and history rows stay readable.
 */
function deriveValue(enabled: Record<string, boolean>): string {
  const ticked = ALL_CODES.filter((c) => enabled[c]);
  const unticked = ALL_CODES.filter((c) => !enabled[c]);
  if (unticked.length === 0) return "";
  if (ticked.length === 0) return "x" + ALL_CODES.join("");
  return unticked.length <= ticked.length
    ? "x" + unticked.join("")
    : ticked.join("");
}

export function TuningPicker({ value, onChange }: Props) {
  const enabled = useMemo(() => buildEnabledMap(value), [value]);
  const enabledCount = ALL_CODES.filter((c) => enabled[c]).length;
  const disabledCount = ALL_CODES.length - enabledCount;

  const setEnabled = (next: Record<string, boolean>) => {
    onChange(deriveValue(next));
  };

  const toggle = (code: string) => {
    setEnabled({ ...enabled, [code]: !enabled[code] });
  };

  const presetAll = () => {
    const next: Record<string, boolean> = {};
    for (const c of ALL_CODES) next[c] = true;
    setEnabled(next);
  };

  const presetSafe = () => {
    const next: Record<string, boolean> = {};
    for (const c of ALL_CODES) next[c] = !CATEGORIES.find((x) => x.code === c)?.unsafe;
    setEnabled(next);
  };

  // Status line — translate the current selection into plain English.
  const labelFor = (code: string) =>
    CATEGORIES.find((c) => c.code === code)?.label ?? code;
  const labelList = (codes: string[], cap = 3) => {
    if (codes.length <= cap) return codes.map(labelFor).join(", ");
    const head = codes.slice(0, cap).map(labelFor).join(", ");
    return `${head}, +${codes.length - cap} more`;
  };
  let statusText: string;
  let statusTooltip = "";
  let statusVariant: "default" | "warn" = "default";

  if (disabledCount === 0) {
    statusText = "Running every check category.";
  } else if (enabledCount === 0) {
    statusText = "All categories disabled — no checks will run.";
    statusVariant = "warn";
  } else if (enabledCount >= disabledCount) {
    const skipped = ALL_CODES.filter((c) => !enabled[c]);
    statusText = `Skipping: ${labelList(skipped)}.`;
    statusTooltip = skipped.map(labelFor).join(", ");
  } else {
    const only = ALL_CODES.filter((c) => enabled[c]);
    statusText = `Running only: ${labelList(only)}.`;
    statusTooltip = only.map(labelFor).join(", ");
  }

  return (
    <div className="field">
      <div className="label-row">
        <label>Check categories</label>
        <InfoTip label="Check-category help">
          <strong>What categories of checks should run?</strong>
          Each box below is a family of vulnerability checks (file
          upload, info disclosure, XSS, SQL injection, DoS, …). Every
          box is ticked by default — untick one to skip that
          category. The <em>Safe (skip DoS)</em> preset turns off
          the one category that can crash a target.
          <dl style={{ marginTop: 6 }}>
            {CATEGORIES.map((c) => (
              <span key={c.code} style={{ display: "contents" }}>
                <dt>{c.label}{c.unsafe ? " ⚠" : ""}</dt>
                <dd>{c.hint}</dd>
              </span>
            ))}
          </dl>
        </InfoTip>
      </div>

      <div
        className={`tuning-status${statusVariant === "warn" ? " tuning-status-warn" : ""}`}
        title={statusTooltip || undefined}
      >
        {statusText}
      </div>

      <div className="tuning-toolbar">
        <button
          type="button"
          className="ghost-btn tuning-preset-btn"
          onClick={presetAll}
          title="Tick every category."
        >
          All
        </button>
        <button
          type="button"
          className="ghost-btn tuning-preset-btn"
          onClick={presetSafe}
          title="Tick everything except DoS — the one category that can crash a target."
        >
          Safe (skip DoS)
        </button>
        <span className="tuning-count">
          {enabledCount}/{ALL_CODES.length} enabled
        </span>
      </div>

      <div className="tuning-grid">
        {CATEGORIES.map((c) => {
          const checked = enabled[c.code];
          return (
            <label
              key={c.code}
              className={`tuning-cat${c.unsafe ? " tuning-cat-warn" : ""}${checked ? " tuning-cat-on" : ""}`}
              title={c.hint}
            >
              <input
                type="checkbox"
                checked={checked}
                onChange={() => toggle(c.code)}
              />
              <span className="tuning-cat-label">
                {c.unsafe && <span aria-hidden className="tuning-cat-warn-icon">⚠</span>}
                {c.label}
              </span>
            </label>
          );
        })}
      </div>
    </div>
  );
}
