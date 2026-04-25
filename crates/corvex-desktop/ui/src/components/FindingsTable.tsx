import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import type { FindingPayload, SeverityLevel } from "../api";
import { ExploitHits } from "./ExploitHits";
import { AssetLink } from "./asset/AssetLink";

type FilterMode = "all" | "signature" | "active" | "fingerprint";
type SeverityFilter = "all" | SeverityLevel;
type SourceFilter = "all" | "sca" | "web";

const FILTER_KEY = "corvexFindingsFilter";
const SEV_FILTER_KEY = "corvexFindingsSevFilter";
const QUERY_KEY = "corvexFindingsQuery";
const SOURCE_FILTER_KEY = "corvexFindingsSourceFilter";

function readStorage(key: string, fallback: string): string {
  try {
    return localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}

function writeStorage(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* quota / disabled */
  }
}

const CSV_COLUMNS: Array<keyof FindingPayload> = [
  "severity",
  "corvex_id",
  "method",
  "uri",
  "host",
  "port",
  "plugin",
  "cve",
  "cvss",
  "epss_score",
  "epss_percentile",
  "fix_version",
  "component",
  "component_version",
  "message",
  "refs",
];

function csvEscape(value: unknown): string {
  if (value === null || value === undefined) return "";
  const s = String(value);
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function toCsv(rows: FindingPayload[]): string {
  const header = CSV_COLUMNS.join(",");
  const body = rows
    .map((r) => CSV_COLUMNS.map((c) => csvEscape((r as unknown as Record<string, unknown>)[c])).join(","))
    .join("\r\n");
  return body ? `${header}\r\n${body}\r\n` : `${header}\r\n`;
}

function download(filename: string, mime: string, data: string) {
  const blob = new Blob([data], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Defer revoke so browsers reliably flush the download.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function timestamp(): string {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

const ACTIVE_PREFIXES = [
  "active:", "xss", "sqli", "lfi_active", "cmd_injection",
  "crlf", "open_redirect", "xxe", "ssti", "ssrf", "file_upload",
  "log4shell", "spring4shell", "cve_chain",
];
const FINGERPRINT_PREFIXES = ["fingerprint:", "cms", "tech", "subdomain_takeover"];

// Plugin names repeat heavily across findings (dozens of unique values,
// thousands of findings). Memoize the prefix scan so repeated lookups
// on filter/sort passes become O(1).
const classifyCache = new Map<string, "active" | "fingerprint" | "signature">();
function classify(plugin: string): "active" | "fingerprint" | "signature" {
  const hit = classifyCache.get(plugin);
  if (hit !== undefined) return hit;
  const lower = plugin.toLowerCase();
  let result: "active" | "fingerprint" | "signature";
  if (ACTIVE_PREFIXES.some((p) => lower.startsWith(p))) result = "active";
  else if (FINGERPRINT_PREFIXES.some((p) => lower.startsWith(p))) result = "fingerprint";
  else result = "signature";
  classifyCache.set(plugin, result);
  return result;
}

type Source = "sca" | "web";

// SCA findings always carry component metadata; every other plugin leaves
// it null. Plugin-name prefix is a secondary safety net for future SCA
// plugins that might not populate `component` immediately.
function source(finding: FindingPayload): Source {
  if (finding.component) return "sca";
  if (finding.plugin.toLowerCase().startsWith("sca")) return "sca";
  return "web";
}

const SOURCE_LABEL: Record<Source, string> = { sca: "SCA", web: "Web" };
const SOURCE_COLOR: Record<Source, string> = {
  sca: "#8e24aa",
  web: "#26a69a",
};

const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

const SEVERITY_COLORS: Record<SeverityLevel, string> = {
  CRITICAL: "#e53935",
  HIGH: "#fb8c00",
  MEDIUM: "#fdd835",
  LOW: "#42a5f5",
  INFO: "#78909c",
};

function SeverityBadge({ severity }: { severity: SeverityLevel }) {
  return (
    <span
      className="severity-badge"
      style={{
        backgroundColor: SEVERITY_COLORS[severity] ?? "#78909c",
        color: severity === "MEDIUM" ? "#333" : "#fff",
      }}
    >
      {severity}
    </span>
  );
}

interface Props {
  findings: FindingPayload[];
  /** Optionally control the severity filter from the outside. When
   *  provided, the table reads this value and calls `onSevFilterChange`
   *  on changes — useful so the minimal Severity strip can double as
   *  the severity filter without duplicating counts in a chip row. */
  sevFilter?: SeverityFilter;
  onSevFilterChange?: (f: SeverityFilter) => void;
  /** Hide the severity chip row. Set when the surrounding UI exposes
   *  its own severity filter control (e.g. the Dashboard's severity
   *  strip). Defaults to false for standalone embeddings like the
   *  Active Fuzzing view. */
  hideSeverityChips?: boolean;
}

export function FindingsTable({
  findings,
  sevFilter: externalSevFilter,
  onSevFilterChange,
  hideSeverityChips = false,
}: Props) {
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set());
  const [filter, setFilter] = useState<FilterMode>(
    () => (readStorage(FILTER_KEY, "all") as FilterMode),
  );
  const [internalSevFilter, setInternalSevFilter] = useState<SeverityFilter>(
    () => (readStorage(SEV_FILTER_KEY, "all") as SeverityFilter),
  );
  const sevFilter = externalSevFilter ?? internalSevFilter;
  const setSevFilter = (f: SeverityFilter) => {
    if (onSevFilterChange) onSevFilterChange(f);
    else setInternalSevFilter(f);
  };
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>(
    () => (readStorage(SOURCE_FILTER_KEY, "all") as SourceFilter),
  );
  const [query, setQuery] = useState(() => readStorage(QUERY_KEY, ""));
  // Deferred copy of `query` — the input stays responsive while the
  // filter pass runs at React's idle priority on large finding sets.
  const deferredQuery = useDeferredValue(query);

  useEffect(() => writeStorage(FILTER_KEY, filter), [filter]);
  useEffect(() => {
    // Only persist the filter value when the table owns it internally —
    // the external caller is responsible for its own persistence.
    if (externalSevFilter === undefined) {
      writeStorage(SEV_FILTER_KEY, internalSevFilter);
    }
  }, [internalSevFilter, externalSevFilter]);
  useEffect(() => writeStorage(SOURCE_FILTER_KEY, sourceFilter), [sourceFilter]);
  // Debounce the query write so fast typing doesn't thrash localStorage.
  // Chip filters write immediately — they fire rarely.
  const queryWriteTimer = useRef<number | null>(null);
  useEffect(() => {
    if (queryWriteTimer.current !== null) {
      window.clearTimeout(queryWriteTimer.current);
    }
    queryWriteTimer.current = window.setTimeout(() => {
      writeStorage(QUERY_KEY, query);
      queryWriteTimer.current = null;
    }, 300);
    return () => {
      if (queryWriteTimer.current !== null) {
        window.clearTimeout(queryWriteTimer.current);
        queryWriteTimer.current = null;
      }
    };
  }, [query]);

  const toggle = useCallback((idx: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  }, []);

  const filtered = useMemo(() => {
    let result = findings;
    if (filter !== "all") {
      result = result.filter((f) => classify(f.plugin) === filter);
    }
    if (sevFilter !== "all") {
      result = result.filter((f) => f.severity === sevFilter);
    }
    if (sourceFilter !== "all") {
      result = result.filter((f) => source(f) === sourceFilter);
    }
    const q = deferredQuery.trim().toLowerCase();
    if (q) {
      result = result.filter((f) => {
        const haystack = [
          f.message,
          f.uri,
          f.corvex_id,
          f.plugin,
          f.cve ?? "",
          f.component ?? "",
          f.host,
        ]
          .join(" ")
          .toLowerCase();
        return haystack.includes(q);
      });
    }
    // Sort by severity descending (Critical first)
    return [...result].sort(
      (a, b) =>
        (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0)
    );
  }, [findings, filter, sevFilter, sourceFilter, deferredQuery]);

  const sourceCounts = useMemo(() => {
    const m: Record<Source, number> = { sca: 0, web: 0 };
    for (const f of findings) {
      m[source(f)]++;
    }
    return m;
  }, [findings]);

  const exportCsv = useCallback(() => {
    if (filtered.length === 0) return;
    download(`corvex-findings-${timestamp()}.csv`, "text/csv;charset=utf-8", toCsv(filtered));
  }, [filtered]);

  const exportJson = useCallback(() => {
    if (filtered.length === 0) return;
    download(
      `corvex-findings-${timestamp()}.json`,
      "application/json;charset=utf-8",
      JSON.stringify(filtered, null, 2) + "\n",
    );
  }, [filtered]);

  const counts = useMemo(() => {
    let sig = 0;
    let act = 0;
    let fp = 0;
    for (const f of findings) {
      const c = classify(f.plugin);
      if (c === "signature") sig++;
      else if (c === "active") act++;
      else fp++;
    }
    return { sig, act, fp };
  }, [findings]);

  const sevCounts = useMemo(() => {
    const m: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const f of findings) {
      m[f.severity] = (m[f.severity] ?? 0) + 1;
    }
    return m;
  }, [findings]);

  const hasFindings = findings.length > 0;

  return (
    <div className="panel results">
      <div className="findings-header">
        <h2 style={{ margin: 0 }}>
          Findings
          <span className="badge-inline">{filtered.length}</span>
        </h2>
        <div className="findings-toolbar">
          <input
            type="search"
            className="findings-search"
            placeholder="Search findings…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Search findings"
          />
          <button
            type="button"
            className="chip"
            onClick={exportCsv}
            disabled={!hasFindings}
            title="Download filtered findings as CSV"
          >
            Export CSV
          </button>
          <button
            type="button"
            className="chip"
            onClick={exportJson}
            disabled={!hasFindings}
            title="Download filtered findings as JSON"
          >
            Export JSON
          </button>
        </div>
      </div>
      <div className="filter-chips filter-chips-combined">
        <button
          className={`chip${filter === "all" ? " active" : ""}`}
          onClick={() => setFilter("all")}
        >
          All ({findings.length})
        </button>
        <button
          className={`chip${filter === "signature" ? " active" : ""}`}
          onClick={() => setFilter("signature")}
        >
          Signature ({counts.sig})
        </button>
        <button
          className={`chip${filter === "active" ? " active" : ""}`}
          onClick={() => setFilter("active")}
        >
          Active ({counts.act})
        </button>
        <button
          className={`chip${filter === "fingerprint" ? " active" : ""}`}
          onClick={() => setFilter("fingerprint")}
        >
          Fingerprint ({counts.fp})
        </button>

        <span className="filter-chip-divider" aria-hidden />

        <button
          className={`chip${sourceFilter === "all" ? " active" : ""}`}
          onClick={() => setSourceFilter("all")}
        >
          All Src
        </button>
        {(["web", "sca"] as const).map((s) => (
          <button
            key={s}
            className={`chip${sourceFilter === s ? " active" : ""}`}
            style={{
              borderColor: SOURCE_COLOR[s],
              ...(sourceFilter === s
                ? { backgroundColor: SOURCE_COLOR[s], color: "#fff" }
                : {}),
            }}
            onClick={() => setSourceFilter(s)}
          >
            {SOURCE_LABEL[s]} ({sourceCounts[s] ?? 0})
          </button>
        ))}
      </div>
      {!hideSeverityChips && (
        <div className="filter-chips severity-chips">
          <button
            className={`chip${sevFilter === "all" ? " active" : ""}`}
            onClick={() => setSevFilter("all")}
          >
            All Sev
          </button>
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as SeverityLevel[]).map((s) => (
            <button
              key={s}
              className={`chip${sevFilter === s ? " active" : ""}`}
              style={{
                borderColor: SEVERITY_COLORS[s],
                ...(sevFilter === s ? { backgroundColor: SEVERITY_COLORS[s], color: s === "MEDIUM" ? "#333" : "#fff" } : {}),
              }}
              onClick={() => setSevFilter(s)}
            >
              {s} ({sevCounts[s] ?? 0})
            </button>
          ))}
        </div>
      )}
      <div className="findings-wrap">
        <table className="findings-table">
          <colgroup>
            <col className="col-toggle" />
            <col className="col-severity" />
            <col className="col-id" />
            <col className="col-method" />
            <col className="col-uri" />
            <col className="col-message" />
            <col className="col-plugin" />
          </colgroup>
          <thead>
            <tr>
              <th></th>
              <th>Severity</th>
              <th>ID</th>
              <th>Method</th>
              <th>URI</th>
              <th>Message</th>
              <th>Plugin</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr className="empty-row">
                <td colSpan={7}>
                  {findings.length === 0
                    ? "No findings yet. Start a scan to populate this table."
                    : "No findings match the selected filter."}
                </td>
              </tr>
            )}
            {filtered.map((f, i) => {
              const isOpen = expanded.has(i);
              return (
                <FindingRow
                  key={`${f.corvex_id}-${i}`}
                  finding={f}
                  isOpen={isOpen}
                  onToggle={() => toggle(i)}
                />
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

interface RowProps {
  finding: FindingPayload;
  isOpen: boolean;
  onToggle: () => void;
}

function FindingRow({ finding, isOpen, onToggle }: RowProps) {
  const src = source(finding);
  return (
    <>
      <tr
        className={`finding-row${isOpen ? " open" : ""}`}
        onClick={onToggle}
        title="Click for full details"
      >
        <td className="cell-toggle" aria-hidden>
          <span className="chev">{isOpen ? "\u25BE" : "\u25B8"}</span>
        </td>
        <td className="cell-severity">
          <SeverityBadge severity={finding.severity} />
        </td>
        <td className="cell-id">
          <code>{finding.corvex_id}</code>
        </td>
        <td className="cell-method">{finding.method}</td>
        <td className="cell-uri">
          <code>{finding.uri}</code>
          {finding.host && (
            <span style={{ marginLeft: 6, verticalAlign: "middle" }}>
              <AssetLink host={finding.host} port={finding.port} />
            </span>
          )}
        </td>
        <td className="cell-message">{finding.message}</td>
        <td className="cell-plugin">
          <div style={{ display: "flex", gap: 4, alignItems: "center", flexWrap: "wrap" }}>
            <span
              className="severity-badge"
              style={{ backgroundColor: SOURCE_COLOR[src], color: "#fff", fontSize: 10 }}
              title={`Source: ${SOURCE_LABEL[src]}`}
            >
              {SOURCE_LABEL[src]}
            </span>
            <span className="badge">{finding.plugin}</span>
          </div>
        </td>
      </tr>
      {isOpen && (
        <tr className="finding-detail-row">
          <td colSpan={7}>
            <div className="finding-detail">
              <dl>
                <dt>Severity</dt>
                <dd>
                  <SeverityBadge severity={finding.severity} />
                  {finding.cvss != null && (
                    <span className="cvss-score"> CVSS {finding.cvss.toFixed(1)}</span>
                  )}
                </dd>
                <dt>Host</dt>
                <dd>
                  <code>
                    {finding.host}:{finding.port}
                  </code>
                </dd>
                <dt>Method</dt>
                <dd>
                  <code>{finding.method}</code>
                </dd>
                <dt>URI</dt>
                <dd className="break">
                  <code>{finding.uri}</code>
                </dd>
                <dt>Plugin</dt>
                <dd>
                  <span className="badge">{finding.plugin}</span>
                </dd>
                <dt>Message</dt>
                <dd className="break">{finding.message}</dd>
                {finding.cve && (
                  <>
                    <dt>CVE</dt>
                    <dd>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${finding.cve}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="cve-link"
                      >
                        {finding.cve}
                      </a>
                    </dd>
                  </>
                )}
                <ExploitHits cve={finding.cve} />
                {finding.component && (
                  <>
                    <dt>Component</dt>
                    <dd>
                      <code>{finding.component}</code>
                      {finding.component_version && (
                        <span className="muted"> @{finding.component_version}</span>
                      )}
                    </dd>
                  </>
                )}
                {finding.epss_score != null && (
                  <>
                    <dt>EPSS</dt>
                    <dd>
                      {(finding.epss_score * 100).toFixed(2)}% probability
                      {finding.epss_percentile != null && (
                        <span className="muted">
                          {" "}({(finding.epss_percentile * 100).toFixed(1)}th percentile)
                        </span>
                      )}
                    </dd>
                  </>
                )}
                {finding.fix_version && (
                  <>
                    <dt>Fix</dt>
                    <dd>
                      <span className="badge" style={{ background: "var(--success)", color: "#fff" }}>
                        {finding.fix_version}
                      </span>
                    </dd>
                  </>
                )}
                {finding.refs && (
                  <>
                    <dt>References</dt>
                    <dd className="break">
                      {finding.refs.split("|").map((r, i) => (
                        <span key={i} className="ref-chip">
                          {r.trim()}
                        </span>
                      ))}
                    </dd>
                  </>
                )}
              </dl>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
