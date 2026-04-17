import { useCallback, useEffect, useMemo, useState } from "react";
import type { FindingPayload, SeverityLevel } from "../api";

type FilterMode = "all" | "signature" | "active" | "fingerprint";
type SeverityFilter = "all" | SeverityLevel;

const FILTER_KEY = "corvexFindingsFilter";
const SEV_FILTER_KEY = "corvexFindingsSevFilter";
const QUERY_KEY = "corvexFindingsQuery";

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

function classify(plugin: string): "active" | "fingerprint" | "signature" {
  const lower = plugin.toLowerCase();
  if (ACTIVE_PREFIXES.some((p) => lower.startsWith(p))) return "active";
  if (FINGERPRINT_PREFIXES.some((p) => lower.startsWith(p))) return "fingerprint";
  return "signature";
}

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
}

export function FindingsTable({ findings }: Props) {
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set());
  const [filter, setFilter] = useState<FilterMode>(
    () => (readStorage(FILTER_KEY, "all") as FilterMode),
  );
  const [sevFilter, setSevFilter] = useState<SeverityFilter>(
    () => (readStorage(SEV_FILTER_KEY, "all") as SeverityFilter),
  );
  const [query, setQuery] = useState(() => readStorage(QUERY_KEY, ""));

  useEffect(() => writeStorage(FILTER_KEY, filter), [filter]);
  useEffect(() => writeStorage(SEV_FILTER_KEY, sevFilter), [sevFilter]);
  useEffect(() => writeStorage(QUERY_KEY, query), [query]);

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
    const q = query.trim().toLowerCase();
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
  }, [findings, filter, sevFilter, query]);

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
      <div className="filter-chips">
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
      </div>
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
        </td>
        <td className="cell-message">{finding.message}</td>
        <td className="cell-plugin">
          <span className="badge">{finding.plugin}</span>
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
