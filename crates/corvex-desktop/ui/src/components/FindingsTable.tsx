import { useCallback, useMemo, useState } from "react";
import type { FindingPayload } from "../api";

type FilterMode = "all" | "signature" | "active" | "fingerprint";

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

interface Props {
  findings: FindingPayload[];
}

export function FindingsTable({ findings }: Props) {
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set());
  const [filter, setFilter] = useState<FilterMode>("all");

  const toggle = useCallback((idx: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  }, []);

  const filtered = useMemo(() => {
    if (filter === "all") return findings;
    return findings.filter((f) => classify(f.plugin) === filter);
  }, [findings, filter]);

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

  return (
    <div className="panel results">
      <h2>
        Findings
        <span className="badge-inline">{filtered.length}</span>
      </h2>
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
      <div className="findings-wrap">
        <table className="findings-table">
          <colgroup>
            <col className="col-toggle" />
            <col className="col-id" />
            <col className="col-method" />
            <col className="col-uri" />
            <col className="col-message" />
            <col className="col-plugin" />
          </colgroup>
          <thead>
            <tr>
              <th></th>
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
                <td colSpan={6}>
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
          <span className="chev">{isOpen ? "▾" : "▸"}</span>
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
          <td colSpan={6}>
            <div className="finding-detail">
              <dl>
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
