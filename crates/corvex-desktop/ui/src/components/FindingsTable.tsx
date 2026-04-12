import { useCallback, useState } from "react";
import type { FindingPayload } from "../api";

interface Props {
  findings: FindingPayload[];
}

export function FindingsTable({ findings }: Props) {
  // Set of row indexes that are currently expanded. Multiple rows can
  // be open at once so the user can compare findings side-by-side.
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set());

  const toggle = useCallback((idx: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  }, []);

  return (
    <div className="panel results">
      <h2>
        Findings
        <span className="badge-inline">{findings.length}</span>
      </h2>
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
            {findings.length === 0 && (
              <tr className="empty-row">
                <td colSpan={6}>
                  No findings yet. Start a scan to populate this table.
                </td>
              </tr>
            )}
            {findings.map((f, i) => {
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
