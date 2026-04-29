import { Fragment, useCallback, useEffect, useState } from "react";
import {
  historyClear,
  historyDelete,
  historyFindings,
  historyList,
  type FindingPayload,
  type HistoryEntry,
  type ScanParams,
} from "../api";
import { AssetLink } from "./asset/AssetLink";
import { FindingsTable } from "./FindingsTable";

interface Props {
  /** Bumped after each scan completion so the view re-fetches. */
  refreshKey: number;
  /** Re-run a historical scan — triggers scan_start and switches to dashboard. */
  onRerun: (params: ScanParams) => void;
  /** True when a scan is currently running — disables re-run to avoid overlap. */
  running: boolean;
}

function parseParams(raw: string): ScanParams | null {
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && typeof parsed.host === "string") {
      return parsed as ScanParams;
    }
  } catch {
    /* fallthrough */
  }
  return null;
}

function fmtTime(unix: number): string {
  if (!unix) return "—";
  const d = new Date(unix * 1000);
  return d.toLocaleString();
}

function fmtDuration(start: number, end: number | null): string {
  if (!end) return "running…";
  const s = Math.max(0, end - start);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return `${m}m${r ? ` ${r}s` : ""}`;
}

function statusBadge(status: string): { label: string; color: string } {
  switch (status) {
    case "running":
      return { label: "Running", color: "var(--accent)" };
    case "done":
      return { label: "Done", color: "var(--success)" };
    case "cancelled":
      return { label: "Cancelled", color: "var(--warning)" };
    case "error":
      return { label: "Error", color: "var(--danger)" };
    default:
      return { label: status, color: "var(--muted)" };
  }
}

interface FindingsState {
  status: "loading" | "loaded" | "error";
  findings?: FindingPayload[];
  error?: string;
}

export function HistoryView({ refreshKey, onRerun, running }: Props) {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Which scan IDs are currently expanded inline. Multiple rows can be
  // open simultaneously.
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set());
  // Per-scan findings cache so re-toggling a row doesn't re-hit the
  // backend. Bumped via `refreshKey` (full reload) drops it implicitly
  // because the component re-runs `load` and the user can re-expand.
  const [findingsState, setFindingsState] = useState<
    Record<number, FindingsState>
  >({});

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await historyList(200);
      setEntries(list);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  const handleClear = useCallback(async () => {
    if (!confirm("Clear all scan history?")) return;
    try {
      await historyClear();
      setExpanded(new Set());
      setFindingsState({});
      await load();
    } catch (e) {
      setError(String(e));
    }
  }, [load]);

  const handleDelete = useCallback(
    async (id: number) => {
      try {
        await historyDelete(id);
        setExpanded((prev) => {
          if (!prev.has(id)) return prev;
          const next = new Set(prev);
          next.delete(id);
          return next;
        });
        setFindingsState((prev) => {
          if (!(id in prev)) return prev;
          const next = { ...prev };
          delete next[id];
          return next;
        });
        await load();
      } catch (e) {
        setError(String(e));
      }
    },
    [load]
  );

  const toggleExpand = useCallback(async (id: number) => {
    let willOpen = false;
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
        willOpen = true;
      }
      return next;
    });
    if (!willOpen) return;
    // Lazy-load on first expansion. Cached entries are reused.
    setFindingsState((prev) => {
      if (prev[id]?.status === "loaded" || prev[id]?.status === "loading") {
        return prev;
      }
      return { ...prev, [id]: { status: "loading" } };
    });
    try {
      const findings = await historyFindings(id);
      setFindingsState((prev) => ({
        ...prev,
        [id]: { status: "loaded", findings },
      }));
    } catch (e) {
      setFindingsState((prev) => ({
        ...prev,
        [id]: { status: "error", error: String(e) },
      }));
    }
  }, []);

  const handleRerun = useCallback(
    (entry: HistoryEntry) => {
      const params = parseParams(entry.params_json);
      if (!params) {
        setError(`Could not parse parameters for scan ${entry.id}`);
        return;
      }
      onRerun(params);
    },
    [onRerun]
  );

  return (
    <div className="history-view">
      <div className="history-header">
        <div>
          <h2 style={{ margin: 0, fontSize: 13, color: "var(--fg)", textTransform: "none", letterSpacing: 0 }}>
            Scan history
          </h2>
          <div className="sub" style={{ marginTop: 4 }}>
            Persisted in <code>history.sqlite</code> under your app data folder.
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button type="button" className="ghost-btn" onClick={load} disabled={loading}>
            Refresh
          </button>
          <button
            type="button"
            className="ghost-btn danger-text"
            onClick={handleClear}
            disabled={loading || entries.length === 0}
          >
            Clear all
          </button>
        </div>
      </div>

      {error && <div className="empty" style={{ color: "var(--danger)" }}>{error}</div>}

      <div className="findings-wrap">
        <table className="findings-table">
          <colgroup>
            <col style={{ width: "3%" }} />
            <col style={{ width: "23%" }} />
            <col style={{ width: "15%" }} />
            <col style={{ width: "9%" }} />
            <col style={{ width: "9%" }} />
            <col style={{ width: "9%" }} />
            <col style={{ width: "11%" }} />
            <col style={{ width: "21%" }} />
          </colgroup>
          <thead>
            <tr>
              <th></th>
              <th>Host</th>
              <th>Started</th>
              <th>Duration</th>
              <th>Requests</th>
              <th>Findings</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {!loading && entries.length === 0 && (
              <tr className="empty-row">
                <td colSpan={8}>
                  No saved scans yet. Run a scan, then click "Save scan" on the Dashboard to keep it here.
                </td>
              </tr>
            )}
            {loading && (
              <tr className="empty-row">
                <td colSpan={8}>Loading…</td>
              </tr>
            )}
            {entries.map((e) => {
              const badge = statusBadge(e.status);
              const canRerun = !running && e.status !== "running";
              const isOpen = expanded.has(e.id);
              const findingState = findingsState[e.id];
              return (
                <Fragment key={e.id}>
                  <tr
                    className={`finding-row${isOpen ? " open" : ""}`}
                    onClick={() => toggleExpand(e.id)}
                    title={isOpen ? "Hide findings" : "Show findings"}
                  >
                    <td className="cell-toggle" aria-hidden>
                      <span className="chev">{isOpen ? "▾" : "▸"}</span>
                    </td>
                    <td>
                      <code>{e.host}</code>
                      <span style={{ marginLeft: 6, verticalAlign: "middle" }}>
                        <AssetLink host={e.host} />
                      </span>
                    </td>
                    <td>{fmtTime(e.started_at)}</td>
                    <td>{fmtDuration(e.started_at, e.ended_at)}</td>
                    <td>{e.total_requests.toLocaleString()}</td>
                    <td>{e.total_findings.toLocaleString()}</td>
                    <td>
                      <span className="badge" style={{ color: badge.color, borderColor: badge.color }}>
                        {badge.label}
                      </span>
                    </td>
                    <td onClick={(ev) => ev.stopPropagation()}>
                      <div style={{ display: "flex", gap: 6 }}>
                        <button
                          type="button"
                          className="ghost-btn"
                          onClick={() => handleRerun(e)}
                          disabled={!canRerun}
                          title={
                            running
                              ? "Cancel the current scan before re-running"
                              : e.status === "running"
                              ? "Scan still in progress"
                              : "Re-run this scan with the same parameters"
                          }
                        >
                          Re-run
                        </button>
                        <button
                          type="button"
                          className="ghost-btn danger-text"
                          onClick={() => handleDelete(e.id)}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="finding-detail-row">
                      <td colSpan={8}>
                        <div className="history-detail">
                          {findingState?.status === "loading" && (
                            <div className="empty">Loading findings…</div>
                          )}
                          {findingState?.status === "error" && (
                            <div className="empty" style={{ color: "var(--danger)" }}>
                              {findingState.error}
                            </div>
                          )}
                          {findingState?.status === "loaded" && (
                            findingState.findings && findingState.findings.length > 0 ? (
                              <FindingsTable
                                findings={findingState.findings}
                                storageNamespace={`history-${e.id}`}
                              />
                            ) : (
                              <div className="empty">
                                No findings recorded for this scan.
                              </div>
                            )
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
