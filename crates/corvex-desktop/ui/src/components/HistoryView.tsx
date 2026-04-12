import { useCallback, useEffect, useState } from "react";
import {
  historyClear,
  historyDelete,
  historyList,
  type HistoryEntry,
} from "../api";

interface Props {
  /** Bumped after each scan completion so the view re-fetches. */
  refreshKey: number;
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

export function HistoryView({ refreshKey }: Props) {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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
      await load();
    } catch (e) {
      setError(String(e));
    }
  }, [load]);

  const handleDelete = useCallback(
    async (id: number) => {
      try {
        await historyDelete(id);
        await load();
      } catch (e) {
        setError(String(e));
      }
    },
    [load]
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
            <col style={{ width: "30%" }} />
            <col style={{ width: "16%" }} />
            <col style={{ width: "10%" }} />
            <col style={{ width: "10%" }} />
            <col style={{ width: "10%" }} />
            <col style={{ width: "12%" }} />
            <col style={{ width: "12%" }} />
          </colgroup>
          <thead>
            <tr>
              <th>Host</th>
              <th>Started</th>
              <th>Duration</th>
              <th>Requests</th>
              <th>Findings</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {!loading && entries.length === 0 && (
              <tr className="empty-row">
                <td colSpan={7}>No scans yet. Start one from the Dashboard.</td>
              </tr>
            )}
            {loading && (
              <tr className="empty-row">
                <td colSpan={7}>Loading…</td>
              </tr>
            )}
            {entries.map((e) => {
              const badge = statusBadge(e.status);
              return (
                <tr key={e.id}>
                  <td><code>{e.host}</code></td>
                  <td>{fmtTime(e.started_at)}</td>
                  <td>{fmtDuration(e.started_at, e.ended_at)}</td>
                  <td>{e.total_requests.toLocaleString()}</td>
                  <td>{e.total_findings.toLocaleString()}</td>
                  <td>
                    <span className="badge" style={{ color: badge.color, borderColor: badge.color }}>
                      {badge.label}
                    </span>
                  </td>
                  <td>
                    <button
                      type="button"
                      className="ghost-btn danger-text"
                      onClick={() => handleDelete(e.id)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
