import { useEffect, useState } from "react";
import {
  assetEndpointsClustered,
  type AssetEndpoint,
  type AssetEndpointCluster,
} from "../../api";
import { InfoTip } from "../InfoTip";
import {
  emptyStateStyle,
  fmtRelative,
  panelHeaderStyle,
  panelStyle,
  panelTitleStyle,
  tableCell,
  tableHeadCell,
  tableStyle,
} from "./panelStyles";

interface Props {
  endpoints: AssetEndpoint[];
  /** Host this panel is rendering. Used by the clustered fetch — the
   *  flat list is already pre-loaded by the parent view. */
  host: string;
}

function statusColor(status: number | null): string {
  if (status === null) return "var(--muted)";
  if (status >= 500) return "var(--danger)";
  if (status >= 400) return "var(--warning)";
  if (status >= 300) return "var(--accent-2)";
  if (status >= 200) return "var(--success)";
  return "var(--muted)";
}

const STORAGE_KEY = "corvexAssetEndpointsClustered";

export function EndpointsPanel({ endpoints, host }: Props) {
  const [clustered, setClustered] = useState<boolean>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) === "1";
    } catch {
      return false;
    }
  });
  const [clusters, setClusters] = useState<AssetEndpointCluster[] | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, clustered ? "1" : "0");
    } catch {
      // ignore
    }
  }, [clustered]);

  useEffect(() => {
    if (!clustered) return;
    let cancelled = false;
    assetEndpointsClustered(host)
      .then((rows) => {
        if (!cancelled) {
          setClusters(rows);
          setError(null);
        }
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [clustered, host]);

  return (
    <section style={panelStyle}>
      <header style={panelHeaderStyle}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          <h3 style={panelTitleStyle}>Endpoints</h3>
          <InfoTip label="What is the Endpoints panel?">
            <p>
              <strong>The URLs this asset has served.</strong> One row
              per <em>(method, path)</em> tuple aggregated across every
              proxy session, with exchange and finding counts.
            </p>
            <p>
              <strong>Source:</strong> the proxy <code>exchanges</code>{" "}
              table (browser traffic, replays, OpenAPI imports). The
              finding count joins through{" "}
              <code>exchange_scan_findings</code>.
            </p>
            <p>
              The <em>Clustered</em> view collapses paths sharing a
              shape (<code>/api/users/1</code>, <code>/api/users/2</code>{" "}
              → <code>/api/users/:id</code>) so REST APIs read at a
              glance. Useful for spotting IDOR-shaped patterns at the
              host level.
            </p>
          </InfoTip>
        </span>
        <span
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            fontSize: "0.82em",
          }}
        >
          <button
            type="button"
            className={`chip${!clustered ? " active" : ""}`}
            onClick={() => setClustered(false)}
          >
            Flat
          </button>
          <button
            type="button"
            className={`chip${clustered ? " active" : ""}`}
            onClick={() => setClustered(true)}
          >
            Clustered
          </button>
          <span style={{ color: "var(--muted)" }}>
            {clustered
              ? `${clusters?.length ?? 0} pattern${clusters?.length === 1 ? "" : "s"}`
              : `${endpoints.length} path${endpoints.length === 1 ? "" : "s"}`}
          </span>
        </span>
      </header>
      {error && (
        <div style={emptyStateStyle}>
          Cluster fetch failed: <code>{error}</code>
        </div>
      )}
      {!clustered && endpoints.length === 0 && (
        <div style={emptyStateStyle}>
          No endpoints captured yet. Browse this host through the proxy
          (or replay an exchange) to populate this panel.
        </div>
      )}
      {!clustered && endpoints.length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={tableHeadCell}>Method</th>
                <th style={tableHeadCell}>Path</th>
                <th style={{ ...tableHeadCell, textAlign: "right" }}>
                  Exchanges
                </th>
                <th style={{ ...tableHeadCell, textAlign: "right" }}>
                  Findings
                </th>
                <th style={tableHeadCell}>Last status</th>
                <th style={tableHeadCell}>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.slice(0, 200).map((e) => (
                <tr key={`${e.port}-${e.method}-${e.path}`}>
                  <td style={{ ...tableCell, color: "var(--accent)" }}>
                    {e.method}
                  </td>
                  <td style={{ ...tableCell, wordBreak: "break-all" }}>
                    <span style={{ color: "var(--muted)" }}>
                      {e.scheme}://{e.host}:{e.port}
                    </span>
                    <span>{e.path}</span>
                  </td>
                  <td
                    style={{
                      ...tableCell,
                      textAlign: "right",
                      color: "var(--fg-strong)",
                    }}
                  >
                    {e.exchange_count}
                  </td>
                  <td
                    style={{
                      ...tableCell,
                      textAlign: "right",
                      color:
                        e.finding_count > 0
                          ? "var(--danger)"
                          : "var(--muted)",
                    }}
                  >
                    {e.finding_count}
                  </td>
                  <td
                    style={{
                      ...tableCell,
                      color: statusColor(e.last_status),
                    }}
                  >
                    {e.last_status ?? "—"}
                  </td>
                  <td style={{ ...tableCell, color: "var(--muted)" }}>
                    {fmtRelative(e.last_seen_unix)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {endpoints.length > 200 && (
            <div
              style={{
                color: "var(--muted)",
                fontSize: "0.82em",
                paddingTop: 6,
              }}
            >
              Showing top 200 by traffic.
            </div>
          )}
        </div>
      )}
      {clustered && clusters && clusters.length === 0 && (
        <div style={emptyStateStyle}>
          No patterns detected yet. The clusterer needs at least one
          numeric / UUID / slug-shaped path segment to fold rows
          together.
        </div>
      )}
      {clustered && clusters && clusters.length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={tableHeadCell}>Method</th>
                <th style={tableHeadCell}>Pattern</th>
                <th style={{ ...tableHeadCell, textAlign: "right" }}>
                  Instances
                </th>
                <th style={{ ...tableHeadCell, textAlign: "right" }}>
                  Exchanges
                </th>
                <th style={{ ...tableHeadCell, textAlign: "right" }}>
                  Findings
                </th>
                <th style={tableHeadCell}>Last status</th>
                <th style={tableHeadCell}>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {clusters.slice(0, 200).map((c) => (
                <tr key={`${c.port}-${c.method}-${c.pattern}`}>
                  <td style={{ ...tableCell, color: "var(--accent)" }}>
                    {c.method}
                  </td>
                  <td style={{ ...tableCell, wordBreak: "break-all" }}>
                    <span style={{ color: "var(--muted)" }}>
                      {c.scheme}://{c.host}:{c.port}
                    </span>
                    <span>{c.pattern}</span>
                    {c.sample_paths.length > 0 && (
                      <div
                        style={{
                          color: "var(--muted)",
                          fontSize: "0.78em",
                          marginTop: 2,
                        }}
                        title={c.sample_paths.join("\n")}
                      >
                        e.g.{" "}
                        {c.sample_paths.slice(0, 3).join(", ")}
                        {c.sample_paths.length > 3
                          ? ` +${c.sample_paths.length - 3} more`
                          : ""}
                      </div>
                    )}
                  </td>
                  <td
                    style={{
                      ...tableCell,
                      textAlign: "right",
                      color: "var(--fg-strong)",
                    }}
                  >
                    {c.instance_count}
                  </td>
                  <td
                    style={{
                      ...tableCell,
                      textAlign: "right",
                      color: "var(--fg-strong)",
                    }}
                  >
                    {c.exchange_count}
                  </td>
                  <td
                    style={{
                      ...tableCell,
                      textAlign: "right",
                      color:
                        c.finding_count > 0
                          ? "var(--danger)"
                          : "var(--muted)",
                    }}
                  >
                    {c.finding_count}
                  </td>
                  <td
                    style={{
                      ...tableCell,
                      color: statusColor(c.last_status),
                    }}
                  >
                    {c.last_status ?? "—"}
                  </td>
                  <td style={{ ...tableCell, color: "var(--muted)" }}>
                    {fmtRelative(c.last_seen_unix)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
