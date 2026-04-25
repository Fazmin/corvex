import type { AssetEndpoint } from "../../api";
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
}

function statusColor(status: number | null): string {
  if (status === null) return "var(--muted)";
  if (status >= 500) return "var(--danger)";
  if (status >= 400) return "var(--warning)";
  if (status >= 300) return "var(--accent-2)";
  if (status >= 200) return "var(--success)";
  return "var(--muted)";
}

export function EndpointsPanel({ endpoints }: Props) {
  return (
    <section style={panelStyle}>
      <header style={panelHeaderStyle}>
        <h3 style={panelTitleStyle}>Endpoints</h3>
        <span style={{ color: "var(--muted)", fontSize: "0.82em" }}>
          {endpoints.length} path{endpoints.length === 1 ? "" : "s"}
        </span>
      </header>
      {endpoints.length === 0 ? (
        <div style={emptyStateStyle}>
          No endpoints captured yet. Browse this host through the proxy
          (or replay an exchange) to populate this panel.
        </div>
      ) : (
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
    </section>
  );
}
