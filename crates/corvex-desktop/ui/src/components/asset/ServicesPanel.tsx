import type { AssetService } from "../../api";
import { JarmInfo } from "../JarmInfo";
import {
  emptyStateStyle,
  fmtRelative,
  monoChipStyle,
  panelHeaderStyle,
  panelStyle,
  panelTitleStyle,
  tableCell,
  tableHeadCell,
  tableStyle,
} from "./panelStyles";

interface Props {
  services: AssetService[];
}

export function ServicesPanel({ services }: Props) {
  return (
    <section style={panelStyle}>
      <header style={panelHeaderStyle}>
        <h3 style={panelTitleStyle}>Services</h3>
        <span style={{ color: "var(--muted)", fontSize: "0.82em" }}>
          {services.length} port{services.length === 1 ? "" : "s"}
        </span>
      </header>
      {services.length === 0 ? (
        <div style={emptyStateStyle}>
          No probe data yet. Run a probe from the{" "}
          <strong style={{ color: "var(--fg)" }}>Probing</strong> view to
          populate this panel.
        </div>
      ) : (
        <table style={tableStyle}>
          <thead>
            <tr>
              <th style={tableHeadCell}>Port</th>
              <th style={tableHeadCell}>Service</th>
              <th style={tableHeadCell}>Product · Version</th>
              <th style={tableHeadCell}>JARM</th>
              <th style={tableHeadCell}>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {services.map((s, i) => (
              <tr key={`${s.port}-${i}`}>
                <td style={{ ...tableCell, color: "var(--accent)" }}>
                  {s.port}
                  {s.over_tls ? " /tls" : ""}
                </td>
                <td style={tableCell}>{s.service ?? "—"}</td>
                <td style={tableCell}>
                  {s.product ?? "—"}
                  {s.version ? (
                    <span style={{ color: "var(--muted)" }}> · {s.version}</span>
                  ) : null}
                  {s.cpe.length > 0 && (
                    <div
                      style={{
                        marginTop: 4,
                        display: "flex",
                        flexWrap: "wrap",
                        gap: 4,
                      }}
                    >
                      {s.cpe.slice(0, 3).map((c) => (
                        <span
                          key={c}
                          style={{ ...monoChipStyle, fontSize: "0.78em" }}
                          title={c}
                        >
                          {c.length > 38 ? `${c.slice(0, 38)}…` : c}
                        </span>
                      ))}
                    </div>
                  )}
                </td>
                <td style={tableCell}>
                  {s.jarm ? <JarmInfo hash={s.jarm} /> : <em style={{ color: "var(--muted)" }}>—</em>}
                </td>
                <td style={{ ...tableCell, color: "var(--muted)" }}>
                  {fmtRelative(s.last_seen_unix)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
