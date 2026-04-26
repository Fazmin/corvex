import type { AssetOverview } from "../../api";
import { InfoTip } from "../InfoTip";
import {
  accentChipStyle,
  emptyStateStyle,
  fmtRelative,
  fmtUnix,
  monoChipStyle,
  panelHeaderStyle,
  panelStyle,
  panelTitleStyle,
  tableCell,
  tableHeadCell,
  tableStyle,
} from "./panelStyles";

interface Props {
  overview: AssetOverview;
}

export function IdentityPanel({ overview }: Props) {
  const counts = [
    { label: "Findings", value: overview.finding_count },
    { label: "Exchanges", value: overview.exchange_count },
    { label: "Open ports", value: overview.probe_port_count },
    { label: "Recon hits", value: overview.recon_hit_count },
    { label: "Scans", value: overview.scanned_count },
  ];
  return (
    <section style={panelStyle}>
      <header style={panelHeaderStyle}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          <h3 style={panelTitleStyle}>Identity</h3>
          <InfoTip label="What is the Identity panel?">
            <p>
              <strong>Who this host is.</strong> Counts across every data
              source the app has captured for this asset, plus IPs, DNS
              records, and the <code>/24</code> networks those IPs sit in.
            </p>
            <p>
              <strong>Sources:</strong> recon findings (DNS records, A/AAAA
              IPs), probe runs (resolved IPs and last-seen), proxy exchanges
              (host observed in traffic), and scan history (web scan rows).
            </p>
            <p>
              <em>ASN</em> is a placeholder — offline ASN lookup is a planned
              follow-up.
            </p>
          </InfoTip>
        </span>
        <span style={{ color: "var(--muted)", fontSize: "0.82em" }}>
          last seen {fmtRelative(overview.last_seen_unix)}
        </span>
      </header>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
        {counts.map((c) => (
          <span key={c.label} style={monoChipStyle} title={c.label}>
            <strong style={{ color: "var(--fg-strong)" }}>{c.value}</strong>{" "}
            <span style={{ color: "var(--muted)", fontSize: "0.85em" }}>
              {c.label.toLowerCase()}
            </span>
          </span>
        ))}
      </div>

      <div>
        <div style={{ ...panelTitleStyle, fontSize: "0.78em", marginBottom: 6 }}>
          IPs
        </div>
        {overview.ips.length === 0 ? (
          <div style={emptyStateStyle}>No IPs recorded yet.</div>
        ) : (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {overview.ips.map((ip) => (
              <span key={ip} style={accentChipStyle}>
                {ip}
              </span>
            ))}
          </div>
        )}
      </div>

      {overview.cidr_24s.length > 0 && (
        <div>
          <div style={{ ...panelTitleStyle, fontSize: "0.78em", marginBottom: 6 }}>
            Networks
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {overview.cidr_24s.map((c) => (
              <span key={c} style={monoChipStyle}>
                {c}
              </span>
            ))}
          </div>
        </div>
      )}

      <div>
        <div style={{ ...panelTitleStyle, fontSize: "0.78em", marginBottom: 6 }}>
          DNS records
        </div>
        {overview.dns_records.length === 0 ? (
          <div style={emptyStateStyle}>
            No DNS records recorded — run a recon to populate.
          </div>
        ) : (
          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={tableHeadCell}>Type</th>
                <th style={tableHeadCell}>Value</th>
                <th style={tableHeadCell}>Sources</th>
              </tr>
            </thead>
            <tbody>
              {overview.dns_records.slice(0, 16).map((r, i) => (
                <tr key={i}>
                  <td style={{ ...tableCell, color: "var(--accent)" }}>{r.kind}</td>
                  <td style={tableCell}>{r.value}</td>
                  <td style={{ ...tableCell, color: "var(--muted)" }}>
                    {r.sources.join(", ") || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div
        style={{
          color: "var(--muted)",
          fontSize: "0.82em",
          marginTop: "auto",
          borderTop: "1px dashed var(--border)",
          paddingTop: 8,
        }}
      >
        First seen: {fmtUnix(overview.first_seen_unix)} · ASN:{" "}
        {overview.asn_placeholder ?? (
          <em style={{ color: "var(--muted)" }}>
            not captured (follow-up)
          </em>
        )}
      </div>
    </section>
  );
}
