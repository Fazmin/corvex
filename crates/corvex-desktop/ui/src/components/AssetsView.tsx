import { useCallback, useEffect, useState } from "react";
import { assetList, type AssetSummary } from "../api";
import { useAssetNav } from "../asset_nav";
import { fmtRelative } from "./asset/panelStyles";

export function AssetsView() {
  const { open } = useAssetNav();
  const [query, setQuery] = useState("");
  const [rows, setRows] = useState<AssetSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (q: string) => {
    setLoading(true);
    setError(null);
    try {
      const list = await assetList(q, 500);
      setRows(list);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load("");
  }, [load]);

  // Debounce the search input — typing fires a SQL pass that's cheap
  // but still pointless on every keystroke.
  useEffect(() => {
    const t = setTimeout(() => {
      void load(query.trim().toLowerCase());
    }, 200);
    return () => clearTimeout(t);
  }, [query, load]);

  return (
    <div
      style={{
        padding: 20,
        display: "flex",
        flexDirection: "column",
        gap: 14,
        flex: 1,
        minHeight: 0,
        height: "100%",
      }}
    >
      <header style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <h2 style={{ margin: 0 }}>Assets</h2>
        <p
          style={{
            margin: 0,
            color: "var(--muted)",
            fontSize: "0.92em",
          }}
        >
          One row per host the app has seen across recon, probing, and the
          proxy. Click a row to open the asset detail view.
        </p>
      </header>

      <input
        type="search"
        placeholder="Filter by host (e.g. login.acme.com)"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        style={{
          padding: "10px 12px",
          borderRadius: 8,
          border: "1px solid var(--border)",
          background: "var(--panel)",
          color: "var(--fg)",
          fontFamily: "var(--mono)",
          fontSize: "0.95em",
        }}
      />

      {error && (
        <div
          style={{
            color: "var(--danger)",
            background: "var(--panel-alt)",
            border: "1px solid var(--danger)",
            padding: 10,
            borderRadius: 8,
          }}
        >
          {error}
        </div>
      )}

      <div
        style={{
          flex: 1,
          minHeight: 0,
          overflowY: "auto",
          background: "var(--panel)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
        }}
      >
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            fontSize: "0.92em",
          }}
        >
          <thead
            style={{
              position: "sticky",
              top: 0,
              background: "var(--panel)",
              zIndex: 1,
            }}
          >
            <tr>
              <th style={th}>Host</th>
              <th style={{ ...th, textAlign: "right" }}>Findings</th>
              <th style={{ ...th, textAlign: "right" }}>Exchanges</th>
              <th style={{ ...th, textAlign: "right" }}>Open ports</th>
              <th style={{ ...th, textAlign: "right" }}>Recon hits</th>
              <th style={th}>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {loading && rows.length === 0 ? (
              <tr>
                <td colSpan={6} style={empty}>
                  Loading…
                </td>
              </tr>
            ) : rows.length === 0 ? (
              <tr>
                <td colSpan={6} style={empty}>
                  No assets yet. Run a recon, probe a host, or browse one
                  through the proxy.
                </td>
              </tr>
            ) : (
              rows.map((r) => (
                <tr
                  key={r.host}
                  onClick={() => open({ host: r.host })}
                  style={{ cursor: "pointer" }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = "var(--panel-hover)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = "transparent";
                  }}
                >
                  <td
                    style={{
                      ...td,
                      color: "var(--accent)",
                      fontWeight: 500,
                    }}
                  >
                    {r.host}
                  </td>
                  <td
                    style={{
                      ...td,
                      textAlign: "right",
                      color:
                        r.finding_count > 0
                          ? "var(--danger)"
                          : "var(--muted)",
                    }}
                  >
                    {r.finding_count}
                  </td>
                  <td style={{ ...td, textAlign: "right" }}>
                    {r.exchange_count}
                  </td>
                  <td style={{ ...td, textAlign: "right" }}>
                    {r.probe_port_count}
                  </td>
                  <td style={{ ...td, textAlign: "right" }}>
                    {r.recon_hit_count}
                  </td>
                  <td style={{ ...td, color: "var(--muted)" }}>
                    {fmtRelative(r.last_seen_unix)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const th: React.CSSProperties = {
  textAlign: "left",
  padding: "10px 12px",
  fontWeight: 500,
  color: "var(--muted)",
  borderBottom: "1px solid var(--border)",
  fontSize: "0.82em",
  textTransform: "uppercase",
  letterSpacing: 0.4,
};

const td: React.CSSProperties = {
  padding: "10px 12px",
  borderBottom: "1px solid var(--border-soft)",
  fontFamily: "var(--mono)",
};

const empty: React.CSSProperties = {
  padding: 20,
  textAlign: "center",
  color: "var(--muted)",
};
