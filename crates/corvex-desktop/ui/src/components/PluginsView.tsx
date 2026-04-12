import { useEffect, useState } from "react";
import { listPlugins, type PluginSummary } from "../api";

export function PluginsView() {
  const [plugins, setPlugins] = useState<PluginSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listPlugins()
      .then(setPlugins)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="history-view">
      <div className="history-header">
        <div>
          <h2 style={{ margin: 0, fontSize: 13, color: "var(--fg)", textTransform: "none", letterSpacing: 0 }}>
            Registered plugins ({plugins.length})
          </h2>
          <div className="sub" style={{ marginTop: 4 }}>
            Compile-time registry — every plugin here ships in this build.
          </div>
        </div>
      </div>
      <div className="findings-wrap">
        <table className="findings-table">
          <colgroup>
            <col style={{ width: "18%" }} />
            <col style={{ width: "12%" }} />
            <col style={{ width: "auto" }} />
            <col style={{ width: "16%" }} />
            <col style={{ width: "8%" }} />
          </colgroup>
          <thead>
            <tr>
              <th>Name</th>
              <th>Hooks</th>
              <th>Description</th>
              <th>Full name</th>
              <th>Weight</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr className="empty-row">
                <td colSpan={5}>Loading…</td>
              </tr>
            )}
            {plugins.map((p) => (
              <tr key={p.name}>
                <td><code>{p.name}</code></td>
                <td>
                  {p.hooks.map((h) => (
                    <span key={h} className="badge" style={{ marginRight: 4 }}>
                      {h}
                    </span>
                  ))}
                </td>
                <td>{p.description}</td>
                <td>{p.full_name}</td>
                <td><span className="badge">w{p.weight}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
