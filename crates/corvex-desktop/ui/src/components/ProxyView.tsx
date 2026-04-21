import { useCallback, useEffect, useState } from "react";
import {
  exchangesList,
  onProxyExchange,
  proxyExportCaPem,
  proxyStart,
  proxyStatus,
  proxyStop,
  type ExchangeSummary,
  type ProxyStatus,
} from "../api";

type Tab = "traffic" | "intercept" | "replay" | "checks" | "settings";

const TAB_LABELS: Record<Tab, string> = {
  traffic: "Traffic",
  intercept: "Intercept",
  replay: "Replay",
  checks: "Checks",
  settings: "Settings",
};

/**
 * Top-level Proxy view. Hosts the toolbar + tabbed sub-views.
 *
 * This milestone ships the Traffic list and Settings (CA export +
 * listen address) panes. Intercept / Replay / Checks render
 * placeholders describing what's coming in the next milestones so the
 * navigation feels complete today.
 */
export function ProxyView() {
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [listen, setListen] = useState<string>("127.0.0.1:8888");
  const [tab, setTab] = useState<Tab>("traffic");
  const [exchanges, setExchanges] = useState<ExchangeSummary[]>([]);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await proxyStatus());
    } catch (e) {
      setError(String(e));
    }
  }, []);

  // Poll status at a slow cadence to pick up listener counters; the
  // listener milestone replaces this with a status-push event.
  useEffect(() => {
    refreshStatus();
    const t = window.setInterval(refreshStatus, 2000);
    return () => window.clearInterval(t);
  }, [refreshStatus]);

  // Subscribe to live exchange events. Events only fire once the
  // listener milestone lands, but the subscription is harmless before
  // that — nothing arrives, nothing breaks.
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    onProxyExchange((summary) => {
      setExchanges((prev) => [summary, ...prev].slice(0, 1000));
    })
      .then((fn) => {
        unlisten = fn;
      })
      .catch(() => {
        // event bus not ready yet — ignore
      });
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  // On session change, pull the persisted exchange list.
  useEffect(() => {
    const session = status?.session_id;
    if (!session) {
      setExchanges([]);
      return;
    }
    exchangesList(session, 500, 0)
      .then(setExchanges)
      .catch((e) => setError(String(e)));
  }, [status?.session_id]);

  const handleStart = async () => {
    setError(null);
    try {
      await proxyStart({ listen });
      await refreshStatus();
    } catch (e) {
      setError(String(e));
    }
  };

  const handleStop = async () => {
    setError(null);
    try {
      await proxyStop();
      await refreshStatus();
    } catch (e) {
      setError(String(e));
    }
  };

  const running = status?.running ?? false;

  return (
    <div className="proxy-view">
      <div className="proxy-toolbar panel">
        <div className="proxy-toolbar-row">
          <div className="proxy-toolbar-left">
            <h2 className="proxy-title">Proxy</h2>
            <span
              className="badge-inline"
              data-status={running ? "running" : "stopped"}
              title={running ? "Listener running" : "Listener stopped"}
            >
              {running ? "Running" : "Stopped"}
            </span>
            {status && !status.ca_ready && (
              <span
                className="badge-inline"
                data-status="warn"
                title="Certificate authority missing"
              >
                CA not ready
              </span>
            )}
          </div>
          <div className="proxy-toolbar-right">
            <label className="proxy-listen-label">
              <span>Listen</span>
              <input
                type="text"
                className="input input-compact"
                value={listen}
                onChange={(e) => setListen(e.target.value)}
                disabled={running}
                placeholder="127.0.0.1:8888"
              />
            </label>
            {running ? (
              <button type="button" className="chip" onClick={handleStop}>
                Stop
              </button>
            ) : (
              <button
                type="button"
                className="chip active"
                onClick={handleStart}
                disabled={!status?.ca_ready}
                title={
                  status?.ca_ready
                    ? "Start the intercepting proxy"
                    : "CA is not ready — check logs"
                }
              >
                Start
              </button>
            )}
          </div>
        </div>
        {error && <div className="proxy-error">{error}</div>}
      </div>

      <div className="proxy-tabs panel">
        <div className="proxy-tab-row">
          {(Object.keys(TAB_LABELS) as Tab[]).map((t) => (
            <button
              key={t}
              type="button"
              className={`chip${tab === t ? " active" : ""}`}
              onClick={() => setTab(t)}
            >
              {TAB_LABELS[t]}
            </button>
          ))}
        </div>

        <div className="proxy-tab-body">
          {tab === "traffic" && (
            <ProxyTrafficTab exchanges={exchanges} running={running} />
          )}
          {tab === "intercept" && <ProxyPlaceholderTab kind="intercept" />}
          {tab === "replay" && <ProxyPlaceholderTab kind="replay" />}
          {tab === "checks" && <ProxyPlaceholderTab kind="checks" />}
          {tab === "settings" && <ProxySettingsTab />}
        </div>
      </div>
    </div>
  );
}

function ProxyTrafficTab({
  exchanges,
  running,
}: {
  exchanges: ExchangeSummary[];
  running: boolean;
}) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (!running && exchanges.length === 0) {
    return (
      <div className="proxy-empty">
        <p>
          The proxy is not running. Click <strong>Start</strong> in the toolbar,
          then point your browser at the listen address to capture traffic.
        </p>
        <p className="muted">
          First-time setup: in the <strong>Settings</strong> tab, export the
          corvex CA certificate and add it to your OS/browser trust store so
          HTTPS pages load without warnings.
        </p>
      </div>
    );
  }

  if (exchanges.length === 0) {
    return (
      <div className="proxy-empty">
        <p>Waiting for traffic…</p>
      </div>
    );
  }

  return (
    <table className="findings-table proxy-traffic-table">
      <colgroup>
        <col style={{ width: "64px" }} />
        <col style={{ width: "80px" }} />
        <col style={{ width: "64px" }} />
        <col />
        <col style={{ width: "90px" }} />
        <col style={{ width: "90px" }} />
      </colgroup>
      <thead>
        <tr>
          <th>#</th>
          <th>Method</th>
          <th>Status</th>
          <th>URL</th>
          <th>Size</th>
          <th>Time</th>
        </tr>
      </thead>
      <tbody>
        {exchanges.map((ex, i) => {
          const open = expandedId === ex.id;
          return (
            <>
              <tr
                key={ex.id}
                className={`proxy-row${ex.scope === "out" ? " scope-out" : ""}`}
                onClick={() => setExpandedId(open ? null : ex.id)}
              >
                <td className="muted">{exchanges.length - i}</td>
                <td><span className="badge-inline">{ex.method}</span></td>
                <td>{ex.status ?? "-"}</td>
                <td className="proxy-url">
                  <span className="muted">{ex.scheme}://{ex.host}</span>
                  {ex.path}
                  {ex.query ? `?${ex.query}` : ""}
                </td>
                <td className="muted">{humanSize(ex.size_response)}</td>
                <td className="muted">{ex.duration_ms ?? "-"} ms</td>
              </tr>
              {open && (
                <tr className="finding-detail-row" key={`${ex.id}-detail`}>
                  <td colSpan={6}>
                    <div className="finding-detail">
                      <dl>
                        <dt>Id</dt><dd>{ex.id}</dd>
                        <dt>Origin</dt><dd>{ex.origin_kind}</dd>
                        <dt>Host</dt><dd>{ex.host}:{ex.port}</dd>
                        <dt>MIME</dt><dd>{ex.mime ?? "-"}</dd>
                        <dt>Scope</dt><dd>{ex.scope}</dd>
                      </dl>
                    </div>
                  </td>
                </tr>
              )}
            </>
          );
        })}
      </tbody>
    </table>
  );
}

function ProxySettingsTab() {
  const [pem, setPem] = useState<string | null>(null);
  const [pemPath, setPemPath] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleExport = async () => {
    setError(null);
    try {
      const exported = await proxyExportCaPem();
      setPem(exported.pem);
      setPemPath(exported.path);
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="proxy-settings">
      <section>
        <h3>Certificate authority</h3>
        <p className="muted">
          To intercept HTTPS, your browser or OS must trust the local
          corvex certificate authority. Install the CA once per machine.
        </p>
        <button type="button" className="chip active" onClick={handleExport}>
          Show CA certificate
        </button>
        {pemPath && (
          <p className="muted">
            Stored at <code>{pemPath}</code>
          </p>
        )}
        {pem && <pre className="proxy-pem">{pem}</pre>}
        {error && <div className="proxy-error">{error}</div>}
      </section>

      <section>
        <h3>Trust the CA</h3>
        <ul className="proxy-instructions">
          <li>
            <strong>Windows:</strong> Save the PEM as <code>corvex-ca.crt</code>,
            then run <code>certutil -addstore -user Root corvex-ca.crt</code>.
            Firefox uses its own store — import under
            Settings → Privacy → Certificates.
          </li>
          <li>
            <strong>macOS:</strong>{" "}
            <code>
              security add-trusted-cert -d -r trustRoot -k
              ~/Library/Keychains/login.keychain corvex-ca.crt
            </code>
            , then mark it "Always Trust" in Keychain Access.
          </li>
          <li>
            <strong>Linux:</strong> Copy to
            <code> /usr/local/share/ca-certificates/</code> and run
            <code> update-ca-certificates</code>. Firefox imports via its NSS
            database with <code>certutil -d sql:~/.pki/nssdb -A -t "CT,," -n
            "corvex" -i corvex-ca.crt</code>.
          </li>
        </ul>
      </section>
    </div>
  );
}

function ProxyPlaceholderTab({ kind }: { kind: "intercept" | "replay" | "checks" }) {
  const copy: Record<typeof kind, { title: string; body: string }> = {
    intercept: {
      title: "Intercept",
      body:
        "Pause, inspect, and edit requests as they flow through the proxy. Arriving in the next milestone.",
    },
    replay: {
      title: "Replay",
      body:
        "Resend any captured request with edits; compare responses side-by-side. Arriving after Intercept.",
    },
    checks: {
      title: "Checks",
      body:
        "Run OWASP Top 10 checks against captured exchanges. Passive checks run automatically; active checks send probes on demand.",
    },
  };
  const c = copy[kind];
  return (
    <div className="proxy-empty">
      <h3>{c.title}</h3>
      <p className="muted">{c.body}</p>
    </div>
  );
}

function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
