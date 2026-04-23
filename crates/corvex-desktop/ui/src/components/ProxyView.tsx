import { useCallback, useEffect, useMemo, useState } from "react";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import {
  checksList,
  checksRun,
  exchangesList,
  exchangeGet,
  findingsForSession,
  interceptDropAll,
  interceptGetMode,
  interceptPendingList,
  interceptResolve,
  interceptSetMode,
  onInterceptPending,
  onProxyExchange,
  onScanFinding,
  onWsFrame,
  owaspTaxonomyInfo,
  proxyExportCaPem,
  proxyExportHar,
  proxyImportSpec,
  proxyStart,
  proxyStatus,
  proxyStop,
  replaySend,
  retentionGet,
  retentionSet,
  scopeGet,
  scopeSet,
  wsFramesForExchange,
  type CheckDescriptor,
  type ExchangeSummary,
  type FindingRow,
  type InterceptMode,
  type LiveFindingPayload,
  type OwaspTaxonomyInfo,
  type PendingIntercept,
  type ProxyStatus,
  type ReplayResult,
  type RetentionPolicy,
  type ScopeRule,
  type ScopeRules,
  type WsFrame,
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
export interface FuzzerSeed {
  url: string;
  exchangeId?: string;
}

interface ProxyViewProps {
  onSendToFuzzer?: (seed: FuzzerSeed) => void;
}

export function ProxyView({ onSendToFuzzer }: ProxyViewProps = {}) {
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [listen, setListen] = useState<string>("127.0.0.1:8888");
  const [tab, setTab] = useState<Tab>("traffic");
  const [exchanges, setExchanges] = useState<ExchangeSummary[]>([]);
  const [replayBase, setReplayBase] = useState<ExchangeSummary | null>(null);
  const [checkTargets, setCheckTargets] = useState<ExchangeSummary[]>([]);

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
      // Dedupe by exchange id — in React 18 strict-mode the effect
      // mounts the listener twice in dev builds, and the backend can
      // also emit a refresh for the same exchange when its intercept
      // state or tags change. Either way we want one row per id.
      setExchanges((prev) => {
        if (prev.some((p) => p.id === summary.id)) return prev;
        return [summary, ...prev].slice(0, 1000);
      });
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
      .then((rows) => {
        // Dedupe defensively so a stale React mount or a race with
        // the live listener can't produce two rows sharing an id.
        const seen = new Set<string>();
        setExchanges(
          rows.filter((r) => (seen.has(r.id) ? false : (seen.add(r.id), true))),
        );
      })
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

  const [harStatus, setHarStatus] = useState<string | null>(null);
  const handleExportHar = async () => {
    const sessionId = status?.session_id;
    if (!sessionId) {
      setError("No active or loaded session to export");
      return;
    }
    setError(null);
    setHarStatus(null);
    let path: string | null;
    try {
      path = (await saveDialog({
        title: "Export HAR",
        defaultPath: `corvex-session-${sessionId.slice(0, 8)}.har`,
        filters: [{ name: "HTTP Archive", extensions: ["har", "json"] }],
      })) as string | null;
    } catch (e) {
      setError(String(e));
      return;
    }
    if (!path) return; // user cancelled
    setHarStatus("Exporting…");
    try {
      const report = await proxyExportHar(sessionId, path);
      const kb = (report.bytes_written / 1024).toFixed(1);
      setHarStatus(
        `Exported ${report.entry_count.toLocaleString()} exchanges · ${kb} KB → ${report.path}`,
      );
    } catch (e) {
      setError(String(e));
      setHarStatus(null);
    }
  };

  const handleImportSpec = async () => {
    if (!status?.session_id) {
      setError(
        "Start a proxy session first — imported rows attach to the active session.",
      );
      return;
    }
    setError(null);
    setHarStatus(null);
    let picked: string | null;
    try {
      picked = (await openDialog({
        title: "Import OpenAPI or Postman collection",
        multiple: false,
        directory: false,
        filters: [
          { name: "Spec files", extensions: ["json", "har"] },
          { name: "All files", extensions: ["*"] },
        ],
      })) as string | null;
    } catch (e) {
      setError(String(e));
      return;
    }
    if (!picked) return;
    setHarStatus("Importing…");
    try {
      const report = await proxyImportSpec(picked);
      const skippedSuffix =
        report.skipped > 0 ? ` · ${report.skipped} skipped` : "";
      setHarStatus(
        `Imported ${report.imported} ${report.format} endpoint(s) from ${report.source}${skippedSuffix}`,
      );
    } catch (e) {
      setError(String(e));
      setHarStatus(null);
    }
  };

  const running = status?.running ?? false;
  const hasSession = Boolean(status?.session_id);

  return (
    <div className="proxy-view">
      <div className="proxy-toolbar panel">
        <div className="proxy-toolbar-row">
          <div className="proxy-toolbar-left">
            <h2 className="proxy-title">Intercept</h2>
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
            <button
              type="button"
              className="chip"
              onClick={handleExportHar}
              disabled={!hasSession}
              title={
                hasSession
                  ? "Export this session's traffic log as a HAR 1.2 file"
                  : "Start a proxy session first"
              }
            >
              Export HAR
            </button>
            <button
              type="button"
              className="chip"
              onClick={handleImportSpec}
              disabled={!hasSession}
              title={
                hasSession
                  ? "Seed Checks targets from an OpenAPI 3 or Postman v2.1 spec"
                  : "Start a proxy session first"
              }
            >
              Import spec
            </button>
          </div>
        </div>
        {error && <div className="proxy-error">{error}</div>}
        {harStatus && <div className="proxy-hint muted">{harStatus}</div>}
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
            <ProxyTrafficTab
              exchanges={exchanges}
              running={running}
              onSendToReplay={(ex) => {
                setReplayBase(ex);
                setTab("replay");
              }}
              onSendToChecks={(ex) => {
                setCheckTargets((prev) =>
                  prev.some((p) => p.id === ex.id) ? prev : [...prev, ex],
                );
                setTab("checks");
              }}
              onSendToFuzzer={
                onSendToFuzzer
                  ? (ex) =>
                      onSendToFuzzer({
                        url: exchangeUrl(ex),
                        exchangeId: ex.id,
                      })
                  : undefined
              }
            />
          )}
          {tab === "intercept" && <ProxyInterceptTab />}
          {tab === "replay" && (
            <ProxyReplayTab base={replayBase} onChangeBase={setReplayBase} />
          )}
          {tab === "checks" && (
            <ProxyChecksTab
              sessionId={status?.session_id ?? null}
              targets={checkTargets}
              onClearTargets={() => setCheckTargets([])}
              onRemoveTarget={(id) =>
                setCheckTargets((prev) => prev.filter((p) => p.id !== id))
              }
            />
          )}
          {tab === "settings" && <ProxySettingsTab />}
        </div>
      </div>
    </div>
  );
}

function ProxyTrafficTab({
  exchanges,
  running,
  onSendToReplay,
  onSendToChecks,
  onSendToFuzzer,
}: {
  exchanges: ExchangeSummary[];
  running: boolean;
  onSendToReplay: (ex: ExchangeSummary) => void;
  onSendToChecks: (ex: ExchangeSummary) => void;
  onSendToFuzzer?: (ex: ExchangeSummary) => void;
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
    <div className="proxy-traffic-wrap">
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
                <td>
                  <span className="badge-inline">{ex.method}</span>
                  {isWebsocketExchange(ex) && (
                    <span
                      className="badge-inline ws-badge"
                      title="WebSocket upgrade — expand the row to see captured frames"
                    >
                      ws
                    </span>
                  )}
                  {ex.tags.includes("body-truncated") && (
                    <span
                      className="badge-inline"
                      data-status="warn"
                      title="One side of this exchange exceeded the 32 MB capture cap. The stored body is the initial prefix; the tail was forwarded to the peer but not recorded."
                    >
                      trunc
                    </span>
                  )}
                </td>
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
                    <div className="proxy-detail-compact">
                      <div className="proxy-detail-fields">
                        <div className="proxy-detail-line">
                          <span className="proxy-field" title={ex.id}>
                            <span className="proxy-field-k">ID</span>
                            <span className="proxy-field-v mono trunc">
                              {ex.id}
                            </span>
                          </span>
                          <span className="proxy-field">
                            <span className="proxy-field-k">Origin</span>
                            <span className="proxy-field-v">{ex.origin_kind}</span>
                          </span>
                          <span className="proxy-field">
                            <span className="proxy-field-k">Host</span>
                            <span className="proxy-field-v mono">
                              {ex.host}:{ex.port}
                            </span>
                          </span>
                        </div>
                        <div className="proxy-detail-line">
                          <span className="proxy-field">
                            <span className="proxy-field-k">MIME</span>
                            <span className="proxy-field-v">
                              {ex.mime ?? "-"}
                            </span>
                          </span>
                          <span className="proxy-field">
                            <span className="proxy-field-k">Scope</span>
                            <span
                              className={`proxy-field-v scope-${ex.scope}`}
                            >
                              {ex.scope}
                            </span>
                          </span>
                          <span className="proxy-field">
                            <span className="proxy-field-k">Req/Res size</span>
                            <span className="proxy-field-v">
                              {humanSize(ex.size_request)} /{" "}
                              {humanSize(ex.size_response)}
                            </span>
                          </span>
                        </div>
                      </div>
                      <div className="proxy-detail-actions">
                        <button
                          type="button"
                          className="proxy-send-btn"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSendToReplay(ex);
                          }}
                        >
                          Send to Replay →
                        </button>
                        <button
                          type="button"
                          className="proxy-send-btn"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSendToChecks(ex);
                          }}
                        >
                          Send to Checks →
                        </button>
                        {onSendToFuzzer && (
                          <button
                            type="button"
                            className="proxy-send-btn"
                            onClick={(e) => {
                              e.stopPropagation();
                              onSendToFuzzer(ex);
                            }}
                            title="Seed the Active Fuzzing form with this URL and open it"
                          >
                            Send to Fuzzer →
                          </button>
                        )}
                      </div>
                      {isWebsocketExchange(ex) && (
                        <WsFrameViewer exchange={ex} />
                      )}
                    </div>
                  </td>
                </tr>
              )}
            </>
          );
        })}
      </tbody>
    </table>
    </div>
  );
}

type SettingsSection =
  | "overview"
  | "ca"
  | "browser"
  | "scope"
  | "retention"
  | "verify"
  | "troubleshoot";

const SETTINGS_SECTIONS: { id: SettingsSection; label: string }[] = [
  { id: "overview", label: "1. Overview" },
  { id: "ca", label: "2. Certificate authority" },
  { id: "browser", label: "3. Browser setup" },
  { id: "scope", label: "4. Scope rules" },
  { id: "retention", label: "5. Retention" },
  { id: "verify", label: "6. Verify" },
  { id: "troubleshoot", label: "7. Troubleshooting" },
];

function ProxySettingsTab() {
  const [section, setSection] = useState<SettingsSection>("overview");
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
      <nav className="proxy-settings-nav">
        {SETTINGS_SECTIONS.map((s) => (
          <button
            key={s.id}
            type="button"
            className={`chip${section === s.id ? " active" : ""}`}
            onClick={() => setSection(s.id)}
          >
            {s.label}
          </button>
        ))}
      </nav>

      {section === "overview" && <SetupOverview onJump={setSection} />}

      {section === "ca" && (
        <SetupCertificateAuthority
          pem={pem}
          pemPath={pemPath}
          error={error}
          onExport={handleExport}
        />
      )}

      {section === "browser" && <SetupBrowser />}

      {section === "scope" && <SetupScopeRules />}

      {section === "retention" && <SetupRetention />}

      {section === "verify" && <SetupVerify />}

      {section === "troubleshoot" && <SetupTroubleshoot />}
    </div>
  );
}

function SetupOverview({ onJump }: { onJump: (s: SettingsSection) => void }) {
  return (
    <section>
      <h3>First-time setup</h3>
      <p className="muted">
        Three things need to line up before HTTPS traffic shows up in the
        Traffic tab. Work through them in order; each step links to its
        own section.
      </p>
      <ol className="proxy-steps">
        <li>
          <strong>Generate and trust the CA.</strong>{" "}
          The app already generated a local certificate authority on
          first launch. Export it and install it into your OS/browser
          trust store so HTTPS pages load without warnings.{" "}
          <button
            type="button"
            className="link-button"
            onClick={() => onJump("ca")}
          >
            Go to Certificate authority →
          </button>
        </li>
        <li>
          <strong>Point your browser at the proxy.</strong>{" "}
          Configure the browser (or a per-browser extension) to send
          traffic through the listen address shown in the toolbar
          (default <code>127.0.0.1:8888</code>).{" "}
          <button
            type="button"
            className="link-button"
            onClick={() => onJump("browser")}
          >
            Go to Browser setup →
          </button>
        </li>
        <li>
          <strong>Verify it's working.</strong>{" "}
          Load a known HTTP page and a known HTTPS page, watch the
          Traffic tab update in real time.{" "}
          <button
            type="button"
            className="link-button"
            onClick={() => onJump("verify")}
          >
            Go to Verify →
          </button>
        </li>
      </ol>
      <p className="muted">
        The proxy listens on loopback only. Nothing leaves the machine
        unless you explicitly change the listen address.
      </p>
    </section>
  );
}

function SetupCertificateAuthority({
  pem,
  pemPath,
  error,
  onExport,
}: {
  pem: string | null;
  pemPath: string | null;
  error: string | null;
  onExport: () => void;
}) {
  return (
    <>
      <section>
        <h3>Export the CA</h3>
        <p className="muted">
          The certificate is generated on first launch and persisted
          under your app data directory. You only need to install it
          once per machine — reinstalling corvex does not invalidate it.
        </p>
        <button type="button" className="chip active" onClick={onExport}>
          Show CA certificate
        </button>
        {pemPath && (
          <p className="muted">
            Stored at <code>{pemPath}</code>
          </p>
        )}
        {pem && <pre className="proxy-pem">{pem}</pre>}
        {error && <div className="proxy-error">{error}</div>}
        <p className="muted">
          To save a copy, select the PEM text above and paste it into a
          file named <code>corvex-ca.crt</code>.
        </p>
      </section>

      <section>
        <h3>Install into the OS trust store</h3>
        <ul className="proxy-instructions">
          <li>
            <strong>Windows.</strong> From an admin-free shell, run:
            <pre className="proxy-cmd">
              certutil -addstore -user Root corvex-ca.crt
            </pre>
            This adds the certificate to your user's Trusted Root store.
            Chromium-based browsers (Edge, Chrome, Brave, Opera) pick it
            up automatically. Firefox uses its own store — see the
            browser section.
          </li>
          <li>
            <strong>macOS.</strong> Run:
            <pre className="proxy-cmd">
              security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain corvex-ca.crt
            </pre>
            Recent macOS still requires you to open Keychain Access,
            double-click the <em>Corvex Local CA</em> entry, expand
            Trust, and set <em>When using this certificate</em> to
            "Always Trust". Safari and Chromium browsers honour the
            keychain.
          </li>
          <li>
            <strong>Linux (Debian/Ubuntu).</strong>
            <pre className="proxy-cmd">
              sudo cp corvex-ca.crt /usr/local/share/ca-certificates/
              sudo update-ca-certificates
            </pre>
            On Fedora/RHEL use <code>/etc/pki/ca-trust/source/anchors/</code>
            and <code>update-ca-trust</code>. Firefox uses its own NSS
            database — see the browser section.
          </li>
        </ul>
      </section>
    </>
  );
}

function SetupBrowser() {
  return (
    <>
      <section>
        <h3>Point your browser at the proxy</h3>
        <p className="muted">
          By default the proxy listens on <code>127.0.0.1:8888</code>.
          If you changed the listen address in the toolbar, substitute
          it below. Both HTTP and HTTPS must route through the same
          address.
        </p>
      </section>

      <section>
        <h3>Firefox (recommended — isolated proxy and cert store)</h3>
        <ol className="proxy-steps">
          <li>
            Open <code>about:preferences</code>, search for{" "}
            <em>proxy</em>, click <strong>Settings…</strong>.
          </li>
          <li>
            Select <strong>Manual proxy configuration</strong>. Set:
            <pre className="proxy-cmd">
              HTTP Proxy:  127.0.0.1   Port: 8888
            </pre>
            Tick <em>Also use this proxy for HTTPS</em>.
          </li>
          <li>
            Clear the <em>No proxy for</em> box (or at minimum leave{" "}
            <code>127.0.0.1</code> out of it so the proxy UI keeps working
            — Firefox bypasses proxies listed here).
          </li>
          <li>
            Open <code>about:preferences#privacy</code> → scroll to{" "}
            <strong>Certificates</strong> → <strong>View Certificates…</strong>{" "}
            → <strong>Authorities</strong> tab → <strong>Import…</strong>.
            Select <code>corvex-ca.crt</code>, tick{" "}
            <em>Trust this CA to identify websites</em>.
          </li>
        </ol>
      </section>

      <section>
        <h3>Chrome / Edge / Brave / Opera (Chromium)</h3>
        <p className="muted">
          Chromium uses the OS proxy settings and the OS trust store.
          The easiest per-profile override is the{" "}
          <strong>FoxyProxy</strong> or <strong>Proxy SwitchyOmega</strong>{" "}
          extension, which avoids rerouting system-wide traffic.
        </p>
        <ol className="proxy-steps">
          <li>
            Install a proxy switcher extension from the Chrome Web Store.
          </li>
          <li>
            Add a profile named <em>corvex</em> with:
            <pre className="proxy-cmd">
              Type: HTTP
              Address: 127.0.0.1
              Port: 8888
            </pre>
            Apply the same host/port to HTTPS.
          </li>
          <li>
            Activate the profile from the extension's toolbar icon when
            you want to capture traffic; switch back to{" "}
            <em>Direct</em> when you don't.
          </li>
        </ol>
        <p className="muted">
          For a system-wide change instead: Windows →{" "}
          <em>Settings → Network &amp; internet → Proxy → Manual proxy
          setup</em>. macOS → <em>System Settings → Network → Wi-Fi →
          Details → Proxies</em>. Any app that respects system proxy
          settings will then route through corvex.
        </p>
      </section>

      <section>
        <h3>Safari (macOS)</h3>
        <ol className="proxy-steps">
          <li>
            Open <strong>System Settings → Network</strong>, select your
            active interface, click <strong>Details… → Proxies</strong>.
          </li>
          <li>
            Tick <strong>Web Proxy (HTTP)</strong> and{" "}
            <strong>Secure Web Proxy (HTTPS)</strong>. Set both to{" "}
            <code>127.0.0.1</code> : <code>8888</code>. Apply.
          </li>
          <li>
            Confirm the CA is trusted in Keychain Access (see previous
            section).
          </li>
        </ol>
      </section>

      <section>
        <h3>Command-line tools</h3>
        <p className="muted">
          Useful while scripting or testing without a browser.
        </p>
        <ul className="proxy-instructions">
          <li>
            <strong>curl</strong>:
            <pre className="proxy-cmd">
              curl -x http://127.0.0.1:8888 --cacert corvex-ca.crt https://example.com/
            </pre>
          </li>
          <li>
            <strong>wget</strong>:
            <pre className="proxy-cmd">
              https_proxy=http://127.0.0.1:8888 \
              http_proxy=http://127.0.0.1:8888 \
              wget --ca-certificate=corvex-ca.crt https://example.com/
            </pre>
          </li>
          <li>
            <strong>POSIX shells</strong> (anything that respects the
            <code> *_proxy</code> env vars):
            <pre className="proxy-cmd">
              export http_proxy=http://127.0.0.1:8888
              export https_proxy=http://127.0.0.1:8888
            </pre>
          </li>
          <li>
            <strong>Windows PowerShell</strong>:
            <pre className="proxy-cmd">
              $env:HTTP_PROXY = "http://127.0.0.1:8888"
              $env:HTTPS_PROXY = "http://127.0.0.1:8888"
            </pre>
          </li>
        </ul>
      </section>

      <section>
        <h3>Devices on your network (optional)</h3>
        <p className="muted">
          The default <code>127.0.0.1</code> bind accepts connections
          only from this machine. To capture traffic from a phone or
          another machine, change the listen address in the toolbar to
          your LAN IP (for example <code>192.168.1.10:8888</code>), then
          configure the device's Wi-Fi proxy to the same host/port and
          install the CA on that device. Only do this on trusted
          networks — the proxy does not authenticate clients.
        </p>
      </section>
    </>
  );
}

function SetupScopeRules() {
  const [include, setInclude] = useState<ScopeRule[]>([]);
  const [exclude, setExclude] = useState<ScopeRule[]>([]);
  const [initial, setInitial] = useState<ScopeRules>({
    include: [],
    exclude: [],
  });
  const [status, setStatus] = useState<"idle" | "saving" | "saved">("idle");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    scopeGet()
      .then((rules) => {
        setInclude(rules.include);
        setExclude(rules.exclude);
        setInitial(rules);
      })
      .catch((e) => setError(String(e)));
  }, []);

  const dirty = useMemo(() => {
    return (
      JSON.stringify({ include, exclude }) !==
      JSON.stringify({
        include: initial.include,
        exclude: initial.exclude,
      })
    );
  }, [include, exclude, initial]);

  const addRule = (kind: "include" | "exclude") => {
    const fresh: ScopeRule = { host: "", path_regex: null, port: null };
    if (kind === "include") setInclude((prev) => [...prev, fresh]);
    else setExclude((prev) => [...prev, fresh]);
    setStatus("idle");
  };

  const updateRule = (
    kind: "include" | "exclude",
    index: number,
    patch: Partial<ScopeRule>,
  ) => {
    const setter = kind === "include" ? setInclude : setExclude;
    setter((prev) =>
      prev.map((r, i) => (i === index ? { ...r, ...patch } : r)),
    );
    setStatus("idle");
  };

  const removeRule = (kind: "include" | "exclude", index: number) => {
    const setter = kind === "include" ? setInclude : setExclude;
    setter((prev) => prev.filter((_, i) => i !== index));
    setStatus("idle");
  };

  const handleSave = async () => {
    setStatus("saving");
    setError(null);
    try {
      const payload: ScopeRules = {
        include: include.map(normaliseRule),
        exclude: exclude.map(normaliseRule),
      };
      await scopeSet(payload);
      setInitial(payload);
      setInclude(payload.include);
      setExclude(payload.exclude);
      setStatus("saved");
    } catch (e) {
      setError(String(e));
      setStatus("idle");
    }
  };

  const handleRevert = () => {
    setInclude(initial.include);
    setExclude(initial.exclude);
    setStatus("idle");
    setError(null);
  };

  return (
    <>
      <section>
        <h3>Scope rules</h3>
        <p className="muted">
          Scope decides which requests active features touch. The Traffic
          log always captures everything — scope only gates intercept,
          replay, and active checks. If the include list is empty, every
          request is treated as in-scope; otherwise only matches count.
          Exclude rules always win over include rules.
        </p>
        <ul className="proxy-scope-help">
          <li>
            <strong>Host</strong> supports exact match (
            <code>api.example.com</code>) and a leading wildcard (
            <code>*.example.com</code>). Empty matches any host.
          </li>
          <li>
            <strong>Path regex</strong> is a Rust regex evaluated against
            the request path. Leave blank to match any path.
          </li>
          <li>
            <strong>Port</strong> filters to one port. Leave blank for any
            port.
          </li>
        </ul>
        {error && <div className="proxy-error">{error}</div>}
      </section>

      <ScopeRuleList
        kind="include"
        title="Include"
        hint="Only requests matching at least one include rule are in-scope."
        rules={include}
        onAdd={() => addRule("include")}
        onUpdate={(i, p) => updateRule("include", i, p)}
        onRemove={(i) => removeRule("include", i)}
      />

      <ScopeRuleList
        kind="exclude"
        title="Exclude"
        hint="Matching requests are always out-of-scope, even if an include rule would cover them."
        rules={exclude}
        onAdd={() => addRule("exclude")}
        onUpdate={(i, p) => updateRule("exclude", i, p)}
        onRemove={(i) => removeRule("exclude", i)}
      />

      <section className="proxy-scope-actions">
        <button
          type="button"
          className="chip active"
          onClick={handleSave}
          disabled={!dirty || status === "saving"}
        >
          {status === "saving" ? "Saving…" : "Save scope rules"}
        </button>
        <button
          type="button"
          className="chip"
          onClick={handleRevert}
          disabled={!dirty || status === "saving"}
        >
          Revert
        </button>
        {status === "saved" && !dirty && (
          <span className="muted">Saved — applies to new requests.</span>
        )}
      </section>
    </>
  );
}

function ScopeRuleList({
  kind,
  title,
  hint,
  rules,
  onAdd,
  onUpdate,
  onRemove,
}: {
  kind: "include" | "exclude";
  title: string;
  hint: string;
  rules: ScopeRule[];
  onAdd: () => void;
  onUpdate: (index: number, patch: Partial<ScopeRule>) => void;
  onRemove: (index: number) => void;
}) {
  return (
    <section className="proxy-scope-list">
      <div className="proxy-scope-list-head">
        <h4>
          {title} <span className="muted">({rules.length})</span>
        </h4>
        <button type="button" className="chip" onClick={onAdd}>
          + Add {kind} rule
        </button>
      </div>
      <p className="muted">{hint}</p>
      {rules.length === 0 ? (
        <p className="muted">
          No {kind} rules configured.
          {kind === "include" &&
            " While empty, the proxy treats every non-excluded request as in-scope."}
        </p>
      ) : (
        <ul className="proxy-scope-rules">
          {rules.map((r, i) => (
            <li key={`${kind}-${i}`} className="proxy-scope-rule">
              <label>
                <span className="muted">Host</span>
                <input
                  type="text"
                  className="input input-compact"
                  value={r.host}
                  onChange={(e) => onUpdate(i, { host: e.target.value })}
                  placeholder="*.example.com"
                  spellCheck={false}
                />
              </label>
              <label>
                <span className="muted">Path regex</span>
                <input
                  type="text"
                  className="input input-compact"
                  value={r.path_regex ?? ""}
                  onChange={(e) =>
                    onUpdate(i, {
                      path_regex: e.target.value === "" ? null : e.target.value,
                    })
                  }
                  placeholder="^/api/"
                  spellCheck={false}
                />
              </label>
              <label>
                <span className="muted">Port</span>
                <input
                  type="number"
                  className="input input-compact"
                  value={r.port ?? ""}
                  onChange={(e) => {
                    const parsed = parseInt(e.target.value, 10);
                    onUpdate(i, {
                      port: Number.isFinite(parsed) ? parsed : null,
                    });
                  }}
                  placeholder="any"
                  min={1}
                  max={65535}
                />
              </label>
              <button
                type="button"
                className="link-button"
                onClick={() => onRemove(i)}
              >
                remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function normaliseRule(r: ScopeRule): ScopeRule {
  return {
    host: r.host.trim(),
    path_regex:
      r.path_regex && r.path_regex.trim() !== "" ? r.path_regex.trim() : null,
    port: r.port && r.port > 0 ? r.port : null,
  };
}

function SetupRetention() {
  const [max, setMax] = useState<number>(5000);
  const [initial, setInitial] = useState<number>(5000);
  const [status, setStatus] = useState<"idle" | "saving" | "saved">("idle");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    retentionGet()
      .then((p) => {
        setMax(p.max_exchanges_per_session);
        setInitial(p.max_exchanges_per_session);
      })
      .catch((e) => setError(String(e)));
  }, []);

  const dirty = max !== initial;

  const handleSave = async () => {
    setStatus("saving");
    setError(null);
    try {
      const policy: RetentionPolicy = { max_exchanges_per_session: max };
      await retentionSet(policy);
      setInitial(max);
      setStatus("saved");
    } catch (e) {
      setError(String(e));
      setStatus("idle");
    }
  };

  const handleRevert = () => {
    setMax(initial);
    setStatus("idle");
    setError(null);
  };

  const preset = (n: number) => {
    setMax(n);
    setStatus("idle");
  };

  return (
    <>
      <section>
        <h3>Retention</h3>
        <p className="muted">
          The proxy keeps a ring buffer of the most recent exchanges per
          session. Once a session exceeds the cap, the oldest rows (and
          their dependent scan findings + WebSocket frames) are dropped
          every ~250 ms as new traffic arrives. Retention is per-session
          — each <strong>Start</strong> / <strong>Stop</strong> cycle
          gets its own budget; historical sessions are preserved at
          whatever size they were when they ended.
        </p>
        <p className="muted">
          Set the cap to <code>0</code> to disable eviction entirely
          (unlimited). Anything over 1,000,000 is clamped on save.
        </p>
      </section>

      <section className="proxy-scope-list">
        <div className="proxy-scope-list-head">
          <h4>Max exchanges per session</h4>
          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
            {[1000, 5000, 20000, 100000, 0].map((n) => (
              <button
                key={n}
                type="button"
                className={`chip${max === n ? " active" : ""}`}
                onClick={() => preset(n)}
                title={
                  n === 0
                    ? "Disable eviction — keep everything"
                    : `${n.toLocaleString()} rows per session`
                }
              >
                {n === 0 ? "Unlimited" : n.toLocaleString()}
              </button>
            ))}
          </div>
        </div>
        <label style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className="muted" style={{ minWidth: 80 }}>
            Custom
          </span>
          <input
            type="number"
            className="input input-compact"
            min={0}
            max={1000000}
            step={100}
            value={max}
            onChange={(e) => {
              const n = parseInt(e.target.value, 10);
              setMax(Number.isFinite(n) ? Math.max(0, n) : 0);
              setStatus("idle");
            }}
          />
          <span className="muted">
            {max === 0 ? "unlimited" : `${max.toLocaleString()} rows`}
          </span>
        </label>
        {error && <div className="proxy-error">{error}</div>}
      </section>

      <section className="proxy-scope-actions">
        <button
          type="button"
          className="chip active"
          onClick={handleSave}
          disabled={!dirty || status === "saving"}
        >
          {status === "saving" ? "Saving…" : "Save retention policy"}
        </button>
        <button
          type="button"
          className="chip"
          onClick={handleRevert}
          disabled={!dirty || status === "saving"}
        >
          Revert
        </button>
        {status === "saved" && !dirty && (
          <span className="muted">
            Saved — applies to new exchanges captured after the next
            flush.
          </span>
        )}
      </section>
    </>
  );
}

function SetupVerify() {
  return (
    <section>
      <h3>Confirm it all works</h3>
      <ol className="proxy-steps">
        <li>
          Click <strong>Start</strong> in the toolbar; the status pill
          turns <em>Running</em>.
        </li>
        <li>
          In your configured browser, visit{" "}
          <code>http://example.com</code>. A row should appear in the
          Traffic tab with method <code>GET</code>, status{" "}
          <code>200</code>, and the host{" "}
          <code>example.com</code>.
        </li>
        <li>
          Visit <code>https://example.com</code>. The page should load
          without certificate warnings, and a second row should appear
          with scheme <code>https</code>.
        </li>
        <li>
          Click a row to inline-expand the detail panel (origin, host,
          MIME, scope).
        </li>
        <li>
          Click <strong>Stop</strong>; the listener unbinds cleanly and
          the status pill flips back to <em>Stopped</em>.
        </li>
      </ol>
    </section>
  );
}

function SetupTroubleshoot() {
  return (
    <section>
      <h3>Common issues</h3>
      <dl className="proxy-troubleshoot">
        <dt>Browser shows a certificate warning on HTTPS pages.</dt>
        <dd>
          The CA isn't in the trust store the browser is using. Firefox
          has its own store — re-import under{" "}
          <em>Privacy &amp; Security → Certificates → Authorities</em>.
          On macOS, confirm the certificate is marked{" "}
          <em>Always Trust</em> in Keychain Access. On Windows, the CA
          must land in the <strong>Trusted Root Certification
          Authorities</strong> store, not <em>Personal</em>.
        </dd>

        <dt>The browser connects but no rows appear.</dt>
        <dd>
          The browser is bypassing the proxy for <code>127.0.0.1</code>.
          Some browsers and extensions skip proxies for loopback by
          default. Remove <code>127.0.0.1</code> and <code>localhost</code>{" "}
          from the <em>No proxy for</em> list, or visit a non-loopback
          hostname.
        </dd>

        <dt>Pages hang or fail with a 502 in the Traffic tab.</dt>
        <dd>
          The target host is unreachable from this machine, or it
          enforces certificate pinning (some mobile apps, some banks)
          and rejects the minted leaf certificate. Pinning cannot be
          bypassed by trusting a custom CA — try a different target to
          rule out corvex itself.
        </dd>

        <dt>
          "Start" is disabled with the message{" "}
          <em>CA not ready</em>.
        </dt>
        <dd>
          CA generation failed at launch — usually a permissions issue
          on the app data directory. Check the app log
          (View → Log) for a line tagged{" "}
          <code>proxy</code>.
        </dd>

        <dt>Port 8888 is already in use.</dt>
        <dd>
          Change the listen address in the toolbar (for example{" "}
          <code>127.0.0.1:8889</code>) and update your browser proxy
          settings to match.
        </dd>
      </dl>
    </section>
  );
}

function ProxyChecksTab({
  sessionId,
  targets,
  onClearTargets,
  onRemoveTarget,
}: {
  sessionId: string | null;
  targets: ExchangeSummary[];
  onClearTargets: () => void;
  onRemoveTarget: (id: string) => void;
}) {
  const [descriptors, setDescriptors] = useState<CheckDescriptor[]>([]);
  const [enabled, setEnabled] = useState<Set<string>>(new Set());
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState<string>("");
  const [onlyEnabled, setOnlyEnabled] = useState<boolean>(false);
  const [taxonomy, setTaxonomy] = useState<OwaspTaxonomyInfo | null>(null);

  // Load the check catalog once.
  useEffect(() => {
    checksList()
      .then((list) => {
        setDescriptors(list);
        // Default: all passive checks on (they run automatically anyway
        // — the toggle is informative). Active checks are off.
        const defaults = new Set(
          list.filter((d) => d.kind === "passive").map((d) => d.id),
        );
        setEnabled(defaults);
      })
      .catch((e) => setError(String(e)));
  }, []);

  // Load the OWASP taxonomy once so the banner + category tooltips
  // always reflect the version shipped in the current binary.
  useEffect(() => {
    owaspTaxonomyInfo().then(setTaxonomy).catch(() => {});
  }, []);

  // Hydrate findings for the current session and stream new ones live.
  useEffect(() => {
    if (!sessionId) {
      setFindings([]);
      return;
    }
    findingsForSession(sessionId, 500).then(setFindings).catch(() => {});
    let unlisten: (() => void) | null = null;
    onScanFinding((live: LiveFindingPayload) => {
      // Adapt the live payload to the stored-row shape.
      setFindings((prev) => [
        {
          id: live.id,
          exchange_id: live.exchange_id,
          check_id: live.check_id,
          severity:
            (live.severity as FindingRow["severity"]) ?? "info",
          title: live.title,
          description: live.description,
          evidence: live.evidence,
          created_at_unix: Math.floor(Date.now() / 1000),
        },
        ...prev,
      ]);
    })
      .then((fn) => {
        unlisten = fn;
      })
      .catch(() => {});
    return () => {
      if (unlisten) unlisten();
    };
  }, [sessionId]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return descriptors.filter((d) => {
      if (onlyEnabled && !enabled.has(d.id)) return false;
      if (!q) return true;
      return (
        d.name.toLowerCase().includes(q) ||
        d.id.toLowerCase().includes(q) ||
        d.category.toLowerCase().includes(q) ||
        d.category_label.toLowerCase().includes(q) ||
        d.kind.toLowerCase().includes(q) ||
        d.description.toLowerCase().includes(q)
      );
    });
  }, [descriptors, query, onlyEnabled, enabled]);

  const grouped = useMemo(() => {
    const map = new Map<string, CheckDescriptor[]>();
    for (const d of filtered) {
      const key = `${d.category} — ${d.category_label}`;
      const arr = map.get(key) ?? [];
      arr.push(d);
      map.set(key, arr);
    }
    return Array.from(map.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  }, [filtered]);

  const totalCount = descriptors.length;
  const visibleCount = filtered.length;

  const toggle = (id: string) =>
    setEnabled((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const activeSelected = Array.from(enabled).filter(
    (id) => descriptors.find((d) => d.id === id)?.kind === "active",
  );

  const handleRun = async () => {
    if (targets.length === 0 || activeSelected.length === 0) return;
    setRunning(true);
    setError(null);
    try {
      await checksRun(
        targets.map((t) => t.id),
        activeSelected,
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="proxy-checks">
      <section>
        <h3>Checks</h3>
        {taxonomy && (
          <div className="proxy-taxonomy-banner" title={taxonomy.source ?? undefined}>
            <span className="proxy-taxonomy-chip">OWASP Top 10</span>
            <strong>v{taxonomy.version}</strong>
            {taxonomy.released && (
              <span className="muted">· released {taxonomy.released}</span>
            )}
            {taxonomy.source && (
              <a
                className="proxy-taxonomy-source"
                href={taxonomy.source}
                target="_blank"
                rel="noreferrer"
                title="Open the official OWASP Top 10 page in your browser"
              >
                owasp.org
              </a>
            )}
          </div>
        )}
        <p className="muted">
          Passive checks (
          {descriptors.filter((d) => d.kind === "passive").length})
          {" "}run automatically on every in-scope exchange. Active checks
          send additional probes against the targets you queue below.
          Category headers below are sourced from the active taxonomy —
          hover ⓘ for the OWASP description.
        </p>
        {error && <div className="proxy-error">{error}</div>}
      </section>

      <div className="proxy-checks-layout">
        <aside className="proxy-checks-library">
          <div className="proxy-checks-library-head">
            <h4>
              Library (OWASP) · {visibleCount}
              {visibleCount !== totalCount ? ` / ${totalCount}` : ""}
            </h4>
            <div className="proxy-checks-search">
              <input
                type="search"
                className="input input-compact"
                placeholder="Search by name, id, category, tag…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                spellCheck={false}
              />
              {query && (
                <button
                  type="button"
                  className="link-button"
                  onClick={() => setQuery("")}
                  title="Clear search"
                >
                  clear
                </button>
              )}
              <label className="proxy-checks-search-toggle">
                <input
                  type="checkbox"
                  checked={onlyEnabled}
                  onChange={(e) => setOnlyEnabled(e.target.checked)}
                />
                <span>Enabled only</span>
              </label>
            </div>
          </div>
          {grouped.length === 0 && (
            <p className="muted">No checks match that search.</p>
          )}
          {grouped.map(([group, items]) => {
            // Pick the description from the first descriptor in the
            // group (they all share a category, so all descriptions
            // are identical). Falls back to the first non-null.
            const groupDescription =
              items.find((d) => d.category_description)?.category_description ??
              null;
            return (
            <div className="proxy-checks-group" key={group}>
              <div
                className="proxy-checks-group-label"
                title={groupDescription ?? undefined}
              >
                {group}
                {groupDescription && <span className="proxy-checks-group-hint">ⓘ</span>}
              </div>
              <ul>
                {items.map((d) => (
                  <li key={d.id} className="proxy-checks-item">
                    <label>
                      <input
                        type="checkbox"
                        checked={enabled.has(d.id)}
                        onChange={() => toggle(d.id)}
                      />
                      <span className={`badge-inline sev-${d.default_severity}`}>
                        {d.default_severity}
                      </span>
                      <span className="proxy-checks-kind">{d.kind}</span>
                      <span className="proxy-checks-name">{d.name}</span>
                    </label>
                    <div className="proxy-checks-desc">{d.description}</div>
                  </li>
                ))}
              </ul>
            </div>
            );
          })}
        </aside>

        <div className="proxy-checks-main">
          <section>
            <h4>Targets ({targets.length})</h4>
            {targets.length === 0 ? (
              <p className="muted">
                Pick rows from the Traffic tab and click{" "}
                <strong>Send to Checks</strong> to queue them here.
              </p>
            ) : (
              <ul className="proxy-checks-targets">
                {targets.map((t) => (
                  <li key={t.id}>
                    <span className="badge-inline">{t.method}</span>
                    <span className="proxy-intercept-url">
                      {t.scheme}://{t.host}
                      {t.path}
                    </span>
                    <button
                      type="button"
                      className="link-button"
                      onClick={() => onRemoveTarget(t.id)}
                    >
                      remove
                    </button>
                  </li>
                ))}
              </ul>
            )}
            <div className="proxy-checks-actions">
              <button
                type="button"
                className="chip active"
                disabled={running || activeSelected.length === 0 || targets.length === 0}
                onClick={handleRun}
              >
                {running
                  ? "Running…"
                  : `Run ${activeSelected.length} active check(s) on ${targets.length} target(s)`}
              </button>
              <button
                type="button"
                className="chip"
                disabled={targets.length === 0}
                onClick={onClearTargets}
              >
                Clear targets
              </button>
            </div>
          </section>

          <section>
            <h4>Findings ({findings.length})</h4>
            {findings.length === 0 ? (
              <p className="muted">No findings yet.</p>
            ) : (
              <ul className="proxy-findings">
                {findings.map((f) => (
                  <li key={f.id} className={`proxy-finding sev-${f.severity}`}>
                    <div className="proxy-finding-head">
                      <span className={`badge-inline sev-${f.severity}`}>
                        {f.severity}
                      </span>
                      <span className="proxy-finding-title">{f.title}</span>
                      <span className="muted proxy-finding-check">
                        {f.check_id}
                      </span>
                    </div>
                    {f.description && (
                      <div className="proxy-finding-desc">{f.description}</div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}


function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function isWebsocketExchange(ex: ExchangeSummary): boolean {
  return ex.tags.includes("websocket");
}

function WsFrameViewer({ exchange }: { exchange: ExchangeSummary }) {
  const [frames, setFrames] = useState<WsFrame[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const extension = exchange.tags.includes("ws-extension");

  useEffect(() => {
    wsFramesForExchange(exchange.id)
      .then(setFrames)
      .catch((e) => setError(String(e)));
    let unlisten: (() => void) | null = null;
    onWsFrame((frame) => {
      if (frame.exchange_id !== exchange.id) return;
      setFrames((prev) => [...prev, frame]);
    })
      .then((fn) => {
        unlisten = fn;
      })
      .catch(() => {});
    return () => {
      if (unlisten) unlisten();
    };
  }, [exchange.id]);

  const selectedFrame =
    selected !== null
      ? frames.find(
          (f) =>
            f.sequence === selected ||
            `${f.direction}-${f.sequence}` === String(selected),
        ) ?? null
      : null;

  return (
    <div
      className="ws-frames"
      onClick={(e) => e.stopPropagation()}
    >
      <div className="ws-frames-head">
        <strong>WebSocket frames</strong>
        <span className="muted">
          · {frames.length} captured
          {frames.length === 0 ? " (waiting for first frame)" : ""}
        </span>
        {extension && (
          <span
            className="badge-inline"
            data-status="warn"
            title="Upstream negotiated a WebSocket extension (e.g. permessage-deflate). Payloads are captured as-is; text preview may be compressed."
          >
            extension active
          </span>
        )}
      </div>
      {error && <div className="proxy-error">{error}</div>}
      {frames.length > 0 && (
        <div className="ws-frames-layout">
          <ul className="ws-frames-list">
            {frames.map((f) => {
              const key = `${f.direction}-${f.sequence}`;
              const active =
                selectedFrame &&
                selectedFrame.direction === f.direction &&
                selectedFrame.sequence === f.sequence;
              return (
                <li
                  key={key}
                  className={`ws-frame-row dir-${f.direction}${
                    active ? " active" : ""
                  }`}
                  onClick={() => setSelected(f.sequence)}
                >
                  <span
                    className={`badge-inline ws-dir-${f.direction}`}
                    title={
                      f.direction === "client"
                        ? "browser → upstream"
                        : "upstream → browser"
                    }
                  >
                    {f.direction === "client" ? "→" : "←"}
                  </span>
                  <span className="badge-inline">{f.opcode_label}</span>
                  <span className="muted">#{f.sequence}</span>
                  <span className="ws-frame-preview mono trunc">
                    {framePreview(f, 80)}
                  </span>
                  <span className="muted">
                    {humanSize(f.payload_size)}
                  </span>
                </li>
              );
            })}
          </ul>
          {selectedFrame && (
            <div className="ws-frame-detail">
              <div className="muted">
                Frame #{selectedFrame.sequence} ·{" "}
                {selectedFrame.direction} ·{" "}
                <code>{selectedFrame.opcode_label}</code>
                {!selectedFrame.fin && " · fragment"} ·{" "}
                {humanSize(selectedFrame.payload_size)}
              </div>
              <pre className="ws-frame-payload">
                {framePayload(selectedFrame)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function framePreview(frame: WsFrame, limit: number): string {
  if (frame.payload_size === 0) return "—";
  if (frame.opcode_label === "text") {
    const text = decodePayload(frame);
    return text.slice(0, limit).replace(/\s+/g, " ");
  }
  if (frame.opcode_label === "close") {
    const bytes = base64ToBytes(frame.payload_base64);
    if (bytes.length >= 2) {
      const code = (bytes[0] << 8) | bytes[1];
      const reason = new TextDecoder("utf-8", { fatal: false })
        .decode(bytes.slice(2))
        .slice(0, limit);
      return `code ${code}${reason ? ` — ${reason}` : ""}`;
    }
    return "no-reason";
  }
  // binary, ping, pong: show a hex-ish preview
  const bytes = base64ToBytes(frame.payload_base64);
  return Array.from(bytes.slice(0, Math.min(bytes.length, limit / 3)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(" ");
}

function framePayload(frame: WsFrame): string {
  if (frame.payload_size === 0) return "<empty frame>";
  if (frame.opcode_label === "text") return decodePayload(frame);
  const bytes = base64ToBytes(frame.payload_base64);
  if (bytes.length === 0) {
    return "<payload too large to capture (forwarded raw)>";
  }
  // Hex + ASCII dump, 16 bytes per row.
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const row = bytes.slice(offset, offset + 16);
    const hex = Array.from(row)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ")
      .padEnd(48, " ");
    const ascii = Array.from(row)
      .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(
      `${offset.toString(16).padStart(6, "0")}  ${hex}  ${ascii}`,
    );
  }
  return lines.join("\n");
}

function decodePayload(frame: WsFrame): string {
  const bytes = base64ToBytes(frame.payload_base64);
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

function base64ToBytes(b64: string): Uint8Array {
  try {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return new Uint8Array();
  }
}

function exchangeUrl(ex: ExchangeSummary): string {
  const defaultPort =
    (ex.scheme === "https" && ex.port === 443) ||
    (ex.scheme === "http" && ex.port === 80);
  const authority = defaultPort ? ex.host : `${ex.host}:${ex.port}`;
  const query = ex.query ? `?${ex.query}` : "";
  return `${ex.scheme}://${authority}${ex.path}${query}`;
}

// --- Intercept tab -------------------------------------------------------

const INTERCEPT_MODES: { value: InterceptMode; label: string }[] = [
  { value: "off", label: "Off" },
  { value: "request", label: "Request" },
  { value: "response", label: "Response" },
  { value: "both", label: "Both" },
];

function ProxyInterceptTab() {
  const [mode, setMode] = useState<InterceptMode>("off");
  const [pending, setPending] = useState<PendingIntercept[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editor, setEditor] = useState<string>("");
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selected = useMemo(
    () => pending.find((p) => p.id === selectedId) ?? null,
    [pending, selectedId],
  );

  const refresh = useCallback(async () => {
    try {
      const [m, list] = await Promise.all([
        interceptGetMode(),
        interceptPendingList(),
      ]);
      setMode(m);
      setPending(list);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
    let unlisten: (() => void) | null = null;
    onInterceptPending(() => {
      refresh();
    })
      .then((fn) => {
        unlisten = fn;
      })
      .catch(() => {});
    return () => {
      if (unlisten) unlisten();
    };
  }, [refresh]);

  // Reset editor when a new pending item is selected or pending list
  // changes out from under us.
  useEffect(() => {
    if (!selected) {
      setEditor("");
      setDirty(false);
      return;
    }
    try {
      const decoded = atob(selected.raw_bytes_base64);
      setEditor(decoded);
      setDirty(false);
    } catch {
      setEditor("");
    }
  }, [selected]);

  const handleModeChange = async (m: InterceptMode) => {
    setError(null);
    try {
      await interceptSetMode(m);
      setMode(m);
      if (m === "off") {
        // Backend releases pending exchanges when switching off;
        // refresh so the UI doesn't show stale rows.
        await refresh();
      }
    } catch (e) {
      setError(String(e));
    }
  };

  const handleForward = async () => {
    if (!selected) return;
    setError(null);
    try {
      if (dirty) {
        const encoded = btoa(editor);
        await interceptResolve(selected.id, {
          kind: "forward_edited",
          bytes_base64: encoded,
        });
      } else {
        await interceptResolve(selected.id, { kind: "forward" });
      }
      await refresh();
      setSelectedId(null);
    } catch (e) {
      setError(String(e));
    }
  };

  const handleDrop = async () => {
    if (!selected) return;
    setError(null);
    try {
      await interceptResolve(selected.id, { kind: "drop" });
      await refresh();
      setSelectedId(null);
    } catch (e) {
      setError(String(e));
    }
  };

  const handleDropAll = async () => {
    setError(null);
    try {
      await interceptDropAll();
      await refresh();
      setSelectedId(null);
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="proxy-intercept">
      <section>
        <h3>Intercept mode</h3>
        <div className="proxy-mode-row">
          {INTERCEPT_MODES.map((m) => (
            <button
              key={m.value}
              type="button"
              className={`chip${mode === m.value ? " active" : ""}`}
              onClick={() => handleModeChange(m.value)}
            >
              {m.label}
            </button>
          ))}
          <button
            type="button"
            className="chip"
            onClick={handleDropAll}
            disabled={pending.length === 0}
            title="Release every pending intercept with Forward"
          >
            Drop all
          </button>
        </div>
        <p className="muted">
          When intercept is on, in-scope exchanges pause here. The
          <strong> Request</strong> phase pauses before forwarding
          upstream — you edit the request line, headers, or body before
          it leaves. The <strong>Response</strong> phase pauses after the
          upstream reply arrives but before it reaches the client —
          useful for tweaking status codes, headers, or response bodies
          on the fly. Out-of-scope traffic is never paused; configure
          scope rules on the Settings tab.
        </p>
        {error && <div className="proxy-error">{error}</div>}
      </section>

      <div className="proxy-intercept-layout">
        <aside className="proxy-intercept-queue">
          <h4>Pending ({pending.length})</h4>
          {pending.length === 0 ? (
            <p className="muted">No paused exchanges.</p>
          ) : (
            <ul>
              {pending.map((p) => (
                <li
                  key={p.id}
                  className={`proxy-intercept-item phase-${p.phase}${
                    selectedId === p.id ? " active" : ""
                  }`}
                  onClick={() => setSelectedId(p.id)}
                >
                  <span
                    className={`badge-inline phase-${p.phase}`}
                    title={
                      p.phase === "response"
                        ? "Upstream reply paused before delivery to the client"
                        : "Request paused before forwarding upstream"
                    }
                  >
                    {p.phase === "response" ? "← resp" : "→ req"}
                  </span>
                  <span className="badge-inline">{p.method}</span>
                  <span className="proxy-intercept-url">
                    {p.scheme}://{p.host}:{p.port}
                    {p.uri}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </aside>

        <div className="proxy-intercept-editor">
          {selected ? (
            <>
              <div className="proxy-intercept-toolbar">
                <span className="muted">
                  {selected.phase === "response" ? (
                    <>
                      Editing the raw <strong>response</strong> — status
                      line first (e.g.{" "}
                      <code>HTTP/1.1 200 OK</code>), then headers, blank
                      line, body. Forward sends the edited reply to the
                      client; Drop returns a 502 instead.
                    </>
                  ) : (
                    <>
                      Editing the raw <strong>request</strong> — request
                      line first (e.g.{" "}
                      <code>GET /path HTTP/1.1</code>), then headers,
                      blank line, body. Forward sends the edited request
                      upstream; Drop returns a 502 to the client.
                    </>
                  )}
                </span>
              </div>
              <textarea
                className="proxy-wire-editor"
                value={editor}
                spellCheck={false}
                onChange={(e) => {
                  setEditor(e.target.value);
                  setDirty(true);
                }}
              />
              <div className="proxy-intercept-actions">
                <button
                  type="button"
                  className="chip active"
                  onClick={handleForward}
                >
                  {dirty
                    ? selected.phase === "response"
                      ? "Forward edited response"
                      : "Forward edited request"
                    : selected.phase === "response"
                      ? "Forward response"
                      : "Forward request"}
                </button>
                <button type="button" className="chip" onClick={handleDrop}>
                  {selected.phase === "response"
                    ? "Drop response"
                    : "Drop request"}
                </button>
              </div>
            </>
          ) : (
            <p className="muted">Pick a pending exchange to inspect.</p>
          )}
        </div>
      </div>
    </div>
  );
}

// --- Replay tab ----------------------------------------------------------

function ProxyReplayTab({
  base,
  onChangeBase,
}: {
  base: ExchangeSummary | null;
  onChangeBase: (ex: ExchangeSummary | null) => void;
}) {
  const [editor, setEditor] = useState<string>("");
  const [initial, setInitial] = useState<string>("");
  const [response, setResponse] = useState<ReplayResult | null>(null);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!base) {
      setEditor("");
      setInitial("");
      setResponse(null);
      return;
    }
    // Hydrate the editor from the stored detail so edits start from the
    // real wire bytes the proxy forwarded.
    exchangeGet(base.id)
      .then((detail) => {
        if (!detail) return;
        const lines: string[] = [];
        const scheme = detail.scheme;
        const path = detail.query
          ? `${detail.path}?${detail.query}`
          : detail.path;
        lines.push(`${detail.method} ${path} HTTP/1.1`);
        let hasHost = false;
        for (const [k, v] of detail.request_headers) {
          if (k.toLowerCase() === "host") hasHost = true;
          lines.push(`${k}: ${v}`);
        }
        if (!hasHost) {
          const needsPort =
            (scheme === "http" && detail.port !== 80) ||
            (scheme === "https" && detail.port !== 443);
          lines.push(
            `Host: ${detail.host}${needsPort ? `:${detail.port}` : ""}`,
          );
        }
        const body = detail.request_body_base64
          ? atob(detail.request_body_base64)
          : "";
        const raw = `${lines.join("\r\n")}\r\n\r\n${body}`;
        setEditor(raw);
        setInitial(raw);
        setResponse(null);
      })
      .catch((e) => setError(String(e)));
  }, [base]);

  const dirty = editor !== initial;

  const handleSend = async () => {
    if (!base) return;
    setSending(true);
    setError(null);
    try {
      const edited = dirty ? btoa(editor) : null;
      const r = await replaySend(base.id, edited);
      setResponse(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setSending(false);
    }
  };

  if (!base) {
    return (
      <div className="proxy-empty">
        <h3>Replay</h3>
        <p className="muted">
          Expand any row in the Traffic tab and click{" "}
          <strong>Send to Replay</strong> to load it here. Edit the raw
          bytes and hit Send — the result is captured as a new row in
          the Traffic log linked back to the original exchange.
        </p>
      </div>
    );
  }

  const responseBody = response?.response_body_base64
    ? (() => {
        try {
          return atob(response.response_body_base64);
        } catch {
          return "<binary body>";
        }
      })()
    : "";

  return (
    <div className="proxy-replay">
      <div className="proxy-replay-toolbar">
        <span>
          Base: <code>{base.method}</code> {base.scheme}://{base.host}
          {base.path}
        </span>
        <div>
          <button
            type="button"
            className="chip active"
            disabled={sending}
            onClick={handleSend}
          >
            {sending ? "Sending…" : dirty ? "Send (edited)" : "Send"}
          </button>
          <button
            type="button"
            className="chip"
            onClick={() => onChangeBase(null)}
          >
            Clear
          </button>
        </div>
      </div>

      <div className="proxy-replay-split">
        <div className="proxy-replay-pane">
          <h4>Request</h4>
          <textarea
            className="proxy-wire-editor"
            value={editor}
            spellCheck={false}
            onChange={(e) => setEditor(e.target.value)}
          />
        </div>
        <div className="proxy-replay-pane">
          <h4>Response</h4>
          {response ? (
            <>
              <p className="muted">
                Status <strong>{response.status ?? "—"}</strong> ·{" "}
                {response.duration_ms ?? "?"} ms
              </p>
              <pre className="proxy-response-headers">
                {response.response_headers
                  .map(([k, v]) => `${k}: ${v}`)
                  .join("\n")}
              </pre>
              <pre className="proxy-response-body">{responseBody}</pre>
            </>
          ) : (
            <p className="muted">Hit Send to run the request.</p>
          )}
        </div>
      </div>

      {error && <div className="proxy-error">{error}</div>}
    </div>
  );
}
