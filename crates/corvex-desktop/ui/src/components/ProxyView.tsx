import { useCallback, useEffect, useMemo, useState } from "react";
import {
  exchangesList,
  exchangeGet,
  interceptDropAll,
  interceptGetMode,
  interceptPendingList,
  interceptResolve,
  interceptSetMode,
  onInterceptPending,
  onProxyExchange,
  proxyExportCaPem,
  proxyStart,
  proxyStatus,
  proxyStop,
  replaySend,
  type ExchangeSummary,
  type InterceptMode,
  type PendingIntercept,
  type ProxyStatus,
  type ReplayResult,
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
  const [replayBase, setReplayBase] = useState<ExchangeSummary | null>(null);

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
            <ProxyTrafficTab
              exchanges={exchanges}
              running={running}
              onSendToReplay={(ex) => {
                setReplayBase(ex);
                setTab("replay");
              }}
            />
          )}
          {tab === "intercept" && <ProxyInterceptTab />}
          {tab === "replay" && (
            <ProxyReplayTab base={replayBase} onChangeBase={setReplayBase} />
          )}
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
  onSendToReplay,
}: {
  exchanges: ExchangeSummary[];
  running: boolean;
  onSendToReplay: (ex: ExchangeSummary) => void;
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
                      <div className="proxy-detail-actions">
                        <button
                          type="button"
                          className="chip"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSendToReplay(ex);
                          }}
                        >
                          Send to Replay
                        </button>
                      </div>
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

type SettingsSection = "overview" | "ca" | "browser" | "verify" | "troubleshoot";

const SETTINGS_SECTIONS: { id: SettingsSection; label: string }[] = [
  { id: "overview", label: "1. Overview" },
  { id: "ca", label: "2. Certificate authority" },
  { id: "browser", label: "3. Browser setup" },
  { id: "verify", label: "4. Verify" },
  { id: "troubleshoot", label: "5. Troubleshooting" },
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

function ProxyPlaceholderTab({ kind }: { kind: "checks" }) {
  const copy: Record<typeof kind, { title: string; body: string }> = {
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
          When intercept is on, in-scope requests pause here before the
          proxy forwards them. Pick one from the queue below to inspect
          or edit before forwarding. Out-of-scope traffic is never
          paused — configure scope rules on the Settings tab.
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
                  className={`proxy-intercept-item${
                    selectedId === p.id ? " active" : ""
                  }`}
                  onClick={() => setSelectedId(p.id)}
                >
                  <span className="badge-inline">{p.method}</span>
                  <span className="proxy-intercept-url">
                    {p.scheme}://{p.host}:{p.port}
                    {p.uri}
                  </span>
                  <span className="muted">{p.phase}</span>
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
                  Edit the raw HTTP/1 bytes below. Keep the blank line
                  between headers and body. Changes only go on the wire
                  when you click Forward.
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
                  {dirty ? "Forward edited" : "Forward"}
                </button>
                <button type="button" className="chip" onClick={handleDrop}>
                  Drop
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
