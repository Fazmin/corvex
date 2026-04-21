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
