import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createRafBatcher } from "../util/rafBatch";
import { AssetLink } from "./asset/AssetLink";
import { InfoTip } from "./InfoTip";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import {
  browserBack,
  browserCaStatus,
  browserClose,
  browserCreate,
  browserForward,
  browserHide,
  browserInstallCa,
  browserNavigate,
  browserReload,
  browserSetBounds,
  browserShow,
  browserStop,
  checksList,
  checksRun,
  clusterInstances,
  csrfClearSession,
  csrfRulesGet,
  csrfRulesResetDefaults,
  csrfRulesSet,
  csrfStatus,
  exchangesClusteredList,
  exchangesList,
  exchangeGet,
  findingsForSession,
  interceptDropAll,
  interceptGetMode,
  interceptPendingList,
  interceptResolve,
  interceptRulesGet,
  interceptRulesSet,
  interceptSetMode,
  onBrowserNavigated,
  onCsrfObserved,
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
  type ClusterAnomaly,
  type CsrfObservation,
  type CsrfRule,
  type EndpointCluster,
  type ExchangeSummary,
  type FindingRow,
  type InterceptMode,
  type InterceptRule,
  type LiveFindingPayload,
  type OwaspTaxonomyInfo,
  type PendingIntercept,
  type PhaseFilter,
  type RuleCondition,
  type RuleKind,
  type ProxyStatus,
  type ReplayResult,
  type RetentionPolicy,
  type ScopeRule,
  type ScopeRules,
  type TokenInject,
  type TokenSource,
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

const TAB_HELP: Record<Tab, React.ReactNode> = {
  traffic: (
    <>
      <strong>Traffic</strong>
      Live, read-only log of every HTTP/HTTPS exchange the proxy
      captured during the active session. Each row shows method,
      status, host, path, and timing. Click a row to expand the full
      raw request and response bytes with body decoding. From there
      you can <em>Send to Replay</em> (re-fire the request with
      edits), <em>Send to Checks</em> (queue it for active or
      passive vulnerability checks), or copy any header / cookie /
      body for use elsewhere. Group by endpoint to fold variants of
      the same URL into clusters.
    </>
  ),
  intercept: (
    <>
      <strong>Intercept</strong>
      Pause in-scope traffic mid-flight so you can inspect, edit, or
      drop it before it reaches the upstream (Request mode) or the
      client (Response mode). Pick a mode chip to turn it on, then
      paused exchanges show up in the <em>Pending</em> queue for you
      to step through. The <em>Browser</em> sub-tab hosts an embedded
      WebView2 routed through the corvex proxy, so you can drive a
      target without touching system proxy settings.
    </>
  ),
  replay: (
    <>
      <strong>Replay</strong>
      Take any captured request, edit the raw bytes (method, path,
      headers, body), and re-fire it through the proxy. Useful for
      probing how an endpoint reacts to mutated input (IDOR, type
      confusion, missing fields), for re-running a request after a
      session refresh, or for crafting a one-off PoC payload. Replays
      reuse the captured cookies and the live CSRF token store, so
      you do not have to rebuild auth state by hand.
    </>
  ),
  checks: (
    <>
      <strong>Checks</strong>
      Vulnerability checks organized by OWASP category. Two flavours:
      <em> passive</em> checks read captured exchanges and flag issues
      from headers, bodies, and cookies (missing security headers,
      verbose errors, dangerous CORS, etc.); <em>active</em> checks
      send extra crafted requests to probe behaviour (XSS reflection,
      open redirect, SSRF probes, IDOR comparisons, and so on). Queue
      specific exchanges via <em>Send to Checks</em> from the Traffic
      tab, then run individual checks or whole categories from here.
    </>
  ),
  settings: (
    <>
      <strong>Settings</strong>
      Per-session knobs that control how the proxy behaves: listen
      address and port, scope rules (which hosts and paths the proxy
      treats as in-scope for capture vs pass-through), conditional
      intercept rules (narrow what the mode toggle pauses), CSRF
      token automation (auto-extract and re-inject CSRF tokens
      across requests), retention policy (max exchanges per session
      before old rows roll off), and the one-time CA export for
      installing the corvex root certificate into your system trust
      store.
    </>
  ),
};

/**
 * Top-level Proxy view. Hosts the toolbar + tabbed sub-views.
 *
 * This milestone ships the Traffic list and Settings (CA export +
 * listen address) panes. Intercept / Replay / Checks render
 * placeholders describing what's coming in the next milestones so the
 * navigation feels complete today.
 */
// Re-export the canonical FuzzerSeed / PathSegmentHint definitions
// from App.tsx so call sites that already imported from this module
// keep working. The shape lives in App.tsx because it's used as the
// shared bus type across views (Traffic, Recon, Fuzzing).
import type { FuzzerSeed, PathSegmentHint } from "../App";
export type { FuzzerSeed, PathSegmentHint };

/** Build a sample URL from a cluster pattern, replacing each
 *  placeholder with a representative sentinel so the fuzzer's URL
 *  parser accepts it. The fuzzer only uses the host/path shape; the
 *  injection hints carry the real semantics. */
function clusterPatternUrl(cluster: EndpointCluster): string {
  const path = cluster.pattern.replace(
    /:(id|oid|uuid|slug)\b/g,
    (_m, kind: string) => {
      switch (kind) {
        case "id":
          return "1";
        case "oid":
          return "507f1f77bcf86cd799439011";
        case "uuid":
          return "00000000-0000-0000-0000-000000000000";
        default:
          return "FUZZ";
      }
    },
  );
  const portPart =
    (cluster.scheme === "https" && cluster.port === 443) ||
    (cluster.scheme === "http" && cluster.port === 80)
      ? ""
      : `:${cluster.port}`;
  return `${cluster.scheme}://${cluster.host}${portPart}${path}`;
}

function pathSegmentHintsFromPattern(pattern: string): PathSegmentHint[] {
  const segments = pattern.replace(/^\//, "").split("/");
  const hints: PathSegmentHint[] = [];
  segments.forEach((seg, idx) => {
    const m = /^:(id|uuid|oid|slug)/.exec(seg);
    if (m) {
      hints.push({ kind: "path_segment", index: idx, placeholder: m[1] });
    }
  });
  return hints;
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
    const batcher = createRafBatcher<ExchangeSummary>((batch) => {
      // Dedupe by exchange id — in React 18 strict-mode the effect
      // mounts the listener twice in dev builds, and the backend can
      // also emit a refresh for the same exchange when its intercept
      // state or tags change. Either way we want one row per id.
      setExchanges((prev) => {
        const seen = new Set(prev.map((p) => p.id));
        const fresh: ExchangeSummary[] = [];
        for (const s of batch) {
          if (!seen.has(s.id)) {
            seen.add(s.id);
            fresh.push(s);
          }
        }
        if (fresh.length === 0) return prev;
        // Reverse so the newest arrival is first within the batch,
        // matching the original per-event prepend order.
        fresh.reverse();
        return [...fresh, ...prev].slice(0, 1000);
      });
    });
    onProxyExchange((summary) => {
      batcher.push(summary);
    })
      .then((fn) => {
        unlisten = fn;
      })
      .catch(() => {
        // event bus not ready yet — ignore
      });
    return () => {
      if (unlisten) unlisten();
      batcher.dispose();
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
            <span
              key={t}
              style={{ display: "inline-flex", alignItems: "center", gap: 4 }}
            >
              <button
                type="button"
                className={`chip${tab === t ? " active" : ""}`}
                onClick={() => setTab(t)}
              >
                {TAB_LABELS[t]}
              </button>
              <InfoTip label={`${TAB_LABELS[t]} tab help`}>
                {TAB_HELP[t]}
              </InfoTip>
            </span>
          ))}
        </div>

        <div className="proxy-tab-body">
          {tab === "traffic" && (
            <ProxyTrafficTab
              exchanges={exchanges}
              running={running}
              sessionId={status?.session_id ?? null}
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
              onSendClusterToChecks={(instances) => {
                // Bulk-add cluster members to the Checks tab queue. The
                // dedup-by-id check prevents the second click on the
                // same expanded cluster from doubling rows.
                setCheckTargets((prev) => {
                  const seen = new Set(prev.map((p) => p.id));
                  const next = [...prev];
                  for (const ex of instances) {
                    if (!seen.has(ex.id)) {
                      next.push(ex);
                      seen.add(ex.id);
                    }
                  }
                  return next;
                });
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
              onSendClusterToFuzzer={
                onSendToFuzzer
                  ? (cluster) => {
                      // Cluster patterns map to path-segment injection
                      // points so the fuzzer can substitute :id / :uuid /
                      // :slug placeholders with attack payloads.
                      onSendToFuzzer({
                        url: clusterPatternUrl(cluster),
                        cluster: {
                          method: cluster.method,
                          host: cluster.host,
                          port: cluster.port,
                          scheme: cluster.scheme,
                          pattern: cluster.pattern,
                        },
                        injectionHints: pathSegmentHintsFromPattern(
                          cluster.pattern,
                        ),
                      });
                    }
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

const GROUPED_STORAGE_KEY = "corvexTrafficGrouped";

function ProxyTrafficTab({
  exchanges,
  running,
  sessionId,
  onSendToReplay,
  onSendToChecks,
  onSendToFuzzer,
  onSendClusterToFuzzer,
  onSendClusterToChecks,
}: {
  exchanges: ExchangeSummary[];
  running: boolean;
  sessionId: string | null;
  onSendToReplay: (ex: ExchangeSummary) => void;
  onSendToChecks: (ex: ExchangeSummary) => void;
  onSendToFuzzer?: (ex: ExchangeSummary) => void;
  onSendClusterToFuzzer?: (cluster: EndpointCluster) => void;
  onSendClusterToChecks?: (instances: ExchangeSummary[]) => void;
}) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [grouped, setGrouped] = useState<boolean>(() => {
    try {
      return localStorage.getItem(GROUPED_STORAGE_KEY) === "1";
    } catch {
      return false;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(GROUPED_STORAGE_KEY, grouped ? "1" : "0");
    } catch {
      // localStorage unavailable (private mode) — view-only toggle.
    }
  }, [grouped]);

  const toolbar = (
    <div className="proxy-traffic-toolbar">
      <span className="muted" style={{ fontSize: 12 }}>View</span>
      <button
        type="button"
        className={`chip${!grouped ? " active" : ""}`}
        onClick={() => setGrouped(false)}
      >
        Flat
      </button>
      <button
        type="button"
        className={`chip${grouped ? " active" : ""}`}
        onClick={() => setGrouped(true)}
        title="Collapse /api/users/1, /api/users/2, … into one /api/users/:id row with anomaly badges"
      >
        Group by endpoint
      </button>
    </div>
  );

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

  if (grouped) {
    return (
      <div className="proxy-traffic-wrap">
        {toolbar}
        <ProxyClusteredView
          sessionId={sessionId}
          exchangeCount={exchanges.length}
          onSendClusterToFuzzer={onSendClusterToFuzzer}
          onSendClusterToChecks={onSendClusterToChecks}
        />
      </div>
    );
  }

  return (
    <div className="proxy-traffic-wrap">
    {toolbar}
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
                  <span style={{ marginLeft: 6, verticalAlign: "middle" }}>
                    <AssetLink host={ex.host} port={ex.port} />
                  </span>
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

const ANOMALY_LABEL: Record<ClusterAnomaly, string> = {
  auth_mismatch: "auth mismatch",
  status_outlier: "status outlier",
  size_outlier: "size outlier",
  rate_limited: "rate limited",
};

const ANOMALY_TITLE: Record<ClusterAnomaly, string> = {
  auth_mismatch:
    "Members are split on the Authorization header — mixing logged-in and anonymous traffic on the same endpoint shape is a classic IDOR/broken-access-control signal.",
  status_outlier:
    "≥80% of members share one status class (2xx/4xx/5xx) and at least one sits outside it. The outliers may reveal authorization bypass or hidden error paths.",
  size_outlier:
    "At least one 2xx response sits more than 3σ from the cluster mean — the body shape of one instance differs meaningfully from the rest.",
  rate_limited:
    "At least one member returned 429. Check whether you're tripping a rate-limit and consider throttling your scan / fuzz against this pattern.",
};

function ProxyClusteredView({
  sessionId,
  exchangeCount,
  onSendClusterToFuzzer,
  onSendClusterToChecks,
}: {
  sessionId: string | null;
  /** Used as a refresh trigger — when new exchanges arrive we re-pull
   *  the cluster snapshot. The actual count is irrelevant; the change
   *  is the signal. */
  exchangeCount: number;
  onSendClusterToFuzzer?: (cluster: EndpointCluster) => void;
  onSendClusterToChecks?: (instances: ExchangeSummary[]) => void;
}) {
  const [clusters, setClusters] = useState<EndpointCluster[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [expandedKey, setExpandedKey] = useState<string | null>(null);
  const [members, setMembers] = useState<Record<string, ExchangeSummary[]>>({});
  const [memberLoading, setMemberLoading] = useState<Record<string, boolean>>(
    {},
  );

  // Refresh the cluster snapshot whenever the live exchange count
  // moves. Cheap — the snapshot reads in-memory aggregates, no DB hit.
  useEffect(() => {
    let cancelled = false;
    if (!sessionId) {
      setClusters([]);
      return () => {
        cancelled = true;
      };
    }
    exchangesClusteredList(sessionId)
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
  }, [sessionId, exchangeCount]);

  const clusterKey = useCallback(
    (c: EndpointCluster) =>
      `${c.method}|${c.scheme}|${c.host}|${c.port}|${c.pattern}`,
    [],
  );

  const loadMembers = useCallback(
    async (c: EndpointCluster) => {
      if (!sessionId) return;
      const key = clusterKey(c);
      setMemberLoading((prev) => ({ ...prev, [key]: true }));
      try {
        const rows = await clusterInstances({
          session: sessionId,
          method: c.method,
          host: c.host,
          port: c.port,
          pattern: c.pattern,
          limit: 200,
        });
        setMembers((prev) => ({ ...prev, [key]: rows }));
      } catch (e) {
        setError(String(e));
      } finally {
        setMemberLoading((prev) => ({ ...prev, [key]: false }));
      }
    },
    [clusterKey, sessionId],
  );

  const onToggle = useCallback(
    (c: EndpointCluster) => {
      const key = clusterKey(c);
      if (expandedKey === key) {
        setExpandedKey(null);
        return;
      }
      setExpandedKey(key);
      if (!members[key]) {
        void loadMembers(c);
      }
    },
    [clusterKey, expandedKey, loadMembers, members],
  );

  if (clusters.length === 0) {
    return (
      <div className="proxy-empty">
        <p>
          No patterns yet. Browse the target — once two requests share a
          numeric / UUID / slug-shaped path segment they'll fold into one row
          here.
        </p>
        {error && <p className="error">Cluster fetch failed: {error}</p>}
      </div>
    );
  }

  return (
    <table className="findings-table proxy-traffic-table">
      <colgroup>
        <col style={{ width: "80px" }} />
        <col />
        <col style={{ width: "70px" }} />
        <col style={{ width: "180px" }} />
        <col style={{ width: "180px" }} />
      </colgroup>
      <thead>
        <tr>
          <th>Method</th>
          <th>Pattern</th>
          <th>Count</th>
          <th>Status mix</th>
          <th>Anomalies</th>
        </tr>
      </thead>
      <tbody>
        {clusters.map((c) => {
          const key = clusterKey(c);
          const open = expandedKey === key;
          const memberRows = members[key] ?? [];
          const loadingMembers = memberLoading[key];
          return (
            <>
              <tr
                key={key}
                className="proxy-row proxy-cluster-row"
                onClick={() => onToggle(c)}
              >
                <td>
                  <span className="badge-inline">{c.method}</span>
                </td>
                <td className="proxy-url">
                  <span className="muted">
                    {c.scheme}://{c.host}
                    {(c.scheme === "https" && c.port === 443) ||
                    (c.scheme === "http" && c.port === 80)
                      ? ""
                      : `:${c.port}`}
                  </span>
                  <span className="mono">{c.pattern}</span>
                </td>
                <td className="muted">{c.instance_count}×</td>
                <td>
                  {c.status_breakdown.map(([s, count]) => (
                    <span
                      key={s}
                      className="badge-inline"
                      style={{ marginRight: 4 }}
                      title={`${count} response${count === 1 ? "" : "s"}`}
                    >
                      {s} · {count}
                    </span>
                  ))}
                </td>
                <td>
                  {c.anomaly_flags.length === 0 && (
                    <span className="muted">—</span>
                  )}
                  {c.anomaly_flags.map((flag) => (
                    <span
                      key={flag}
                      className="badge-inline"
                      data-status="warn"
                      title={ANOMALY_TITLE[flag]}
                      style={{ marginRight: 4 }}
                    >
                      ⚠ {ANOMALY_LABEL[flag]}
                    </span>
                  ))}
                </td>
              </tr>
              {open && (
                <tr
                  className="finding-detail-row"
                  key={`${key}-detail`}
                >
                  <td colSpan={5}>
                    <div className="proxy-detail-compact">
                      <div className="proxy-detail-fields">
                        <div className="proxy-detail-line">
                          <span className="proxy-field">
                            <span className="proxy-field-k">Avg duration</span>
                            <span className="proxy-field-v">
                              {c.avg_duration_ms} ms
                            </span>
                          </span>
                          <span className="proxy-field">
                            <span className="proxy-field-k">Size mean</span>
                            <span className="proxy-field-v">
                              {humanSize(c.size_mean)}
                              {c.size_stddev > 0
                                ? ` ± ${humanSize(c.size_stddev)}`
                                : ""}
                            </span>
                          </span>
                          <span className="proxy-field">
                            <span className="proxy-field-k">Last seen</span>
                            <span className="proxy-field-v">
                              {new Date(
                                c.last_seen_unix * 1000,
                              ).toLocaleTimeString()}
                            </span>
                          </span>
                        </div>
                      </div>
                      <div className="proxy-detail-actions">
                        {onSendClusterToFuzzer && (
                          <button
                            type="button"
                            className="proxy-send-btn"
                            onClick={(e) => {
                              e.stopPropagation();
                              onSendClusterToFuzzer(c);
                            }}
                            title="Seed the Active Fuzzer with this pattern. Path-segment placeholders (:id / :uuid / :slug) become injection points."
                          >
                            Send cluster to Fuzzer →
                          </button>
                        )}
                        {onSendClusterToChecks && memberRows.length > 0 && (
                          <button
                            type="button"
                            className="proxy-send-btn"
                            onClick={(e) => {
                              e.stopPropagation();
                              onSendClusterToChecks(memberRows);
                            }}
                            title="Queue every member of this cluster in the Checks tab. Auth-consistency runs across the cluster to surface IDOR signals."
                          >
                            Send cluster to Checks →
                          </button>
                        )}
                      </div>
                      <div style={{ marginTop: 8 }}>
                        <strong style={{ fontSize: 12 }}>Instances</strong>
                        {loadingMembers && (
                          <span className="muted" style={{ marginLeft: 8 }}>
                            loading…
                          </span>
                        )}
                        <table
                          className="findings-table"
                          style={{ marginTop: 4 }}
                        >
                          <tbody>
                            {memberRows.map((m) => (
                              <tr key={m.id} className="proxy-row">
                                <td style={{ width: 64 }} className="muted">
                                  {m.status ?? "-"}
                                </td>
                                <td className="proxy-url mono">
                                  {m.path}
                                  {m.query ? `?${m.query}` : ""}
                                </td>
                                <td
                                  style={{ width: 80 }}
                                  className="muted"
                                >
                                  {humanSize(m.size_response)}
                                </td>
                                <td
                                  style={{ width: 80 }}
                                  className="muted"
                                >
                                  {m.duration_ms ?? "-"} ms
                                </td>
                              </tr>
                            ))}
                            {memberRows.length === 0 && !loadingMembers && (
                              <tr>
                                <td colSpan={4} className="muted">
                                  No members loaded — the cluster index lost
                                  state? Try toggling Flat / Group again.
                                </td>
                              </tr>
                            )}
                          </tbody>
                        </table>
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
  );
}

type SettingsSection =
  | "overview"
  | "ca"
  | "browser"
  | "scope"
  | "intercept_rules"
  | "csrf"
  | "retention"
  | "verify"
  | "troubleshoot";

const SETTINGS_SECTIONS: { id: SettingsSection; label: string }[] = [
  { id: "overview", label: "1. Overview" },
  { id: "ca", label: "2. Certificate authority" },
  { id: "browser", label: "3. Browser setup" },
  { id: "scope", label: "4. Scope rules" },
  { id: "intercept_rules", label: "5. Intercept rules" },
  { id: "csrf", label: "6. CSRF tokens" },
  { id: "retention", label: "7. Retention" },
  { id: "verify", label: "8. Verify" },
  { id: "troubleshoot", label: "9. Troubleshooting" },
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

      {section === "intercept_rules" && <SetupInterceptRules />}

      {section === "csrf" && <SetupCsrfRules />}

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

interface InterceptPreset {
  id: string;
  label: string;
  description: string;
  rules: InterceptRule[];
}

function newRuleId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

const INTERCEPT_PRESETS: InterceptPreset[] = [
  {
    id: "skip-static",
    label: "Skip static assets",
    description:
      "Exclude image / font / stylesheet / script / map paths so the queue doesn't drown in browser background fetches.",
    rules: [
      {
        id: "preset-skip-static",
        kind: "exclude",
        phase: "both",
        enabled: true,
        conditions: [
          {
            kind: "PathRegex",
            pattern:
              "\\.(?:png|jpe?g|gif|svg|ico|woff2?|ttf|eot|css|js|map)(?:$|\\?)",
          },
        ],
      },
    ],
  },
  {
    id: "only-mutations",
    label: "Only mutating requests",
    description:
      "Include POST / PUT / PATCH / DELETE on the request side. GETs flow through unimpeded.",
    rules: [
      {
        id: "preset-mutations",
        kind: "include",
        phase: "request",
        enabled: true,
        conditions: [
          {
            kind: "MethodIn",
            methods: ["POST", "PUT", "PATCH", "DELETE"],
          },
        ],
      },
    ],
  },
  {
    id: "auth-endpoints",
    label: "Only auth endpoints",
    description:
      "Include requests to login / logout / signup / signin / auth / token / session paths. Useful when probing how a target hands out and rotates credentials.",
    rules: [
      {
        id: "preset-auth",
        kind: "include",
        phase: "request",
        enabled: true,
        conditions: [
          {
            kind: "PathRegex",
            pattern: "(?i)(login|logout|signin|signup|auth|token|session)",
          },
        ],
      },
    ],
  },
  {
    id: "error-responses",
    label: "Only error responses",
    description:
      "Include responses with 4xx / 5xx status. Lets the request pass through and only pauses on the way back if something failed.",
    rules: [
      {
        id: "preset-errors",
        kind: "include",
        phase: "response",
        enabled: true,
        conditions: [{ kind: "StatusRange", min: 400, max: 599 }],
      },
    ],
  },
];

const PHASE_OPTIONS: { value: PhaseFilter; label: string }[] = [
  { value: "request", label: "Request" },
  { value: "response", label: "Response" },
  { value: "both", label: "Both" },
];

const COND_KINDS: { value: RuleCondition["kind"]; label: string }[] = [
  { value: "HostGlob", label: "Host glob" },
  { value: "PathRegex", label: "Path regex" },
  { value: "MethodIn", label: "Method in" },
  { value: "ContentTypeContains", label: "Content-Type contains" },
  { value: "StatusRange", label: "Status range" },
  { value: "HasHeader", label: "Has header" },
];

function defaultCondition(kind: RuleCondition["kind"]): RuleCondition {
  switch (kind) {
    case "HostGlob":
      return { kind: "HostGlob", pattern: "" };
    case "PathRegex":
      return { kind: "PathRegex", pattern: "" };
    case "MethodIn":
      return { kind: "MethodIn", methods: ["POST"] };
    case "ContentTypeContains":
      return { kind: "ContentTypeContains", needle: "" };
    case "StatusRange":
      return { kind: "StatusRange", min: 400, max: 599 };
    case "HasHeader":
      return { kind: "HasHeader", name: "", regex: null };
  }
}

function SetupInterceptRules() {
  const [rules, setRules] = useState<InterceptRule[]>([]);
  const [initial, setInitial] = useState<string>("[]");
  const [status, setStatus] =
    useState<"idle" | "saving" | "saved">("idle");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    interceptRulesGet()
      .then((r) => {
        if (cancelled) return;
        setRules(r.rules);
        setInitial(JSON.stringify(r.rules));
      })
      .catch((e) => !cancelled && setError(String(e)));
    return () => {
      cancelled = true;
    };
  }, []);

  const dirty = JSON.stringify(rules) !== initial;

  const update = (idx: number, patch: Partial<InterceptRule>) => {
    setRules((prev) =>
      prev.map((r, i) => (i === idx ? { ...r, ...patch } : r)),
    );
  };
  const remove = (idx: number) => {
    setRules((prev) => prev.filter((_, i) => i !== idx));
  };
  const addRule = (kind: RuleKind) => {
    setRules((prev) => [
      ...prev,
      {
        id: newRuleId(kind),
        kind,
        phase: "both",
        enabled: true,
        conditions: [defaultCondition("HostGlob")],
      },
    ]);
  };
  const applyPreset = (preset: InterceptPreset) => {
    // Each preset's rules get a fresh id stamp so reapplying doesn't
    // collide with previously-applied copies.
    setRules((prev) => [
      ...prev,
      ...preset.rules.map((r) => ({
        ...r,
        id: newRuleId(`${preset.id}-${r.kind}`),
        conditions: r.conditions.map((c) => ({ ...c })),
      })),
    ]);
  };
  const updateCondition = (
    ruleIdx: number,
    condIdx: number,
    next: RuleCondition,
  ) => {
    setRules((prev) =>
      prev.map((r, i) =>
        i === ruleIdx
          ? {
              ...r,
              conditions: r.conditions.map((c, j) =>
                j === condIdx ? next : c,
              ),
            }
          : r,
      ),
    );
  };
  const addCondition = (ruleIdx: number) => {
    setRules((prev) =>
      prev.map((r, i) =>
        i === ruleIdx
          ? { ...r, conditions: [...r.conditions, defaultCondition("HostGlob")] }
          : r,
      ),
    );
  };
  const removeCondition = (ruleIdx: number, condIdx: number) => {
    setRules((prev) =>
      prev.map((r, i) =>
        i === ruleIdx
          ? {
              ...r,
              conditions: r.conditions.filter((_, j) => j !== condIdx),
            }
          : r,
      ),
    );
  };
  const save = async () => {
    setStatus("saving");
    setError(null);
    try {
      await interceptRulesSet({ rules });
      setInitial(JSON.stringify(rules));
      setStatus("saved");
      window.setTimeout(() => setStatus("idle"), 1500);
    } catch (e) {
      setError(String(e));
      setStatus("idle");
    }
  };
  const revert = async () => {
    try {
      const r = await interceptRulesGet();
      setRules(r.rules);
      setInitial(JSON.stringify(r.rules));
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <section>
      <h3>Intercept rules</h3>
      <p className="muted">
        Layer on top of the Intercept mode toggle. <em>Include</em>{" "}
        rules narrow what pauses (the listener pauses only when at
        least one include matches). <em>Exclude</em> rules short-
        circuit a pause regardless — exclude wins. An empty list
        reverts to mode-only behaviour. All conditions inside one
        rule must match (AND); rules of the same kind are OR-ed.
      </p>

      {error && <p className="error">{error}</p>}

      <div style={{ marginTop: 8 }}>
        <strong style={{ fontSize: "0.92em" }}>Presets</strong>
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 6,
            marginTop: 4,
          }}
        >
          {INTERCEPT_PRESETS.map((p) => (
            <button
              key={p.id}
              type="button"
              className="chip"
              onClick={() => applyPreset(p)}
              title={p.description}
            >
              + {p.label}
            </button>
          ))}
        </div>
      </div>

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          margin: "12px 0 6px",
        }}
      >
        <strong>Rules ({rules.length})</strong>
        <div style={{ display: "flex", gap: 6 }}>
          <button
            type="button"
            className="chip"
            onClick={() => addRule("include")}
          >
            + Include rule
          </button>
          <button
            type="button"
            className="chip"
            onClick={() => addRule("exclude")}
          >
            + Exclude rule
          </button>
        </div>
      </div>

      {rules.length === 0 ? (
        <p className="muted">
          No rules. Mode-only intercept fires for every in-scope
          exchange that the toggle permits.
        </p>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {rules.map((rule, idx) => (
            <div
              key={rule.id}
              className="panel"
              style={{
                padding: "8px 10px",
                borderLeft: `3px solid var(--${rule.kind === "include" ? "accent" : "warning"})`,
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  marginBottom: 6,
                }}
              >
                <input
                  type="checkbox"
                  checked={rule.enabled}
                  onChange={(e) => update(idx, { enabled: e.target.checked })}
                  title="Enable / disable"
                />
                <select
                  value={rule.kind}
                  onChange={(e) =>
                    update(idx, { kind: e.target.value as RuleKind })
                  }
                >
                  <option value="include">Include</option>
                  <option value="exclude">Exclude</option>
                </select>
                <select
                  value={rule.phase}
                  onChange={(e) =>
                    update(idx, { phase: e.target.value as PhaseFilter })
                  }
                >
                  {PHASE_OPTIONS.map((p) => (
                    <option key={p.value} value={p.value}>
                      {p.label}
                    </option>
                  ))}
                </select>
                <span className="muted mono" style={{ flex: 1 }}>
                  {rule.id}
                </span>
                <button
                  type="button"
                  className="chip"
                  onClick={() => remove(idx)}
                >
                  ×
                </button>
              </div>

              {rule.conditions.map((cond, ci) => (
                <ConditionEditor
                  key={ci}
                  condition={cond}
                  onChange={(c) => updateCondition(idx, ci, c)}
                  onRemove={() => removeCondition(idx, ci)}
                />
              ))}

              <button
                type="button"
                className="link-button"
                onClick={() => addCondition(idx)}
                style={{ marginTop: 4 }}
              >
                + condition
              </button>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
        <button
          type="button"
          className="primary-btn"
          onClick={save}
          disabled={!dirty || status === "saving"}
        >
          Save
        </button>
        <button
          type="button"
          className="chip"
          onClick={revert}
          disabled={!dirty}
        >
          Revert
        </button>
        {status === "saving" && <span className="muted">Saving…</span>}
        {status === "saved" && <span className="muted">Saved.</span>}
      </div>
    </section>
  );
}

function ConditionEditor({
  condition,
  onChange,
  onRemove,
}: {
  condition: RuleCondition;
  onChange: (c: RuleCondition) => void;
  onRemove: () => void;
}) {
  const changeKind = (kind: RuleCondition["kind"]) => {
    onChange(defaultCondition(kind));
  };
  return (
    <div
      style={{
        display: "flex",
        gap: 4,
        alignItems: "center",
        marginTop: 4,
      }}
    >
      <select
        value={condition.kind}
        onChange={(e) => changeKind(e.target.value as RuleCondition["kind"])}
        style={{ width: 180 }}
      >
        {COND_KINDS.map((k) => (
          <option key={k.value} value={k.value}>
            {k.label}
          </option>
        ))}
      </select>
      {condition.kind === "HostGlob" && (
        <input
          type="text"
          value={condition.pattern}
          onChange={(e) =>
            onChange({ kind: "HostGlob", pattern: e.target.value })
          }
          placeholder="example.com or *.tenant.com"
          style={{ flex: 1 }}
        />
      )}
      {condition.kind === "PathRegex" && (
        <input
          type="text"
          value={condition.pattern}
          onChange={(e) =>
            onChange({ kind: "PathRegex", pattern: e.target.value })
          }
          placeholder="/auth | \.png$"
          style={{ flex: 1 }}
        />
      )}
      {condition.kind === "MethodIn" && (
        <input
          type="text"
          value={condition.methods.join(",")}
          onChange={(e) =>
            onChange({
              kind: "MethodIn",
              methods: e.target.value
                .split(",")
                .map((s) => s.trim().toUpperCase())
                .filter((s) => s.length > 0),
            })
          }
          placeholder="POST, PUT, PATCH, DELETE"
          style={{ flex: 1 }}
        />
      )}
      {condition.kind === "ContentTypeContains" && (
        <input
          type="text"
          value={condition.needle}
          onChange={(e) =>
            onChange({ kind: "ContentTypeContains", needle: e.target.value })
          }
          placeholder="image/ | application/json"
          style={{ flex: 1 }}
        />
      )}
      {condition.kind === "StatusRange" && (
        <>
          <input
            type="number"
            value={condition.min}
            onChange={(e) =>
              onChange({
                kind: "StatusRange",
                min: Number(e.target.value) || 0,
                max: condition.max,
              })
            }
            min={100}
            max={599}
            style={{ width: 80 }}
          />
          <span className="muted">–</span>
          <input
            type="number"
            value={condition.max}
            onChange={(e) =>
              onChange({
                kind: "StatusRange",
                min: condition.min,
                max: Number(e.target.value) || 0,
              })
            }
            min={100}
            max={599}
            style={{ width: 80 }}
          />
          <span className="muted" style={{ flex: 1, fontSize: "0.85em" }}>
            (response phase only)
          </span>
        </>
      )}
      {condition.kind === "HasHeader" && (
        <>
          <input
            type="text"
            value={condition.name}
            onChange={(e) =>
              onChange({
                kind: "HasHeader",
                name: e.target.value,
                regex: condition.regex ?? null,
              })
            }
            placeholder="Authorization"
            style={{ width: 160 }}
          />
          <input
            type="text"
            value={condition.regex ?? ""}
            onChange={(e) =>
              onChange({
                kind: "HasHeader",
                name: condition.name,
                regex: e.target.value.trim() === "" ? null : e.target.value,
              })
            }
            placeholder="optional value regex"
            style={{ flex: 1 }}
          />
        </>
      )}
      <button
        type="button"
        className="chip"
        onClick={onRemove}
        title="Remove condition"
      >
        ×
      </button>
    </div>
  );
}

const SOURCE_KINDS: { value: TokenSource["kind"]; label: string; field: string }[] = [
  { value: "HtmlInput", label: "HTML <input>", field: "name regex" },
  { value: "MetaTag", label: "<meta> tag", field: "name regex" },
  { value: "JsonPath", label: "JSON pointer", field: "/path/to/token" },
  { value: "SetCookie", label: "Set-Cookie", field: "cookie name" },
  { value: "ResponseHeader", label: "Response header", field: "header name" },
];

const INJECT_KINDS: { value: TokenInject["kind"]; label: string; field: string }[] = [
  { value: "FormField", label: "Form field", field: "field name" },
  { value: "JsonField", label: "JSON pointer", field: "/path/to/field" },
  { value: "Header", label: "Request header", field: "header name" },
  { value: "Cookie", label: "Cookie", field: "cookie name" },
];

function sourceField(s: TokenSource): string {
  switch (s.kind) {
    case "HtmlInput":
    case "MetaTag":
      return s.name_regex;
    case "JsonPath":
      return s.pointer;
    case "SetCookie":
    case "ResponseHeader":
      return s.name;
  }
}

function setSourceField(s: TokenSource, value: string): TokenSource {
  switch (s.kind) {
    case "HtmlInput":
      return { kind: "HtmlInput", name_regex: value };
    case "MetaTag":
      return { kind: "MetaTag", name_regex: value };
    case "JsonPath":
      return { kind: "JsonPath", pointer: value };
    case "SetCookie":
      return { kind: "SetCookie", name: value };
    case "ResponseHeader":
      return { kind: "ResponseHeader", name: value };
  }
}

function changeSourceKind(kind: TokenSource["kind"], existing: string): TokenSource {
  switch (kind) {
    case "HtmlInput":
      return { kind: "HtmlInput", name_regex: existing };
    case "MetaTag":
      return { kind: "MetaTag", name_regex: existing };
    case "JsonPath":
      return { kind: "JsonPath", pointer: existing };
    case "SetCookie":
      return { kind: "SetCookie", name: existing };
    case "ResponseHeader":
      return { kind: "ResponseHeader", name: existing };
  }
}

function injectField(i: TokenInject): string {
  switch (i.kind) {
    case "FormField":
    case "Header":
    case "Cookie":
      return i.name;
    case "JsonField":
      return i.pointer;
  }
}

function setInjectField(i: TokenInject, value: string): TokenInject {
  switch (i.kind) {
    case "FormField":
      return { kind: "FormField", name: value };
    case "JsonField":
      return { kind: "JsonField", pointer: value };
    case "Header":
      return { kind: "Header", name: value };
    case "Cookie":
      return { kind: "Cookie", name: value };
  }
}

function changeInjectKind(kind: TokenInject["kind"], existing: string): TokenInject {
  switch (kind) {
    case "FormField":
      return { kind: "FormField", name: existing };
    case "JsonField":
      return { kind: "JsonField", pointer: existing };
    case "Header":
      return { kind: "Header", name: existing };
    case "Cookie":
      return { kind: "Cookie", name: existing };
  }
}

function fmtAge(unix: number): string {
  const ageSec = Math.max(0, Math.floor(Date.now() / 1000 - unix));
  if (ageSec < 60) return `${ageSec}s ago`;
  if (ageSec < 3600) return `${Math.floor(ageSec / 60)}m ago`;
  if (ageSec < 86400) return `${Math.floor(ageSec / 3600)}h ago`;
  return `${Math.floor(ageSec / 86400)}d ago`;
}

function SetupCsrfRules() {
  const [rules, setRules] = useState<CsrfRule[]>([]);
  const [initial, setInitial] = useState<string>("[]");
  const [status, setStatus] =
    useState<"idle" | "saving" | "saved">("idle");
  const [error, setError] = useState<string | null>(null);
  const [observations, setObservations] = useState<CsrfObservation[]>([]);

  // Initial load + live observation feed.
  useEffect(() => {
    let cancelled = false;
    Promise.all([csrfRulesGet(), csrfStatus()])
      .then(([r, obs]) => {
        if (cancelled) return;
        setRules(r);
        setInitial(JSON.stringify(r));
        setObservations(obs);
      })
      .catch((e) => !cancelled && setError(String(e)));
    let unlisten: (() => void) | undefined;
    onCsrfObserved((obs) => {
      setObservations((prev) => {
        const next = prev.filter(
          (p) => !(p.rule_id === obs.rule_id && p.host === obs.host),
        );
        next.push(obs);
        return next;
      });
    }).then((u) => {
      if (cancelled) u();
      else unlisten = u;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  const dirty = JSON.stringify(rules) !== initial;

  const update = (idx: number, patch: Partial<CsrfRule>) => {
    setRules((prev) =>
      prev.map((r, i) => (i === idx ? { ...r, ...patch } : r)),
    );
  };
  const remove = (idx: number) => {
    setRules((prev) => prev.filter((_, i) => i !== idx));
  };
  const addRule = () => {
    setRules((prev) => [
      ...prev,
      {
        id: `custom-${Date.now()}`,
        name: "Custom rule",
        enabled: true,
        host_glob: null,
        source: { kind: "HtmlInput", name_regex: "" },
        inject: { kind: "FormField", name: "" },
      },
    ]);
  };
  const save = async () => {
    setStatus("saving");
    setError(null);
    try {
      await csrfRulesSet(rules);
      setInitial(JSON.stringify(rules));
      setStatus("saved");
      window.setTimeout(() => setStatus("idle"), 1500);
    } catch (e) {
      setError(String(e));
      setStatus("idle");
    }
  };
  const revert = async () => {
    try {
      const r = await csrfRulesGet();
      setRules(r);
      setInitial(JSON.stringify(r));
    } catch (e) {
      setError(String(e));
    }
  };
  const resetDefaults = async () => {
    setStatus("saving");
    try {
      const defaults = await csrfRulesResetDefaults();
      setRules(defaults);
      setInitial(JSON.stringify(defaults));
      setStatus("saved");
      window.setTimeout(() => setStatus("idle"), 1500);
    } catch (e) {
      setError(String(e));
      setStatus("idle");
    }
  };
  const clearObs = async () => {
    try {
      await csrfClearSession();
      setObservations([]);
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <section>
      <h3>CSRF tokens</h3>
      <p className="muted">
        Token-rotating apps cycle a fresh CSRF token on every login or
        page render. The proxy auto-captures tokens from each response
        and splices them into matching outbound requests, so Replay,
        Active Checks, and the Active Fuzzer all stay logged-in for
        free. Each rule pairs a <em>source</em> (where to read the
        token from in the response) with an <em>inject</em> step (how
        to write it into the next request). The bundled defaults
        cover Laravel, Rails, ASP.NET, Django, generic{" "}
        <code>&lt;meta name="csrf-token"&gt;</code>, and the Angular
        XSRF cookie convention.
      </p>

      {error && <p className="error">{error}</p>}

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", margin: "8px 0" }}>
        <strong>Rules</strong>
        <div style={{ display: "flex", gap: 6 }}>
          <button type="button" className="chip" onClick={addRule}>
            + Add rule
          </button>
          <button
            type="button"
            className="chip"
            onClick={resetDefaults}
            title="Replace the rule list with the bundled defaults. Custom rules are dropped."
          >
            Reset to defaults
          </button>
        </div>
      </div>

      {rules.length === 0 ? (
        <p className="muted">No rules — click <strong>Reset to defaults</strong> to bring back the bundled set.</p>
      ) : (
        <table className="findings-table" style={{ marginBottom: 12 }}>
          <thead>
            <tr>
              <th style={{ width: "32px" }}>On</th>
              <th>Name</th>
              <th>Host glob</th>
              <th>Source</th>
              <th>Inject</th>
              <th style={{ width: "60px" }}></th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r, idx) => (
              <tr key={r.id}>
                <td>
                  <input
                    type="checkbox"
                    checked={r.enabled}
                    onChange={(e) => update(idx, { enabled: e.target.checked })}
                  />
                </td>
                <td>
                  <input
                    type="text"
                    value={r.name}
                    onChange={(e) => update(idx, { name: e.target.value })}
                    style={{ width: "100%" }}
                  />
                </td>
                <td>
                  <input
                    type="text"
                    value={r.host_glob ?? ""}
                    onChange={(e) =>
                      update(idx, {
                        host_glob: e.target.value.trim() === "" ? null : e.target.value,
                      })
                    }
                    placeholder="* (any)"
                    style={{ width: "100%" }}
                  />
                </td>
                <td>
                  <div style={{ display: "flex", gap: 4 }}>
                    <select
                      value={r.source.kind}
                      onChange={(e) =>
                        update(idx, {
                          source: changeSourceKind(
                            e.target.value as TokenSource["kind"],
                            sourceField(r.source),
                          ),
                        })
                      }
                    >
                      {SOURCE_KINDS.map((k) => (
                        <option key={k.value} value={k.value}>
                          {k.label}
                        </option>
                      ))}
                    </select>
                    <input
                      type="text"
                      value={sourceField(r.source)}
                      onChange={(e) =>
                        update(idx, {
                          source: setSourceField(r.source, e.target.value),
                        })
                      }
                      placeholder={
                        SOURCE_KINDS.find((k) => k.value === r.source.kind)?.field
                      }
                      style={{ flex: 1 }}
                    />
                  </div>
                </td>
                <td>
                  <div style={{ display: "flex", gap: 4 }}>
                    <select
                      value={r.inject.kind}
                      onChange={(e) =>
                        update(idx, {
                          inject: changeInjectKind(
                            e.target.value as TokenInject["kind"],
                            injectField(r.inject),
                          ),
                        })
                      }
                    >
                      {INJECT_KINDS.map((k) => (
                        <option key={k.value} value={k.value}>
                          {k.label}
                        </option>
                      ))}
                    </select>
                    <input
                      type="text"
                      value={injectField(r.inject)}
                      onChange={(e) =>
                        update(idx, {
                          inject: setInjectField(r.inject, e.target.value),
                        })
                      }
                      placeholder={
                        INJECT_KINDS.find((k) => k.value === r.inject.kind)?.field
                      }
                      style={{ flex: 1 }}
                    />
                  </div>
                </td>
                <td>
                  <button
                    type="button"
                    className="chip"
                    onClick={() => remove(idx)}
                    title="Delete rule"
                  >
                    ×
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <button
          type="button"
          className="primary-btn"
          onClick={save}
          disabled={!dirty || status === "saving"}
        >
          Save
        </button>
        <button
          type="button"
          className="chip"
          onClick={revert}
          disabled={!dirty}
        >
          Revert
        </button>
        {status === "saving" && <span className="muted">Saving…</span>}
        {status === "saved" && <span className="muted">Saved.</span>}
      </div>

      <div style={{ marginTop: 18 }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <strong>Live status</strong>
          <button
            type="button"
            className="chip"
            onClick={clearObs}
            title="Wipe observed values (e.g. after re-logging in to a target)."
          >
            Clear observations
          </button>
        </div>
        {observations.length === 0 ? (
          <p className="muted">
            No tokens observed yet. Browse a target through the proxy
            and watch them flow in here.
          </p>
        ) : (
          <table className="findings-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Host</th>
                <th>Latest value</th>
                <th>Observed</th>
              </tr>
            </thead>
            <tbody>
              {observations
                .slice()
                .sort((a, b) => b.observed_at_unix - a.observed_at_unix)
                .map((o) => (
                  <tr key={`${o.rule_id}|${o.host}`}>
                    <td>
                      {rules.find((r) => r.id === o.rule_id)?.name ?? o.rule_id}
                    </td>
                    <td className="muted mono">{o.host || "(global)"}</td>
                    <td className="mono" title={o.value}>
                      {o.value.length > 32
                        ? `${o.value.slice(0, 16)}…${o.value.slice(-8)}`
                        : o.value}
                    </td>
                    <td className="muted">{fmtAge(o.observed_at_unix)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
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
    const batcher = createRafBatcher<FindingRow>((batch) => {
      // Reverse so the newest within a batch ends up closest to the
      // top, matching the original per-event prepend order.
      const fresh = batch.slice().reverse();
      setFindings((prev) => [...fresh, ...prev]);
    });
    onScanFinding((live: LiveFindingPayload) => {
      // Adapt the live payload to the stored-row shape.
      batcher.push({
        id: live.id,
        exchange_id: live.exchange_id,
        check_id: live.check_id,
        severity:
          (live.severity as FindingRow["severity"]) ?? "info",
        title: live.title,
        description: live.description,
        evidence: live.evidence,
        created_at_unix: Math.floor(Date.now() / 1000),
      });
    })
      .then((fn) => {
        unlisten = fn;
      })
      .catch(() => {});
    return () => {
      if (unlisten) unlisten();
      batcher.dispose();
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

const INTERCEPT_MODE_HELP: Record<InterceptMode, React.ReactNode> = {
  off: (
    <>
      <strong>Off — pass-through</strong>
      Nothing pauses. Traffic still gets <em>captured</em> (Traffic tab,
      Checks, Replay all keep working) but every request flows straight
      through to the upstream and back. This is the default. Switch
      back to Off when you're done editing live traffic so you don't
      accidentally hold up your own browser session.
    </>
  ),
  request: (
    <>
      <strong>Request — pause before forwarding</strong>
      The most common mode. In-scope requests pause in the{" "}
      <em>Pending</em> queue <em>before</em> they leave for the
      upstream. You can edit the method, path, headers, or body, then
      Forward to send your edited bytes upstream. Use this for
      authorization-bypass probes (flip a role field), CSRF tests
      (drop a token), or anything where you want to mutate what the
      server sees.
    </>
  ),
  response: (
    <>
      <strong>Response — pause before delivery to the client</strong>
      Lets the request go upstream untouched, then pauses the{" "}
      <em>reply</em> in the queue before the client (your browser)
      receives it. Edit status code, headers, or body to simulate
      error states, flip feature-flag JSON, strip security headers
      to see how the client copes, or hand the browser a response the
      server never sent.
    </>
  ),
  both: (
    <>
      <strong>Both — pause at request and response</strong>
      Each in-scope exchange hits the queue twice: once with the{" "}
      <code>→ req</code> badge (going out), once with{" "}
      <code>← resp</code> (coming back). Heavier on attention but the
      only mode that lets you observe how the upstream reacted to
      your edited request and then mutate the reply before the client
      sees it.
    </>
  ),
};

function ProxyInterceptTab() {
  const [mode, setMode] = useState<InterceptMode>("off");
  const [pending, setPending] = useState<PendingIntercept[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editor, setEditor] = useState<string>("");
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeRuleCount, setActiveRuleCount] = useState<number>(0);

  const selected = useMemo(
    () => pending.find((p) => p.id === selectedId) ?? null,
    [pending, selectedId],
  );

  const refresh = useCallback(async () => {
    try {
      const [m, list, ruleSet] = await Promise.all([
        interceptGetMode(),
        interceptPendingList(),
        interceptRulesGet(),
      ]);
      setMode(m);
      setPending(list);
      setActiveRuleCount(ruleSet.rules.filter((r) => r.enabled).length);
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
      <div
        className="proxy-mode-row"
        style={{ alignItems: "center", marginBottom: 6, rowGap: 4 }}
      >
        <span
          className="muted"
          style={{ fontSize: "0.85em", marginRight: 4 }}
        >
          Intercept mode:
        </span>
        {INTERCEPT_MODES.map((m) => (
          <span
            key={m.value}
            style={{ display: "inline-flex", alignItems: "center", gap: 2 }}
          >
            <button
              type="button"
              className={`chip${mode === m.value ? " active" : ""}`}
              onClick={() => handleModeChange(m.value)}
            >
              {m.label}
            </button>
            <InfoTip label={`${m.label} mode help`}>
              {INTERCEPT_MODE_HELP[m.value]}
            </InfoTip>
          </span>
        ))}
        <span style={{ display: "inline-flex", alignItems: "center", gap: 2 }}>
          <button
            type="button"
            className="chip"
            onClick={handleDropAll}
            disabled={pending.length === 0}
          >
            Drop all
          </button>
          <InfoTip label="Drop all help">
            <strong>Drop all</strong>
            Returns a <code>502 Bad Gateway</code> to the client for
            every exchange currently sitting in the Pending queue
            and clears the queue. The upstream is never contacted
            for those requests. Use this when you've turned on
            Intercept by accident and a long page load piled up
            dozens of paused subresources you don't want to step
            through one-by-one. Disabled when the queue is empty.
          </InfoTip>
        </span>
        {activeRuleCount > 0 && (
          <span
            className="chip"
            data-status="warn"
            title="Active intercept rules narrow what the mode toggle pauses. Configure under Settings, Intercept rules."
          >
            ⚠ {activeRuleCount} rule{activeRuleCount === 1 ? "" : "s"} active
          </span>
        )}
      </div>
      {error && <div className="proxy-error">{error}</div>}

      <div
        className="proxy-intercept-split"
        style={{
          display: "grid",
          gridTemplateColumns: "minmax(360px, 1fr) minmax(360px, 1fr)",
          gap: 12,
          alignItems: "stretch",
        }}
      >
        <div
          className="proxy-intercept-pending-col"
          style={{ display: "flex", flexDirection: "column", minWidth: 0 }}
        >
          <div
            className="proxy-mode-row"
            style={{ alignItems: "center", marginBottom: 4 }}
          >
            <strong style={{ fontSize: "0.9em" }}>
              Pending ({pending.length})
            </strong>
            <InfoTip label="Pending queue help">
              <strong>Pending</strong>
              The queue of in-scope exchanges currently paused awaiting
              your verdict. Each row is one paused side of one exchange:
              an outbound request held before forwarding (
              <code>→ req</code> badge), or an upstream reply held
              before delivery to the client (<code>← resp</code> badge).
              Click a row to load the raw bytes into the editor on the
              right, then Forward (with or without edits) or Drop. The
              queue stays empty when Intercept mode is Off, or when no
              in-scope traffic is hitting a phase the active mode
              covers. Forgotten rows auto-forward after 5 minutes so
              upstream sockets do not leak.
            </InfoTip>
          </div>
      <div className="proxy-intercept-layout">
        <aside className="proxy-intercept-queue">
          {pending.length === 0 ? (
            <p className="muted">No paused exchanges.</p>
          ) : (
            <ul>
              {pending.map((p) => (
                <Fragment key={p.id}>
                  <li
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
                  {selectedId === p.id && selected && (
                    <li className="proxy-intercept-inline-editor">
                      <div className="proxy-intercept-editor">
                        <div className="proxy-intercept-toolbar">
                          <span className="muted">
                            {selected.phase === "response" ? (
                              <>
                                Editing the raw{" "}
                                <strong>response</strong>: status line
                                first (e.g.{" "}
                                <code>HTTP/1.1 200 OK</code>), then
                                headers, blank line, body. Forward
                                sends the edited reply to the client;
                                Drop returns a 502 instead.
                              </>
                            ) : (
                              <>
                                Editing the raw{" "}
                                <strong>request</strong>: request line
                                first (e.g.{" "}
                                <code>GET /path HTTP/1.1</code>), then
                                headers, blank line, body. Forward
                                sends the edited request upstream;
                                Drop returns a 502 to the client.
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
                          <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
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
                            <InfoTip label="Forward help">
                              {selected.phase === "response" ? (
                                <>
                                  <strong>Forward response</strong>
                                  Releases the paused upstream reply
                                  and lets it reach the client. If you
                                  edited the textarea, the button
                                  label flips to <em>Forward edited
                                  response</em>: corvex re-parses
                                  your bytes, rewrites{" "}
                                  <code>Content-Length</code>, and the
                                  client receives your edited reply
                                  instead of what the server actually
                                  sent. Untouched bytes forward
                                  verbatim with zero re-parse cost.
                                </>
                              ) : (
                                <>
                                  <strong>Forward request</strong>
                                  Releases the paused outbound request
                                  to the upstream. If you edited the
                                  textarea, the button label flips to{" "}
                                  <em>Forward edited request</em>:
                                  corvex re-parses your bytes,
                                  recomputes the body length, and
                                  forwards your edited request. The
                                  exchange shows up in the Traffic tab
                                  with a{" "}
                                  <code>request-edited</code> intercept
                                  flag so you can audit what you
                                  changed later.
                                </>
                              )}
                            </InfoTip>
                          </span>
                          <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                            <button type="button" className="chip" onClick={handleDrop}>
                              {selected.phase === "response"
                                ? "Drop response"
                                : "Drop request"}
                            </button>
                            <InfoTip label="Drop help">
                              {selected.phase === "response" ? (
                                <>
                                  <strong>Drop response</strong>
                                  Discards the upstream reply you were
                                  about to edit. The client receives a
                                  synthetic{" "}
                                  <code>502 Bad Gateway</code> instead.
                                  The upstream already saw and
                                  processed the request, so Drop only
                                  affects what the client gets back.
                                  Use this to simulate a flaky upstream
                                  or connection reset.
                                </>
                              ) : (
                                <>
                                  <strong>Drop request</strong>
                                  Discards the paused request without
                                  forwarding. The upstream is never
                                  contacted. The client receives a
                                  synthetic <code>502 Bad Gateway</code>.
                                  Use this to test how the client
                                  reacts to a failed network call, or
                                  to silently kill a request you don't
                                  want hitting the server.
                                </>
                              )}
                            </InfoTip>
                          </span>
                        </div>
                      </div>
                    </li>
                  )}
                </Fragment>
              ))}
            </ul>
          )}
        </aside>
      </div>
        </div>

        <div
          className="proxy-intercept-browser-col"
          style={{ display: "flex", flexDirection: "column", minWidth: 0 }}
        >
          <InterceptBrowserPane />
        </div>
      </div>
    </div>
  );
}

interface BrowserCaState {
  present_in_store: boolean;
}

function InterceptBrowserPane() {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const [urlInput, setUrlInput] = useState("");
  const [currentUrl, setCurrentUrl] = useState<string>("");
  const [caState, setCaState] = useState<BrowserCaState | null>(null);
  const [caInstalling, setCaInstalling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  // Look up CA trust state once per mount. The result is cheap to
  // re-query but we only need it to decide whether to show the install
  // banner.
  useEffect(() => {
    let cancelled = false;
    browserCaStatus()
      .then((s) => {
        if (!cancelled) setCaState(s);
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Subscribe to navigation events so the URL bar tracks in-page
  // redirects, history.back(), and JS-driven location changes.
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    onBrowserNavigated(({ url }) => {
      setCurrentUrl(url);
      setUrlInput(url);
    })
      .then((fn) => {
        unlisten = fn;
      })
      .catch(() => {});
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  // Create the child webview on first mount; reposition + show on
  // every subsequent mount (the native rectangle persists across React
  // renders). Hide on unmount so the WebView2 surface doesn't bleed
  // over other tabs while the user is elsewhere.
  useEffect(() => {
    const el = mountRef.current;
    if (!el) return;
    let active = true;
    let pendingRaf: number | null = null;
    let started = false;

    const measure = () => {
      const r = el.getBoundingClientRect();
      return { x: r.x, y: r.y, width: r.width, height: r.height };
    };

    const sync = () => {
      if (!active) return;
      pendingRaf = null;
      browserSetBounds(measure()).catch(() => {});
    };

    const queueSync = () => {
      if (pendingRaf !== null) cancelAnimationFrame(pendingRaf);
      pendingRaf = requestAnimationFrame(sync);
    };

    const init = async () => {
      const bounds = measure();
      try {
        // about:blank is a clean baseline — the user navigates from
        // the URL bar. browser_create is idempotent so re-mounts just
        // re-show the existing surface.
        await browserCreate("about:blank", bounds);
        if (!active) return;
        await browserSetBounds(bounds).catch(() => {});
        await browserShow().catch(() => {});
        started = true;
      } catch (e) {
        if (active) setError(String(e));
      }
    };
    init();

    const ro = new ResizeObserver(queueSync);
    ro.observe(el);
    window.addEventListener("scroll", queueSync, true);
    window.addEventListener("resize", queueSync);

    return () => {
      active = false;
      if (pendingRaf !== null) cancelAnimationFrame(pendingRaf);
      ro.disconnect();
      window.removeEventListener("scroll", queueSync, true);
      window.removeEventListener("resize", queueSync);
      if (started) {
        // Hide rather than close — the user may flip back to the
        // Browser sub-tab and expect their session intact.
        browserHide().catch(() => {});
      }
    };
  }, []);

  const submitNav = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);
      let target = urlInput.trim();
      if (!target) return;
      if (!/^[a-z]+:\/\//i.test(target) && target !== "about:blank") {
        target = "https://" + target;
      }
      try {
        await browserNavigate(target);
        setUrlInput(target);
      } catch (err) {
        setError(String(err));
      }
    },
    [urlInput],
  );

  const handleInstallCa = useCallback(async () => {
    setCaInstalling(true);
    setError(null);
    setInfo(null);
    try {
      const result = await browserInstallCa();
      setCaState({ present_in_store: true });
      setInfo(
        result.already_present
          ? "CA was already trusted."
          : "CA installed into Windows CurrentUser Root store. HTTPS sites will now load without certificate warnings.",
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setCaInstalling(false);
    }
  }, []);

  return (
    <div className="proxy-intercept-browser">
      {caState && !caState.present_in_store && (
        <div className="proxy-error" role="alert" style={{ background: "var(--surface-warn, rgba(255,170,0,0.12))" }}>
          HTTPS pages will show certificate warnings until the corvex root
          CA is trusted by Windows.{" "}
          <button
            type="button"
            className="chip active"
            disabled={caInstalling}
            onClick={handleInstallCa}
          >
            {caInstalling ? "Installing…" : "Install CA into Windows trust store"}
          </button>{" "}
          <span className="muted">
            (no admin required — writes to your CurrentUser Root store)
          </span>
        </div>
      )}
      {info && <div className="proxy-error" role="status">{info}</div>}
      {error && <div className="proxy-error">{error}</div>}

      <form className="proxy-mode-row" onSubmit={submitNav}>
        <button
          type="button"
          className="chip"
          title="Back"
          onClick={() => browserBack().catch((e) => setError(String(e)))}
        >
          ‹
        </button>
        <button
          type="button"
          className="chip"
          title="Forward"
          onClick={() => browserForward().catch((e) => setError(String(e)))}
        >
          ›
        </button>
        <button
          type="button"
          className="chip"
          title="Reload"
          onClick={() => browserReload().catch((e) => setError(String(e)))}
        >
          ↻
        </button>
        <button
          type="button"
          className="chip"
          title="Stop loading"
          onClick={() => browserStop().catch((e) => setError(String(e)))}
        >
          ✕
        </button>
        <input
          type="text"
          className="proxy-browser-url"
          spellCheck={false}
          value={urlInput}
          onChange={(e) => setUrlInput(e.target.value)}
          placeholder="https://target.example/login"
          style={{ flex: 1, minWidth: "16em" }}
        />
        <button type="submit" className="chip active">
          Go
        </button>
        <button
          type="button"
          className="chip"
          title="Close the embedded browser and free its memory"
          onClick={() => {
            browserClose().catch(() => {});
          }}
        >
          Close browser
        </button>
      </form>

      <p className="muted">
        Traffic from this browser flows through the corvex proxy at{" "}
        <code>127.0.0.1:8888</code>. Pages you visit appear in the{" "}
        <strong>Traffic</strong> tab and respect Scope, Intercept rules,
        and the Intercept mode toggle above. Start the proxy from the
        toolbar before navigating.
      </p>
      {currentUrl && (
        <p className="muted">
          Current URL: <code>{currentUrl}</code>
        </p>
      )}

      <div
        ref={mountRef}
        className="proxy-browser-mount"
        style={{
          flex: 1,
          minHeight: "20em",
          width: "100%",
          background: "var(--surface-2, rgba(0,0,0,0.05))",
          border: "1px solid var(--border, rgba(255,255,255,0.08))",
          borderRadius: 4,
        }}
      />
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
  /** Default ON — token-rotating apps reject replays with stale
   *  CSRF tokens. Toggle off to send the request exactly as typed
   *  (useful when reproducing a deliberate token-mismatch). */
  const [applyCsrf, setApplyCsrf] = useState<boolean>(true);

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
      const r = await replaySend(base.id, edited, applyCsrf);
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
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <label
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
              fontSize: "calc(var(--font-base) - 1px)",
            }}
            title="Splice the latest captured CSRF token into the outbound request after your edits. Turn off to reproduce a deliberate token-mismatch."
          >
            <input
              type="checkbox"
              checked={applyCsrf}
              onChange={(e) => setApplyCsrf(e.target.checked)}
            />
            Apply CSRF
          </label>
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
