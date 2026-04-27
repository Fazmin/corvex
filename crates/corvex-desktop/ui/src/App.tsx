import { useCallback, useEffect, useRef, useState } from "react";
import {
  cancelScan,
  dbSummary,
  onDone,
  onFinding,
  interceptRulesGet,
  interceptRulesSet,
  onHostEnd,
  onHostStart,
  onLogLine,
  onSummary,
  proxySeedHost,
  scanStats,
  scopeGet,
  scopeSet,
  startScan,
  versionInfo,
  type DbSummary,
  type FindingPayload,
  type LogLine,
  type ScanParams,
  type ScanStats,
  type VersionInfo,
} from "./api";
import { ScanForm } from "./components/ScanForm";
import { ScanIndicator } from "./components/ScanIndicator";
import { StatsBar } from "./components/StatsBar";
import { FindingsTable } from "./components/FindingsTable";
import { LogPanel } from "./components/LogPanel";
import { TitleBar } from "./components/TitleBar";
import { Sidebar, type View } from "./components/Sidebar";
import { HistoryView } from "./components/HistoryView";
import { PluginsView } from "./components/PluginsView";
import { DatabasesView } from "./components/DatabasesView";
import { FuzzingView } from "./components/FuzzingView";
import { ProbingView } from "./components/ProbingView";
import { ProxyView } from "./components/ProxyView";
import { ReconView } from "./components/ReconView";
import { ScaView } from "./components/ScaView";
import { SettingsView } from "./components/SettingsView";
import { HelpView } from "./components/HelpView";
import { LandingView } from "./components/LandingView";
import { AssetsView } from "./components/AssetsView";
import { AssetDetailView } from "./components/AssetDetailView";
import { useAssetNav } from "./asset_nav";
import { ToastContainer, type Toast, type ToastKind } from "./components/Toast";
import {
  SeverityBreakdown,
  type SeverityFilter,
} from "./components/SeverityBreakdown";
import { OnboardingTour, hasSeenTour } from "./components/OnboardingTour";
import { createRafBatcher } from "./util/rafBatch";

export interface FuzzerSeed {
  url: string;
  // Origin exchange id — mainly used so the runner can label its run in
  // the history alongside the captured request that seeded it.
  exchangeId?: string;
  /** Set when the seed came from a clustered endpoint pattern in the
   *  Traffic tab's "Group by endpoint" view. Carries the pattern shape
   *  so the fuzzer banner can show the user where path-segment
   *  injection points came from. */
  cluster?: {
    method: string;
    host: string;
    port: number;
    scheme: string;
    pattern: string;
  };
  /** Path-segment injection hints derived from the cluster pattern.
   *  Each hint names a 0-based path segment index the fuzzer should
   *  treat as an injection point. Consumed by
   *  `FuzzTarget::from_pattern_url` once the runner picks them up. */
  injectionHints?: PathSegmentHint[];
}

export interface PathSegmentHint {
  kind: "path_segment";
  /** 0-based index of the segment in the path (excluding leading
   *  slash). For `/api/users/:id` the placeholder sits at index 2. */
  index: number;
  /** The placeholder kind (`id` / `uuid` / `oid` / `slug`) so a future
   *  payload corpus can be picked per kind. */
  placeholder: string;
}

export default function App() {
  const [view, setView] = useState<View>("home");
  const assetNav = useAssetNav();
  // Selecting an asset (from any source — sidebar Assets row, an
  // AssetLink in another view, a related-asset chip) flips the main
  // view into the detail mode. Clearing the selection or navigating
  // back to the assets list nukes detail mode automatically.
  useEffect(() => {
    if (assetNav.selected) {
      setView("asset-detail");
    } else if (view === "asset-detail") {
      setView("assets");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [assetNav.selected]);
  const [fuzzerSeed, setFuzzerSeed] = useState<FuzzerSeed | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem("corvexSidebarCollapsed") === "1";
    } catch {
      return false;
    }
  });
  const toggleSidebar = useCallback(() => {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem("corvexSidebarCollapsed", next ? "1" : "0");
      } catch {
        // ignore quota / disabled storage
      }
      return next;
    });
  }, []);
  const [scanId, setScanId] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  // Distinguishes a Web-scan run from a pure Fuzzing run so the
  // dashboard, sidebar pulse and history "kind" labels reflect what
  // the user actually launched. Both flows hit the same backend
  // engine; this tag lives only in the UI.
  const [scanSource, setScanSource] = useState<"web" | "fuzz" | null>(null);
  const [findings, setFindings] = useState<FindingPayload[]>([]);
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [log, setLog] = useState<string[]>([]);
  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [dbs, setDbs] = useState<DbSummary | null>(null);
  const [requestRate, setRequestRate] = useState<number | null>(null);
  const [activeMode, setActiveMode] = useState(false);
  const [currentHost, setCurrentHost] = useState<string | null>(null);
  const [scanMaxUrls, setScanMaxUrls] = useState(500);
  const [scanCrawlDepth, setScanCrawlDepth] = useState(3);

  // Dashboard severity filter — lifted here so the minimal severity
  // strip below the Findings table can act as the filter control,
  // avoiding a duplicate "All Sev" chip row inside the Findings panel.
  const SEV_FILTER_KEY = "corvexFindingsSevFilter";
  const [dashSevFilter, setDashSevFilter] = useState<SeverityFilter>(() => {
    try {
      const raw = localStorage.getItem(SEV_FILTER_KEY);
      if (
        raw === "all" ||
        raw === "CRITICAL" ||
        raw === "HIGH" ||
        raw === "MEDIUM" ||
        raw === "LOW" ||
        raw === "INFO"
      ) {
        return raw as SeverityFilter;
      }
    } catch {
      /* ignore */
    }
    return "all";
  });
  useEffect(() => {
    try {
      localStorage.setItem(SEV_FILTER_KEY, dashSevFilter);
    } catch {
      /* ignore */
    }
  }, [dashSevFilter]);

  // User-draggable height for the Findings panel. `null` means "use the
  // responsive CSS default" (a viewport-relative `clamp()`), which is
  // the first-run behaviour so the layout can't overflow the window.
  // Once the user drags the handle, we switch to an explicit pixel
  // height and persist it.
  const FINDINGS_HEIGHT_KEY = "corvexFindingsHeight";
  const FINDINGS_MIN = 160;
  const FINDINGS_MAX = 1200;
  const [findingsHeight, setFindingsHeight] = useState<number | null>(() => {
    try {
      const raw = localStorage.getItem(FINDINGS_HEIGHT_KEY);
      const n = raw ? Number(raw) : NaN;
      if (Number.isFinite(n) && n >= FINDINGS_MIN && n <= FINDINGS_MAX) return n;
    } catch {
      /* ignore */
    }
    return null;
  });
  const findingsContainerRef = useRef<HTMLDivElement | null>(null);
  const dragRef = useRef<{ startY: number; startHeight: number } | null>(null);
  const [dragging, setDragging] = useState(false);

  const startResize = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    // Capture the current *rendered* height so the first drag picks up
    // wherever the responsive default has placed the panel.
    const current =
      findingsContainerRef.current?.getBoundingClientRect().height ?? 360;
    dragRef.current = { startY: e.clientY, startHeight: Math.round(current) };
    setDragging(true);
  }, []);

  useEffect(() => {
    if (!dragging) return;
    const onMove = (e: MouseEvent) => {
      if (!dragRef.current) return;
      const delta = e.clientY - dragRef.current.startY;
      const next = Math.max(
        FINDINGS_MIN,
        Math.min(FINDINGS_MAX, dragRef.current.startHeight + delta)
      );
      setFindingsHeight(next);
    };
    const onUp = () => {
      dragRef.current = null;
      setDragging(false);
    };
    document.body.style.cursor = "row-resize";
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [dragging]);

  useEffect(() => {
    try {
      if (findingsHeight === null) {
        localStorage.removeItem(FINDINGS_HEIGHT_KEY);
      } else {
        localStorage.setItem(FINDINGS_HEIGHT_KEY, String(findingsHeight));
      }
    } catch {
      /* ignore */
    }
  }, [findingsHeight]);
  // Bumped on every scan completion so HistoryView re-fetches.
  const [historyRefresh, setHistoryRefresh] = useState(0);

  const [showTour, setShowTour] = useState(() => !hasSeenTour());

  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastIdRef = useRef(0);
  const pushToast = useCallback((kind: ToastKind, message: string) => {
    const id = ++toastIdRef.current;
    setToasts((prev) => [...prev, { id, kind, message }]);
  }, []);
  const dismissToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const unlisteners = useRef<(() => void)[]>([]);
  const statsTimer = useRef<number | null>(null);
  const lastStatsSample = useRef<{ requests: number; at: number } | null>(null);
  const findingsBatcher = useRef<ReturnType<typeof createRafBatcher<FindingPayload>> | null>(null);

  // One-time: load version banner, DB stats, plugin count, and
  // subscribe to the global tracing log stream. The log subscription
  // lives for the whole app lifetime, independent of any particular
  // scan.
  useEffect(() => {
    versionInfo().then(setVersion);
    dbSummary().then(setDbs);

    let unlisten: (() => void) | null = null;
    const logBatcher = createRafBatcher<string>((batch) => {
      setLog((prev) => {
        const next = prev.length === 0 ? batch.slice() : [...prev, ...batch];
        return next.length > 500 ? next.slice(-500) : next;
      });
    });
    onLogLine((line: LogLine) => {
      const short = line.target.split("::").pop() ?? line.target;
      logBatcher.push(`${line.level.padEnd(5)} ${short.padEnd(14)} ${line.message}`);
    }).then((fn) => {
      unlisten = fn;
    });

    return () => {
      if (unlisten) unlisten();
      logBatcher.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const appendLog = useCallback((line: string) => {
    setLog((prev) => {
      const next = [...prev, `UI    frontend       ${line}`];
      return next.length > 500 ? next.slice(-500) : next;
    });
  }, []);

  const cleanupListeners = useCallback(() => {
    unlisteners.current.forEach((fn) => {
      try {
        fn();
      } catch {
        // ignore
      }
    });
    unlisteners.current = [];
    if (statsTimer.current !== null) {
      window.clearInterval(statsTimer.current);
      statsTimer.current = null;
    }
    if (findingsBatcher.current) {
      findingsBatcher.current.dispose();
      findingsBatcher.current = null;
    }
    lastStatsSample.current = null;
    setRequestRate(null);
  }, []);

  const handleStart = useCallback(
    async (params: ScanParams) => {
      cleanupListeners();
      setFindings([]);
      setStats(null);
      setCurrentHost(null);
      setActiveMode(params.active ?? false);
      setScanMaxUrls(params.max_urls ?? 500);
      setScanCrawlDepth(params.crawl_depth ?? 3);
      // A pure Fuzzing run sets `plugins: "@@ACTIVE"` so the engine
      // keeps only the active modules and drops the signature set —
      // that's the marker for "this came from the Fuzzing view."
      // (`@@NONE` is treated the same way for forward compatibility.)
      // Anything else is a Web scan.
      const fuzzMarker =
        params.plugins === "@@ACTIVE" || params.plugins === "@@NONE";
      const source: "web" | "fuzz" =
        fuzzMarker && params.active ? "fuzz" : "web";
      setScanSource(source);
      appendLog(
        `→ starting ${source === "fuzz" ? "fuzz" : "scan"} against ${params.host}${params.active ? " [active]" : ""}`,
      );
      try {
        const id = await startScan(params);
        setScanId(id);
        setRunning(true);
        appendLog(`✓ scan id ${id}`);
        // A new row is in the history DB now — refresh the History
        // view if the user navigates to it.
        setHistoryRefresh((n) => n + 1);

        const hs = await onHostStart(id, (h) => {
          setCurrentHost(`${h.hostname}:${h.port}${h.ssl ? " (ssl)" : ""}`);
          appendLog(`⊙ host start ${h.hostname}:${h.port}${h.ssl ? " [ssl]" : ""}`);
        });
        const he = await onHostEnd(id, (h) => {
          setCurrentHost(null);
          appendLog(`⊗ host end ${h.hostname}:${h.port}`);
        });
        const batcher = createRafBatcher<FindingPayload>((batch) => {
          setFindings((prev) => [...prev, ...batch]);
        });
        findingsBatcher.current = batcher;
        const f = await onFinding(id, (finding) => {
          batcher.push(finding);
        });
        const sum = await onSummary(id, (s) => {
          appendLog(
            `Σ ${s.total_requests} requests · ${s.total_findings} findings · ${s.total_errors} errors · ${s.elapsed_secs}s`
          );
        });
        const done = await onDone(id, (d) => {
          setRunning(false);
          batcher.flush();
          if (d.cancelled) {
            appendLog("✗ cancelled");
            pushToast("info", "Scan cancelled");
          } else if (d.error) {
            appendLog(`✗ error: ${d.error}`);
            pushToast("error", `Scan failed: ${d.error}`);
          } else {
            appendLog("✓ done");
            pushToast("success", "Scan complete");
          }
          setHistoryRefresh((n) => n + 1);
        });
        unlisteners.current.push(hs, he, f, sum, done);

        // Poll stats while running and compute a rolling request rate
        // from the delta between successive samples.
        statsTimer.current = window.setInterval(async () => {
          try {
            const s = await scanStats(id);
            if (!s) return;
            setStats(s);
            const now = Date.now();
            const prev = lastStatsSample.current;
            if (prev) {
              const dt = (now - prev.at) / 1000;
              if (dt > 0) {
                setRequestRate((s.total_requests - prev.requests) / dt);
              }
            }
            lastStatsSample.current = { requests: s.total_requests, at: now };
          } catch (_) {
            // ignore
          }
        }, 750);
      } catch (err) {
        appendLog(`✗ failed to start: ${err}`);
        pushToast("error", `Failed to start scan: ${err}`);
        setRunning(false);
      }
    },
    [appendLog, cleanupListeners, pushToast]
  );

  const handleCancel = useCallback(async () => {
    if (!scanId) return;
    appendLog("→ cancelling");
    const ok = await cancelScan(scanId);
    appendLog(ok ? "✓ cancel requested" : "? scan not found");
  }, [scanId, appendLog]);

  const handleRerun = useCallback(
    (params: ScanParams) => {
      setView("dashboard");
      handleStart(params);
    },
    [handleStart]
  );

  // "New scan" — return to the dashboard and clear the previous run's
  // findings/stats so the form is uncluttered.
  const handleNewScan = useCallback(() => {
    setView("dashboard");
    if (running) return; // don't wipe an in-flight scan's state
    cleanupListeners();
    setScanId(null);
    setFindings([]);
    setStats(null);
    appendLog("→ ready for a new scan");
  }, [running, cleanupListeners, appendLog]);

  useEffect(() => () => cleanupListeners(), [cleanupListeners]);

  const headline = running
    ? currentHost
      ? `Scanning ${currentHost}`
      : "Scan in progress"
    : scanId
    ? "Last scan complete"
    : "Ready to scan";
  const sub = version
    ? `corvex-rust v${version.version}${
        dbs
          ? ` · ${dbs.tests.toLocaleString()} tests · ${dbs.outdated.toLocaleString()} outdated sigs`
          : ""
      }`
    : "";

  const titleByView: Record<View, string> = {
    home: "corvex-rust",
    dashboard: "Web scan",
    history: "Scan history",
    plugins: "Plugins",
    probing: "Service Probing",
    fuzzing: "Active Fuzzing",
    proxy: "Intercept",
    recon: "Recon",
    databases: "Databases",
    sca: "Software Composition Analysis",
    assets: "Assets",
    "asset-detail": "Asset detail",
    settings: "Settings",
    help: "Help",
  };

  return (
    <div className="app">
      <TitleBar
        sidebarCollapsed={sidebarCollapsed}
        onToggleSidebar={toggleSidebar}
      />
      <div className={`shell${sidebarCollapsed ? " collapsed" : ""}`}>
        <Sidebar
          view={view}
          onSelect={(v) => {
            // Reset asset selection when the user clicks the Assets
            // sidebar entry, so they always land on the browseable
            // list rather than staying inside the previously open
            // detail page.
            if (v === "assets") assetNav.reset();
            setView(v);
          }}
          collapsed={sidebarCollapsed}
          webScanRunning={running && scanSource === "web"}
          fuzzRunning={running && scanSource === "fuzz"}
        />
        <main className={`main${view === "home" ? " main-home" : ""}`}>
          {/* The landing page has its own hero — skip the standard
              page header so the two don't compete. */}
          {view !== "home" && (
            <header className="main-header">
              <div>
                <h1>{titleByView[view]}</h1>
                <div className="sub">{sub}</div>
              </div>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  justifyContent: "flex-end",
                }}
              >
                <div className="sub" style={{ textAlign: "right" }}>
                  {headline}
                  {scanId && (
                    <>
                      {" · "}
                      <code>{scanId.slice(0, 8)}</code>
                    </>
                  )}
                </div>
                {view === "dashboard" &&
                  !(running && scanSource === "web") &&
                  (findings.length > 0 || stats !== null || log.length > 0) && (
                    <button
                      type="button"
                      className="ghost-btn"
                      onClick={handleNewScan}
                      title="Clear previous results and start fresh"
                    >
                      New scan
                    </button>
                  )}
              </div>
            </header>
          )}

          {view === "home" && <LandingView onNavigate={setView} />}

          {view === "dashboard" && (
            <div className="dashboard">
              {/* `webRunning` is the dashboard's "is *my* run live?"
                  flag — true only for Web scans. A Fuzzing-view run
                  doesn't claim the dashboard; we surface a small
                  cross-link instead so the user knows where it lives. */}
              {(() => {
                const webRunning = running && scanSource === "web";
                const fuzzRunning = running && scanSource === "fuzz";
                return (
                  <>
                    {webRunning && (
                      <ScanIndicator label="Scanning" onCancel={handleCancel} />
                    )}
                    {fuzzRunning && (
                      <div
                        style={{
                          padding: "4px 10px",
                          marginBottom: 8,
                          borderRadius: 999,
                          background: "var(--accent-soft)",
                          border: "1px solid var(--accent-border)",
                          color: "var(--accent)",
                          fontSize: "calc(var(--font-base) - 2px)",
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 8,
                          alignSelf: "flex-start",
                          width: "fit-content",
                        }}
                      >
                        <span
                          aria-hidden
                          style={{
                            width: 6,
                            height: 6,
                            borderRadius: 999,
                            background: "var(--accent)",
                          }}
                        />
                        <span>Fuzzing run in progress</span>
                        <button
                          type="button"
                          onClick={() => setView("fuzzing")}
                          style={{
                            background: "transparent",
                            border: "none",
                            color: "var(--accent)",
                            cursor: "pointer",
                            padding: 0,
                            fontSize: "inherit",
                            textDecoration: "underline",
                          }}
                        >
                          open
                        </button>
                      </div>
                    )}
                    <StatsBar
                      stats={webRunning ? stats : null}
                      running={webRunning}
                      requestRate={webRunning ? requestRate : null}
                      activeMode={activeMode}
                      maxUrls={scanMaxUrls}
                      crawlDepth={scanCrawlDepth}
                    />
                    <ScanForm
                      running={webRunning}
                      onStart={handleStart}
                      onCancel={handleCancel}
                    />
                  </>
                );
              })()}
              {(() => {
                // Log + findings on the dashboard only mean something
                // for Web-scan runs. While a Fuzzing run is in flight
                // (or its findings are still in the shared buffer)
                // suppress the table so the dashboard doesn't claim
                // them; the Fuzzing view shows them inline already.
                const isFuzz = scanSource === "fuzz";
                const dashFindings = isFuzz ? [] : findings;
                const dashLog = isFuzz ? [] : log;
                const logVisible =
                  (running && scanSource === "web") || dashLog.length > 0;
                return (
                  <div
                    className={`dashboard-right-col${logVisible ? "" : " idle"}`}
                  >
                    <div
                      className="findings-container"
                      ref={findingsContainerRef}
                      style={
                        logVisible && findingsHeight !== null
                          ? ({ ["--findings-h" as string]: `${findingsHeight}px` } as React.CSSProperties)
                          : undefined
                      }
                    >
                      <FindingsTable
                        findings={dashFindings}
                        sevFilter={dashSevFilter}
                        onSevFilterChange={setDashSevFilter}
                        hideSeverityChips
                      />
                    </div>
                    {logVisible && (
                      <div
                        className={`findings-resize-handle${dragging ? " dragging" : ""}`}
                        onMouseDown={startResize}
                        role="separator"
                        aria-orientation="horizontal"
                        aria-label="Resize findings panel"
                        title="Drag to resize findings panel"
                      />
                    )}
                    <SeverityBreakdown
                      findings={dashFindings}
                      value={dashSevFilter}
                      onChange={setDashSevFilter}
                    />
                    {logVisible && <LogPanel lines={dashLog} />}
                  </div>
                );
              })()}
            </div>
          )}
          {view === "history" && (
            <div className="dashboard single-pane">
              <HistoryView refreshKey={historyRefresh} onRerun={handleRerun} running={running} />
            </div>
          )}
          {view === "plugins" && (
            <div className="dashboard single-pane">
              <PluginsView />
            </div>
          )}
          {view === "probing" && (
            <div className="dashboard single-pane">
              <ProbingView />
            </div>
          )}
          {view === "fuzzing" && (
            <div className="dashboard single-pane">
              <FuzzingView
                running={running && scanSource === "fuzz"}
                scanId={scanSource === "fuzz" ? scanId : null}
                findings={scanSource === "fuzz" ? findings : []}
                stats={scanSource === "fuzz" ? stats : null}
                onStart={handleStart}
                onCancel={handleCancel}
                seed={fuzzerSeed}
                onSeedConsumed={() => setFuzzerSeed(null)}
                currentHost={scanSource === "fuzz" ? currentHost : null}
                requestRate={scanSource === "fuzz" ? requestRate : null}
              />
            </div>
          )}
          {view === "databases" && (
            <div className="dashboard single-pane">
              <DatabasesView onNavigate={setView} />
            </div>
          )}
          {view === "sca" && (
            <div className="dashboard single-pane">
              <ScaView />
            </div>
          )}
          {view === "proxy" && (
            <div className="dashboard single-pane">
              <ProxyView
                onSendToFuzzer={(seed) => {
                  setFuzzerSeed(seed);
                  setView("fuzzing");
                }}
              />
            </div>
          )}
          {view === "recon" && (
            <div className="dashboard single-pane">
              <ReconView
                onSendToFuzzer={(seed) => {
                  setFuzzerSeed(seed);
                  setView("fuzzing");
                }}
                onAddToProxyScope={async (host) => {
                  // Fetch current, append as an include rule if not
                  // already present, save.
                  const rules = await scopeGet();
                  const already = rules.include.some(
                    (r) =>
                      r.host.toLowerCase() === host.toLowerCase() &&
                      !r.path_regex &&
                      !r.port,
                  );
                  if (already) return;
                  const next = {
                    include: [
                      ...rules.include,
                      { host, path_regex: null, port: null },
                    ],
                    exclude: rules.exclude,
                  };
                  await scopeSet(next);
                }}
                onSendToChecks={async (host) => {
                  await proxySeedHost({ host, source: "recon" });
                }}
                onPauseHost={async (host) => {
                  // Append an Include intercept rule for the host
                  // (request phase) so the next request to a freshly-
                  // discovered subdomain pauses. Symmetric to
                  // onAddToProxyScope: scope admits, this pauses.
                  const current = await interceptRulesGet();
                  const already = current.rules.some((r) =>
                    r.kind === "include" &&
                    r.conditions.some(
                      (c) =>
                        c.kind === "HostGlob" &&
                        c.pattern.toLowerCase() === host.toLowerCase(),
                    ),
                  );
                  if (already) return;
                  await interceptRulesSet({
                    rules: [
                      ...current.rules,
                      {
                        id: `recon-${host}-${Date.now().toString(36)}`,
                        kind: "include",
                        phase: "request",
                        enabled: true,
                        conditions: [{ kind: "HostGlob", pattern: host }],
                      },
                    ],
                  });
                }}
              />
            </div>
          )}
          {view === "assets" && (
            <div className="dashboard single-pane">
              <AssetsView />
            </div>
          )}
          {view === "asset-detail" && (
            <div className="dashboard single-pane">
              <AssetDetailView />
            </div>
          )}
          {view === "settings" && (
            <div className="dashboard single-pane">
              <SettingsView />
            </div>
          )}
          {view === "help" && (
            <div className="dashboard single-pane">
              <HelpView />
            </div>
          )}
        </main>
      </div>
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
      {showTour && <OnboardingTour onClose={() => setShowTour(false)} />}
    </div>
  );
}
