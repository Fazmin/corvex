import { useCallback, useEffect, useRef, useState } from "react";
import {
  cancelScan,
  dbSummary,
  onDone,
  onFinding,
  onHostEnd,
  onHostStart,
  onLogLine,
  onSummary,
  scanStats,
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
import { ScaView } from "./components/ScaView";
import { SettingsView } from "./components/SettingsView";
import { HelpView } from "./components/HelpView";
import { ToastContainer, type Toast, type ToastKind } from "./components/Toast";
import {
  SeverityBreakdown,
  type SeverityFilter,
} from "./components/SeverityBreakdown";
import { OnboardingTour, hasSeenTour } from "./components/OnboardingTour";

export interface FuzzerSeed {
  url: string;
  // Origin exchange id — mainly used so the runner can label its run in
  // the history alongside the captured request that seeded it.
  exchangeId?: string;
}

export default function App() {
  const [view, setView] = useState<View>("dashboard");
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

  // One-time: load version banner, DB stats, plugin count, and
  // subscribe to the global tracing log stream. The log subscription
  // lives for the whole app lifetime, independent of any particular
  // scan.
  useEffect(() => {
    versionInfo().then(setVersion);
    dbSummary().then(setDbs);

    let unlisten: (() => void) | null = null;
    onLogLine((line: LogLine) => {
      const short = line.target.split("::").pop() ?? line.target;
      const formatted = `${line.level.padEnd(5)} ${short.padEnd(14)} ${line.message}`;
      setLog((prev) => {
        const next = [...prev, formatted];
        return next.length > 500 ? next.slice(-500) : next;
      });
    }).then((fn) => {
      unlisten = fn;
    });

    return () => {
      if (unlisten) unlisten();
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
      appendLog(`→ starting scan against ${params.host}${params.active ? " [active]" : ""}`);
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
        const f = await onFinding(id, (finding) => {
          setFindings((prev) => [...prev, finding]);
        });
        const sum = await onSummary(id, (s) => {
          appendLog(
            `Σ ${s.total_requests} requests · ${s.total_findings} findings · ${s.total_errors} errors · ${s.elapsed_secs}s`
          );
        });
        const done = await onDone(id, (d) => {
          setRunning(false);
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
    dashboard: "Dashboard",
    history: "Scan history",
    plugins: "Plugins",
    probing: "Service Probing",
    fuzzing: "Active Fuzzing",
    proxy: "Intercept",
    databases: "Databases",
    sca: "Software Composition Analysis",
    settings: "Settings",
    help: "Help",
  };

  return (
    <div className="app">
      <TitleBar />
      <div className={`shell${sidebarCollapsed ? " collapsed" : ""}`}>
        <Sidebar
          view={view}
          onSelect={setView}
          onNewScan={handleNewScan}
          collapsed={sidebarCollapsed}
          onToggleCollapsed={toggleSidebar}
          webScanRunning={running}
        />
        <main className="main">
          <header className="main-header">
            <div>
              <h1>{titleByView[view]}</h1>
              <div className="sub">{sub}</div>
            </div>
            <div className="sub" style={{ textAlign: "right" }}>
              {headline}
              {scanId && (
                <>
                  {" · "}
                  <code>{scanId.slice(0, 8)}</code>
                </>
              )}
            </div>
          </header>

          {view === "dashboard" && (
            <div className="dashboard">
              {running && (
                <ScanIndicator label="Scanning" onCancel={handleCancel} />
              )}
              <StatsBar
                stats={stats}
                running={running}
                requestRate={requestRate}
                activeMode={activeMode}
                maxUrls={scanMaxUrls}
                crawlDepth={scanCrawlDepth}
              />
              <ScanForm running={running} onStart={handleStart} onCancel={handleCancel} />
              {(() => {
                // Log only makes sense once scan traffic exists — hide it
                // (and the findings/log resize handle with it) when the
                // dashboard is idle so findings + severity fit the viewport
                // without an empty "—" log panel under them.
                const logVisible = running || log.length > 0;
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
                        findings={findings}
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
                      findings={findings}
                      value={dashSevFilter}
                      onChange={setDashSevFilter}
                    />
                    {logVisible && <LogPanel lines={log} />}
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
                running={running}
                scanId={scanId}
                findings={findings}
                stats={stats}
                onStart={handleStart}
                onCancel={handleCancel}
                seed={fuzzerSeed}
                onSeedConsumed={() => setFuzzerSeed(null)}
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
