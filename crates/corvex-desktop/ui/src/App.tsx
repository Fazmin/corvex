import { useCallback, useEffect, useRef, useState } from "react";
import {
  cancelScan,
  dbSummary,
  listPlugins,
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
import { ScaView } from "./components/ScaView";
import { SettingsView } from "./components/SettingsView";
import { HelpView } from "./components/HelpView";
import { ToastContainer, type Toast, type ToastKind } from "./components/Toast";
import { SeverityBreakdown } from "./components/SeverityBreakdown";
import { OnboardingTour, hasSeenTour } from "./components/OnboardingTour";

export default function App() {
  const [view, setView] = useState<View>("dashboard");
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
  const [pluginCount, setPluginCount] = useState(0);
  const [requestRate, setRequestRate] = useState<number | null>(null);
  const [activeMode, setActiveMode] = useState(false);
  const [currentHost, setCurrentHost] = useState<string | null>(null);
  const [scanMaxUrls, setScanMaxUrls] = useState(500);
  const [scanCrawlDepth, setScanCrawlDepth] = useState(3);
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
    listPlugins().then((list) => setPluginCount(list.length));

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
          pluginCount={pluginCount}
          testsCount={dbs?.tests ?? 0}
          collapsed={sidebarCollapsed}
          onToggleCollapsed={toggleSidebar}
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
              <StatsBar
              stats={stats}
              running={running}
              requestRate={requestRate}
              activeMode={activeMode}
              maxUrls={scanMaxUrls}
              crawlDepth={scanCrawlDepth}
            />
              <SeverityBreakdown findings={findings} />
              <ScanForm running={running} onStart={handleStart} onCancel={handleCancel} />
              <FindingsTable findings={findings} />
              <LogPanel lines={log} />
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
              />
            </div>
          )}
          {view === "databases" && (
            <div className="dashboard single-pane">
              <DatabasesView />
            </div>
          )}
          {view === "sca" && (
            <div className="dashboard single-pane">
              <ScaView />
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
