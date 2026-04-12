import type { ScanStats } from "../api";
import { StatCard } from "./StatCard";

interface Props {
  stats: ScanStats | null;
  running: boolean;
  requestRate: number | null;
  activeMode?: boolean;
  urlsCrawled?: number;
}

/**
 * Four-up stat grid. Each card shows a raw count plus a percentile
 * visualisation so the operator can see how the scan is progressing
 * relative to the total request volume.
 */
export function StatsBar({ stats, running, requestRate, activeMode, urlsCrawled }: Props) {
  const requests = stats?.total_requests ?? 0;
  const findings = stats?.total_findings ?? 0;
  const errors = stats?.total_errors ?? 0;
  const elapsed = stats?.elapsed_secs ?? 0;
  const hosts = stats?.hosts_completed ?? 0;

  // "Percentile" style indicators derived from live stats.
  // findings/requests and errors/requests, clamped 0–100.
  const findingsPct = requests > 0 ? (findings / requests) * 100 : 0;
  const errorsPct = requests > 0 ? (errors / requests) * 100 : 0;

  // Requests card: scale against a rolling target so the meter visibly
  // fills as the scan progresses. 7,500 is a rough upper bound for the
  // full db_tests run — the meter caps out for big scans.
  const REQ_TARGET = 7500;
  const requestsPct = Math.min((requests / REQ_TARGET) * 100, 100);
  const rateLabel = requestRate !== null ? `${requestRate.toFixed(1)}/s` : "—";

  return (
    <div className="stats-grid">
      <StatCard
        label="Requests"
        value={requests}
        delta={running ? rateLabel : undefined}
        percent={requestsPct}
        meterLeft={`${requestsPct.toFixed(0)}% of budget`}
        meterRight={`${hosts} host${hosts === 1 ? "" : "s"}`}
        info={
          <>
            <strong>Total HTTP requests sent</strong>
            Every probe the engine has sent so far across every plugin —
            initial fetch, robots.txt, favicon, db_tests rows, OPTIONS,
            PUT/DELETE checks and so on. The trend value shows the live
            request rate (per second). The meter is scaled against a
            7,500-request budget, which is roughly the size of a full{" "}
            <code>db_tests</code> run. The right-hand caption is the
            number of hosts the scan is spread across.
          </>
        }
      />
      <StatCard
        label="Findings"
        value={findings}
        delta={requests > 0 ? `${findingsPct.toFixed(1)}%` : undefined}
        percent={findingsPct}
        meterLeft="finding rate"
        meterRight={`${findings}/${requests || "—"}`}
        info={
          <>
            <strong>Confirmed findings</strong>
            Distinct issues the scan has reported so far — missing
            security headers, exposed admin endpoints, outdated
            software banners, DSL test matches, robots.txt entries and
            so on. The percentage is the finding-to-request ratio (how
            often a probe lands on something interesting). A high
            ratio usually means the target is poorly hardened or the
            tuning filter selected aggressive categories.
          </>
        }
      />
      <StatCard
        label="Errors"
        value={errors}
        delta={errors > 0 ? `${errorsPct.toFixed(1)}%` : "0%"}
        danger={errors > 0}
        percent={errorsPct}
        meterLeft="error rate"
        meterRight={errors > 0 ? `${errors}/${requests}` : "healthy"}
        info={
          <>
            <strong>Network / parse errors</strong>
            Requests that failed before producing a usable response —
            connection refused, TLS handshake failure, request timeout,
            unparseable HTTP, or the target dropping the socket. A
            handful of errors during a scan is normal (some endpoints
            simply 503 or RST). A high error rate (more than ~5%)
            usually means a network issue, an aggressive WAF, or that
            the concurrency setting is too high for this host.
          </>
        }
      />
      <StatCard
        label="Elapsed"
        value={`${elapsed}s`}
        delta={running ? "running" : "idle"}
        percent={running ? Math.min((elapsed / 600) * 100, 100) : 0}
        meterLeft={running ? "10m target" : "scan complete"}
        meterRight={hosts > 0 ? `${hosts} done` : ""}
        info={
          <>
            <strong>Wall-clock time</strong>
            Seconds since the scan started, sampled from the engine's{" "}
            <code>GlobalState</code>. The meter is scaled against a
            10-minute target — most full <code>db_tests</code> runs
            against a single host land between 2 and 8 minutes
            depending on concurrency, target latency, and the{" "}
            <code>-Pause</code> setting. Multi-host scans run in
            parallel and bound this number to the slowest host.
          </>
        }
      />
      {activeMode && (
        <StatCard
          label="URLs Crawled"
          value={urlsCrawled ?? 0}
          delta={running ? "crawling" : ""}
          percent={Math.min(((urlsCrawled ?? 0) / 500) * 100, 100)}
          meterLeft="max-urls target"
          meterRight={`depth ≤ 3`}
          info={
            <>
              <strong>Crawler progress</strong>
              Pages the BFS crawler has visited so far. The crawler follows
              links within the configured <code>--scope</code> and stops at
              either the <code>--crawl-depth</code> or{" "}
              <code>--max-urls</code> cap — whichever hits first. Each
              crawled page is scanned for forms and parameters that the
              active fuzzers then probe.
            </>
          }
        />
      )}
    </div>
  );
}
