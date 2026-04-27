import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import {
  onReconEvent,
  reconCancel,
  reconFindingsForRun,
  reconRunDelete,
  reconRunsList,
  reconStart,
  type ReconEvent,
  type ReconFindingRow,
  type ReconRunSummary,
  type ReconStartInput,
} from "../api";
import type { FuzzerSeed } from "../App";
import { InfoTip } from "./InfoTip";
import { AssetLink } from "./asset/AssetLink";

/** Source list the backend knows about. Keep in sync with
 *  corvex_core::recon::passive_source_by_name. */
const KNOWN_SOURCES = ["crt.sh", "AlienVault OTX", "CertSpotter"] as const;
type KnownSource = (typeof KNOWN_SOURCES)[number];

type Pane = "run" | "history";

interface Props {
  /** Dispatched when the user clicks Send-to-Fuzzer on a result. */
  onSendToFuzzer?: (seed: FuzzerSeed) => void;
  /** Add a host to the Proxy scope rules. Returns once the scope has
   *  been updated so the view can show a status message. */
  onAddToProxyScope?: (host: string) => Promise<void>;
  /** Push a synthetic Exchange for the host into the active proxy
   *  session (goes through the same pipeline as OpenAPI import). */
  onSendToChecks?: (host: string) => Promise<void>;
  /** Append an Include intercept rule for the host so first-contact
   *  traffic to a freshly-discovered subdomain pauses for inspection.
   *  Symmetric counterpart to onAddToProxyScope: scope admits, this
   *  pauses. */
  onPauseHost?: (host: string) => Promise<void>;
}

export function ReconView({
  onSendToFuzzer,
  onAddToProxyScope,
  onSendToChecks,
  onPauseHost,
}: Props) {
  const [pane, setPane] = useState<Pane>("run");

  // Form state
  const [domain, setDomain] = useState<string>("");
  const [enabledSources, setEnabledSources] = useState<Set<KnownSource>>(
    new Set(KNOWN_SOURCES),
  );
  const [active, setActive] = useState<boolean>(false);
  const [wordlistPath, setWordlistPath] = useState<string | null>(null);
  const [maxConcurrent, setMaxConcurrent] = useState<number>(500);

  // Live run state
  const [runId, setRunId] = useState<string | null>(null);
  const [running, setRunning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string>("Idle");
  const [wildcardIps, setWildcardIps] = useState<string[]>([]);
  const [sourceStatus, setSourceStatus] = useState<
    Record<string, { found: number; error: string | null; done: boolean }>
  >({});
  const [bruteProgress, setBruteProgress] = useState<
    { tested: number; total: number; found: number } | null
  >(null);
  const [subdomains, setSubdomains] = useState<
    Record<string, { sources: string[]; ips: string[] }>
  >({});
  const [records, setRecords] = useState<
    Array<{ name: string; record_type: string; value: string }>
  >([]);

  // Transient action feedback
  const [actionStatus, setActionStatus] = useState<string | null>(null);

  // History pane
  const [historyRuns, setHistoryRuns] = useState<ReconRunSummary[]>([]);
  const [selectedHistory, setSelectedHistory] = useState<string | null>(null);
  const [historyFindings, setHistoryFindings] = useState<ReconFindingRow[]>([]);

  const runIdRef = useRef<string | null>(null);

  useEffect(() => {
    runIdRef.current = runId;
  }, [runId]);

  // Subscribe once to the live event bus.
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    onReconEvent((event: ReconEvent) => {
      // Only react to events for the currently-displayed run.
      if (!runIdRef.current || event.run_id !== runIdRef.current) return;
      switch (event.kind) {
        case "source_started":
          setStatus(`${event.source} — querying…`);
          setSourceStatus((prev) => ({
            ...prev,
            [event.source]: { found: 0, error: null, done: false },
          }));
          break;
        case "source_finished":
          setSourceStatus((prev) => ({
            ...prev,
            [event.source]: {
              found: event.found,
              error: event.error,
              done: true,
            },
          }));
          break;
        case "wildcard_detected":
          setWildcardIps(event.ips);
          setStatus(`Wildcard detected → ${event.ips.join(", ")}`);
          break;
        case "subdomain_discovered":
          setSubdomains((prev) => ({
            ...prev,
            [event.host]: { sources: event.sources, ips: event.ips },
          }));
          break;
        case "record_discovered":
          setRecords((prev) => [
            ...prev,
            {
              name: event.name,
              record_type: event.record_type,
              value: event.value,
            },
          ]);
          break;
        case "zone_transfer":
          setStatus(`Zone transfer succeeded — ${event.records} records`);
          break;
        case "brute_progress":
          setBruteProgress({
            tested: event.tested,
            total: event.total,
            found: event.found,
          });
          break;
        case "complete":
          setRunning(false);
          setStatus(
            `Complete — ${event.found_subdomains} subdomain(s), ${event.found_records} record(s), ${(
              event.duration_ms / 1000
            ).toFixed(1)}s`,
          );
          break;
        case "failed":
          setRunning(false);
          setError(event.error);
          setStatus("Failed");
          break;
        case "cancelled":
          setRunning(false);
          setStatus("Cancelled");
          break;
      }
    })
      .then((fn) => {
        unlisten = fn;
      })
      .catch(() => {});
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  const loadHistory = useCallback(async () => {
    try {
      const runs = await reconRunsList(50);
      setHistoryRuns(runs);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    if (pane === "history") loadHistory();
  }, [pane, loadHistory]);

  const loadHistoryFindings = useCallback(async (id: string) => {
    try {
      const rows = await reconFindingsForRun(id);
      setHistoryFindings(rows);
      setSelectedHistory(id);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  const toggleSource = (source: KnownSource) => {
    setEnabledSources((prev) => {
      const next = new Set(prev);
      if (next.has(source)) next.delete(source);
      else next.add(source);
      return next;
    });
  };

  const handlePickWordlist = async () => {
    try {
      const picked = (await openDialog({
        title: "Select wordlist",
        multiple: false,
        directory: false,
        filters: [
          { name: "Text files", extensions: ["txt", "list"] },
          { name: "All files", extensions: ["*"] },
        ],
      })) as string | null;
      if (picked) setWordlistPath(picked);
    } catch (e) {
      setError(String(e));
    }
  };

  const handleStart = async () => {
    if (!domain.trim()) {
      setError("Enter a domain first.");
      return;
    }
    setError(null);
    setActionStatus(null);
    setSubdomains({});
    setRecords([]);
    setSourceStatus({});
    setWildcardIps([]);
    setBruteProgress(null);
    setStatus("Starting…");
    setRunning(true);

    const input: ReconStartInput = {
      domain: domain.trim(),
      passive_sources: Array.from(enabledSources),
      active,
      wordlist_path: wordlistPath ?? undefined,
      max_concurrent: maxConcurrent,
    };
    try {
      const id = await reconStart(input);
      setRunId(id);
    } catch (e) {
      setError(String(e));
      setRunning(false);
    }
  };

  const handleCancel = async () => {
    if (!runId) return;
    try {
      await reconCancel(runId);
    } catch (e) {
      setError(String(e));
    }
  };

  const handleDeleteRun = async (id: string) => {
    try {
      await reconRunDelete(id);
      if (selectedHistory === id) {
        setSelectedHistory(null);
        setHistoryFindings([]);
      }
      await loadHistory();
    } catch (e) {
      setError(String(e));
    }
  };

  const subdomainRows = useMemo(() => {
    return Object.entries(subdomains)
      .map(([host, v]) => ({ host, ...v }))
      .sort((a, b) => a.host.localeCompare(b.host));
  }, [subdomains]);

  const addAllToScope = async () => {
    if (!onAddToProxyScope) return;
    setActionStatus("Adding all hosts to proxy scope…");
    let added = 0;
    for (const row of subdomainRows) {
      try {
        await onAddToProxyScope(row.host);
        added += 1;
      } catch (e) {
        setError(String(e));
        break;
      }
    }
    setActionStatus(`Added ${added} host(s) to Proxy → Scope rules.`);
  };

  const historySummary = selectedHistory
    ? historyRuns.find((r) => r.id === selectedHistory)
    : null;

  return (
    <div className="recon-view">
      <div className="recon-header">
        <h2>Recon</h2>
        <div className="recon-tabs">
          <button
            type="button"
            className={`chip${pane === "run" ? " active" : ""}`}
            onClick={() => setPane("run")}
          >
            Run
          </button>
          <button
            type="button"
            className={`chip${pane === "history" ? " active" : ""}`}
            onClick={() => setPane("history")}
          >
            History
          </button>
        </div>
      </div>

      {error && <div className="proxy-error">{error}</div>}

      {pane === "run" && (
        <>
          <section className="panel recon-form">
            <label>
              <span className="recon-label-row">
                <span className="muted">Target domain</span>
                <InfoTip label="Target domain help">
                  <strong>Target domain</strong>
                  The apex domain (or any subdomain) you want to expand.
                  Enter the bare host without a scheme or path —{" "}
                  <code>example.com</code>, not{" "}
                  <code>https://example.com/login</code>. Passive sources
                  are queried for <code>*.domain</code>; active mode runs
                  record lookups against this exact name and brute-forces{" "}
                  <code>prefix.domain</code> from the wordlist.
                </InfoTip>
              </span>
              <input
                type="text"
                className="input"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="example.com"
                disabled={running}
                spellCheck={false}
              />
            </label>

            <div>
              <div className="recon-label-row" style={{ marginBottom: 4 }}>
                <span className="muted">Passive sources</span>
                <InfoTip label="Passive sources help">
                  <strong>Passive sources</strong>
                  Public aggregators that have already indexed the
                  target's certificates or past DNS activity. Toggle any
                  subset — the runner fans out to the enabled ones
                  concurrently and unions the results.
                  <ul style={{ margin: "6px 0 0 16px", padding: 0 }}>
                    <li>
                      <strong>crt.sh</strong> — certificate transparency
                      search. High yield; every TLS cert ever issued for
                      the domain shows up here.
                    </li>
                    <li>
                      <strong>AlienVault OTX</strong> — community passive
                      DNS. Good coverage for hosts that ever resolved in
                      the wild.
                    </li>
                    <li>
                      <strong>CertSpotter</strong> — a second CT source
                      with a different lookback window. Often surfaces
                      short-lived staging / preprod certs crt.sh missed.
                    </li>
                  </ul>
                  All three are keyless; no traffic ever touches the
                  target itself.
                </InfoTip>
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {KNOWN_SOURCES.map((s) => (
                  <button
                    key={s}
                    type="button"
                    className={`chip${enabledSources.has(s) ? " active" : ""}`}
                    onClick={() => toggleSource(s)}
                    disabled={running}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            <label className="checkbox">
              <input
                type="checkbox"
                checked={active}
                onChange={(e) => setActive(e.target.checked)}
                disabled={running}
              />
              <span>
                <strong>Active mode</strong> — enumerate DNS records + attempt
                zone transfer + run wildcard-aware wordlist brute-force
              </span>
              <InfoTip label="Active mode help">
                <strong>Active mode</strong>
                When on, the runner also issues real DNS queries against
                the target's authoritative nameservers — this is the
                only phase where traffic touches infrastructure the
                target operates. Runs four stages in order:
                <ol style={{ margin: "6px 0 0 16px", padding: 0 }}>
                  <li>
                    <strong>Records</strong>: A, AAAA, MX, NS, TXT, SOA,
                    CNAME for the seed domain.
                  </li>
                  <li>
                    <strong>Zone transfer (AXFR)</strong>: attempted
                    against every NS. Almost always refused; success is
                    a misconfiguration worth reporting.
                  </li>
                  <li>
                    <strong>Wildcard probe</strong>: resolves a
                    random-name subdomain. If it answers, the catch-all
                    IPs are captured so brute-force results that only
                    match them are filtered out.
                  </li>
                  <li>
                    <strong>Wordlist brute-force</strong>: resolves{" "}
                    <code>{`{prefix}.{domain}`}</code> for every prefix,
                    up to the configured concurrency.
                  </li>
                </ol>
                Keep wordlists + concurrency reasonable, and only run
                against assets you're authorised to test.
              </InfoTip>
            </label>

            {active && (
              <div className="recon-active-opts">
                <label>
                  <span className="recon-label-row">
                    <span className="muted">Wordlist</span>
                    <InfoTip label="Wordlist help">
                      <strong>Wordlist</strong>
                      Newline-separated subdomain prefixes the
                      brute-force resolves as{" "}
                      <code>{`{prefix}.{domain}`}</code>. Leaving the
                      field blank uses the bundled ~200-name default —
                      fine for a quick sweep. For deeper coverage,
                      browse to a bigger list (e.g.{" "}
                      <code>subdomains-top1million-5000.txt</code> from
                      SecLists). Lines starting with <code>#</code> and
                      blank lines are skipped.
                    </InfoTip>
                  </span>
                  <div style={{ display: "flex", gap: 6 }}>
                    <input
                      type="text"
                      className="input"
                      value={wordlistPath ?? "<built-in default>"}
                      readOnly
                      spellCheck={false}
                      style={{ flex: 1 }}
                    />
                    <button
                      type="button"
                      className="chip"
                      onClick={handlePickWordlist}
                      disabled={running}
                    >
                      Browse…
                    </button>
                    {wordlistPath && (
                      <button
                        type="button"
                        className="chip"
                        onClick={() => setWordlistPath(null)}
                        disabled={running}
                        title="Revert to built-in default"
                      >
                        Reset
                      </button>
                    )}
                  </div>
                </label>
                <label>
                  <span className="recon-label-row">
                    <span className="muted">Concurrency</span>
                    <InfoTip label="Concurrency help">
                      <strong>Concurrency</strong>
                      Maximum number of DNS queries in flight at once
                      during the brute-force. Default <code>500</code>{" "}
                      is a sane starting point for most home
                      connections. Bump it to <code>1000</code>+ on a
                      fast link; drop it to <code>50</code>–
                      <code>100</code> if you're hitting a resolver
                      that rate-limits or dropping queries. Values
                      over <code>2000</code> are clamped.
                    </InfoTip>
                  </span>
                  <input
                    type="number"
                    className="input input-compact"
                    min={1}
                    max={2000}
                    value={maxConcurrent}
                    onChange={(e) =>
                      setMaxConcurrent(parseInt(e.target.value, 10) || 500)
                    }
                    disabled={running}
                  />
                </label>
              </div>
            )}

            <div className="recon-actions">
              {running ? (
                <button type="button" className="chip" onClick={handleCancel}>
                  Cancel
                </button>
              ) : (
                <button
                  type="button"
                  className="chip active"
                  onClick={handleStart}
                  disabled={
                    !domain.trim() ||
                    (enabledSources.size === 0 && !active)
                  }
                >
                  Start recon
                </button>
              )}
            </div>
          </section>

          <section className="panel recon-status">
            <div className="recon-status-line">
              {running && <span className="recon-spinner" aria-hidden="true" />}
              <span className="muted">Status: {status}</span>
            </div>
            {Object.keys(sourceStatus).length > 0 && (
              <div className="recon-source-row">
                {Object.entries(sourceStatus).map(([source, s]) => (
                  <span
                    key={source}
                    className="badge-inline"
                    data-status={
                      s.error ? "warn" : s.done ? "running" : "stopped"
                    }
                    title={s.error ?? undefined}
                  >
                    {source}: {s.error ? "err" : s.found}
                  </span>
                ))}
              </div>
            )}
            {wildcardIps.length > 0 && (
              <div className="muted">
                Wildcard: <code>*.{domain}</code> →{" "}
                <code>{wildcardIps.join(", ")}</code> — matching brute-force
                hits are filtered
              </div>
            )}
            {bruteProgress && (
              <div className="muted">
                Brute-force: {bruteProgress.tested.toLocaleString()} /{" "}
                {bruteProgress.total.toLocaleString()} tested
              </div>
            )}
            {actionStatus && <div className="muted">{actionStatus}</div>}
          </section>

          <section className="panel recon-subdomains-panel">
            <h3 style={{ marginTop: 0 }}>
              Subdomains ({subdomainRows.length})
            </h3>
            {subdomainRows.length === 0 ? (
              <p className="muted">
                Run a recon to populate this list. Discovered hosts stream in
                live.
              </p>
            ) : (
              <div className="recon-table-scroll">
                <table className="findings-table">
                  <colgroup>
                    <col />
                    <col style={{ width: "220px" }} />
                    <col style={{ width: "200px" }} />
                    <col style={{ width: "320px" }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th>Host</th>
                      <th>Sources</th>
                      <th>IPs</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {subdomainRows.map((row) => (
                      <tr key={row.host}>
                        <td className="mono">
                          {row.host}
                          <span style={{ marginLeft: 6, verticalAlign: "middle" }}>
                            <AssetLink host={row.host} />
                          </span>
                        </td>
                        <td>
                          {row.sources.map((s) => (
                            <span
                              key={s}
                              className="badge-inline"
                              style={{ marginRight: 4 }}
                            >
                              {s}
                            </span>
                          ))}
                        </td>
                        <td className="mono">
                          {row.ips.length === 0
                            ? "—"
                            : row.ips.slice(0, 2).join(", ") +
                              (row.ips.length > 2
                                ? ` (+${row.ips.length - 2})`
                                : "")}
                        </td>
                        <td>
                          {onAddToProxyScope && (
                            <button
                              type="button"
                              className="link-button"
                              onClick={async () => {
                                try {
                                  await onAddToProxyScope(row.host);
                                  setActionStatus(
                                    `${row.host} → Proxy scope`,
                                  );
                                } catch (e) {
                                  setError(String(e));
                                }
                              }}
                            >
                              Scope
                            </button>
                          )}
                          {onSendToChecks && (
                            <button
                              type="button"
                              className="link-button"
                              onClick={async () => {
                                try {
                                  await onSendToChecks(row.host);
                                  setActionStatus(
                                    `${row.host} → Checks (proxy session)`,
                                  );
                                } catch (e) {
                                  setError(String(e));
                                }
                              }}
                              style={{ marginLeft: 6 }}
                            >
                              Checks
                            </button>
                          )}
                          {onSendToFuzzer && (
                            <button
                              type="button"
                              className="link-button"
                              onClick={() =>
                                onSendToFuzzer({
                                  url: `https://${row.host}/`,
                                })
                              }
                              style={{ marginLeft: 6 }}
                            >
                              Fuzzer
                            </button>
                          )}
                          {onPauseHost && (
                            <button
                              type="button"
                              className="link-button"
                              onClick={async () => {
                                try {
                                  await onPauseHost(row.host);
                                  setActionStatus(
                                    `${row.host} → Intercept (pause on next request)`,
                                  );
                                } catch (e) {
                                  setError(String(e));
                                }
                              }}
                              style={{ marginLeft: 6 }}
                              title="Add an Include intercept rule for this host so first-contact traffic pauses for inspection."
                            >
                              Pause
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {subdomainRows.length > 0 && onAddToProxyScope && (
              <div style={{ marginTop: 8 }}>
                <button
                  type="button"
                  className="chip"
                  onClick={addAllToScope}
                >
                  Add all {subdomainRows.length} to Proxy scope
                </button>
              </div>
            )}
          </section>

          {records.length > 0 && (
            <section className="panel">
              <h3 style={{ marginTop: 0 }}>DNS records ({records.length})</h3>
              <div className="recon-table-scroll">
                <table className="findings-table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Type</th>
                      <th>Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {records.map((r, i) => (
                      <tr key={`${r.name}-${r.record_type}-${i}`}>
                        <td className="mono">{r.name}</td>
                        <td>
                          <span className="badge-inline">{r.record_type}</span>
                        </td>
                        <td className="mono trunc" title={r.value}>
                          {r.value}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </>
      )}

      {pane === "history" && (
        <>
          <section className="panel">
            <h3 style={{ marginTop: 0 }}>Past runs</h3>
            {historyRuns.length === 0 ? (
              <p className="muted">No recon runs yet.</p>
            ) : (
              <div className="recon-table-scroll">
                <table className="findings-table">
                  <thead>
                    <tr>
                      <th>Domain</th>
                      <th>Started</th>
                      <th>Status</th>
                      <th>Subdomains</th>
                      <th>Records</th>
                      <th>Mode</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {historyRuns.map((r) => (
                      <tr
                        key={r.id}
                        className={selectedHistory === r.id ? "active" : ""}
                        onClick={() => loadHistoryFindings(r.id)}
                        style={{ cursor: "pointer" }}
                      >
                        <td className="mono">{r.domain}</td>
                        <td className="muted">
                          {new Date(r.started_at_unix * 1000).toLocaleString()}
                        </td>
                        <td>
                          <span className="badge-inline">{r.status}</span>
                        </td>
                        <td>{r.found_subdomains}</td>
                        <td>{r.found_records}</td>
                        <td>{r.active_enabled ? "passive+active" : "passive"}</td>
                        <td>
                          <button
                            type="button"
                            className="link-button"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteRun(r.id);
                            }}
                          >
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {historySummary && (
            <section className="panel">
              <h3 style={{ marginTop: 0 }}>
                {historySummary.domain} — {historyFindings.length} findings
              </h3>
              <div className="recon-table-scroll">
                <table className="findings-table">
                  <thead>
                    <tr>
                      <th>Kind</th>
                      <th>Name</th>
                      <th>Type</th>
                      <th>Value</th>
                      <th>Sources</th>
                    </tr>
                  </thead>
                  <tbody>
                    {historyFindings.map((f) => (
                      <tr key={f.id}>
                        <td>
                          <span className="badge-inline">{f.kind}</span>
                        </td>
                        <td className="mono">{f.name}</td>
                        <td>
                          {f.record_type ? (
                            <span className="badge-inline">{f.record_type}</span>
                          ) : (
                            ""
                          )}
                        </td>
                        <td className="mono trunc" title={f.value ?? ""}>
                          {f.value ?? ""}
                        </td>
                        <td>
                          {f.sources.map((s) => (
                            <span
                              key={s}
                              className="badge-inline"
                              style={{ marginRight: 4 }}
                            >
                              {s}
                            </span>
                          ))}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </>
      )}
    </div>
  );
}
