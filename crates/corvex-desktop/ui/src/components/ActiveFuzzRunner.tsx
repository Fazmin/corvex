import { useEffect, useMemo, useRef, useState } from "react";
import type { FindingPayload, ScanParams, ScanStats } from "../api";
import type { FuzzerSeed } from "./FuzzingView";
import { FindingsTable } from "./FindingsTable";
import { InfoTip } from "./InfoTip";
import { ScanIndicator, type MetricChip } from "./ScanIndicator";

const HOST_REGEX = /^(?:[a-z][a-z0-9+.-]*:\/\/)?[^\s/]+(?::\d{1,5})?(?:\/\S*)?$/i;

const FORM_KEY = "corvexActiveFuzzForm";

interface PersistedForm {
  host: string;
  scope: string;
  crawlDepth: number;
  maxUrls: number;
  sqliLevel: number;
  sqliRisk: number;
  sqliTechniques: string;
  sqliDbms: string;
  sqliTimeDelay: number;
  tamper: string;
  sqliEnumerate: string[];
}

const DEFAULTS: PersistedForm = {
  host: "http://example.com",
  scope: "domain",
  crawlDepth: 3,
  maxUrls: 500,
  sqliLevel: 1,
  sqliRisk: 1,
  sqliTechniques: "BEUST",
  sqliDbms: "",
  sqliTimeDelay: 5,
  tamper: "",
  sqliEnumerate: [],
};

function readForm(): PersistedForm {
  try {
    const raw = localStorage.getItem(FORM_KEY);
    if (!raw) return DEFAULTS;
    return { ...DEFAULTS, ...JSON.parse(raw) };
  } catch {
    return DEFAULTS;
  }
}

function writeForm(value: PersistedForm) {
  try {
    localStorage.setItem(FORM_KEY, JSON.stringify(value));
  } catch {
    /* quota / disabled */
  }
}

interface Props {
  running: boolean;
  scanId: string | null;
  findings: FindingPayload[];
  stats: ScanStats | null;
  onStart: (params: ScanParams) => void;
  onCancel: () => void;
  /** URL forwarded from another view (e.g. Send to Fuzzer). Applied on
   *  arrival by overwriting the host field + forcing scope to `page`,
   *  then acknowledged via `onSeedConsumed` so it doesn't re-apply on
   *  every render. */
  seed?: FuzzerSeed | null;
  onSeedConsumed?: () => void;
  /** Currently-targeted host (set by App.tsx on the host_start event). */
  currentHost?: string | null;
  /** Live request rate from the App-level stats poller. */
  requestRate?: number | null;
}

export function ActiveFuzzRunner({
  running,
  scanId,
  findings,
  stats,
  onStart,
  onCancel,
  seed,
  onSeedConsumed,
  currentHost,
  requestRate,
}: Props) {
  const initial = useMemo(readForm, []);
  const [host, setHost] = useState(initial.host);
  const [scope, setScope] = useState(initial.scope);
  const [seedBanner, setSeedBanner] = useState<string | null>(null);
  const lastSeededId = useRef<string | null>(null);
  const [crawlDepth, setCrawlDepth] = useState(initial.crawlDepth);
  const [maxUrls, setMaxUrls] = useState(initial.maxUrls);
  const [sqliLevel, setSqliLevel] = useState(initial.sqliLevel);
  const [sqliRisk, setSqliRisk] = useState(initial.sqliRisk);
  const [sqliTechniques, setSqliTechniques] = useState(initial.sqliTechniques);
  const [sqliDbms, setSqliDbms] = useState(initial.sqliDbms);
  const [sqliTimeDelay, setSqliTimeDelay] = useState(initial.sqliTimeDelay);
  const [tamper, setTamper] = useState(initial.tamper);
  const [sqliEnumerate, setSqliEnumerate] = useState<string[]>(initial.sqliEnumerate);

  // Consume the seed exactly once per incoming value. Using an id-based
  // ref instead of just `seed` in the dep array lets the user edit the
  // host field after the seed lands without it getting overwritten if
  // the effect re-fires for any unrelated reason.
  useEffect(() => {
    if (!seed) return;
    const key = seed.exchangeId ?? seed.url;
    if (lastSeededId.current === key) return;
    lastSeededId.current = key;
    setHost(seed.url);
    setScope("page");
    setSeedBanner(seed.url);
    writeForm({
      host: seed.url,
      scope: "page",
      crawlDepth,
      maxUrls,
      sqliLevel,
      sqliRisk,
      sqliTechniques,
      sqliDbms,
      sqliTimeDelay,
      tamper,
      sqliEnumerate,
    });
    onSeedConsumed?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [seed]);

  const hostError =
    !host.trim()
      ? "Required"
      : !HOST_REGEX.test(host.trim())
      ? "Enter a URL or host[:port][/path]"
      : null;

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (hostError) return;
    writeForm({
      host, scope, crawlDepth, maxUrls,
      sqliLevel, sqliRisk, sqliTechniques, sqliDbms, sqliTimeDelay,
      tamper, sqliEnumerate,
    });
    onStart({
      host,
      active: true,
      scope,
      crawl_depth: crawlDepth,
      max_urls: maxUrls,
      sqli_level: sqliLevel,
      sqli_risk: sqliRisk,
      sqli_techniques: sqliTechniques,
      sqli_dbms: sqliDbms || undefined,
      sqli_time_delay: sqliTimeDelay,
      tamper: tamper || undefined,
      sqli_enumerate: sqliEnumerate.length > 0 ? sqliEnumerate.join(",") : undefined,
      // Pure fuzzing run: keep only plugins exposing the Active hook
      // (xss_reflected, sqli_*, lfi_active, cmd_injection,
      // open_redirect, crlf, xxe, ssti, spring4shell, nuclei) and drop
      // every signature plugin. Without `@@ACTIVE` the engine either
      // inherits the full @@DEFAULT set (run looks like a Web scan)
      // or `@@NONE` empties the registry and the active fuzzers never
      // get to iterate the crawl graph.
      plugins: "@@ACTIVE",
      timeout_secs: 15,
      max_concurrent_requests: 8,
      follow_redirects: true,
    });
  };

  return (
    <div className="active-fuzz-runner">
      {seedBanner && (
        <div
          className="panel"
          style={{
            padding: "8px 12px",
            marginBottom: 10,
            borderLeft: "3px solid var(--accent)",
            display: "flex",
            alignItems: "center",
            gap: 10,
            fontSize: "calc(var(--font-base) - 1px)",
          }}
        >
          <span className="muted">Seeded from Intercept →</span>
          <code style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {seedBanner}
          </code>
          <span className="muted">scope forced to <code>page</code></span>
          <button
            type="button"
            className="link-button"
            onClick={() => setSeedBanner(null)}
            title="Dismiss"
          >
            ×
          </button>
        </div>
      )}
      <form className="panel" onSubmit={submit} style={{ marginBottom: 12 }}>
        <div className="panel-body">
          <div className="field">
            <div className="label-row">
              <label>Target URL</label>
              <InfoTip label="Target URL help">
                <strong>Target URL</strong>
                The origin or starting URL for the fuzzing run. The scheme
                is optional &mdash; all of these are accepted:
                <ul style={{ margin: "6px 0 0 16px", padding: 0 }}>
                  <li><code>example.com</code></li>
                  <li><code>example.com:8080</code></li>
                  <li><code>https://example.com/login?id=1</code></li>
                  <li><code>10.0.0.1/app</code></li>
                </ul>
                For a single endpoint, paste the full URL and set scope to{" "}
                <code>Page only</code> so the crawler doesn't spread.
              </InfoTip>
            </div>
            <input
              type="text"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="http://example.com"
              aria-invalid={!!hostError}
              required
            />
            {hostError && <div className="field-error">{hostError}</div>}
          </div>

          <div className="row">
            <div>
              <div className="label-row">
                <label>Scope</label>
                <InfoTip label="Scope help">
                  <strong>Scope</strong>
                  Controls how far the crawler spreads from the target URL
                  before it starts fuzzing.
                  <ul style={{ margin: "6px 0 0 16px", padding: 0 }}>
                    <li>
                      <strong>Domain</strong> &mdash; same host only. Default
                      for new runs.
                    </li>
                    <li>
                      <strong>Subdomains</strong> &mdash; host plus every{" "}
                      <code>*.host</code>. Use when an app spans{" "}
                      <code>api.</code>, <code>admin.</code>,{" "}
                      <code>static.</code>, etc.
                    </li>
                    <li>
                      <strong>Folder</strong> &mdash; only paths under the
                      current directory, e.g. a target of{" "}
                      <code>/app/v2/</code> stays inside <code>/app/v2/*</code>.
                    </li>
                    <li>
                      <strong>Page only</strong> &mdash; hit exactly this URL,
                      no crawl. This is what "Send to Fuzzer" uses so a single
                      intercepted request is re-played against every injection
                      point.
                    </li>
                  </ul>
                </InfoTip>
              </div>
              <select value={scope} onChange={(e) => setScope(e.target.value)}>
                <option value="domain">Domain</option>
                <option value="subdomains">Subdomains</option>
                <option value="folder">Folder</option>
                <option value="page">Page only</option>
              </select>
            </div>
            <div>
              <div className="label-row">
                <label>Crawl depth</label>
                <InfoTip label="Crawl depth help">
                  <strong>Crawl depth</strong>
                  Maximum number of link hops the crawler follows outward
                  from the target URL.
                  <ul style={{ margin: "6px 0 0 16px", padding: 0 }}>
                    <li>
                      <code>1</code> &mdash; only the target page and its
                      direct links
                    </li>
                    <li>
                      <code>3</code> &mdash; default; reaches most app
                      routes without wandering
                    </li>
                    <li>
                      <code>5+</code> &mdash; deep crawl; cost grows roughly
                      geometrically with the branching factor
                    </li>
                  </ul>
                  Clamped to 1&ndash;20. Ignored when scope is{" "}
                  <code>Page only</code>.
                </InfoTip>
              </div>
              <input
                type="number"
                min={1}
                max={20}
                value={crawlDepth}
                onChange={(e) => setCrawlDepth(parseInt(e.target.value) || 3)}
              />
            </div>
          </div>

          <div className="field">
            <div className="label-row">
              <label>Max URLs</label>
              <InfoTip label="Max URLs help">
                <strong>Max URLs</strong>
                Hard cap on how many unique URLs the crawler will visit in
                this run. A safety belt that keeps a broad scope from
                running away.
                <ul style={{ margin: "6px 0 0 16px", padding: 0 }}>
                  <li>
                    <code>50&ndash;100</code> &mdash; quick sanity probe
                  </li>
                  <li>
                    <code>500</code> &mdash; default, covers most mid-sized
                    apps
                  </li>
                  <li>
                    <code>2000+</code> &mdash; large portals / full-site
                    sweeps
                  </li>
                </ul>
                Clamped to 10&ndash;10000. Combined with{" "}
                <em>Crawl depth</em> to bound the run.
              </InfoTip>
            </div>
            <input
              type="number"
              min={10}
              max={10000}
              value={maxUrls}
              onChange={(e) => setMaxUrls(parseInt(e.target.value) || 500)}
            />
          </div>

          <div className="sqli-section" style={{ marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--border)" }}>
            <div className="label-row" style={{ marginBottom: 6 }}>
              <label style={{ fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--muted)" }}>
                SQL Injection
              </label>
              <InfoTip label="SQLi help">
                <strong>SQL Injection Engine</strong>
                Tests every discovered parameter for injection using five
                techniques (Error, Boolean, Time, Union, Stacked) across 8 DBMS
                backends with configurable WAF-bypass tamper modules.
              </InfoTip>
            </div>

            <div className="row">
              <div>
                <div className="label-row">
                  <label>Level (1-5)</label>
                  <InfoTip label="Level help">
                    <strong>Level</strong>
                    Breadth of SQLi testing &mdash; higher levels inject into
                    more parameter locations and use more payload variants
                    per parameter.
                    <ul style={{ margin: "6px 0 0 16px", padding: 0 }}>
                      <li>
                        <code>1</code> &mdash; GET / POST parameters only
                        (default, fast)
                      </li>
                      <li>
                        <code>2</code> &mdash; + cookies
                      </li>
                      <li>
                        <code>3</code> &mdash; + HTTP headers
                      </li>
                      <li>
                        <code>4</code> &mdash; + User-Agent / Referer / Host
                      </li>
                      <li>
                        <code>5</code> &mdash; all of the above plus extended
                        payload vectors
                      </li>
                    </ul>
                    Start at <code>1</code>; raise only if the app looks like
                    it reads SQLi-reachable data from cookies or headers.
                  </InfoTip>
                </div>
                <input
                  type="number"
                  min={1}
                  max={5}
                  value={sqliLevel}
                  onChange={(e) => setSqliLevel(parseInt(e.target.value) || 1)}
                />
              </div>
              <div>
                <div className="label-row">
                  <label>Risk (1-3)</label>
                  <InfoTip label="Risk help">
                    <strong>Risk</strong>
                    How destructive the injected payloads are allowed to be.
                    <ul style={{ margin: "6px 0 0 16px", padding: 0 }}>
                      <li>
                        <code>1</code> &mdash; safe, read-only payloads
                        (default)
                      </li>
                      <li>
                        <code>2</code> &mdash; + heavy timing payloads +
                        stacked-query booleans that may briefly block the DB
                      </li>
                      <li>
                        <code>3</code> &mdash; unlocks file read/write and
                        OS-command exploitation (<code>sqli_exploit</code>,
                        <code>file-read</code>, <code>os-cmd</code>).
                        <strong> Only use on systems you own or have
                        written authorisation to attack.</strong>
                      </li>
                    </ul>
                  </InfoTip>
                </div>
                <input
                  type="number"
                  min={1}
                  max={3}
                  value={sqliRisk}
                  onChange={(e) => setSqliRisk(parseInt(e.target.value) || 1)}
                />
              </div>
            </div>

            <div className="field">
              <div className="label-row">
                <label>Techniques</label>
                <InfoTip label="Techniques help">
                  <strong>Techniques</strong>
                  Which SQLi detection techniques the engine tries, in
                  priority order. Short-circuits once a parameter is
                  confirmed at high confidence.
                  <ul style={{ margin: "6px 0 0 16px", padding: 0 }}>
                    <li>
                      <strong>Boolean</strong> (<code>B</code>) &mdash; compare
                      true/false page responses. Works when errors are
                      suppressed.
                    </li>
                    <li>
                      <strong>Error</strong> (<code>E</code>) &mdash; parse DB
                      error messages. Fastest &mdash; 1&ndash;3 requests per
                      parameter.
                    </li>
                    <li>
                      <strong>Union</strong> (<code>U</code>) &mdash;{" "}
                      <code>UNION SELECT</code> to extract data directly. Most
                      powerful for dumping.
                    </li>
                    <li>
                      <strong>Stacked</strong> (<code>S</code>) &mdash;{" "}
                      <code>;</code>-separated statements. Requires Risk{" "}
                      &ge; 2.
                    </li>
                    <li>
                      <strong>Time</strong> (<code>T</code>) &mdash;{" "}
                      <code>SLEEP</code> / <code>WAITFOR</code> payloads.
                      Slowest, but works when nothing else does.
                    </li>
                  </ul>
                  Default <code>BEUST</code> enables all five. See the
                  Techniques tab for deeper details.
                </InfoTip>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "4px 8px" }}>
                {["B", "E", "U", "S", "T"].map((t) => (
                  <label key={t} className="checkbox" style={{ margin: 0, fontSize: "var(--font-base)", whiteSpace: "nowrap" }}>
                    <input
                      type="checkbox"
                      checked={sqliTechniques.includes(t)}
                      onChange={(e) => {
                        if (e.target.checked) setSqliTechniques((prev) => prev + t);
                        else setSqliTechniques((prev) => prev.replace(t, ""));
                      }}
                    />
                    {t === "B" ? "Boolean" : t === "E" ? "Error" : t === "U" ? "Union" : t === "S" ? "Stacked" : "Time"}
                  </label>
                ))}
              </div>
            </div>

            <div className="row">
              <div>
                <div className="label-row">
                  <label>DBMS</label>
                  <InfoTip label="DBMS help">
                    <strong>DBMS</strong>
                    Force a specific database backend when auto-detect picks
                    the wrong one or keeps firing useless dialect-specific
                    probes.
                    <ul style={{ margin: "6px 0 0 16px", padding: 0 }}>
                      <li>
                        <strong>Auto-detect</strong> (default) &mdash; engine
                        fingerprints the backend from error strings, version
                        banners, and dialect-specific function responses
                      </li>
                      <li>
                        Pin to one backend (MySQL, PostgreSQL, MSSQL, Oracle,
                        SQLite, MariaDB, DB2, Firebird) to skip
                        fingerprinting and cut request count
                      </li>
                    </ul>
                    See the DBMS tab for per-backend error patterns, sleep
                    functions, and catalog queries.
                  </InfoTip>
                </div>
                <select value={sqliDbms} onChange={(e) => setSqliDbms(e.target.value)}>
                  <option value="">Auto-detect</option>
                  <option value="mysql">MySQL</option>
                  <option value="postgresql">PostgreSQL</option>
                  <option value="mssql">MSSQL</option>
                  <option value="oracle">Oracle</option>
                  <option value="sqlite">SQLite</option>
                  <option value="mariadb">MariaDB</option>
                  <option value="db2">DB2</option>
                  <option value="firebird">Firebird</option>
                </select>
              </div>
              <div>
                <div className="label-row">
                  <label>Time delay (s)</label>
                  <InfoTip label="Time delay help">
                    <strong>Time delay</strong>
                    Seconds each time-based SQLi payload should sleep.
                    Confirmation probes double this delay, so the real upper
                    bound is 2&times; this value per confirmation.
                    <ul style={{ margin: "6px 0 0 16px", padding: 0 }}>
                      <li>
                        <code>5</code> &mdash; default, safe on LAN / low-RTT
                        targets
                      </li>
                      <li>
                        <code>10&ndash;15</code> &mdash; noisy or slow
                        network; lifts the signal above RTT jitter
                      </li>
                      <li>
                        <code>1&ndash;3</code> &mdash; very fast localhost
                        testing only
                      </li>
                    </ul>
                    The request timeout is automatically extended to fit.
                    Clamped to 1&ndash;30.
                  </InfoTip>
                </div>
                <input
                  type="number"
                  min={1}
                  max={30}
                  value={sqliTimeDelay}
                  onChange={(e) => setSqliTimeDelay(parseInt(e.target.value) || 5)}
                />
              </div>
            </div>

            <div className="field">
              <div className="label-row">
                <label>Tamper modules</label>
                <InfoTip label="Tamper modules help">
                  <strong>Tamper modules</strong>
                  Comma-separated list of payload transforms applied
                  left-to-right to every SQLi payload before it's sent.
                  Useful for bypassing WAFs, mod_security rules, and
                  homegrown input filters.
                  <ul style={{ margin: "6px 0 0 16px", padding: 0 }}>
                    <li>
                      <code>space2comment,randomcase</code> &mdash; rewrites
                      spaces as <code>/**/</code> and randomises keyword
                      case &mdash; a solid first attempt against most WAFs
                    </li>
                    <li>
                      <code>charunicodeencode,between</code> &mdash; Unicode
                      URL-encoded + rewrites <code>&gt;</code> as{" "}
                      <code>NOT BETWEEN</code>
                    </li>
                    <li>
                      <code>versionedkeywords</code> &mdash; MySQL-only, wraps
                      keywords in <code>/*!50000&hellip;*/</code> versioned
                      comments
                    </li>
                  </ul>
                  Leave blank for no transforms. See the Tamper tab for the
                  full list of 50 modules grouped by strategy.
                </InfoTip>
              </div>
              <input
                type="text"
                value={tamper}
                onChange={(e) => setTamper(e.target.value)}
                placeholder="e.g. space2comment,randomcase"
              />
            </div>

            <div className="field">
              <div className="label-row">
                <label>Enumerate</label>
                <InfoTip label="Enumerate help">
                  <strong>Enumerate</strong>
                  Post-detection extraction actions the engine runs once a
                  parameter is confirmed injectable. Each ticked box costs
                  extra requests; the blind techniques (~8 requests per
                  character) dominate the cost.
                  <ul style={{ margin: "6px 0 0 16px", padding: 0 }}>
                    <li>
                      <strong>Databases / Tables / Columns / Users</strong>{" "}
                      &mdash; catalog enumeration. Safe and cheap; good
                      first-run combo for "prove it's real".
                    </li>
                    <li>
                      <strong>Passwords</strong> &mdash; reads{" "}
                      <code>mysql.user</code>, <code>pg_shadow</code>,{" "}
                      <code>sys.sql_logins</code>, etc. Pulls credential
                      material &mdash; only if you have permission.
                    </li>
                    <li>
                      <strong>Dump</strong> &mdash; extracts full row data
                      from discovered tables. Very expensive over blind.
                    </li>
                    <li>
                      <strong>File read / OS cmd</strong> &mdash; reads files
                      off the host or runs shell commands as the DB user.
                      <strong> Requires Risk 3.</strong>
                    </li>
                  </ul>
                  Leave all unchecked for a detection-only run.
                </InfoTip>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "4px 8px" }}>
                {[
                  { value: "dbs", label: "Databases" },
                  { value: "tables", label: "Tables" },
                  { value: "columns", label: "Columns" },
                  { value: "users", label: "Users" },
                  { value: "passwords", label: "Passwords" },
                  { value: "dump", label: "Dump" },
                  { value: "file-read", label: "File read" },
                  { value: "os-cmd", label: "OS cmd" },
                ].map((opt) => (
                  <label key={opt.value} className="checkbox" style={{ margin: 0, fontSize: "var(--font-base)" }}>
                    <input
                      type="checkbox"
                      checked={sqliEnumerate.includes(opt.value)}
                      onChange={(e) => {
                        if (e.target.checked) setSqliEnumerate((prev) => [...prev, opt.value]);
                        else setSqliEnumerate((prev) => prev.filter((v) => v !== opt.value));
                      }}
                    />
                    {opt.label}
                  </label>
                ))}
              </div>
            </div>
          </div>

          {running ? (
            <button type="button" className="danger" onClick={onCancel}>
              Cancel scan
            </button>
          ) : (
            <button
              type="submit"
              className="primary"
              disabled={!!hostError}
              title={hostError ? "Fix the highlighted fields above" : undefined}
            >
              Start active fuzzing
            </button>
          )}
        </div>
      </form>

      {/* Live progress while a fuzz is in flight. The crawler runs
          first (URLs/maxUrls is a determinate progress bar), then the
          active modules iterate over each captured URL. We surface the
          stage + current host so the user sees what's actually being
          fuzzed right now, plus the standard request / finding /
          rate counters. */}
      {running && (() => {
        const urls = stats?.urls_crawled ?? 0;
        const cap = maxUrls > 0 ? maxUrls : 0;
        const inCrawlPhase = cap > 0 && urls < cap;
        const chips: MetricChip[] = [
          { label: "requests", value: (stats?.total_requests ?? 0).toLocaleString() },
          { label: "findings", value: findings.length.toLocaleString() },
          { label: "URLs", value: cap > 0 ? `${urls}/${cap}` : `${urls}` },
          {
            label: "rate",
            value:
              requestRate != null && requestRate >= 0
                ? `${Math.round(requestRate)}/s`
                : "—",
          },
          { label: "elapsed", value: `${stats?.elapsed_secs ?? 0}s` },
        ];
        const target = currentHost ?? host;
        const stageText = stats?.stage?.trim();
        const phase = inCrawlPhase
          ? `Crawling ${target}`
          : stageText
            ? `${stageText} · ${target}`
            : `Fuzzing ${target}`;
        return (
          <div style={{ marginBottom: 12 }}>
            <ScanIndicator
              label={phase}
              progress={
                inCrawlPhase ? { current: urls, total: cap } : undefined
              }
              chips={chips}
              onCancel={onCancel}
              cancelLabel="Cancel"
            />
          </div>
        );
      })()}

      {!running && scanId && (
        <div
          className="panel"
          style={{ marginBottom: 12, padding: "10px 14px" }}
        >
          <div
            style={{
              display: "flex",
              gap: 24,
              fontSize: "calc(var(--font-base) - 1px)",
              color: "var(--muted)",
            }}
          >
            <span>
              <strong style={{ color: "var(--fg)" }}>
                {stats?.total_requests ?? 0}
              </strong>{" "}
              requests
            </span>
            <span>
              <strong style={{ color: "var(--fg)" }}>{findings.length}</strong>{" "}
              findings
            </span>
            <span>
              <strong style={{ color: "var(--fg)" }}>
                {stats?.urls_crawled ?? 0}
              </strong>{" "}
              URLs crawled
            </span>
            <span>
              <strong style={{ color: "var(--fg)" }}>
                {stats?.elapsed_secs ?? 0}s
              </strong>{" "}
              elapsed
            </span>
            <span style={{ color: "var(--success)" }}>● complete</span>
          </div>
        </div>
      )}

      <FindingsTable findings={findings} storageNamespace="fuzz" />
    </div>
  );
}
