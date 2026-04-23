import { useEffect, useMemo, useRef, useState } from "react";
import type { FindingPayload, ScanParams, ScanStats } from "../api";
import type { FuzzerSeed } from "./FuzzingView";
import { FindingsTable } from "./FindingsTable";
import { InfoTip } from "./InfoTip";

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
      // Sensible defaults for a focused fuzzing run:
      plugins: "@@DEFAULT",
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
            <label>Target URL</label>
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
              <label>Scope</label>
              <select value={scope} onChange={(e) => setScope(e.target.value)}>
                <option value="domain">Domain</option>
                <option value="subdomains">Subdomains</option>
                <option value="folder">Folder</option>
                <option value="page">Page only</option>
              </select>
            </div>
            <div>
              <label>Crawl depth</label>
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
            <label>Max URLs</label>
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
                <label>Level (1-5)</label>
                <input
                  type="number"
                  min={1}
                  max={5}
                  value={sqliLevel}
                  onChange={(e) => setSqliLevel(parseInt(e.target.value) || 1)}
                />
              </div>
              <div>
                <label>Risk (1-3)</label>
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
              <label>Techniques</label>
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
                <label>DBMS</label>
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
                <label>Time delay (s)</label>
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
              <label>Tamper modules</label>
              <input
                type="text"
                value={tamper}
                onChange={(e) => setTamper(e.target.value)}
                placeholder="e.g. space2comment,randomcase"
              />
            </div>

            <div className="field">
              <label>Enumerate</label>
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

      {(running || scanId) && (
        <div className="panel" style={{ marginBottom: 12, padding: "10px 14px" }}>
          <div style={{ display: "flex", gap: 24, fontSize: "calc(var(--font-base) - 1px)" }}>
            <span><strong>{stats?.total_requests ?? 0}</strong> requests</span>
            <span><strong>{findings.length}</strong> findings</span>
            <span><strong>{stats?.urls_crawled ?? 0}</strong> URLs crawled</span>
            <span><strong>{stats?.elapsed_secs ?? 0}s</strong> elapsed</span>
            {running && <span style={{ color: "var(--accent)" }}>● running</span>}
          </div>
        </div>
      )}

      <FindingsTable findings={findings} />
    </div>
  );
}
