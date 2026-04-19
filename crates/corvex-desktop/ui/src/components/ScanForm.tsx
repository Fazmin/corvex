import { useMemo, useState } from "react";
import type { ScanParams } from "../api";
import { PluginPicker } from "./PluginPicker";
import { TuningPicker } from "./TuningPicker";
import { InfoTip } from "./InfoTip";
import { useSettings } from "../settings";
import { readDefault as readProbingDefaults } from "./ProbingView";

const PRESETS_KEY = "corvexScanPresets";

interface FormSnapshot {
  host: string;
  ports: string;
  ssl: boolean;
  tuning: string;
  plugins: string;
  format: string;
  output: string;
  timeout: number;
  concurrent: number;
  followRedirects: boolean;
  id: string;
  useragent: string;
  evasion: string;
  portscan: boolean;
  portsRange: string;
  scanMode: "rapid" | "deep";
  jarm: boolean;
  dnsBrute: boolean;
  active: boolean;
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

function readPresets(): Record<string, FormSnapshot> {
  try {
    const raw = localStorage.getItem(PRESETS_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function writePresets(presets: Record<string, FormSnapshot>) {
  try {
    localStorage.setItem(PRESETS_KEY, JSON.stringify(presets));
  } catch {
    /* quota / disabled */
  }
}

// Host accepts either a scheme://... URL or a bare host[:port][/path].
const HOST_REGEX = /^(?:[a-z][a-z0-9+.-]*:\/\/)?[^\s/]+(?::\d{1,5})?(?:\/\S*)?$/i;
// Comma-separated ports or port ranges: "80", "80,443", "1-1000", "80,8000-8100".
const PORT_LIST_REGEX = /^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$/;
const EVASION_REGEX = /^[1-9aA]*$/;
const TUNING_REGEX = /^[0-9a-ex]*$/i;

function validatePortList(raw: string, max = 65535): string | null {
  if (!raw) return null;
  const stripped = raw.replace(/\s+/g, "");
  if (!PORT_LIST_REGEX.test(stripped)) return "Use comma-separated ports or ranges (e.g. 80,443,8000-8100)";
  for (const segment of stripped.split(",")) {
    const parts = segment.split("-").map(Number);
    for (const n of parts) {
      if (!Number.isFinite(n) || n < 1 || n > max) return `Port ${n} is out of range (1–${max})`;
    }
    if (parts.length === 2 && parts[0] > parts[1]) return `Range ${segment} is reversed`;
  }
  return null;
}

interface Props {
  running: boolean;
  onStart: (params: ScanParams) => void;
  onCancel: () => void;
}

export function ScanForm({ running, onStart, onCancel }: Props) {
  const { extraProbeFiles } = useSettings();
  const [host, setHost] = useState("http://example.com");
  const [ports, setPorts] = useState("");
  const [ssl, setSsl] = useState(false);
  const [tuning, setTuning] = useState("");
  const [plugins, setPlugins] = useState("@@DEFAULT");
  const [format, setFormat] = useState("txt");
  const [output, setOutput] = useState("");
  const [timeout, setTimeoutVal] = useState(15);
  const [concurrent, setConcurrent] = useState(8);
  const [followRedirects, setFollowRedirects] = useState(false);
  const [id, setId] = useState("");
  const [useragent, setUseragent] = useState("");
  const [evasion, setEvasion] = useState("");
  // Port scanning — initial values come from the Probing view's saved defaults
  // so configuring there actually takes effect on new scans.
  const [portscan, setPortscan] = useState(false);
  const [portsRange, setPortsRange] = useState(() => readProbingDefaults().portsRange);
  const [scanMode, setScanMode] = useState<"rapid" | "deep">(
    () => readProbingDefaults().scanMode
  );
  const [jarm, setJarm] = useState<boolean>(() => readProbingDefaults().jarm);
  // DNS enumeration
  const [dnsBrute, setDnsBrute] = useState(false);
  // Active fuzzing
  const [active, setActive] = useState(false);
  const [scope, setScope] = useState("domain");
  const [crawlDepth, setCrawlDepth] = useState(3);
  const [maxUrls, setMaxUrls] = useState(500);
  // SQL injection
  const [sqliLevel, setSqliLevel] = useState(1);
  const [sqliRisk, setSqliRisk] = useState(1);
  const [sqliTechniques, setSqliTechniques] = useState("BEUST");
  const [sqliDbms, setSqliDbms] = useState("");
  const [sqliTimeDelay, setSqliTimeDelay] = useState(5);
  const [tamper, setTamper] = useState("");
  const [sqliEnumerate, setSqliEnumerate] = useState<string[]>([]);

  const [presets, setPresets] = useState<Record<string, FormSnapshot>>(() => readPresets());
  const [selectedPreset, setSelectedPreset] = useState<string>("");

  const applyPreset = (name: string) => {
    const snap = presets[name];
    if (!snap) return;
    setHost(snap.host);
    setPorts(snap.ports);
    setSsl(snap.ssl);
    setTuning(snap.tuning);
    setPlugins(snap.plugins);
    setFormat(snap.format);
    setOutput(snap.output);
    setTimeoutVal(snap.timeout);
    setConcurrent(snap.concurrent);
    setFollowRedirects(snap.followRedirects);
    setId(snap.id);
    setUseragent(snap.useragent);
    setEvasion(snap.evasion);
    setPortscan(snap.portscan);
    setPortsRange(snap.portsRange);
    setScanMode(snap.scanMode ?? "rapid");
    setJarm(Boolean(snap.jarm));
    setDnsBrute(snap.dnsBrute);
    setActive(snap.active);
    setScope(snap.scope);
    setCrawlDepth(snap.crawlDepth);
    setMaxUrls(snap.maxUrls);
    setSqliLevel(snap.sqliLevel);
    setSqliRisk(snap.sqliRisk);
    setSqliTechniques(snap.sqliTechniques);
    setSqliDbms(snap.sqliDbms);
    setSqliTimeDelay(snap.sqliTimeDelay);
    setTamper(snap.tamper);
    setSqliEnumerate(snap.sqliEnumerate ?? []);
  };

  const savePreset = () => {
    const name = window.prompt("Preset name:")?.trim();
    if (!name) return;
    const snap: FormSnapshot = {
      host, ports, ssl, tuning, plugins, format, output,
      timeout, concurrent, followRedirects, id, useragent, evasion,
      portscan, portsRange, scanMode, jarm, dnsBrute,
      active, scope, crawlDepth, maxUrls,
      sqliLevel, sqliRisk, sqliTechniques, sqliDbms, sqliTimeDelay, tamper,
      sqliEnumerate,
    };
    const next = { ...presets, [name]: snap };
    setPresets(next);
    writePresets(next);
    setSelectedPreset(name);
  };

  const deletePreset = () => {
    if (!selectedPreset) return;
    if (!window.confirm(`Delete preset "${selectedPreset}"?`)) return;
    const next = { ...presets };
    delete next[selectedPreset];
    setPresets(next);
    writePresets(next);
    setSelectedPreset("");
  };

  const errors = useMemo(() => {
    const e: Record<string, string> = {};
    if (!host.trim()) e.host = "Required";
    else if (!HOST_REGEX.test(host.trim())) e.host = "Enter a URL or host[:port][/path]";
    const pErr = validatePortList(ports);
    if (pErr) e.ports = pErr;
    if (portscan) {
      const prErr = validatePortList(portsRange);
      if (prErr) e.portsRange = prErr;
      else if (!portsRange.trim()) e.portsRange = "Required when port scanning is enabled";
    }
    if (evasion && !EVASION_REGEX.test(evasion)) e.evasion = "Only digits 1–9 and letter A";
    if (tuning && !TUNING_REGEX.test(tuning)) e.tuning = "Only 0–9, a–e, or x (inverse)";
    if (timeout < 1) e.timeout = "Must be ≥ 1";
    if (concurrent < 1 || concurrent > 64) e.concurrent = "1–64";
    return e;
  }, [host, ports, portscan, portsRange, evasion, tuning, timeout, concurrent]);

  const hasErrors = Object.keys(errors).length > 0;

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (hasErrors) return;
    onStart({
      host,
      ports: ports || undefined,
      ssl,
      tuning: tuning || undefined,
      plugins: plugins || undefined,
      format: format || undefined,
      output: output || undefined,
      timeout_secs: timeout,
      max_concurrent_requests: concurrent,
      follow_redirects: followRedirects,
      id: id || undefined,
      useragent: useragent || undefined,
      evasion: evasion || undefined,
      portscan: portscan || undefined,
      ports_range: portscan ? portsRange : undefined,
      scan_mode: portscan ? scanMode : undefined,
      jarm: portscan && scanMode === "deep" && jarm ? true : undefined,
      extra_probe_files:
        portscan && scanMode === "deep" && extraProbeFiles.length > 0
          ? extraProbeFiles
          : undefined,
      dns_brute: dnsBrute || undefined,
      active,
      scope: active ? scope : undefined,
      crawl_depth: active ? crawlDepth : undefined,
      max_urls: active ? maxUrls : undefined,
      sqli_level: active ? sqliLevel : undefined,
      sqli_risk: active ? sqliRisk : undefined,
      sqli_techniques: active ? sqliTechniques : undefined,
      sqli_dbms: active && sqliDbms ? sqliDbms : undefined,
      sqli_time_delay: active ? sqliTimeDelay : undefined,
      tamper: active && tamper ? tamper : undefined,
      sqli_enumerate: active && sqliEnumerate.length > 0
        ? sqliEnumerate.join(",")
        : undefined,
    });
  };

  return (
    <form className="panel scan-form" onSubmit={submit}>
      <div className="panel-fixed-header">
        <h2>Scan target</h2>
      </div>
      <div className="panel-body">
      <div className="field preset-row">
        <label>Preset</label>
        <div className="preset-controls">
          <select
            value={selectedPreset}
            onChange={(e) => {
              const name = e.target.value;
              setSelectedPreset(name);
              if (name) applyPreset(name);
            }}
          >
            <option value="">— none —</option>
            {Object.keys(presets).sort().map((name) => (
              <option key={name} value={name}>{name}</option>
            ))}
          </select>
          <button type="button" className="chip" onClick={savePreset} title="Save current form as a named preset">
            Save as…
          </button>
          <button
            type="button"
            className="chip"
            onClick={deletePreset}
            disabled={!selectedPreset}
            title="Delete selected preset"
          >
            Delete
          </button>
        </div>
      </div>
      <div className="field">
        <label>Host / URL</label>
        <input
          type="text"
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="http://example.com"
          aria-invalid={!!errors.host}
          required
        />
        {errors.host && <div className="field-error">{errors.host}</div>}
      </div>
      <div className="row">
        <div>
          <label>Ports</label>
          <input
            type="text"
            value={ports}
            onChange={(e) => setPorts(e.target.value)}
            placeholder="80,443"
            aria-invalid={!!errors.ports}
          />
          {errors.ports && <div className="field-error">{errors.ports}</div>}
        </div>
        <div>
          <label>Timeout (s)</label>
          <input
            type="number"
            min={1}
            value={timeout}
            onChange={(e) => setTimeoutVal(parseInt(e.target.value) || 15)}
            aria-invalid={!!errors.timeout}
          />
          {errors.timeout && <div className="field-error">{errors.timeout}</div>}
        </div>
      </div>

      <div className="field">
        <label className="checkbox">
          <input type="checkbox" checked={ssl} onChange={(e) => setSsl(e.target.checked)} />
          Force SSL
        </label>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={followRedirects}
            onChange={(e) => setFollowRedirects(e.target.checked)}
          />
          Follow redirects
        </label>
      </div>

      <TuningPicker value={tuning} onChange={setTuning} />

      <PluginPicker value={plugins} onChange={setPlugins} />

      {/* ---- Port Scanning Section ---- */}
      <div className="field">
        <label className="checkbox">
          <input
            type="checkbox"
            checked={portscan}
            onChange={(e) => setPortscan(e.target.checked)}
          />
          Port scanning
        </label>
        <InfoTip label="Port scanning help">
          <strong>Port Scanner</strong>
          TCP connect scan before web tests. Discovers open ports, identifies
          services via banner grabbing, and auto-adds HTTP services as scan targets.
          Non-HTTP services (FTP, SSH, SMTP, etc.) are tested for common vulnerabilities.
        </InfoTip>
      </div>
      {portscan && (
        <>
          <div className="field indent">
            <label>Port range</label>
            <input
              type="text"
              value={portsRange}
              onChange={(e) => setPortsRange(e.target.value)}
              placeholder="1-1000"
              aria-invalid={!!errors.portsRange}
            />
            {errors.portsRange && <div className="field-error">{errors.portsRange}</div>}
          </div>
          <div className="field indent">
            <label>Scan mode</label>
            <div role="radiogroup" style={{ display: "flex", gap: 12 }}>
              <label className="radio">
                <input
                  type="radio"
                  name="scanMode"
                  value="rapid"
                  checked={scanMode === "rapid"}
                  onChange={() => setScanMode("rapid")}
                />
                Rapid (fast sweep)
              </label>
              <label className="radio">
                <input
                  type="radio"
                  name="scanMode"
                  value="deep"
                  checked={scanMode === "deep"}
                  onChange={() => setScanMode("deep")}
                />
                Deep (service fingerprint)
              </label>
            </div>
          </div>
          {scanMode === "deep" && (
            <div className="field indent">
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={jarm}
                  onChange={(e) => setJarm(e.target.checked)}
                />
                Collect JARM TLS fingerprint (extra probes per TLS port)
              </label>
            </div>
          )}
        </>
      )}

      {/* ---- DNS Enumeration Section ---- */}
      <div className="field">
        <label className="checkbox">
          <input
            type="checkbox"
            checked={dnsBrute}
            onChange={(e) => setDnsBrute(e.target.checked)}
          />
          DNS subdomain brute-force
        </label>
        <InfoTip label="DNS enumeration help">
          <strong>DNS Enumeration</strong>
          DNS record lookups (A, AAAA, MX, NS, TXT, CNAME, SOA), SPF
          analysis, and zone transfer checks always run automatically.
          Enable this toggle to also brute-force subdomain discovery
          using a built-in wordlist of common prefixes.
        </InfoTip>
      </div>

      {/* ---- Active Fuzzing Section ---- */}
      <div className="field active-section">
        <div className="label-row">
          <label className="checkbox" style={{ margin: 0 }}>
            <input
              type="checkbox"
              checked={active}
              onChange={(e) => setActive(e.target.checked)}
            />
            Active fuzzing
          </label>
          <InfoTip label="Active fuzzing help">
            <strong>Active fuzzing engine</strong>
            When enabled, the scanner crawls the target using BFS link
            following to discover pages, forms, and query parameters.
            Every discovered parameter becomes an injection point tested
            by the active plugin suite.
            <br /><br />
            The <strong>SQL Injection engine</strong> below runs 5 detection
            techniques (error, boolean-blind, time-blind, UNION, stacked
            queries) across 8 DBMS backends with ~50 WAF-bypass tamper
            modules, plus database enumeration and exploitation.
            <br /><br />
            This is <em>invasive</em> — only use against targets you own
            or have explicit written permission to test. The scanner will
            send hundreds to thousands of requests depending on the number
            of parameters discovered.
          </InfoTip>
        </div>
        {active && (
          <div className="active-options">
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

            {/* ---- SQL Injection Section ---- */}
            <div className="sqli-section" style={{ marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--border)" }}>
              <div className="label-row" style={{ marginBottom: 6 }}>
                <label style={{ fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--muted)" }}>
                  SQL Injection
                </label>
                <InfoTip label="SQLi help">
                  <strong>SQL Injection Engine</strong>
                  The SQLi engine tests every discovered parameter for injection
                  vulnerabilities by sending crafted SQL payloads and analyzing
                  how the application responds. It runs five detection techniques
                  in priority order (Error, Boolean, Time, Union, Stacked) and
                  short-circuits when a parameter is confirmed injectable.
                  <br /><br />
                  Supports <strong>8 DBMS backends</strong>: MySQL, PostgreSQL,
                  MSSQL, Oracle, SQLite, MariaDB, DB2, and Firebird — each with
                  tailored payloads, error fingerprints, and catalog queries.
                  <br /><br />
                  Includes <strong>~50 tamper modules</strong> for WAF/IDS bypass
                  and <strong>post-exploitation</strong> capabilities including
                  database enumeration, file read/write, and OS command execution.
                </InfoTip>
              </div>

              <div className="row">
                <div>
                  <div className="label-row">
                    <label>Level (1-5)</label>
                    <InfoTip label="Level help">
                      <strong>Testing level</strong>
                      Controls which injection points are tested. Higher levels
                      generate more requests but find injections in less obvious
                      locations.
                      <dl>
                        <dt>1</dt><dd>GET and POST parameters only (fastest, least noise)</dd>
                        <dt>2</dt><dd>+ Cookie values — tests each cookie as an injection point</dd>
                        <dt>3</dt><dd>+ User-Agent and Referer headers — catches header-based SQLi</dd>
                        <dt>4</dt><dd>+ All other HTTP headers (Host, Accept, X-Forwarded-For, etc.)</dd>
                        <dt>5</dt><dd>+ URL path segments — tests each /segment/ as an injection point</dd>
                      </dl>
                      <br />
                      Start with level 1-2 for most targets. Use level 3+ when
                      you suspect header-based injection or need comprehensive coverage.
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
                      <strong>Payload risk</strong>
                      Controls how aggressive and potentially destructive the
                      injected payloads are. Higher risk may modify data on the
                      target.
                      <dl>
                        <dt>1</dt><dd><strong>Safe</strong> — read-only queries
                          only: AND-based conditions, ORDER BY probes, SELECT
                          statements. No risk of data modification.</dd>
                        <dt>2</dt><dd><strong>Moderate</strong> — adds OR-based
                          payloads (e.g. <code>OR 1=1</code>) which may alter query
                          results and return unintended data. Also enables
                          stacked queries detection.</dd>
                        <dt>3</dt><dd><strong>Dangerous</strong> — adds
                          UPDATE/INSERT/DELETE payloads, file write operations
                          (<code>INTO OUTFILE</code>, <code>COPY TO</code>), and
                          OS command execution (<code>xp_cmdshell</code>,
                          <code>COPY TO PROGRAM</code>). Use only on targets you
                          own.</dd>
                      </dl>
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
                    <strong>Detection techniques</strong>
                    Each technique detects SQL injection differently. They run
                    in priority order and short-circuit once a parameter is
                    confirmed.
                    <dl>
                      <dt>E &mdash; Error</dt>
                      <dd>Injects boundary characters (<code>'</code>,
                        <code>"</code>, <code>\</code>) and scans responses for
                        database error messages (48 patterns across 8 DBMS).
                        Fastest technique — typically 1-3 requests per parameter.
                        Can extract data via EXTRACTVALUE, UPDATEXML, or CAST
                        errors.</dd>
                      <dt>B &mdash; Boolean</dt>
                      <dd>Sends true/false condition pairs
                        (<code>AND 1=1</code> vs <code>AND 1=2</code>) and
                        compares response bodies using trigram page-ratio
                        analysis. Detects blind injection when the page content
                        changes based on the condition. Confirms with a second
                        boolean pair to reduce false positives.</dd>
                      <dt>T &mdash; Time</dt>
                      <dd>Injects time-delay payloads
                        (<code>SLEEP()</code>, <code>WAITFOR DELAY</code>,
                        <code>pg_sleep()</code>) and measures response time
                        against a baseline. Works when there is no visible
                        output difference at all. Confirms by doubling the
                        delay and checking proportional increase. Slowest
                        technique — use a higher time delay on laggy targets.</dd>
                      <dt>U &mdash; Union</dt>
                      <dd>Determines the column count via binary-search
                        <code>ORDER BY</code>, then injects
                        <code>UNION SELECT</code> with marker strings to find
                        which column is reflected in the response. Once a
                        visible column is found, extracts version, database
                        name, and current user directly. Most powerful for
                        data extraction.</dd>
                      <dt>S &mdash; Stacked</dt>
                      <dd>Tests whether the database supports multiple
                        statements separated by semicolons
                        (<code>; WAITFOR DELAY</code>,
                        <code>; SELECT pg_sleep()</code>). Primarily effective
                        against MSSQL and PostgreSQL. Enables INSERT/UPDATE
                        and OS command execution. Requires risk &ge; 2.</dd>
                    </dl>
                  </InfoTip>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "4px 8px" }}>
                  {["B", "E", "U", "S", "T"].map((t) => (
                    <label key={t} className="checkbox" style={{ margin: 0, fontSize: "var(--font-base)", whiteSpace: "nowrap" }}>
                      <input
                        type="checkbox"
                        checked={sqliTechniques.includes(t)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSqliTechniques((prev) => prev + t);
                          } else {
                            setSqliTechniques((prev) => prev.replace(t, ""));
                          }
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
                      <strong>Target database backend</strong>
                      <strong>Auto-detect</strong> fingerprints the DBMS from
                      error messages (48 regex patterns). Force a specific
                      backend to skip fingerprinting and use only that DBMS's
                      payloads — faster and less noisy when you already know
                      the stack.
                      <dl>
                        <dt>MySQL</dt><dd>SLEEP(), EXTRACTVALUE, UPDATEXML, information_schema, LOAD_FILE</dd>
                        <dt>PostgreSQL</dt><dd>pg_sleep(), CAST errors, pg_database, pg_read_file, COPY TO PROGRAM</dd>
                        <dt>MSSQL</dt><dd>WAITFOR DELAY, CONVERT errors, sysdatabases, xp_cmdshell, OPENROWSET</dd>
                        <dt>Oracle</dt><dd>DBMS_PIPE.RECEIVE_MESSAGE, ORA-xxxxx errors, all_tables, UTL_FILE</dd>
                        <dt>SQLite</dt><dd>RANDOMBLOB delay, sqlite_master, PRAGMA table_info</dd>
                        <dt>MariaDB</dt><dd>Same as MySQL with MariaDB-specific error patterns</dd>
                        <dt>DB2</dt><dd>SQLCODE errors, syscat.tables, SYSIBM.SYSDUMMY1</dd>
                        <dt>Firebird</dt><dd>Dynamic SQL Error, RDB$RELATIONS, RDB$RELATION_FIELDS</dd>
                      </dl>
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
                      <strong>Time-based detection delay</strong>
                      Seconds injected into SLEEP/WAITFOR payloads. The engine
                      measures whether the response takes at least this long
                      compared to the baseline.
                      <br /><br />
                      <strong>Default: 5</strong> works for most targets.
                      Increase to 8-10 on high-latency or slow targets to
                      avoid false positives. Decrease to 2-3 for faster scans
                      on low-latency targets (but risk more false positives).
                      <br /><br />
                      The request timeout is automatically extended to
                      accommodate the injected delay.
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
                  <InfoTip label="Tamper help">
                    <strong>WAF/IDS bypass (50 modules)</strong>
                    Transforms applied to each SQL payload before injection to
                    evade web application firewalls and input filters. Modules
                    are chained left-to-right.
                    <dl>
                      <dt>Space</dt>
                      <dd><code>space2comment</code> (spaces to <code>/**/</code>),
                        <code>space2hash</code> (<code>#\n</code>),
                        <code>space2dash</code>, <code>space2plus</code>,
                        <code>space2randomblank</code></dd>
                      <dt>Encode</dt>
                      <dd><code>charencode</code> (URL-encode),
                        <code>chardoubleencode</code>,
                        <code>base64encode</code>,
                        <code>charunicodeencode</code>,
                        <code>overlongutf8</code>,
                        <code>unmagicquotes</code></dd>
                      <dt>Keywords</dt>
                      <dd><code>randomcase</code> (rAnDoM casing),
                        <code>randomcomments</code> (<code>SEL/**/ECT</code>),
                        <code>versionedkeywords</code>
                        (<code>/*!50000 UNION*/</code>),
                        <code>nonrecursivereplacement</code>
                        (<code>SELSELECTECT</code>)</dd>
                      <dt>Logic</dt>
                      <dd><code>between</code> (<code>&gt;</code> to
                        <code>NOT BETWEEN</code>),
                        <code>equaltolike</code> (<code>=</code> to
                        <code>LIKE</code>),
                        <code>symboliclogical</code> (<code>AND</code>/<code>OR</code>
                        to <code>&amp;&amp;</code>/<code>||</code>)</dd>
                      <dt>Special</dt>
                      <dd><code>apostrophemask</code> (fullwidth <code>'</code>),
                        <code>appendnullbyte</code>,
                        <code>sp_password</code> (hide from MSSQL logs),
                        <code>sleep2getlock</code></dd>
                    </dl>
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
                    <strong>Post-detection enumeration</strong>
                    After confirming an injectable parameter, the engine can
                    extract data from the backend database. Extraction method
                    depends on the technique that found the injection.
                    <dl>
                      <dt>Databases</dt>
                      <dd>List all database/schema names
                        (<code>information_schema</code>, <code>pg_database</code>,
                        <code>sysdatabases</code>)</dd>
                      <dt>Tables</dt>
                      <dd>List tables in the current database</dd>
                      <dt>Columns</dt>
                      <dd>List columns for each discovered table</dd>
                      <dt>Users</dt>
                      <dd>Enumerate database user accounts</dd>
                      <dt>Passwords</dt>
                      <dd>Extract password hashes from system tables
                        (<code>mysql.user</code>, <code>pg_shadow</code>,
                        <code>sys.sql_logins</code>)</dd>
                      <dt>Dump</dt>
                      <dd>Dump full table contents (row by row)</dd>
                      <dt>File read</dt>
                      <dd>Read files from the server via
                        <code>LOAD_FILE()</code>, <code>pg_read_file()</code>,
                        or <code>OPENROWSET</code>. Requires risk 3.</dd>
                      <dt>OS cmd</dt>
                      <dd>Execute OS commands via
                        <code>xp_cmdshell</code>,
                        <code>COPY TO PROGRAM</code>, or UDF injection.
                        Requires risk 3.</dd>
                    </dl>
                    For blind techniques (boolean/time), extraction uses
                    character-by-character binary search (~8 requests per
                    character). UNION-based extraction is much faster.
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
                          if (e.target.checked) {
                            setSqliEnumerate((prev) => [...prev, opt.value]);
                          } else {
                            setSqliEnumerate((prev) => prev.filter((v) => v !== opt.value));
                          }
                        }}
                      />
                      {opt.label}
                    </label>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="row">
        <div>
          <div className="label-row">
            <label>Format</label>
            <InfoTip label="Format help">
              <strong>Output formats</strong>
              Choose the file format for a saved report. The UI always
              streams findings live regardless; this only affects what
              gets written to <em>Output file</em> below.
            </InfoTip>
          </div>
          <select value={format} onChange={(e) => setFormat(e.target.value)}>
            <option value="txt">Text</option>
            <option value="json">JSON</option>
            <option value="csv">CSV</option>
            <option value="htm">HTML</option>
            <option value="xml">XML</option>
            <option value="sql">SQL</option>
          </select>
        </div>
        <div>
          <div className="label-row">
            <label>Concurrency</label>
            <InfoTip label="Concurrency help">
              <strong>Concurrent requests</strong>
              Cap on in-flight HTTP requests per host. The scan loop uses a
              tokio semaphore so higher values shorten total scan time at
              the cost of server load. Default is 8.
            </InfoTip>
          </div>
          <input
            type="number"
            min={1}
            max={64}
            value={concurrent}
            onChange={(e) => setConcurrent(parseInt(e.target.value) || 8)}
          />
        </div>
      </div>

      <div className="field">
        <label>Output file (optional)</label>
        <input
          type="text"
          value={output}
          onChange={(e) => setOutput(e.target.value)}
          placeholder="/path/to/report.html"
        />
      </div>

      <div className="field">
        <div className="label-row">
          <label>Auth (user:pass[:realm])</label>
          <InfoTip label="Auth help">
            <strong>HTTP authentication</strong>
            The scheme (<em>Basic</em>, <em>Digest</em>, or <em>NTLM</em>) is
            picked automatically from the server's WWW-Authenticate challenge.
            Leave blank if the target doesn't require auth.
          </InfoTip>
        </div>
        <input type="text" value={id} onChange={(e) => setId(e.target.value)} />
      </div>

      <div className="field">
        <label>Custom User-Agent</label>
        <input type="text" value={useragent} onChange={(e) => setUseragent(e.target.value)} />
      </div>

      <div className="field">
        <div className="label-row">
          <label>Evasion</label>
          <InfoTip label="Evasion help">
            <strong>IDS evasion</strong>
            Flags <dt style={{ display: "inline" }}>1</dt>–
            <dt style={{ display: "inline" }}>9</dt> +{" "}
            <dt style={{ display: "inline" }}>A</dt> apply URI transforms that
            obfuscate requests — random %-encoding, directory self-reference,
            session splicing, etc. Combine multiple flags in one string.
          </InfoTip>
        </div>
        <input
          type="text"
          value={evasion}
          onChange={(e) => setEvasion(e.target.value)}
          placeholder="e.g. 13"
          aria-invalid={!!errors.evasion}
        />
        {errors.evasion && <div className="field-error">{errors.evasion}</div>}
      </div>

      {running ? (
        <button type="button" className="danger" onClick={onCancel}>
          Cancel scan
        </button>
      ) : (
        <button
          type="submit"
          className="primary"
          disabled={hasErrors}
          title={hasErrors ? "Fix the highlighted fields above" : undefined}
        >
          Start scan
        </button>
      )}
      </div>
    </form>
  );
}
