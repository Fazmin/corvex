import { useState } from "react";
import type { ScanParams } from "../api";
import { PluginPicker } from "./PluginPicker";
import { TuningPicker } from "./TuningPicker";
import { InfoTip } from "./InfoTip";

interface Props {
  running: boolean;
  onStart: (params: ScanParams) => void;
  onCancel: () => void;
}

export function ScanForm({ running, onStart, onCancel }: Props) {
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

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
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
      <div className="field">
        <label>Host / URL</label>
        <input
          type="text"
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="http://example.com"
          required
        />
      </div>
      <div className="row">
        <div>
          <label>Ports</label>
          <input
            type="text"
            value={ports}
            onChange={(e) => setPorts(e.target.value)}
            placeholder="80,443"
          />
        </div>
        <div>
          <label>Timeout (s)</label>
          <input
            type="number"
            min={1}
            value={timeout}
            onChange={(e) => setTimeoutVal(parseInt(e.target.value) || 15)}
          />
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
            When enabled, the scanner crawls the target to discover pages
            and forms, then injects payloads into every parameter to probe
            for XSS, SQLi, LFI, command injection, CRLF, open redirects
            and more. This is <em>invasive</em> — only use against targets
            you own or have explicit permission to test.
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
                  Configures the active SQLi scanner that tests every discovered
                  parameter for injection vulnerabilities. Supports error-based,
                  boolean-blind, time-blind, UNION query, and stacked query
                  techniques across MySQL, PostgreSQL, MSSQL, Oracle, SQLite,
                  MariaDB, DB2, and Firebird.
                </InfoTip>
              </div>

              <div className="row">
                <div>
                  <div className="label-row">
                    <label>Level (1-5)</label>
                    <InfoTip label="Level help">
                      <strong>Testing level</strong>
                      <br />1 = GET/POST params only
                      <br />2 = + Cookie params
                      <br />3 = + User-Agent, Referer
                      <br />4 = + other headers
                      <br />5 = all injection points
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
                      <br />1 = safe, read-only queries
                      <br />2 = + OR-based (may alter results)
                      <br />3 = + UPDATE/INSERT/file-write/OS-cmd
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
                    <br />B = Boolean-based blind
                    <br />E = Error-based
                    <br />U = UNION query
                    <br />S = Stacked queries
                    <br />T = Time-based blind
                    <br />Combine letters to enable multiple.
                  </InfoTip>
                </div>
                <div style={{ display: "flex", gap: 4 }}>
                  {["B", "E", "U", "S", "T"].map((t) => (
                    <label key={t} className="checkbox" style={{ margin: 0, fontSize: "var(--font-base)" }}>
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
                <div className="label-row">
                  <label>Tamper modules</label>
                  <InfoTip label="Tamper help">
                    <strong>WAF/IDS bypass</strong>
                    Comma-separated list of payload transform modules.
                    Examples: <code>space2comment</code>, <code>randomcase</code>,
                    <code>between</code>, <code>base64encode</code>,
                    <code>apostrophemask</code>.
                    50 modules available.
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
                    Select what to extract after confirming an injectable parameter.
                    Higher options require higher risk levels.
                  </InfoTip>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
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
        />
      </div>

      {running ? (
        <button type="button" className="danger" onClick={onCancel}>
          Cancel scan
        </button>
      ) : (
        <button type="submit" className="primary">
          Start scan
        </button>
      )}
      </div>
    </form>
  );
}
