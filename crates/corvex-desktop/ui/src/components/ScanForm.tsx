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
