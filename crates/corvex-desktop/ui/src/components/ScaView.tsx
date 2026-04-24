import { useCallback, useEffect, useRef, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import {
  startScan,
  cancelScan,
  scanStats,
  onFinding,
  onDone,
  vulndbSummary,
  vulndbUpdate,
  type FindingPayload,
  type ScanStats,
  type VulnDbInfo,
} from "../api";
import { InfoTip } from "./InfoTip";
import { ExploitHits } from "./ExploitHits";
import { createRafBatcher } from "../util/rafBatch";

type Tab = "dependency" | "binary" | "results" | "vulndb";

const SEV_ORDER: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#e53935",
  HIGH: "#fb8c00",
  MEDIUM: "#fdd835",
  LOW: "#42a5f5",
  INFO: "#78909c",
};

export function ScaView() {
  const [tab, setTab] = useState<Tab>("dependency");
  // Dependency analysis form
  const [scanDir, setScanDir] = useState("");
  const [sbomInput, setSbomInput] = useState("");
  const [epssThreshold, setEpssThreshold] = useState(0);
  const [showFixes, setShowFixes] = useState(true);
  // Binary analysis form
  const [binaryScan, setBinaryScan] = useState("");
  const [binaryRecursive, setBinaryRecursive] = useState(true);
  const [binaryExtract, setBinaryExtract] = useState(true);
  // VulnDB state
  const [vulndb, setVulndb] = useState<VulnDbInfo | null>(null);
  const [updating, setUpdating] = useState(false);
  const [updateMsg, setUpdateMsg] = useState("");
  // Scan state
  const [running, setRunning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [findings, setFindings] = useState<FindingPayload[]>([]);
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  const unlisteners = useRef<(() => void)[]>([]);
  const statsTimer = useRef<number | null>(null);
  const findingsBatcher = useRef<ReturnType<typeof createRafBatcher<FindingPayload>> | null>(null);

  useEffect(() => {
    vulndbSummary().then(setVulndb);
    return () => cleanup();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const cleanup = () => {
    unlisteners.current.forEach((fn) => { try { fn(); } catch {} });
    unlisteners.current = [];
    if (statsTimer.current !== null) {
      window.clearInterval(statsTimer.current);
      statsTimer.current = null;
    }
    if (findingsBatcher.current) {
      findingsBatcher.current.dispose();
      findingsBatcher.current = null;
    }
  };

  const runScan = useCallback(async (params: Record<string, unknown>) => {
    cleanup();
    setFindings([]);
    setStats(null);
    setRunning(true);
    setTab("results");
    try {
      const id = await startScan({ host: "sca://local", ...params } as any);
      setScanId(id);
      const batcher = createRafBatcher<FindingPayload>((batch) => {
        setFindings((prev) => [...prev, ...batch]);
      });
      findingsBatcher.current = batcher;
      const f = await onFinding(id, (finding) => {
        batcher.push(finding);
      });
      const done = await onDone(id, () => {
        setRunning(false);
        batcher.flush();
      });
      unlisteners.current.push(f, done);
      statsTimer.current = window.setInterval(async () => {
        try {
          const s = await scanStats(id);
          if (s) setStats(s);
        } catch {}
      }, 750);
    } catch {
      setRunning(false);
    }
  }, []);

  const handleDependencyScan = (e: React.FormEvent) => {
    e.preventDefault();
    runScan({
      scan_dir: scanDir || undefined,
      sbom_input: sbomInput || undefined,
      epss_threshold: epssThreshold > 0 ? epssThreshold : undefined,
      show_fixes: showFixes,
    });
  };

  const handleBinaryScan = (e: React.FormEvent) => {
    e.preventDefault();
    runScan({
      binary_scan: binaryScan || undefined,
      binary_recursive: binaryRecursive,
      binary_extract: binaryExtract,
    });
  };

  const handleCancel = async () => {
    if (scanId) await cancelScan(scanId);
  };

  const handleVulndbUpdate = async () => {
    setUpdating(true);
    setUpdateMsg("");
    try {
      // Use "latest" mode — only fetch CVEs modified since last update
      const msg = await vulndbUpdate("latest");
      setUpdateMsg(msg);
      const info = await vulndbSummary();
      setVulndb(info);
    } catch (e: any) {
      setUpdateMsg(`Error: ${e?.message || e}`);
    } finally {
      setUpdating(false);
    }
  };

  const toggle = (i: number) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(i) ? next.delete(i) : next.add(i);
      return next;
    });

  const sorted = [...findings].sort(
    (a, b) => (SEV_ORDER[b.severity] ?? 0) - (SEV_ORDER[a.severity] ?? 0)
  );

  return (
    <div className="history-view" style={{ display: "flex", flexDirection: "column", gap: 0 }}>
      {/* Tab bar */}
      <div style={{ display: "flex", gap: 0, borderBottom: "1px solid var(--border)" }}>
        {(
          [
            ["dependency", "Dependency Analysis"],
            ["binary", "Binary Analysis"],
            ["results", `Results${findings.length ? ` (${findings.length})` : ""}`],
            ["vulndb", "Vulnerability DB"],
          ] as [Tab, string][]
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => setTab(key)}
            style={{
              padding: "10px 18px",
              fontSize: 12,
              fontWeight: tab === key ? 600 : 400,
              color: tab === key ? "var(--accent)" : "var(--muted)",
              background: "transparent",
              border: "none",
              borderBottom: tab === key ? "2px solid var(--accent)" : "2px solid transparent",
              cursor: "pointer",
              transition: "all 0.15s",
            }}
          >
            {label}
          </button>
        ))}
      </div>

      <div style={{ padding: 16, flex: 1, overflow: "auto" }}>
        {/* ---- Dependency Analysis Tab ---- */}
        {tab === "dependency" && (
          <form onSubmit={handleDependencyScan}>
            <div style={{ marginBottom: 16 }}>
              <h3 style={{ margin: "0 0 4px", fontSize: 14, color: "var(--fg)" }}>
                Dependency Analysis
              </h3>
              <div className="sub">
                Scan project directories for dependency manifest files and cross-reference
                detected components against the CVE vulnerability database.
              </div>
            </div>

            <div className="field">
              <label>
                Project directory
                <InfoTip label="Supported files">
                  <strong>Supported manifest files</strong>
                  <dl style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "4px 12px", margin: "8px 0" }}>
                    <dt style={{ color: "var(--accent)" }}>Rust</dt><dd>Cargo.lock</dd>
                    <dt style={{ color: "var(--accent)" }}>JavaScript</dt><dd>package-lock.json, yarn.lock</dd>
                    <dt style={{ color: "var(--accent)" }}>Python</dt><dd>requirements.txt, Pipfile.lock</dd>
                    <dt style={{ color: "var(--accent)" }}>Java</dt><dd>pom.xml</dd>
                    <dt style={{ color: "var(--accent)" }}>Go</dt><dd>go.mod, go.sum</dd>
                    <dt style={{ color: "var(--accent)" }}>Ruby</dt><dd>Gemfile.lock</dd>
                    <dt style={{ color: "var(--accent)" }}>PHP</dt><dd>composer.lock</dd>
                  </dl>
                </InfoTip>
              </label>
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  type="text"
                  value={scanDir}
                  onChange={(e) => setScanDir(e.target.value)}
                  placeholder="/path/to/project"
                  style={{ flex: 1 }}
                />
                <button
                  type="button"
                  className="browse-btn"
                  onClick={async () => {
                    const selected = await open({
                      directory: true,
                      multiple: false,
                      title: "Select project directory",
                    });
                    if (typeof selected === "string") setScanDir(selected);
                  }}
                >
                  Browse...
                </button>
              </div>
            </div>

            <div className="field">
              <label>SBOM file (optional)</label>
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  type="text"
                  value={sbomInput}
                  onChange={(e) => setSbomInput(e.target.value)}
                  placeholder="bom.json (CycloneDX or SPDX)"
                  style={{ flex: 1 }}
                />
                <button
                  type="button"
                  className="browse-btn"
                  onClick={async () => {
                    const selected = await open({
                      directory: false,
                      multiple: false,
                      title: "Select SBOM file",
                      filters: [
                        { name: "SBOM", extensions: ["json", "xml", "spdx"] },
                        { name: "All files", extensions: ["*"] },
                      ],
                    });
                    if (typeof selected === "string") setSbomInput(selected);
                  }}
                >
                  Browse...
                </button>
              </div>
            </div>

            <div className="row">
              <div className="field">
                <label>EPSS threshold (0.0 - 1.0)</label>
                <input
                  type="number"
                  min={0}
                  max={1}
                  step={0.01}
                  value={epssThreshold}
                  onChange={(e) => setEpssThreshold(Number(e.target.value))}
                />
              </div>
              <div className="field" style={{ display: "flex", alignItems: "flex-end", paddingBottom: 10 }}>
                <label className="checkbox">
                  <input
                    type="checkbox"
                    checked={showFixes}
                    onChange={(e) => setShowFixes(e.target.checked)}
                  />
                  Show available fixes
                </label>
              </div>
            </div>

            {running ? (
              <button
                type="button"
                className="danger"
                onClick={handleCancel}
              >
                Cancel scan
              </button>
            ) : (
              <button
                type="submit"
                className="primary"
                disabled={!scanDir && !sbomInput}
              >
                Scan dependencies
              </button>
            )}
          </form>
        )}

        {/* ---- Binary Analysis Tab ---- */}
        {tab === "binary" && (
          <form onSubmit={handleBinaryScan}>
            <div style={{ marginBottom: 16 }}>
              <h3 style={{ margin: "0 0 4px", fontSize: 14, color: "var(--fg)" }}>
                Binary Analysis
              </h3>
              <div className="sub">
                Scan compiled binaries and libraries for known vulnerable components
                by extracting strings and matching against 50+ library version patterns.
              </div>
            </div>

            <div className="field">
              <label>Path to scan</label>
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  type="text"
                  value={binaryScan}
                  onChange={(e) => setBinaryScan(e.target.value)}
                  placeholder="/path/to/binary or /path/to/directory"
                  style={{ flex: 1 }}
                />
                <button
                  type="button"
                  className="browse-btn"
                  onClick={async () => {
                    const selected = await open({
                      directory: false,
                      multiple: false,
                      title: "Select binary file",
                    });
                    if (typeof selected === "string") setBinaryScan(selected);
                  }}
                >
                  File...
                </button>
                <button
                  type="button"
                  className="browse-btn"
                  onClick={async () => {
                    const selected = await open({
                      directory: true,
                      multiple: false,
                      title: "Select directory",
                    });
                    if (typeof selected === "string") setBinaryScan(selected);
                  }}
                >
                  Folder...
                </button>
              </div>
            </div>

            <div className="row">
              <div className="field">
                <label className="checkbox">
                  <input
                    type="checkbox"
                    checked={binaryRecursive}
                    onChange={(e) => setBinaryRecursive(e.target.checked)}
                  />
                  Recursive directory scan
                </label>
              </div>
              <div className="field">
                <label className="checkbox">
                  <input
                    type="checkbox"
                    checked={binaryExtract}
                    onChange={(e) => setBinaryExtract(e.target.checked)}
                  />
                  Extract archives (ZIP, TAR, TAR.GZ)
                </label>
              </div>
            </div>

            {running ? (
              <button
                type="button"
                className="danger"
                onClick={handleCancel}
              >
                Cancel scan
              </button>
            ) : (
              <button
                type="submit"
                className="primary"
                disabled={!binaryScan}
              >
                Scan binaries
              </button>
            )}
          </form>
        )}

        {/* ---- Results Tab ---- */}
        {tab === "results" && (
          <div>
            {stats && (
              <div style={{ display: "flex", gap: 16, marginBottom: 16 }}>
                <div className="info-cell" style={{ flex: 1 }}>
                  <div className="label">Findings</div>
                  <div className="value">{findings.length}</div>
                </div>
                <div className="info-cell" style={{ flex: 1 }}>
                  <div className="label">Status</div>
                  <div className="value" style={{ fontSize: 14 }}>
                    {running ? "Scanning..." : "Complete"}
                  </div>
                </div>
              </div>
            )}

            {findings.length === 0 && !running && (
              <div className="empty" style={{ padding: 32, textAlign: "center" }}>
                No findings yet. Run a dependency or binary analysis scan.
              </div>
            )}

            {findings.length > 0 && (
              <div className="findings-wrap">
                <table className="findings-table">
                  <colgroup>
                    <col style={{ width: 26 }} />
                    <col style={{ width: 82 }} />
                    <col style={{ width: 140 }} />
                    <col style={{ width: 100 }} />
                    <col />
                    <col style={{ width: 80 }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th />
                      <th>Severity</th>
                      <th>CVE</th>
                      <th>Component</th>
                      <th>Description</th>
                      <th>CVSS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sorted.map((f, i) => {
                      const isOpen = expanded.has(i);
                      return (
                        <ScaRow
                          key={i}
                          finding={f}
                          isOpen={isOpen}
                          onToggle={() => toggle(i)}
                        />
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ---- VulnDB Tab ---- */}
        {tab === "vulndb" && (
          <div>
            <div style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 12 }}>
              <div style={{ flex: 1 }}>
                <h3 style={{ margin: "0 0 4px", fontSize: 14, color: "var(--fg)" }}>
                  Vulnerability Database
                </h3>
                <div className="sub">
                  Local CVE database powered by NVD and EPSS data.
                  {vulndb && !vulndb.available && (
                    <span style={{ color: "var(--warning)", marginLeft: 8 }}>
                      Not initialized — click Update to download CVE data.
                    </span>
                  )}
                </div>
              </div>
              <button
                type="button"
                className="primary"
                onClick={handleVulndbUpdate}
                disabled={updating}
                style={{ width: "auto", margin: 0, padding: "10px 20px" }}
              >
                {updating ? "Updating..." : "Update database"}
              </button>
            </div>

            {updateMsg && (
              <div style={{
                padding: "8px 12px",
                marginBottom: 12,
                fontSize: 12,
                borderRadius: 6,
                background: updateMsg.startsWith("Error") ? "rgba(239,68,68,0.1)" : "rgba(34,197,94,0.1)",
                color: updateMsg.startsWith("Error") ? "var(--danger)" : "var(--success)",
              }}>
                {updateMsg}
              </div>
            )}

            {vulndb && vulndb.available && (
              <div
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                  gap: "6px 18px",
                  padding: "8px 12px",
                  marginTop: 4,
                  borderRadius: 6,
                  background: "var(--panel-alt)",
                  border: "1px solid var(--border-soft)",
                  fontSize: "calc(var(--font-base) - 2px)",
                  fontFamily: "monospace",
                  color: "var(--fg)",
                }}
              >
                <span>
                  <span style={{ color: "var(--muted)" }}>cves </span>
                  {vulndb.cve_count.toLocaleString()}
                </span>
                <span>
                  <span style={{ color: "var(--muted)" }}>cpe matches </span>
                  {vulndb.cpe_match_count.toLocaleString()}
                </span>
                <span>
                  <span style={{ color: "var(--muted)" }}>epss scores </span>
                  {vulndb.epss_count.toLocaleString()}
                </span>
                <span>
                  <span style={{ color: "var(--muted)" }}>fixes </span>
                  {vulndb.fix_count.toLocaleString()}
                </span>
                <span>
                  <span style={{ color: "var(--muted)" }}>nvd </span>
                  {vulndb.last_nvd_update || "\u2014"}
                </span>
                <span>
                  <span style={{ color: "var(--muted)" }}>epss </span>
                  {vulndb.last_epss_update || "\u2014"}
                </span>
              </div>
            )}

            <div
              className="sub"
              style={{ marginTop: 10, lineHeight: 1.5 }}
            >
              Full provenance (NVD / EPSS / CPE dictionary sources, licence
              notes, cross-cutting dataset counts) lives in the{" "}
              <strong>Databases</strong> view under its SCA / VulnDB tab.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ---- SCA finding row with expandable detail ---- */

function ScaRow({
  finding,
  isOpen,
  onToggle,
}: {
  finding: FindingPayload;
  isOpen: boolean;
  onToggle: () => void;
}) {
  const sevColor = SEV_COLOR[finding.severity] ?? "#78909c";
  const textColor = finding.severity === "MEDIUM" ? "#333" : "#fff";

  return (
    <>
      <tr
        className={`finding-row${isOpen ? " open" : ""}`}
        onClick={onToggle}
      >
        <td style={{ textAlign: "center", fontSize: 10 }}>
          {isOpen ? "\u25BC" : "\u25B6"}
        </td>
        <td>
          <span
            className="severity-badge"
            style={{ background: sevColor, color: textColor }}
          >
            {finding.severity}
          </span>
        </td>
        <td>
          {finding.cve ? (
            <a
              href={`https://nvd.nist.gov/vuln/detail/${finding.cve}`}
              target="_blank"
              rel="noopener noreferrer"
              className="cve-link"
              onClick={(e) => e.stopPropagation()}
            >
              {finding.cve}
            </a>
          ) : (
            <span className="muted">{finding.corvex_id}</span>
          )}
        </td>
        <td>
          {finding.component && (
            <code style={{ fontSize: 11 }}>
              {finding.component}
              {finding.component_version && (
                <span className="muted">@{finding.component_version}</span>
              )}
            </code>
          )}
        </td>
        <td className="ellipsis">{finding.message}</td>
        <td style={{ textAlign: "center" }}>
          {finding.cvss != null ? finding.cvss.toFixed(1) : "\u2014"}
        </td>
      </tr>
      {isOpen && (
        <tr className="finding-detail-row">
          <td colSpan={6}>
            <div className="finding-detail">
              <dl>
                <dt>Severity</dt>
                <dd>
                  <span
                    className="severity-badge"
                    style={{ background: sevColor, color: textColor }}
                  >
                    {finding.severity}
                  </span>
                  {finding.cvss != null && (
                    <span className="cvss-score"> CVSS {finding.cvss.toFixed(1)}</span>
                  )}
                </dd>
                {finding.component && (
                  <>
                    <dt>Component</dt>
                    <dd>
                      <code>{finding.component}</code>
                      {finding.component_version && (
                        <span className="muted"> @{finding.component_version}</span>
                      )}
                    </dd>
                  </>
                )}
                {finding.epss_score != null && (
                  <>
                    <dt>EPSS</dt>
                    <dd>
                      {(finding.epss_score * 100).toFixed(2)}% probability
                      {finding.epss_percentile != null && (
                        <span className="muted">
                          {" "}({(finding.epss_percentile * 100).toFixed(1)}th percentile)
                        </span>
                      )}
                    </dd>
                  </>
                )}
                {finding.fix_version && (
                  <>
                    <dt>Fix available</dt>
                    <dd>
                      <span
                        className="badge"
                        style={{ background: "var(--success)", color: "#fff", padding: "2px 8px", borderRadius: 4 }}
                      >
                        Upgrade to {finding.fix_version}
                      </span>
                    </dd>
                  </>
                )}
                {finding.cve && (
                  <>
                    <dt>CVE</dt>
                    <dd>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${finding.cve}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="cve-link"
                      >
                        {finding.cve}
                      </a>
                    </dd>
                  </>
                )}
                <ExploitHits cve={finding.cve} />
                <dt>Message</dt>
                <dd className="break">{finding.message}</dd>
                <dt>Plugin</dt>
                <dd><span className="badge">{finding.plugin}</span></dd>
              </dl>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
