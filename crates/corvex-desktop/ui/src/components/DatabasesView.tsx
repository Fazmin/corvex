import { useEffect, useState } from "react";
import { dbSummary, vulndbSummary, vulndbUpdate, type DbSummary, type VulnDbInfo } from "../api";

interface Cell {
  label: string;
  value: number;
  hint: string;
}

export function DatabasesView() {
  const [dbs, setDbs] = useState<DbSummary | null>(null);
  const [vulndb, setVulndb] = useState<VulnDbInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [updateMsg, setUpdateMsg] = useState("");

  useEffect(() => {
    Promise.all([dbSummary(), vulndbSummary()])
      .then(([db, vdb]) => {
        setDbs(db);
        setVulndb(vdb);
      })
      .finally(() => setLoading(false));
  }, []);

  const handleVulndbUpdate = async () => {
    setUpdating(true);
    setUpdateMsg("");
    try {
      const msg = await vulndbUpdate("now");
      setUpdateMsg(msg);
      const info = await vulndbSummary();
      setVulndb(info);
    } catch (e: any) {
      setUpdateMsg(`Error: ${e?.message || e}`);
    } finally {
      setUpdating(false);
    }
  };

  const cells: Cell[] = dbs
    ? [
        { label: "db_tests", value: dbs.tests, hint: "Main vulnerability signature database (DSL-driven)" },
        { label: "db_outdated", value: dbs.outdated, hint: "Outdated server-version regex matchers" },
        { label: "db_favicon", value: dbs.favicon, hint: "MD5-hashed favicon → software identifier" },
        { label: "db_server_msgs", value: dbs.server_msgs, hint: "Server banner → CVE / vulnerability mapping" },
        { label: "db_realms", value: dbs.realms, hint: "HTTP auth realm → device identifier + default creds" },
        { label: "db_variables", value: dbs.variables, hint: "Template variables (@CGIDIRS, @ADMIN, @LFI, …)" },
        { label: "db_content_search", value: dbs.content_search, hint: "Body regex matchers (per response)" },
        { label: "db_headers_common", value: dbs.headers_common, hint: "Reference list of common HTTP headers" },
        { label: "db_headers_suggested", value: dbs.headers_suggested, hint: "Recommended security headers" },
        { label: "db_multiple_index", value: dbs.multiple_index, hint: "Default index file variations" },
        { label: "db_options", value: dbs.options, hint: "HTTP method names + danger ratings" },
        { label: "db_useragents", value: dbs.useragents, hint: "Realistic User-Agent strings" },
        { label: "db_dictionary", value: dbs.dictionary, hint: "Dictionary words for path brute-forcing" },
        { label: "db_404_strings", value: dbs.fourohfour, hint: "Body fragments that mark a 404 page" },
      ]
    : [];

  return (
    <div className="history-view">
      <div className="history-header">
        <div>
          <h2 style={{ margin: 0, fontSize: 13, color: "var(--fg)", textTransform: "none", letterSpacing: 0 }}>
            Embedded databases
          </h2>
          <div className="sub" style={{ marginTop: 4 }}>
            All 14 Corvex databases are compiled into the binary at build time
            and deserialized once at startup.
          </div>
        </div>
      </div>
      {loading && <div className="empty">Loading…</div>}
      <div className="info-grid">
        {cells.map((c) => (
          <div className="info-cell" key={c.label}>
            <div className="label">{c.label}</div>
            <div className="value">{c.value.toLocaleString()}</div>
            <div className="hint">{c.hint}</div>
          </div>
        ))}
      </div>

      {/* ---- Vulnerability Database Section ---- */}
      <div className="history-header" style={{ marginTop: 24 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 13, color: "var(--fg)", textTransform: "none", letterSpacing: 0 }}>
            Vulnerability database
          </h2>
          <div className="sub" style={{ marginTop: 4 }}>
            CVE data from NVD and EPSS scores for SCA and binary analysis.
            {vulndb && !vulndb.available && (
              <span style={{ color: "var(--warning)", marginLeft: 8 }}>
                Not initialized — run an update to download CVE data.
              </span>
            )}
          </div>
        </div>
        <button
          className="btn"
          onClick={handleVulndbUpdate}
          disabled={updating}
          style={{ marginLeft: "auto" }}
        >
          {updating ? "Updating…" : "Update database"}
        </button>
      </div>
      {updateMsg && (
        <div style={{ padding: "8px 12px", fontSize: 12, color: updateMsg.startsWith("Error") ? "var(--danger)" : "var(--success)" }}>
          {updateMsg}
        </div>
      )}
      {vulndb && vulndb.available && (
        <div className="info-grid">
          <div className="info-cell">
            <div className="label">CVEs</div>
            <div className="value">{vulndb.cve_count.toLocaleString()}</div>
            <div className="hint">Total CVE records from NVD</div>
          </div>
          <div className="info-cell">
            <div className="label">CPE matches</div>
            <div className="value">{vulndb.cpe_match_count.toLocaleString()}</div>
            <div className="hint">Software version → CVE mappings</div>
          </div>
          <div className="info-cell">
            <div className="label">EPSS scores</div>
            <div className="value">{vulndb.epss_count.toLocaleString()}</div>
            <div className="hint">Exploit probability predictions</div>
          </div>
          <div className="info-cell">
            <div className="label">Fix records</div>
            <div className="value">{vulndb.fix_count.toLocaleString()}</div>
            <div className="hint">Known available fixes</div>
          </div>
          <div className="info-cell">
            <div className="label">Last NVD update</div>
            <div className="value" style={{ fontSize: 13 }}>{vulndb.last_nvd_update || "—"}</div>
            <div className="hint">When CVE data was last refreshed</div>
          </div>
          <div className="info-cell">
            <div className="label">Last EPSS update</div>
            <div className="value" style={{ fontSize: 13 }}>{vulndb.last_epss_update || "—"}</div>
            <div className="hint">When exploit scores were last refreshed</div>
          </div>
        </div>
      )}
    </div>
  );
}
