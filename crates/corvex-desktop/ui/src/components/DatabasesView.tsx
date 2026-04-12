import { useEffect, useState } from "react";
import { dbSummary, type DbSummary } from "../api";

interface Cell {
  label: string;
  value: number;
  hint: string;
}

export function DatabasesView() {
  const [dbs, setDbs] = useState<DbSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    dbSummary()
      .then(setDbs)
      .finally(() => setLoading(false));
  }, []);

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
    </div>
  );
}
