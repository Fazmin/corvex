import { useEffect, useState } from "react";
import {
  dbSummary,
  sonarSummary,
  vulndbSummary,
  type DbSummary,
  type SonarSummary,
  type VulnDbInfo,
} from "../api";
import { useSettings } from "../settings";
import type { View } from "./Sidebar";
import {
  MODULES as FUZZ_MODULES,
  TECHNIQUES as FUZZ_TECHNIQUES,
  TAMPER_MODULES as FUZZ_TAMPER,
  DBMS_DETAILS as FUZZ_DBMS,
  ENUMERATE_TARGETS as FUZZ_ENUMERATE,
} from "./FuzzingView";

interface Cell {
  label: string;
  value: number | string;
  hint: string;
}

type DbTab = "web" | "probing" | "sca" | "fuzzing";

const TABS: { key: DbTab; label: string }[] = [
  { key: "web", label: "Web signatures" },
  { key: "probing", label: "Probing" },
  { key: "sca", label: "SCA / VulnDB" },
  { key: "fuzzing", label: "Fuzzing" },
];

interface Props {
  /** Optional: lets "See X view →" links jump to the appropriate sidebar
   *  entry. Safe to omit; the links degrade to static text. */
  onNavigate?: (view: View) => void;
}

export function DatabasesView({ onNavigate }: Props) {
  const [tab, setTab] = useState<DbTab>("web");

  return (
    <div className="history-view" style={{ overflow: "auto" }}>
      <div className="history-header">
        <div>
          <h2
            style={{
              margin: 0,
              fontSize: "var(--font-base)",
              color: "var(--fg)",
              textTransform: "none",
              letterSpacing: 0,
            }}
          >
            Embedded datasets
          </h2>
          <div className="sub" style={{ marginTop: 4, lineHeight: 1.5 }}>
            Everything Corvex ships bundled into the binary. Probe payloads,
            web-test signatures, JARM fingerprints, and vulnerability data —
            all loaded once at startup. For feature-specific documentation
            open the relevant view in the sidebar.
          </div>
        </div>
      </div>

      <div
        style={{
          display: "flex",
          gap: 2,
          marginBottom: 12,
          borderBottom: "1px solid var(--border)",
          paddingBottom: 0,
        }}
      >
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTab(t.key)}
            style={{
              all: "unset",
              cursor: "pointer",
              padding: "7px 14px",
              fontSize: "calc(var(--font-base) - 2px)",
              fontWeight: tab === t.key ? 600 : 400,
              color: tab === t.key ? "var(--accent)" : "var(--muted)",
              borderBottom:
                tab === t.key ? "2px solid var(--accent)" : "2px solid transparent",
              marginBottom: -1,
              transition: "color 0.15s, border-color 0.15s",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "web" && <WebTab />}
      {tab === "probing" && <ProbingTab onNavigate={onNavigate} />}
      {tab === "sca" && <ScaTab onNavigate={onNavigate} />}
      {tab === "fuzzing" && <FuzzingTab onNavigate={onNavigate} />}
    </div>
  );
}

/* ====================================================================== */
/* Tab 1 — Web signatures                                                  */
/* ====================================================================== */

function WebTab() {
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
    <>
      {loading && <div className="empty">Loading…</div>}
      <div className="info-grid">
        {cells.map((c) => (
          <InfoCell key={c.label} cell={c} />
        ))}
      </div>
    </>
  );
}

/* ====================================================================== */
/* Tab 2 — Probing                                                         */
/* ====================================================================== */

function ProbingTab({ onNavigate }: { onNavigate?: (v: View) => void }) {
  const { extraProbeFiles } = useSettings();
  const [summary, setSummary] = useState<SonarSummary | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    sonarSummary(extraProbeFiles)
      .then((s) => {
        setSummary(s);
        setErr(null);
      })
      .catch((e: unknown) => {
        setErr(
          typeof e === "string" ? e : e instanceof Error ? e.message : "unknown"
        );
      });
  }, [extraProbeFiles]);

  if (err) {
    return <div className="empty">Failed to load probe database: {err}</div>;
  }
  if (!summary) return <div className="empty">Loading…</div>;

  const bakedStatic = summary.static_count - summary.extra_probes_loaded;
  const bakedFps = summary.fingerprint_count - summary.extra_fps_loaded;

  const cells: Cell[] = [
    {
      label: "Scripted probes",
      value: summary.scripted_count,
      hint: "Rust protocol modules (TLS, HTTP, SSH, MySQL, SMB, RDP, LDAP, …)",
    },
    {
      label: "Declarative probes",
      value: bakedStatic,
      hint: "probes.toml entries: port list + payload + linked Recog sets",
    },
    {
      label: "Recog fingerprint sets",
      value: summary.fingerprint_sets.length,
      hint: "Grouped regex matchers keyed by probe hint",
    },
    {
      label: "Recog fingerprints",
      value: bakedFps,
      hint: "Individual regex → product/version/CPE extractors",
    },
    {
      label: "Extra probe files loaded",
      value: summary.extra_files_loaded,
      hint: "User-supplied directive-format files (Configure tab)",
    },
    {
      label: "Extra probes merged",
      value: summary.extra_probes_loaded + summary.extra_fps_loaded,
      hint: "Additional probes + fingerprints from Layer-3 drop-ins",
    },
  ];

  return (
    <>
      <div className="info-grid">
        {cells.map((c) => (
          <InfoCell key={c.label} cell={c} />
        ))}
      </div>

      <Provenance title="Where the data comes from">
        <ul style={{ margin: "6px 0 0 18px", padding: 0, lineHeight: 1.6 }}>
          <li>
            <strong>Recog</strong> (Rapid7, BSD-2-Clause) bundled under{" "}
            <code>crates/corvex-sonar/data/recog/*.xml</code>. Copyright and
            license notice ship in <code>THIRD_PARTY_LICENSES.md</code>.
          </li>
          <li>
            <strong>Probe payloads</strong> authored in-house from public
            protocol specs (RFCs, vendor documentation). Not redistributed
            from any third-party scanner dataset.
          </li>
          <li>
            <strong>Known JARM hashes</strong> live in{" "}
            <code>crates/corvex-sonar/data/jarm_known.toml</code> — curated
            locally, extensible.
          </li>
          <li>
            <strong>Layer-3 extras</strong> are never bundled. Paths configured
            on the Configure tab are read at process startup and merged in
            memory only.
          </li>
        </ul>
      </Provenance>

      <ViewLink
        onNavigate={onNavigate}
        view="probing"
        label="Probe families, scan modes, JARM explainer, directive format → Probing view"
      />
    </>
  );
}

/* ====================================================================== */
/* Tab 3 — SCA / VulnDB                                                   */
/* ====================================================================== */

function ScaTab({ onNavigate }: { onNavigate?: (v: View) => void }) {
  const [vulndb, setVulndb] = useState<VulnDbInfo | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    vulndbSummary()
      .then(setVulndb)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="empty">Loading…</div>;
  if (!vulndb || !vulndb.available) {
    return (
      <>
        <div className="empty" style={{ marginBottom: 12 }}>
          Vulnerability database is not initialised yet.
        </div>
        <ViewLink
          onNavigate={onNavigate}
          view="sca"
          label="Download CVE data → SCA view"
        />
      </>
    );
  }

  const cells: Cell[] = [
    {
      label: "CVEs",
      value: vulndb.cve_count.toLocaleString(),
      hint: "Total CVE records from NVD",
    },
    {
      label: "CPE matches",
      value: vulndb.cpe_match_count.toLocaleString(),
      hint: "Software-version → CVE mappings",
    },
    {
      label: "EPSS scores",
      value: vulndb.epss_count.toLocaleString(),
      hint: "Exploit-probability predictions",
    },
    {
      label: "Fix records",
      value: vulndb.fix_count.toLocaleString(),
      hint: "Known available fixes",
    },
    {
      label: "Last NVD update",
      value: vulndb.last_nvd_update || "—",
      hint: "When CVE data was last refreshed",
    },
    {
      label: "Last EPSS update",
      value: vulndb.last_epss_update || "—",
      hint: "When exploit scores were last refreshed",
    },
  ];

  return (
    <>
      <div className="info-grid">
        {cells.map((c) => (
          <InfoCell key={c.label} cell={c} />
        ))}
      </div>

      <Provenance title="Where the data comes from">
        <ul style={{ margin: "6px 0 0 18px", padding: 0, lineHeight: 1.6 }}>
          <li>
            <strong>NVD</strong> — National Vulnerability Database CVE feeds
            (nvd.nist.gov). Downloaded on-demand via the SCA view's Update
            button; requires no API key for the default cadence.
          </li>
          <li>
            <strong>EPSS</strong> — Exploit Prediction Scoring System
            (first.org/epss). Daily refresh provides per-CVE exploit
            probability + percentile.
          </li>
          <li>
            <strong>CPE dictionary</strong> — official NIST CPE matches used
            to resolve a component/version to a CVE list.
          </li>
        </ul>
      </Provenance>

      <ViewLink
        onNavigate={onNavigate}
        view="sca"
        label="Scan a project, update the database, browse SCA findings → SCA view"
      />
    </>
  );
}

/* ====================================================================== */
/* Tab 4 — Fuzzing                                                         */
/* ====================================================================== */

function FuzzingTab({ onNavigate }: { onNavigate?: (v: View) => void }) {
  const totalTamper = FUZZ_TAMPER.reduce((s, c) => s + c.count, 0);
  const readyModules = FUZZ_MODULES.filter((m) => m.status === "ready").length;

  const cells: Cell[] = [
    {
      label: "Fuzz modules",
      value: FUZZ_MODULES.length,
      hint: `${readyModules} ready, ${FUZZ_MODULES.length - readyModules} planned — XSS, SQLi, LFI, cmd-inject, SSRF, …`,
    },
    {
      label: "SQLi techniques",
      value: FUZZ_TECHNIQUES.length,
      hint: "Error · Boolean · Time · Union · Stacked",
    },
    {
      label: "Tamper modules",
      value: FUZZ_TAMPER.length,
      hint: `${totalTamper.toLocaleString()} WAF-bypass payloads across space2comment, between, randomcase, …`,
    },
    {
      label: "DBMS backends",
      value: FUZZ_DBMS.length,
      hint: "MySQL, PostgreSQL, MSSQL, Oracle, SQLite, DB2, Firebird, Sybase",
    },
    {
      label: "Enumeration targets",
      value: FUZZ_ENUMERATE.length,
      hint: "Databases · tables · columns · users · hashes · dump · file-read · os-cmd",
    },
  ];

  return (
    <>
      <div className="info-grid">
        {cells.map((c) => (
          <InfoCell key={c.label} cell={c} />
        ))}
      </div>

      <Provenance title="Where the data comes from">
        <ul style={{ margin: "6px 0 0 18px", padding: 0, lineHeight: 1.6 }}>
          <li>
            <strong>Fuzz modules</strong> live in-tree as Rust plugins —
            shipped with the binary, no external download.
          </li>
          <li>
            <strong>SQLi techniques</strong> are hand-authored from public
            research (sqlmap technique taxonomy, OWASP testing guide).
          </li>
          <li>
            <strong>Tamper payloads</strong> authored in-house — each module
            is a small pure function that rewrites a payload (e.g. replace
            spaces with <code>/**/</code>).
          </li>
        </ul>
      </Provenance>

      <ViewLink
        onNavigate={onNavigate}
        view="fuzzing"
        label="Per-technique explainers, tamper lists, DBMS matrices → Fuzzing view"
      />
    </>
  );
}

/* ====================================================================== */
/* Shared bits                                                             */
/* ====================================================================== */

function InfoCell({ cell }: { cell: Cell }) {
  const isLongText = typeof cell.value === "string" && cell.value.length > 10;
  return (
    <div className="info-cell">
      <div className="label">{cell.label}</div>
      <div className="value" style={isLongText ? { fontSize: 13 } : undefined}>
        {typeof cell.value === "number"
          ? cell.value.toLocaleString()
          : cell.value}
      </div>
      <div className="hint">{cell.hint}</div>
    </div>
  );
}

function Provenance({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div
      className="form-panel"
      style={{
        maxWidth: 900,
        marginTop: 16,
        fontSize: "calc(var(--font-base) - 1px)",
      }}
    >
      <strong>{title}</strong>
      {children}
    </div>
  );
}

function ViewLink({
  onNavigate,
  view,
  label,
}: {
  onNavigate?: (v: View) => void;
  view: View;
  label: string;
}) {
  if (!onNavigate) {
    return (
      <div className="sub" style={{ marginTop: 10 }}>
        {label}
      </div>
    );
  }
  return (
    <div style={{ marginTop: 10 }}>
      <button
        type="button"
        className="ghost-btn"
        onClick={() => onNavigate(view)}
        style={{ padding: "6px 12px" }}
      >
        {label}
      </button>
    </div>
  );
}
