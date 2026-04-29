import { useEffect, useState } from "react";
import {
  dbSummary,
  exploitdbSummary,
  exploitdbUpdate,
  nucleiExtrasDownload,
  nucleiExtrasRemove,
  nucleiSummary,
  rulesSummary,
  sonarSummary,
  vulndbSummary,
  wappalyzerSummary,
  type DbSummary,
  type ExploitDbSummary,
  type NucleiSummary,
  type RulesSummary,
  type SonarSummary,
  type VulnDbInfo,
  type WappalyzerSummary,
} from "../api";
import { clearExploitHitsCache } from "./ExploitHits";
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

type DbTab =
  | "web"
  | "probing"
  | "sca"
  | "fuzzing"
  | "nuclei"
  | "fingerprints"
  | "exploits"
  | "rules";

const TABS: { key: DbTab; label: string }[] = [
  { key: "web", label: "Web signatures" },
  { key: "probing", label: "Probing" },
  { key: "sca", label: "SCA / VulnDB" },
  { key: "fuzzing", label: "Fuzzing" },
  { key: "nuclei", label: "Nuclei templates" },
  { key: "fingerprints", label: "Fingerprints (Wappalyzer)" },
  { key: "exploits", label: "Exploit-DB" },
  { key: "rules", label: "Unified rules" },
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
      {tab === "nuclei" && <NucleiTab onNavigate={onNavigate} />}
      {tab === "fingerprints" && <FingerprintsTab onNavigate={onNavigate} />}
      {tab === "exploits" && <ExploitDbTab />}
      {tab === "rules" && <RulesTab />}
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

/* ====================================================================== */
/* Tab 5 — Nuclei templates                                                */
/* ====================================================================== */

function NucleiTab({ onNavigate }: { onNavigate?: (v: View) => void }) {
  const [summary, setSummary] = useState<NucleiSummary | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [extrasBusy, setExtrasBusy] = useState<"download" | "remove" | null>(
    null
  );
  const [extrasMsg, setExtrasMsg] = useState<string | null>(null);
  const [extrasErr, setExtrasErr] = useState<string | null>(null);

  const refresh = () => {
    nucleiSummary()
      .then((s) => {
        setSummary(s);
        setErr(null);
      })
      .catch((e: unknown) => {
        setErr(
          typeof e === "string" ? e : e instanceof Error ? e.message : "unknown"
        );
      });
  };

  useEffect(() => {
    refresh();
  }, []);

  const onExpandCoverage = async () => {
    if (extrasBusy) return;
    setExtrasBusy("download");
    setExtrasMsg(null);
    setExtrasErr(null);
    try {
      const status = await nucleiExtrasDownload();
      setExtrasMsg(
        `Downloaded ${status.http_template_count.toLocaleString()} templates at ${status.tag} into ${status.cache_path}`
      );
      refresh();
    } catch (e: unknown) {
      setExtrasErr(
        typeof e === "string" ? e : e instanceof Error ? e.message : "unknown"
      );
    } finally {
      setExtrasBusy(null);
    }
  };

  const onRemoveExtras = async () => {
    if (extrasBusy) return;
    setExtrasBusy("remove");
    setExtrasMsg(null);
    setExtrasErr(null);
    try {
      await nucleiExtrasRemove();
      setExtrasMsg("Tier-2 cache removed. Scans will use the bundled set only.");
      refresh();
    } catch (e: unknown) {
      setExtrasErr(
        typeof e === "string" ? e : e instanceof Error ? e.message : "unknown"
      );
    } finally {
      setExtrasBusy(null);
    }
  };

  if (err) {
    return <div className="empty">Failed to load Nuclei summary: {err}</div>;
  }
  if (!summary) return <div className="empty">Loading…</div>;

  const cells: Cell[] = [
    {
      label: "Supported",
      value: summary.supported,
      hint: "Templates the v1 engine will execute against each crawled origin.",
    },
    {
      label: "Skipped",
      value: summary.skipped,
      hint: "Templates excluded at load time (unsupported feature, DSL helper, interactsh, non-HTTP protocol).",
    },
    {
      label: "Upstream tag",
      value: summary.bundle_tag ?? "—",
      hint: "Pinned nuclei-templates release the bundle was built from.",
    },
    {
      label: "Upstream commit",
      value: summary.bundle_commit
        ? summary.bundle_commit.slice(0, 10)
        : "—",
      hint: "SHA recorded in MANIFEST.toml when the bundle was refreshed.",
    },
    {
      label: "Bundled count",
      value: summary.manifest_template_count ?? summary.supported + summary.skipped,
      hint: "Total templates shipped on disk (pre-classification).",
    },
    {
      label: "Engine enabled",
      value: summary.enabled ? "yes" : "no",
      hint: "Set nuclei.enabled=true/false in corvex.conf to toggle. Counts are loaded regardless.",
    },
  ];

  const sevLabel = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

  return (
    <>
      <div className="info-grid">
        {cells.map((c) => (
          <InfoCell key={c.label} cell={c} />
        ))}
      </div>

      {summary.by_severity.length > 0 && (
        <div
          className="form-panel"
          style={{
            maxWidth: 900,
            marginTop: 16,
            fontSize: "calc(var(--font-base) - 1px)",
          }}
        >
          <strong>Supported by severity</strong>
          <div
            style={{
              marginTop: 8,
              display: "flex",
              flexWrap: "wrap",
              gap: "6px 14px",
              fontFamily: "monospace",
              fontSize: "calc(var(--font-base) - 2px)",
            }}
          >
            {summary.by_severity.map(([sev, n]) => (
              <span key={sev}>
                <span style={{ color: "var(--muted)" }}>{sevLabel(sev)} </span>
                {n.toLocaleString()}
              </span>
            ))}
          </div>
        </div>
      )}

      {summary.by_bucket.length > 0 && (
        <div
          className="form-panel"
          style={{
            maxWidth: 900,
            marginTop: 12,
            fontSize: "calc(var(--font-base) - 1px)",
          }}
        >
          <strong>Skipped breakdown</strong>
          <div className="sub" style={{ marginTop: 4 }}>
            Why a template doesn't run in v1.
          </div>
          <div
            style={{
              marginTop: 8,
              display: "flex",
              flexWrap: "wrap",
              gap: "6px 14px",
              fontFamily: "monospace",
              fontSize: "calc(var(--font-base) - 2px)",
            }}
          >
            {summary.by_bucket.map(([bucket, n]) => (
              <span key={bucket} title={BUCKET_HINTS[bucket] ?? ""}>
                <span style={{ color: "var(--muted)" }}>{bucket} </span>
                {n.toLocaleString()}
              </span>
            ))}
          </div>
        </div>
      )}

      {summary.by_tag_top.length > 0 && (
        <div
          className="form-panel"
          style={{
            maxWidth: 900,
            marginTop: 12,
            fontSize: "calc(var(--font-base) - 1px)",
          }}
        >
          <strong>Top tags (supported)</strong>
          <div
            style={{
              marginTop: 8,
              display: "flex",
              flexWrap: "wrap",
              gap: "4px 10px",
              fontFamily: "monospace",
              fontSize: "calc(var(--font-base) - 2px)",
            }}
          >
            {summary.by_tag_top.slice(0, 20).map(([tag, n]) => (
              <span key={tag}>
                <span style={{ color: "var(--muted)" }}>{tag} </span>
                {n.toLocaleString()}
              </span>
            ))}
          </div>
        </div>
      )}

      <Provenance title="Where the data comes from">
        <ul style={{ margin: "6px 0 0 18px", padding: 0, lineHeight: 1.6 }}>
          <li>
            <strong>nuclei-templates</strong> (ProjectDiscovery, MIT). The
            bundled subset is filtered to severity <em>critical</em> /{" "}
            <em>high</em> / <em>medium</em> plus the <code>kev</code> tag.
            Pinned to release tag shown above; full copyright notice ships
            in <code>THIRD_PARTY_LICENSES.md</code>.
          </li>
          <li>
            <strong>Per-template authors</strong> are preserved in each YAML
            <code>info.author</code> field and emitted with every finding's{" "}
            <code>refs</code> string.
          </li>
          <li>
            <strong>Overlap skiplist</strong> —{" "}
            <code>program/databases/nuclei/overlap.toml</code> suppresses
            templates whose detection is already covered by a native corvex
            plugin (spring4shell, shellshock, ms10_070, …) to avoid
            double-reporting.
          </li>
          <li>
            <strong>Load roots</strong> (priority order):
            <ul>
              {summary.roots.length === 0 && (
                <li>
                  <em>
                    No roots found — bundled templates are missing. Run{" "}
                    <code>scripts/refresh-nuclei-bundle.sh</code>.
                  </em>
                </li>
              )}
              {summary.roots.map((r) => (
                <li key={r}>
                  <code>{r}</code>
                </li>
              ))}
            </ul>
          </li>
          <li>
            <strong>Tier-2 extras cache</strong>{" "}
            {summary.extras_cached && summary.extras_cache_path ? (
              <>
                present at <code>{summary.extras_cache_path}</code>. The full
                upstream HTTP template tree is layered on top of the bundled
                set at scan time.
              </>
            ) : (
              <>
                not populated. Click <em>Expand coverage</em> below to fetch
                the full upstream HTTP template tree into your user data
                directory; it layers on top of the bundled set at scan time.
              </>
            )}
          </li>
        </ul>

        <div
          style={{
            marginTop: 12,
            display: "flex",
            gap: 8,
            flexWrap: "wrap",
            alignItems: "center",
          }}
        >
          <button
            type="button"
            className="ghost-btn"
            onClick={onExpandCoverage}
            disabled={extrasBusy !== null}
            style={{ padding: "6px 12px" }}
            title="Downloads the full upstream nuclei-templates HTTP tree into your user data dir. Adds medium/low/info coverage on top of the bundled set."
          >
            {extrasBusy === "download"
              ? "Downloading…"
              : summary.extras_cached
              ? "Re-download full library"
              : "Expand coverage (download full library)"}
          </button>
          {summary.extras_cached && (
            <button
              type="button"
              className="ghost-btn"
              onClick={onRemoveExtras}
              disabled={extrasBusy !== null}
              style={{ padding: "6px 12px" }}
              title="Delete the Tier-2 cache. Bundled templates are untouched."
            >
              {extrasBusy === "remove" ? "Removing…" : "Remove Tier-2 cache"}
            </button>
          )}
        </div>
        {extrasMsg && (
          <div className="sub" style={{ marginTop: 6 }}>
            {extrasMsg}
          </div>
        )}
        {extrasErr && (
          <div className="field-error" style={{ marginTop: 6 }}>
            {extrasErr}
          </div>
        )}
      </Provenance>

      <ViewLink
        onNavigate={onNavigate}
        view="fuzzing"
        label="Nuclei engine module card, severity/tag filters → Fuzzing view"
      />
    </>
  );
}

/* ====================================================================== */
/* Tab 6 — Fingerprints (Wappalyzer)                                       */
/* ====================================================================== */

function FingerprintsTab({ onNavigate }: { onNavigate?: (v: View) => void }) {
  const [summary, setSummary] = useState<WappalyzerSummary | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    wappalyzerSummary()
      .then((s) => {
        setSummary(s);
        setErr(null);
      })
      .catch((e: unknown) => {
        setErr(
          typeof e === "string" ? e : e instanceof Error ? e.message : "unknown"
        );
      });
  }, []);

  if (err) {
    return <div className="empty">Failed to load fingerprint summary: {err}</div>;
  }
  if (!summary) return <div className="empty">Loading…</div>;

  const total = summary.loaded_count + summary.seed_count;

  const cells: Cell[] = [
    {
      label: "Active fingerprints",
      value: total,
      hint: "Total technology fingerprints available to the Stack Fingerprint passive check (upstream dataset + compile-time seed).",
    },
    {
      label: "Upstream loaded",
      value: summary.loaded_count,
      hint: "Wappalyzer-schema entries loaded from the vendored dataset on disk.",
    },
    {
      label: "Seed fallback",
      value: summary.seed_count,
      hint: "Compile-time entries built into the binary — covers the most common stacks so detection works even without the upstream drop.",
    },
    {
      label: "Upstream source",
      value: summary.upstream ?? "—",
      hint: "Project the dataset was pulled from.",
    },
  ];

  return (
    <>
      <div
        className="sub"
        style={{ marginBottom: 10, lineHeight: 1.5 }}
      >
        Wappalyzer-compatible technology fingerprints power the{" "}
        <strong>Stack Fingerprint</strong> passive check on the Proxy view —
        detecting the web server, framework, language, CMS, CDN, analytics
        and JS libraries behind every captured response. The engine keeps the
        upstream dataset and a compile-time seed side by side: upstream wins
        on versions, the seed fills gaps so detection still works if the
        vendored data is missing.
      </div>

      <div className="info-grid">
        {cells.map((c) => (
          <InfoCell key={c.label} cell={c} />
        ))}
      </div>

      {summary.top_categories.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div
            style={{
              fontSize: "calc(var(--font-base) - 1px)",
              fontWeight: 600,
              marginBottom: 8,
              color: "var(--muted)",
              textTransform: "uppercase",
              letterSpacing: "0.04em",
            }}
          >
            Top categories ({summary.top_categories.length} shown)
          </div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))",
              gap: 6,
            }}
          >
            {summary.top_categories.map(([name, count]) => (
              <div
                key={name}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "6px 10px",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  background: "var(--panel-alt)",
                  fontSize: "calc(var(--font-base) - 1px)",
                }}
              >
                <span
                  style={{
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    marginRight: 8,
                  }}
                  title={name}
                >
                  {name}
                </span>
                <span
                  style={{
                    fontVariantNumeric: "tabular-nums",
                    color: "var(--muted)",
                  }}
                >
                  {count.toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <ViewLink
        onNavigate={onNavigate}
        view="proxy"
        label="Stack Fingerprint check lives under Proxy → Checks"
      />
    </>
  );
}

/* ====================================================================== */
/* Tab 7 — Exploit-DB                                                      */
/* ====================================================================== */

function ExploitDbTab() {
  const [summary, setSummary] = useState<ExploitDbSummary | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState<string | null>(null);
  const [syncErr, setSyncErr] = useState<string | null>(null);

  const refresh = () => {
    exploitdbSummary()
      .then((s) => {
        setSummary(s);
        setErr(null);
      })
      .catch((e: unknown) => {
        setErr(
          typeof e === "string" ? e : e instanceof Error ? e.message : "unknown"
        );
      });
  };

  useEffect(() => {
    refresh();
  }, []);

  const onResync = async () => {
    if (syncing) return;
    setSyncing(true);
    setSyncMsg(null);
    setSyncErr(null);
    try {
      const s = await exploitdbUpdate();
      setSummary(s);
      // Invalidate the detail-pane cache so already-open Findings and
      // SCA rows see fresh results on next expand.
      clearExploitHitsCache();
      setSyncMsg(
        `Synced ${s.total.toLocaleString()} exploits from upstream${
          s.source_commit ? ` @ ${s.source_commit.slice(0, 10)}` : ""
        }.`
      );
    } catch (e: unknown) {
      setSyncErr(
        typeof e === "string" ? e : e instanceof Error ? e.message : "unknown"
      );
    } finally {
      setSyncing(false);
    }
  };

  if (err) {
    return <div className="empty">Failed to load Exploit-DB summary: {err}</div>;
  }
  if (!summary) return <div className="empty">Loading…</div>;

  const commitShort = summary.source_commit
    ? summary.source_commit.slice(0, 10)
    : "—";
  const refreshedShort = summary.refreshed_at_utc
    ? summary.refreshed_at_utc.replace("T", " ").replace("Z", " UTC")
    : "—";
  const originLabel = summary.origin
    ? summary.origin === "bundled"
      ? "bundled snapshot"
      : "user-synced"
    : "—";

  const cells: Cell[] = [
    {
      label: "Indexed exploits",
      value: summary.total,
      hint: "Unique EDB-IDs loaded from files_exploits.csv.",
    },
    {
      label: "Verified",
      value: summary.verified,
      hint: "Entries Exploit-DB maintainers have independently verified.",
    },
    {
      label: "Snapshot commit",
      value: commitShort,
      hint: "Upstream gitlab.com/exploit-database/exploitdb commit the current index was built from.",
    },
    {
      label: "Refreshed",
      value: refreshedShort,
      hint: "When the current index was written — bundled snapshot date or the moment you last clicked Re-sync.",
    },
    {
      label: "Origin",
      value: originLabel,
      hint: "`bundled` means this is the snapshot shipped with the app; `user-synced` means you re-synced from upstream.",
    },
  ];

  return (
    <>
      <div className="sub" style={{ marginBottom: 10, lineHeight: 1.5 }}>
        A local SQLite snapshot of the Exploit-DB CSV index. CVE-bearing
        findings on the <strong>Findings</strong> and <strong>SCA</strong>
        views expand to show matching public exploits, each with type,
        platform, verification status, and an on-demand "View source"
        action that pulls the exploit body from upstream and caches it
        locally.
      </div>

      <div className="info-grid">
        {cells.map((c) => (
          <InfoCell key={c.label} cell={c} />
        ))}
      </div>

      {summary.by_type.length > 0 && (
        <div
          className="form-panel"
          style={{
            maxWidth: 900,
            marginTop: 16,
            fontSize: "calc(var(--font-base) - 1px)",
          }}
        >
          <strong>Type breakdown</strong>
          <div
            style={{
              marginTop: 8,
              display: "flex",
              flexWrap: "wrap",
              gap: "6px 14px",
              fontFamily: "monospace",
              fontSize: "calc(var(--font-base) - 2px)",
            }}
          >
            {summary.by_type.map(([t, n]) => (
              <span key={t}>
                <span style={{ color: "var(--muted)" }}>{t} </span>
                {n.toLocaleString()}
              </span>
            ))}
          </div>
        </div>
      )}

      {summary.by_platform_top.length > 0 && (
        <div
          className="form-panel"
          style={{
            maxWidth: 900,
            marginTop: 12,
            fontSize: "calc(var(--font-base) - 1px)",
          }}
        >
          <strong>Top platforms</strong>
          <div
            style={{
              marginTop: 8,
              display: "flex",
              flexWrap: "wrap",
              gap: "6px 14px",
              fontFamily: "monospace",
              fontSize: "calc(var(--font-base) - 2px)",
            }}
          >
            {summary.by_platform_top.map(([p, n]) => (
              <span key={p}>
                <span style={{ color: "var(--muted)" }}>{p} </span>
                {n.toLocaleString()}
              </span>
            ))}
          </div>
        </div>
      )}

      <Provenance title="Where the data comes from">
        <ul style={{ margin: "6px 0 0 18px", padding: 0, lineHeight: 1.6 }}>
          <li>
            <strong>Exploit-DB</strong> is maintained by OffSec and
            published under <strong>GPL-2.0</strong> at{" "}
            <code>gitlab.com/exploit-database/exploitdb</code>. Full
            copyright and license notice ships in{" "}
            <code>THIRD_PARTY_LICENSES.md</code>.
          </li>
          <li>
            <strong>What ships with the app:</strong> a pre-built
            SQLite snapshot of the CSV index (~12 MB). No exploit
            source code is bundled.
          </li>
          <li>
            <strong>What's stored locally after use:</strong> clicking
            Re-sync below overwrites the user copy at{" "}
            <code>&lt;app_data_dir&gt;/exploitdb.sqlite</code> with a
            fresh pull from upstream. Individual exploit source files
            are fetched on demand the first time you click{" "}
            <em>View source</em> on a hit and cached under{" "}
            <code>&lt;app_data_dir&gt;/exploitdb/cache/</code>.
          </li>
          <li>
            <strong>Attribution per exploit:</strong> each hit's{" "}
            <code>author</code> field is preserved and shown in the
            detail pane next to its EDB-ID.
          </li>
          <li>
            ⚠ <strong>Authorisation:</strong> running exploits against
            systems you do not own or have written permission to test
            is illegal in most jurisdictions. This tool surfaces
            exploits for triage and research; actioning them is your
            responsibility.
          </li>
        </ul>

        <div
          style={{
            marginTop: 12,
            display: "flex",
            gap: 8,
            flexWrap: "wrap",
            alignItems: "center",
          }}
        >
          <button
            type="button"
            className="ghost-btn"
            onClick={onResync}
            disabled={syncing}
            style={{ padding: "6px 12px" }}
            title="Download the latest files_exploits.csv from upstream and rebuild the local index."
          >
            {syncing ? "Syncing…" : summary.total === 0 ? "Sync from upstream" : "Re-sync"}
          </button>
        </div>
        {syncMsg && (
          <div className="sub" style={{ marginTop: 6 }}>
            {syncMsg}
          </div>
        )}
        {syncErr && (
          <div className="field-error" style={{ marginTop: 6 }}>
            {syncErr}
          </div>
        )}
      </Provenance>
    </>
  );
}

const BUCKET_HINTS: Record<string, string> = {
  unsupported_feature:
    "Template uses a feature outside the v1 scope: raw HTTP requests, self-contained, race, unsafe, pipeline, or payload file references.",
  dsl_fn:
    "Matcher / extractor references a DSL helper function outside the v1 allowlist.",
  interactsh:
    "Template relies on out-of-band interactions (OOB server) — v2 will add that infrastructure.",
  protocol: "Template declares a non-HTTP protocol (network, dns, ssl, code, headless, …).",
  parse_error: "YAML failed to deserialize — schema bug, worth reporting.",
  no_http: "Template has no HTTP requests at all.",
};

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

/* ====================================================================== */
/* Tab 8 — Unified rules catalog (rules.sqlite)                            */
/* ====================================================================== */

function RulesTab() {
  const [summary, setSummary] = useState<RulesSummary | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    rulesSummary()
      .then((s) => {
        setSummary(s);
        setErr(null);
      })
      .catch((e: unknown) => {
        setErr(
          typeof e === "string" ? e : e instanceof Error ? e.message : "unknown"
        );
      });
  }, []);

  if (err) {
    return (
      <div className="empty">Failed to load rules.sqlite summary: {err}</div>
    );
  }
  if (!summary) return <div className="empty">Loading…</div>;

  if (!summary.loaded) {
    return (
      <>
        <div className="sub" style={{ marginBottom: 10, lineHeight: 1.5 }}>
          The unified rules catalog (<code>rules.sqlite</code>) consolidates
          checks from <strong>Nikto</strong>, <strong>OWASP ZAP</strong>, and{" "}
          <strong>Burp Suite BChecks</strong> into one queryable SQLite file
          alongside the binary. Findings from this catalog are emitted by
          <code> RulesPlugin</code> at scan time.
        </div>
        <div className="empty" style={{ padding: 16 }}>
          No <code>rules.sqlite</code> was found in the working directory or
          executable directory. Build it from the repo with:
          <pre
            style={{
              marginTop: 8,
              padding: 8,
              background: "var(--card)",
              border: "1px solid var(--border)",
              borderRadius: 4,
              fontSize: "calc(var(--font-base) - 1px)",
            }}
          >
            cargo run -p corvex-rules-builder -- --sources rules-sources --output rules.sqlite
          </pre>
          The desktop falls back to the legacy bincode <code>db_tests</code>{" "}
          path silently when this file is absent.
        </div>
      </>
    );
  }

  const totalLowered = summary.total_executable;
  const totalIngested = summary.total_ingested;
  const lowerPct =
    totalIngested > 0
      ? ((totalLowered / totalIngested) * 100).toFixed(1)
      : "0.0";

  const cells: Cell[] = [
    {
      label: "Total rules ingested",
      value: totalIngested,
      hint: "Rules parsed from rules-sources/{nikto,zap,burp}/ and persisted into rules.sqlite.",
    },
    {
      label: "Total executable",
      value: `${totalLowered} (${lowerPct}%)`,
      hint: "Rules with non-NULL match_spec_json — these can fire via RulesPlugin at scan time.",
    },
    {
      label: "Schema version",
      value: summary.schema_version ?? "—",
      hint: "rules.sqlite schema. v2 added the match_spec_json column for runtime execution.",
    },
    {
      label: "Built (UTC)",
      value: summary.build_ts
        ? summary.build_ts.replace("T", " ").replace(/\..*Z$/, " UTC")
        : "—",
      hint: "When corvex-rules-builder produced this catalog.",
    },
    {
      label: "Invalid JSON rows",
      value: summary.invalid_json_rows,
      hint: "Rows whose JSON columns failed json_valid(). Healthy catalogs report 0.",
    },
    {
      label: "Path",
      value: summary.path
        ? summary.path.length > 48
          ? "…" + summary.path.slice(-46)
          : summary.path
        : "—",
      hint: "Absolute path the catalog was loaded from.",
    },
  ];

  return (
    <>
      <div className="sub" style={{ marginBottom: 10, lineHeight: 1.5 }}>
        The unified rules catalog (<code>rules.sqlite</code>) consolidates
        checks from <strong>Nikto</strong>, <strong>OWASP ZAP</strong>, and{" "}
        <strong>Burp Suite BChecks</strong>. <code>RulesPlugin</code> reads
        the executable subset at scan time. By default the desktop runs in
        side-by-side mode (legacy <code>TestsPlugin</code> owns Nikto;{" "}
        <code>RulesPlugin</code> owns ZAP+Burp); the CLI flag{" "}
        <code>--rules-only</code> flips ownership for parity validation.
      </div>

      <div className="info-grid">
        {cells.map((c) => (
          <InfoCell key={c.label} cell={c} />
        ))}
      </div>

      <h3
        style={{
          marginTop: 16,
          marginBottom: 8,
          fontSize: "var(--font-base)",
        }}
      >
        Per-source coverage
      </h3>
      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          fontSize: "calc(var(--font-base) - 1px)",
        }}
      >
        <thead>
          <tr style={{ borderBottom: "1px solid var(--border)" }}>
            <th style={{ textAlign: "left", padding: "6px 8px", color: "var(--muted)" }}>
              Source
            </th>
            <th style={{ textAlign: "right", padding: "6px 8px", color: "var(--muted)" }}>
              Ingested
            </th>
            <th style={{ textAlign: "right", padding: "6px 8px", color: "var(--muted)" }}>
              Executable
            </th>
            <th style={{ textAlign: "right", padding: "6px 8px", color: "var(--muted)" }}>
              Coverage
            </th>
            <th style={{ textAlign: "left", padding: "6px 8px", color: "var(--muted)" }}>
              Upstream commit
            </th>
          </tr>
        </thead>
        <tbody>
          {summary.by_source.map((src) => {
            const commit =
              src.source_tool === "nikto"
                ? summary.nikto_commit
                : src.source_tool === "zap"
                ? summary.zap_commit
                : src.source_tool === "burp"
                ? summary.burp_commit
                : null;
            const pct =
              src.ingested > 0
                ? ((src.lowered / src.ingested) * 100).toFixed(1)
                : "0.0";
            return (
              <tr
                key={src.source_tool}
                style={{ borderBottom: "1px solid var(--border)" }}
              >
                <td style={{ padding: "6px 8px", textTransform: "capitalize" }}>
                  {src.source_tool}
                </td>
                <td style={{ padding: "6px 8px", textAlign: "right" }}>
                  {src.ingested.toLocaleString()}
                </td>
                <td style={{ padding: "6px 8px", textAlign: "right" }}>
                  {src.lowered.toLocaleString()}
                </td>
                <td
                  style={{
                    padding: "6px 8px",
                    textAlign: "right",
                    color: "var(--muted)",
                  }}
                >
                  {pct}%
                </td>
                <td
                  style={{
                    padding: "6px 8px",
                    color: "var(--muted)",
                    fontFamily: "monospace",
                  }}
                >
                  {commit ? commit.slice(0, 10) : "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <h3
        style={{
          marginTop: 16,
          marginBottom: 8,
          fontSize: "var(--font-base)",
        }}
      >
        Severity distribution
      </h3>
      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          fontSize: "calc(var(--font-base) - 1px)",
        }}
      >
        <thead>
          <tr style={{ borderBottom: "1px solid var(--border)" }}>
            <th style={{ textAlign: "left", padding: "6px 8px", color: "var(--muted)" }}>
              Source
            </th>
            <th style={{ textAlign: "left", padding: "6px 8px", color: "var(--muted)" }}>
              Severity
            </th>
            <th style={{ textAlign: "right", padding: "6px 8px", color: "var(--muted)" }}>
              Count
            </th>
          </tr>
        </thead>
        <tbody>
          {summary.by_severity.map((row, i) => (
            <tr
              key={`${row.source_tool}-${row.severity}-${i}`}
              style={{ borderBottom: "1px solid var(--border)" }}
            >
              <td style={{ padding: "6px 8px", textTransform: "capitalize" }}>
                {row.source_tool}
              </td>
              <td style={{ padding: "6px 8px", textTransform: "capitalize" }}>
                {row.severity}
              </td>
              <td style={{ padding: "6px 8px", textAlign: "right" }}>
                {row.count.toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
