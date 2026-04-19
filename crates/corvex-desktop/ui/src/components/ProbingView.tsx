/**
 * Service Probing — dedicated view for port discovery and service
 * fingerprinting configuration, with detailed reference material for
 * each knob, probe family, and bundled dataset.
 */

import { useEffect, useMemo, useState } from "react";
import { sonarSummary, type SonarSummary } from "../api";
import { useSettings } from "../settings";
import { InfoTip } from "./InfoTip";

type Tab = "configure" | "modes" | "families" | "datasets" | "directive" | "jarm";

const TABS: { key: Tab; label: string }[] = [
  { key: "configure", label: "Configure" },
  { key: "modes", label: "Scan modes" },
  { key: "families", label: "Probe families" },
  { key: "datasets", label: "Datasets" },
  { key: "jarm", label: "JARM" },
  { key: "directive", label: "Directive format" },
];

/**
 * Probing preferences that ScanForm reads on mount to pre-populate its
 * defaults. Mirrors the localStorage store shape in `settings.tsx`.
 */
export interface ProbingDefaults {
  scanMode: "rapid" | "deep";
  portsRange: string;
  jarm: boolean;
}

const DEFAULT_PORTS_RANGE = "1-1000";

export function ProbingView() {
  const { extraProbeFiles, setExtraProbeFiles } = useSettings();
  const [tab, setTab] = useState<Tab>("configure");
  const [summary, setSummary] = useState<SonarSummary | null>(null);
  const [summaryErr, setSummaryErr] = useState<string | null>(null);
  const [draftMode, setDraftMode] = useState<"rapid" | "deep">(() => readDefault().scanMode);
  const [draftPorts, setDraftPorts] = useState<string>(() => readDefault().portsRange);
  const [draftJarm, setDraftJarm] = useState<boolean>(() => readDefault().jarm);

  useEffect(() => {
    sonarSummary(extraProbeFiles)
      .then((s) => {
        setSummary(s);
        setSummaryErr(null);
      })
      .catch((e: unknown) => {
        setSummaryErr(
          typeof e === "string" ? e : e instanceof Error ? e.message : "unknown"
        );
      });
  }, [extraProbeFiles]);

  const saveDefaults = () => {
    writeDefault({
      scanMode: draftMode,
      portsRange: draftPorts.trim() || DEFAULT_PORTS_RANGE,
      jarm: draftJarm,
    });
  };

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
            Service Probing
          </h2>
          <div className="sub" style={{ marginTop: 4, lineHeight: 1.6 }}>
            Port discovery, TLS handshake inspection, and service fingerprinting.
            Rapid mode sweeps large ranges for open/closed; Deep mode sends
            protocol-aware probes and matches responses to a bundled fingerprint
            database to extract product, version, CPE, OS hint, and JARM.
            {summary && (
              <>
                {" "}
                <strong>
                  {summary.scripted_count} scripted probes · {summary.static_count}{" "}
                  declarative probes · {summary.fingerprint_count} fingerprints
                </strong>
                {summary.extra_files_loaded > 0 && (
                  <>
                    {" · "}
                    <span style={{ color: "var(--accent)" }}>
                      +{summary.extra_probes_loaded} probes / +{summary.extra_fps_loaded}{" "}
                      fingerprints from {summary.extra_files_loaded} extra file
                      {summary.extra_files_loaded === 1 ? "" : "s"}
                    </span>
                  </>
                )}
              </>
            )}
          </div>
        </div>
      </div>

      {/* ---- Tab bar ---- */}
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

      {tab === "configure" && (
        <ConfigureTab
          draftMode={draftMode}
          setDraftMode={setDraftMode}
          draftPorts={draftPorts}
          setDraftPorts={setDraftPorts}
          draftJarm={draftJarm}
          setDraftJarm={setDraftJarm}
          extraProbeFiles={extraProbeFiles}
          setExtraProbeFiles={setExtraProbeFiles}
          onSave={saveDefaults}
          summary={summary}
          summaryErr={summaryErr}
        />
      )}
      {tab === "modes" && <ModesTab />}
      {tab === "families" && <FamiliesTab summary={summary} />}
      {tab === "datasets" && <DatasetsTab summary={summary} summaryErr={summaryErr} />}
      {tab === "jarm" && <JarmTab />}
      {tab === "directive" && <DirectiveTab />}
    </div>
  );
}

/* ============================================================ */
/* Default persistence                                           */
/* ============================================================ */

const DEFAULTS_KEY = "corvexProbingDefaults";

export function readDefault(): ProbingDefaults {
  try {
    const raw = localStorage.getItem(DEFAULTS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (
        parsed &&
        (parsed.scanMode === "rapid" || parsed.scanMode === "deep") &&
        typeof parsed.portsRange === "string"
      ) {
        return {
          scanMode: parsed.scanMode,
          portsRange: parsed.portsRange,
          jarm: Boolean(parsed.jarm),
        };
      }
    }
  } catch {
    // ignore
  }
  return { scanMode: "rapid", portsRange: DEFAULT_PORTS_RANGE, jarm: false };
}

function writeDefault(d: ProbingDefaults) {
  try {
    localStorage.setItem(DEFAULTS_KEY, JSON.stringify(d));
  } catch {
    // ignore
  }
}

/* ============================================================ */
/* Configure tab                                                 */
/* ============================================================ */

interface ConfigureProps {
  draftMode: "rapid" | "deep";
  setDraftMode: (m: "rapid" | "deep") => void;
  draftPorts: string;
  setDraftPorts: (p: string) => void;
  draftJarm: boolean;
  setDraftJarm: (j: boolean) => void;
  extraProbeFiles: string[];
  setExtraProbeFiles: (p: string[]) => void;
  onSave: () => void;
  summary: SonarSummary | null;
  summaryErr: string | null;
}

function ConfigureTab({
  draftMode,
  setDraftMode,
  draftPorts,
  setDraftPorts,
  draftJarm,
  setDraftJarm,
  extraProbeFiles,
  setExtraProbeFiles,
  onSave,
  summary,
  summaryErr,
}: ConfigureProps) {
  const [saved, setSaved] = useState(false);
  const handleSave = () => {
    onSave();
    setSaved(true);
    setTimeout(() => setSaved(false), 1800);
  };

  const portsValid = useMemo(
    () => /^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$/.test(draftPorts.replace(/\s+/g, "")),
    [draftPorts]
  );

  return (
    <div className="single-pane">
      <div className="form-panel" style={{ maxWidth: 860 }}>
        <div className="field">
          <label>
            Scan mode
            <InfoTip label="Scan mode help">
              <strong>Rapid</strong> is a fast TCP connect sweep: short timeout,
              high concurrency, no probes, no TLS inspection. Best for discovering
              which ports are open across a large range. Typical use: "1-65535"
              against a host you own.
              <br />
              <br />
              <strong>Deep</strong> adds per-port TLS handshake attempt plus a
              scripted and static probe chain, runs regex fingerprint matching
              against responses, and can collect the JARM TLS-stack fingerprint.
              Produces <code>product</code>, <code>version</code>, <code>cpe23</code>,
              and <code>os</code> hints that flow into the scan report and can
              drive CVE matching via the vulnerability database.
            </InfoTip>
          </label>
          <div role="radiogroup" style={{ display: "flex", gap: 14 }}>
            <label className="radio">
              <input
                type="radio"
                name="draftScanMode"
                checked={draftMode === "rapid"}
                onChange={() => setDraftMode("rapid")}
              />
              Rapid (fast sweep)
            </label>
            <label className="radio">
              <input
                type="radio"
                name="draftScanMode"
                checked={draftMode === "deep"}
                onChange={() => setDraftMode("deep")}
              />
              Deep (service fingerprint)
            </label>
          </div>
          <div className="field-hint">
            Default mode for new scans launched from the Dashboard. Override per
            scan in the scan form.
          </div>
        </div>

        <div className="field">
          <label>
            Default port range
            <InfoTip label="Port range help">
              Comma-separated list of ports and ranges. Examples:
              <br />
              <code>1-1000</code> — top 1000 TCP ports
              <br />
              <code>22,80,443,8080-8090</code> — specific ports plus a range
              <br />
              <code>1-65535</code> — full TCP space (Rapid mode only; Deep mode
              is much slower per port)
              <br />
              <br />
              Rapid mode can comfortably cover the full range in seconds on a
              local network. Deep mode spends up to the probe budget (default
              4s) on each open port, so narrow the range or use it after a
              Rapid sweep.
            </InfoTip>
          </label>
          <input
            type="text"
            value={draftPorts}
            onChange={(e) => setDraftPorts(e.target.value)}
            placeholder={DEFAULT_PORTS_RANGE}
            aria-invalid={!portsValid}
            style={{ fontFamily: "monospace" }}
          />
          {!portsValid && draftPorts.length > 0 && (
            <div className="field-error">
              Use comma-separated ports or ranges (e.g. 80,443,8000-8100)
            </div>
          )}
        </div>

        <div className="field">
          <label className="checkbox">
            <input
              type="checkbox"
              checked={draftJarm}
              onChange={(e) => setDraftJarm(e.target.checked)}
              disabled={draftMode !== "deep"}
            />
            Collect JARM TLS fingerprint
            <InfoTip label="JARM help">
              JARM sends ten crafted TLS Client Hellos per TLS-enabled port and
              hashes the ServerHello responses into a 62-character fingerprint
              that identifies the exact TLS stack (e.g. "Apache + mod_ssl on
              OpenSSL 3.x" vs. "nginx + BoringSSL"). Useful for pivoting and
              malware C2 attribution, at the cost of ten extra TCP sessions per
              TLS port. Only runs when Deep mode is selected.
            </InfoTip>
          </label>
          <div className="field-hint">
            Adds up to 10 TCP sessions × 800 ms per TLS port. Off by default.
          </div>
        </div>

        <div className="field">
          <label>
            Additional probe files
            <InfoTip label="Extra probe files help">
              Absolute paths to user-supplied probe files in the Corvex
              directive format — one path per line. Each file is parsed once
              per process at the first Deep-mode scan that names it, merged
              into the running fingerprint database alongside the bundled
              probes, and cached for subsequent scans.
              <br />
              <br />
              See the <strong>Directive format</strong> tab for syntax, or drop
              in a file authored from the well-known service-probe grammar.
            </InfoTip>
          </label>
          <textarea
            value={extraProbeFiles.join("\n")}
            onChange={(e) => {
              const lines = e.target.value
                .split(/\r?\n/)
                .map((s) => s.trim())
                .filter((s) => s.length > 0);
              setExtraProbeFiles(lines);
            }}
            spellCheck={false}
            rows={4}
            placeholder="C:\\path\\to\\extra-probes.txt"
            style={{ width: "100%", fontFamily: "monospace" }}
          />
          {summary && summary.extra_files_loaded > 0 && (
            <div className="field-hint" style={{ color: "var(--success)" }}>
              ✓ {summary.extra_files_loaded} file
              {summary.extra_files_loaded === 1 ? "" : "s"} loaded —{" "}
              {summary.extra_probes_loaded} probes, {summary.extra_fps_loaded}{" "}
              fingerprints added.
            </div>
          )}
          {summaryErr && (
            <div className="field-error">Failed to query probe database: {summaryErr}</div>
          )}
        </div>

        <div className="field" style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <button type="button" onClick={handleSave} disabled={!portsValid}>
            Save as defaults
          </button>
          {saved && (
            <span style={{ color: "var(--success)", fontSize: "calc(var(--font-base) - 2px)" }}>
              ✓ Saved — new scans start with these values.
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

/* ============================================================ */
/* Modes tab                                                     */
/* ============================================================ */

function ModesTab() {
  return (
    <div className="single-pane" style={{ display: "grid", gap: 16 }}>
      <ModeCard
        title="Rapid"
        tagline="Fast sweep. Open/closed only."
        items={[
          ["Connect timeout", "300 ms / port"],
          ["Concurrency", "2000 simultaneous connects"],
          ["Per-host cap", "500 simultaneous connects"],
          ["TLS handshake", "Disabled"],
          ["Probes", "None — records only port state"],
          ["Budget per port", "Immediate — no read after connect"],
          [
            "Best for",
            "Full-range sweeps (1-65535), checking which services are exposed, pairing with a later Deep run on just the open ports.",
          ],
          [
            "Output",
            "A list of open ports with no service detail. HTTP-like ports (80/8080/443/8443) still trigger the port-based fallback for the web-scan handoff.",
          ],
        ]}
      />
      <ModeCard
        title="Deep"
        tagline="Probe, fingerprint, extract."
        items={[
          ["Connect timeout", "2500 ms / port"],
          ["Concurrency", "256 simultaneous connects"],
          ["Per-host cap", "64 simultaneous connects"],
          ["TLS handshake", "Attempted on every open port"],
          [
            "Probes",
            "Scripted protocol modules + declarative TOML probes + user-supplied layer-3 probes",
          ],
          ["Budget per port", "≈ 4 s probe chain + optional JARM"],
          [
            "Output",
            "service, product, version, vendor, CPE list, OS hint, JARM hash (if enabled), negotiated TLS version/cipher/ALPN.",
          ],
          [
            "Best for",
            "Narrow ranges (e.g. common service ports or the output of a Rapid sweep) where you want real identification: CPE strings feed the vulnerability database for CVE matching, and HTTPS on non-standard ports automatically routes into the web-scan pipeline.",
          ],
        ]}
      />
    </div>
  );
}

function ModeCard({ title, tagline, items }: { title: string; tagline: string; items: [string, string][] }) {
  return (
    <div className="form-panel" style={{ maxWidth: 860 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
        <h3 style={{ margin: 0 }}>{title}</h3>
        <div className="sub">{tagline}</div>
      </div>
      <table className="sub" style={{ width: "100%", marginTop: 8, borderCollapse: "collapse" }}>
        <tbody>
          {items.map(([k, v]) => (
            <tr key={k}>
              <td style={{ padding: "4px 10px 4px 0", whiteSpace: "nowrap", color: "var(--muted)", verticalAlign: "top", width: "30%" }}>{k}</td>
              <td style={{ padding: "4px 0", color: "var(--fg)" }}>{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ============================================================ */
/* Families tab                                                  */
/* ============================================================ */

function FamiliesTab({ summary }: { summary: SonarSummary | null }) {
  return (
    <div className="single-pane" style={{ display: "grid", gap: 16 }}>
      <FamilyCard
        name="Scripted protocol probes"
        summary={
          "One Rust module per protocol. Each opens a fresh connection, runs a " +
          "multi-step protocol exchange, and produces an Evidence record with " +
          "response bytes plus structured fields."
        }
        example={
          "The MySQL probe parses the 4-byte packet header and reads the " +
          "NUL-terminated server-version field; the PostgreSQL probe sends a " +
          "v3 StartupMessage and parses the ErrorResponse payload; the SMB " +
          "probe sends an SMB2 NEGOTIATE packet and asserts `\\xFESMB` in the " +
          "reply; the RDP probe confirms via TPKT/X.224."
        }
        fingerprint="Feeds response bytes into the matching Recog fingerprint set (e.g. ssh.banner, mysql.greeting)."
        items={summary?.scripted_probes ?? []}
        itemLabel="probe"
      />
      <FamilyCard
        name="Declarative static probes"
        summary={
          "Entries in the bundled probes.toml: a payload to send, a list of " +
          "ports to try it on, and the fingerprint sets to match responses against. " +
          "No code — just data — so adding a new protocol banner is a one-file change."
        }
        example={
          "Examples bundled today: HTTP GET, Redis INFO, SMTP EHLO, POP3 CAPA, " +
          "IMAP CAPABILITY, FTP SYST, VNC banner, Elasticsearch /, Docker /version, " +
          "etcd /version, DNS version.bind CHAOS TXT."
        }
        fingerprint="Each probe lists the fingerprints it triggers; responses feed through the Recog matcher."
        items={summary?.static_probes ?? []}
        itemLabel="probe"
      />
      <FamilyCard
        name="Recog fingerprint matcher"
        summary={
          "Rapid7's BSD-2-Clause Recog database. Each fingerprint is a regex " +
          "plus a list of params that lift capture groups (and fixed literals) " +
          "into named output fields: service.product, service.version, service.cpe23, " +
          "os.product, host.hostname, etc."
        }
        example={
          "Banner `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4` → product=OpenSSH, " +
          "version=9.6p1, os.product=Ubuntu-3ubuntu13.4, cpe=cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*."
        }
        fingerprint="Compiled once at process startup with fancy-regex; per-match wrapped in a 50 ms timeout to defuse adversarial patterns."
        items={summary?.fingerprint_sets ?? []}
        itemLabel="set"
      />
      <FamilyCard
        name="JARM TLS fingerprint"
        summary={
          "Sends ten crafted TLS Client Hellos with deliberate version / cipher-order " +
          "/ extension-order permutations, parses each ServerHello's negotiated " +
          "(version, cipher, extension list), and distils the result into a " +
          "62-character string that identifies the TLS stack."
        }
        example={
          "Used for C2 attribution, CDN / WAF detection, and grouping hosts " +
          "behind the same load balancer by their TLS fingerprint."
        }
        fingerprint="Separate from Recog. The hash is attached directly to the ProbeMatch and shown in the findings detail pane."
      />
    </div>
  );
}

function FamilyCard({
  name,
  summary,
  example,
  fingerprint,
  items,
  itemLabel,
}: {
  name: string;
  summary: string;
  example: string;
  fingerprint: string;
  items?: string[];
  itemLabel?: string;
}) {
  return (
    <div className="form-panel" style={{ maxWidth: 860 }}>
      <h3 style={{ margin: 0 }}>{name}</h3>
      <p className="sub" style={{ marginTop: 8, lineHeight: 1.6 }}>
        {summary}
      </p>
      <p className="sub" style={{ marginTop: 8, lineHeight: 1.6 }}>
        <strong>Example.</strong> {example}
      </p>
      <p className="sub" style={{ marginTop: 8, lineHeight: 1.6 }}>
        <strong>How it plugs in.</strong> {fingerprint}
      </p>
      {items && items.length > 0 && (
        <details style={{ marginTop: 10 }}>
          <summary className="sub" style={{ cursor: "pointer" }}>
            {items.length} {itemLabel}
            {items.length === 1 ? "" : "s"}
          </summary>
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: 6,
              marginTop: 8,
              fontFamily: "monospace",
              fontSize: "calc(var(--font-base) - 2px)",
            }}
          >
            {items.map((x) => (
              <span
                key={x}
                style={{
                  padding: "2px 8px",
                  background: "var(--panel-alt)",
                  borderRadius: 4,
                  color: "var(--fg)",
                }}
              >
                {x}
              </span>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

/* ============================================================ */
/* Datasets tab                                                  */
/* ============================================================ */

function DatasetsTab({ summary, summaryErr }: { summary: SonarSummary | null; summaryErr: string | null }) {
  return (
    <div className="single-pane" style={{ display: "grid", gap: 16 }}>
      <div className="form-panel" style={{ maxWidth: 860 }}>
        <h3 style={{ margin: 0 }}>Bundled in the binary</h3>
        <p className="sub" style={{ marginTop: 6, lineHeight: 1.6 }}>
          At build time, <code>crates/corvex-sonar/build.rs</code> parses the
          declarative probes TOML and every XML file under{" "}
          <code>data/recog/</code> into a single bincode blob embedded via{" "}
          <code>include_bytes!</code>. The blob is deserialised on the first
          probe, every regex is compiled once with fancy-regex on a parallel
          iterator, and the result lives in a process-wide OnceCell. Nothing
          touches the filesystem at scan time.
        </p>
        {summaryErr && (
          <div className="field-error">Failed to query probe database: {summaryErr}</div>
        )}
        {summary && (
          <table className="sub" style={{ width: "100%", marginTop: 12, borderCollapse: "collapse" }}>
            <tbody>
              <StatRow k="Scripted probes" v={`${summary.scripted_count}`} />
              <StatRow k="Declarative (TOML) probes" v={`${summary.static_count - summary.extra_probes_loaded}`} />
              <StatRow k="Recog fingerprint sets" v={`${summary.fingerprint_sets.length}`} />
              <StatRow k="Recog fingerprints (total)" v={`${summary.fingerprint_count - summary.extra_fps_loaded}`} />
              <StatRow
                k="Extra layer-3 files loaded"
                v={`${summary.extra_files_loaded} (+${summary.extra_probes_loaded} probes, +${summary.extra_fps_loaded} fingerprints)`}
              />
            </tbody>
          </table>
        )}
      </div>

      <div className="form-panel" style={{ maxWidth: 860 }}>
        <h3 style={{ margin: 0 }}>Recog fingerprint database</h3>
        <p className="sub" style={{ marginTop: 6, lineHeight: 1.6 }}>
          Rapid7's open-source fingerprint corpus — regex → product / version /
          CPE mappings for a wide range of banner protocols. Bundled under{" "}
          <code>crates/corvex-sonar/data/recog/*.xml</code> under the
          BSD-2-Clause licence. The required copyright notice ships with the
          binary as <code>THIRD_PARTY_LICENSES.md</code> at the repo root; the
          Help view links to it.
        </p>
        <p className="sub" style={{ marginTop: 6, lineHeight: 1.6 }}>
          Sets currently wired into probes:{" "}
          <code>http_header.server</code>, <code>ssh.banner</code>,{" "}
          <code>ftp.banner</code>, <code>smtp.banner</code>,{" "}
          <code>pop3.banner</code>, <code>imap.banner</code>,{" "}
          <code>vnc.banner</code>, <code>mysql.greeting</code>,{" "}
          <code>redis.info</code>, <code>memcached.version</code>,{" "}
          <code>postgres.error</code>, <code>mongodb.banner</code>,{" "}
          <code>elasticsearch.response</code>, <code>docker.response</code>,{" "}
          <code>etcd.response</code>, <code>dns.version</code>.
        </p>
      </div>

      <div className="form-panel" style={{ maxWidth: 860 }}>
        <h3 style={{ margin: 0 }}>In-house probe payloads</h3>
        <p className="sub" style={{ marginTop: 6, lineHeight: 1.6 }}>
          <code>crates/corvex-sonar/data/probes.toml</code> — declarative
          payloads and port lists authored from public protocol specs
          (RFCs, MS-open protocol specs, vendor documentation). Not redistributed
          from any third-party scanner dataset. Each entry names the Recog
          fingerprint sets to match the response against.
        </p>
      </div>

      <div className="form-panel" style={{ maxWidth: 860 }}>
        <h3 style={{ margin: 0 }}>User-supplied probe files</h3>
        <p className="sub" style={{ marginTop: 6, lineHeight: 1.6 }}>
          Optional drop-in probe files in the Corvex directive format (see the{" "}
          <strong>Directive format</strong> tab). Paths configured on the
          Configure tab are parsed at process startup, merged into the running
          fingerprint database, and cached per path-set. Nothing is redistributed
          — Corvex only reads what you drop into the configured paths.
        </p>
      </div>

      <div className="form-panel" style={{ maxWidth: 860 }}>
        <h3 style={{ margin: 0 }}>Performance budget</h3>
        <p className="sub" style={{ marginTop: 6, lineHeight: 1.6 }}>
          Build-time compilation: a few hundred microseconds per regex during
          the build script; nothing happens at scan time. Process-startup
          compilation: all regexes compiled once with fancy-regex on a parallel
          iterator (~ms for the bundled set). Per-match cost is bounded by a
          50 ms spawn_blocking timeout to defuse adversarial inputs. The
          baseline bincode blob is currently on the order of ~12 KB; size will
          grow as the corpus expands.
        </p>
      </div>
    </div>
  );
}

function StatRow({ k, v }: { k: string; v: string }) {
  return (
    <tr>
      <td style={{ padding: "4px 10px 4px 0", color: "var(--muted)", width: "45%" }}>{k}</td>
      <td style={{ padding: "4px 0", color: "var(--fg)", fontFamily: "monospace" }}>{v}</td>
    </tr>
  );
}

/* ============================================================ */
/* JARM tab                                                      */
/* ============================================================ */

function JarmTab() {
  return (
    <div className="single-pane" style={{ display: "grid", gap: 16 }}>
      <div className="form-panel" style={{ maxWidth: 860 }}>
        <h3 style={{ margin: 0 }}>What JARM fingerprints</h3>
        <p className="sub" style={{ marginTop: 6, lineHeight: 1.6 }}>
          JARM identifies the remote TLS <em>stack</em>, not the certificate
          subject or the HTTP layer behind it. Two hosts running OpenSSL 3.0.11
          produce the same JARM hash even when their certs, hostnames, and
          application content differ. Two hosts running different stacks
          (OpenSSL vs BoringSSL vs rustls vs SChannel) produce different
          hashes even when the observable cert is identical.
        </p>
      </div>

      <div className="form-panel" style={{ maxWidth: 860 }}>
        <h3 style={{ margin: 0 }}>How the hash is built</h3>
        <ol className="sub" style={{ marginTop: 6, lineHeight: 1.6, paddingLeft: 20 }}>
          <li>
            Ten TCP connections, one per probe in a fixed permutation table.
            Each probe varies the offered TLS version (1.0 – 1.3), cipher list
            (all / no-forward-secrecy / TLS 1.3-only), cipher order (forward /
            reverse / top / bottom / middle), GREASE values, extension order,
            and ALPN set.
          </li>
          <li>
            Client Hellos are constructed byte-by-byte — not via rustls — so
            Corvex owns the exact wire layout.
          </li>
          <li>
            For each connection we parse the ServerHello's chosen TLS version,
            chosen cipher suite, and the ordered list of extension codes.
          </li>
          <li>
            The 30-character cipher/version prefix concatenates one "cipher
            (4 hex) + version (2 hex)" group per probe.
          </li>
          <li>
            The 32-character suffix is the first 32 hex characters of a SHA-256
            over the pipe-joined per-probe extension digests.
          </li>
        </ol>
      </div>

      <div className="form-panel" style={{ maxWidth: 860 }}>
        <h3 style={{ margin: 0 }}>Cost</h3>
        <p className="sub" style={{ marginTop: 6, lineHeight: 1.6 }}>
          10 extra TCP sessions × 800 ms per TLS-capable port with a successful
          first handshake. Non-TLS ports skip JARM entirely. A worst-case Deep
          scan with JARM enabled against a host with 20 open TLS ports adds
          about 160 seconds of best-effort probing on top of the normal budget.
          Off by default — enable on the Configure tab or per-scan in the scan
          form.
        </p>
      </div>
    </div>
  );
}

/* ============================================================ */
/* Directive format tab                                          */
/* ============================================================ */

function DirectiveTab() {
  return (
    <div className="single-pane" style={{ display: "grid", gap: 16 }}>
      <div className="form-panel" style={{ maxWidth: 860 }}>
        <h3 style={{ margin: 0 }}>Optional layer-3 probe files</h3>
        <p className="sub" style={{ marginTop: 6, lineHeight: 1.6 }}>
          Corvex can merge additional probes from user-supplied files at
          process startup. One path per line on the Configure tab; CLI users
          pass <code>--service-probes &lt;path&gt;</code> (repeatable).
          The files are never redistributed — they sit on your filesystem and
          are read only when the process starts. Each file is parsed once and
          cached per path-set.
        </p>
      </div>

      <div className="form-panel" style={{ maxWidth: 860 }}>
        <h3 style={{ margin: 0 }}>Directive reference</h3>
        <table className="sub" style={{ width: "100%", marginTop: 8, borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid var(--border)" }}>
              <th style={{ textAlign: "left", padding: "6px 10px 6px 0", width: "22%" }}>Directive</th>
              <th style={{ textAlign: "left", padding: "6px 0" }}>Purpose</th>
            </tr>
          </thead>
          <tbody>
            <DirRow d={"Probe TCP <id> q|<payload>|"} p={"Start a new probe. Payload supports \\r \\n \\t \\0 \\xNN \\\\ \\\" and the {host} token (substituted with the target hostname)."} />
            <DirRow d={"rarity <1-9>"} p={"How aggressively the probe participates in the fallback chain — lower means tried earlier."} />
            <DirRow d={"ports <list>"} p={"Comma list of single ports and ranges. `ports 80,8080-8090`."} />
            <DirRow d={"sslports <list>"} p={"Same shape as ports, but the probe is sent inside a TLS tunnel."} />
            <DirRow d={"totalwaitms <n>"} p={"How long to wait for the response (ms) before giving up on this probe."} />
            <DirRow d={"tcpwrappedms <n>"} p={"Marker for tcpwrapped detection (parsed, currently not acted on — reserved)."} />
            <DirRow d={"fallback <id1,id2,...>"} p={"If this probe's own rules do not match, apply these probes' fingerprint sets against the same response."} />
            <DirRow d={"match <service> m|<regex>|<flags> <templates>"} p={"Strong match: if the regex hits, the result wins immediately. Flags: `i` ignore case, `s` dot matches newline. Templates assign extracted fields (see below)."} />
            <DirRow d={"softmatch <service> m|<regex>|<flags> <templates>"} p={"Weak match — remembered as a fallback if nothing stronger wins."} />
            <DirRow d={"Exclude <ports>"} p={"Directive is parsed and stored; v1 honours probe-level ports/sslports directly and does not enforce global Exclude lists."} />
          </tbody>
        </table>
      </div>

      <div className="form-panel" style={{ maxWidth: 860 }}>
        <h3 style={{ margin: 0 }}>Regex delimiters and templates</h3>
        <p className="sub" style={{ marginTop: 6, lineHeight: 1.6 }}>
          The regex after <code>m</code> can use any of <code>|</code>,{" "}
          <code>=</code>, <code>/</code>, <code>%</code> as the delimiter —
          whichever character you pass after <code>m</code> is used as the
          terminator. Templates after the closing delimiter use the same
          letter-then-delimiter form:
        </p>
        <table className="sub" style={{ width: "100%", marginTop: 8, borderCollapse: "collapse" }}>
          <tbody>
            <DirRow d="p/.../ " p="service.product" />
            <DirRow d="v/.../ " p="service.version" />
            <DirRow d="i/.../ " p="service.info" />
            <DirRow d="h/.../ " p="host.hostname" />
            <DirRow d="o/.../ " p="os.product" />
            <DirRow d="d/.../ " p="service.device" />
            <DirRow d="cpe:/.../ " p="service.cpe23 — repeatable, all hits accumulate into the CPE list." />
          </tbody>
        </table>
        <p className="sub" style={{ marginTop: 8, lineHeight: 1.6 }}>
          Template values can be literals or backrefs (<code>$1</code>..
          <code>$9</code>) to capture groups in the matched regex. Pure
          backrefs substitute the captured string at match time; mixed
          literals are stored verbatim.
        </p>
      </div>

      <div className="form-panel" style={{ maxWidth: 860 }}>
        <h3 style={{ margin: 0 }}>Worked example</h3>
        <pre
          style={{
            margin: "8px 0 0",
            padding: 10,
            background: "var(--panel-alt)",
            borderRadius: 6,
            overflowX: "auto",
            fontFamily: "monospace",
            fontSize: "calc(var(--font-base) - 2px)",
            lineHeight: 1.5,
          }}
        >{`# My custom probe
Probe TCP MyHttpGet q|GET / HTTP/1.0\\r\\n\\r\\n|
rarity 1
ports 80,8080
sslports 443,8443
totalwaitms 4000
fallback NULL
match myapp m|^HTTP/1\\.[01] \\d+.*\\r\\nServer: MyApp/(\\d+\\.\\d+)|i p/MyApp/ v/$1/ cpe:/a:acme:myapp:$1:*:*:*:*:*:*:*/`}</pre>
        <p className="sub" style={{ marginTop: 8, lineHeight: 1.6 }}>
          Save that to a file, paste the absolute path into the Configure tab,
          and the next Deep-mode scan will pick it up. The Datasets tab's
          "Extra layer-3 files loaded" line confirms how many probes and
          fingerprints ended up in the merged database.
        </p>
      </div>

      <div className="form-panel" style={{ maxWidth: 860 }}>
        <h3 style={{ margin: 0 }}>Regex engine caveats</h3>
        <p className="sub" style={{ marginTop: 6, lineHeight: 1.6 }}>
          Corvex uses <code>fancy-regex</code> (PCRE superset including
          backrefs and lookbehind). Unlike the stock Rust <code>regex</code>{" "}
          crate, <code>fancy-regex</code> does not guarantee linear time, so
          every match is wrapped in a 50 ms <code>spawn_blocking</code>{" "}
          timeout. Patterns that fail to compile at startup are dropped with a
          trace-level log; they never stop the rest of the database from
          loading.
        </p>
      </div>
    </div>
  );
}

function DirRow({ d, p }: { d: string; p: string }) {
  return (
    <tr>
      <td
        style={{
          padding: "4px 10px 4px 0",
          fontFamily: "monospace",
          color: "var(--accent)",
          verticalAlign: "top",
          whiteSpace: "nowrap",
        }}
      >
        {d}
      </td>
      <td style={{ padding: "4px 0", color: "var(--fg)", verticalAlign: "top" }}>{p}</td>
    </tr>
  );
}
