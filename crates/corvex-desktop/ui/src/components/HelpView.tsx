import { useEffect, useRef, useState } from "react";

interface Section {
  id: string;
  title: string;
}

const SECTIONS: Section[] = [
  { id: "getting-started", title: "Getting started" },
  { id: "views", title: "Views" },
  { id: "scenarios", title: "Scenario recipes" },
  { id: "scan-form", title: "Scan form reference" },
  { id: "interface-tips", title: "Interface tips" },
  { id: "data-storage", title: "Data & storage" },
  { id: "glossary", title: "Glossary" },
  { id: "limitations", title: "Known limitations" },
  { id: "troubleshooting", title: "Troubleshooting" },
];

export function HelpView() {
  const [active, setActive] = useState<string>(SECTIONS[0].id);
  const contentRef = useRef<HTMLDivElement | null>(null);

  // Highlight the TOC entry for whatever section is closest to the top
  // of the viewport. Pure scroll-spy — no router involved.
  useEffect(() => {
    const root = contentRef.current;
    if (!root) return;
    const onScroll = () => {
      const headings = SECTIONS.map((s) => ({
        id: s.id,
        el: root.querySelector(`#${s.id}`) as HTMLElement | null,
      })).filter((h): h is { id: string; el: HTMLElement } => !!h.el);
      const scrollTop = root.scrollTop;
      let current = headings[0]?.id ?? "";
      for (const h of headings) {
        if (h.el.offsetTop - root.offsetTop <= scrollTop + 40) current = h.id;
      }
      setActive(current);
    };
    root.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
    return () => root.removeEventListener("scroll", onScroll);
  }, []);

  const jumpTo = (id: string) => {
    const root = contentRef.current;
    if (!root) return;
    const el = root.querySelector(`#${id}`) as HTMLElement | null;
    if (!el) return;
    root.scrollTo({ top: el.offsetTop - root.offsetTop - 8, behavior: "smooth" });
  };

  return (
    <div className="help-view">
      <aside className="help-toc" aria-label="Documentation contents">
        <div className="help-toc-title">Contents</div>
        <ol>
          {SECTIONS.map((s) => (
            <li key={s.id}>
              <button
                type="button"
                className={`help-toc-link${active === s.id ? " active" : ""}`}
                onClick={() => jumpTo(s.id)}
              >
                {s.title}
              </button>
            </li>
          ))}
        </ol>
      </aside>

      <div className="help-content" ref={contentRef}>
        <header className="help-header">
          <h2>Help & documentation</h2>
          <p className="sub">
            Everything this desktop app can do, grounded in what's actually wired
            up today. If something isn't documented here, assume it hasn't
            shipped yet.
          </p>
        </header>

        {/* ------------------------------------------------------------------ */}
        <section id="getting-started">
          <h3>Getting started</h3>
          <p>
            The fastest path to a working scan — pick a target, press start, read
            the results.
          </p>

          <h4>Your first scan, step by step</h4>
          <ol className="numbered">
            <li>
              <strong>Open the Dashboard.</strong> It's the default view. You'll
              see the Scan form, a stats strip, a severity-mix bar, and an empty
              findings table.
            </li>
            <li>
              <strong>Enter a target.</strong> In the <em>Host / URL</em> field,
              put either a full URL (<code>http://example.com</code>) or a bare
              host (<code>example.com</code>). For HTTPS targets either use the{" "}
              <code>https://</code> scheme or enable the <em>Force SSL</em>{" "}
              checkbox.
            </li>
            <li>
              <strong>Pick tuning and plugins (optional).</strong> Leave tuning
              empty to run everything, or click categories to narrow scope. The
              plugin selector defaults to <code>@@DEFAULT</code>, which runs the
              standard set.
            </li>
            <li>
              <strong>Press Start scan.</strong> The button is disabled if any
              field shows a red validation error — fix those first.
            </li>
            <li>
              <strong>Watch the results stream in.</strong> Findings appear in
              the table below as they're discovered. The stats strip updates
              every ~750 ms. The log panel shows engine messages; toggle{" "}
              <em>Follow</em> off if you want to scroll back.
            </li>
            <li>
              <strong>When the scan finishes,</strong> a toast pops in the
              bottom-right. The findings table is now exportable (CSV / JSON
              buttons above the table) and the run is saved to History.
            </li>
          </ol>

          <h4>What the output means</h4>
          <ul>
            <li>
              <strong>Stats cards:</strong> total requests sent, findings count,
              network errors, and elapsed time. The fifth <em>URLs crawled</em>{" "}
              card only shows when active fuzzing is on.
            </li>
            <li>
              <strong>Severity mix:</strong> a horizontal bar broken down by
              CRITICAL / HIGH / MEDIUM / LOW / INFO proportions, with counts in
              the legend below.
            </li>
            <li>
              <strong>Findings table:</strong> one row per finding. Click a row
              to expand details (CVE, CVSS, EPSS, component, references, fix
              version). A purple <em>SCA</em> pill marks software-composition
              findings; teal <em>Web</em> marks everything else.
            </li>
            <li>
              <strong>Log panel:</strong> raw engine messages at TRACE / DEBUG /
              INFO / WARN / ERROR levels. Capped at the last 500 lines.
            </li>
          </ul>
        </section>

        {/* ------------------------------------------------------------------ */}
        <section id="views">
          <h3>Views</h3>
          <p>
            Each sidebar entry is a full view — findings, stats, and scan state
            are shared across them where it makes sense.
          </p>

          <h4>Dashboard</h4>
          <p>
            The main scan cockpit. The scan form supports roughly 30 fields
            covering HTTP basics (host, ports, SSL, redirects, timeout,
            concurrency), tuning, plugin selection, evasion flags, port
            scanning, DNS subdomain brute-force, active fuzzing with crawl
            controls, and a SQL-injection sub-section that reveals when active
            fuzzing is on.
          </p>

          <h4>Active Fuzzing</h4>
          <p>
            A focused view with six tabs. The default <strong>Run</strong> tab
            is a compact form that launches an active fuzzing scan without
            touching the Dashboard — target URL, scope, crawl depth, max URLs,
            plus the full SQL-injection configuration. Findings appear inline in
            the same view. The other five tabs (<strong>Modules</strong>,{" "}
            <strong>Techniques</strong>, <strong>Tamper</strong>,{" "}
            <strong>DBMS</strong>, <strong>Enumerate</strong>) are reference
            catalogs of what the engine supports.
          </p>
          <p className="callout">
            Modules are labeled <em>ready</em> or <em>planned</em>. Only the
            <em> ready</em> modules actually run. The SQL-injection family is
            fully wired; several other active modules (XSS, LFI, CRLF, open
            redirect, SSRF, etc.) are stubs at the moment.
          </p>

          <h4>History</h4>
          <p>
            Every scan — successful, cancelled, or errored — gets a row here.
            Columns: host, started timestamp, duration, requests, findings,
            status. Per-row actions:
          </p>
          <ul>
            <li>
              <strong>Re-run:</strong> starts a new scan with the exact same
              parameters as the historical run, then switches to the Dashboard.
              Disabled while another scan is in progress.
            </li>
            <li>
              <strong>Delete:</strong> removes that single history entry.
            </li>
            <li>
              Top-right: <strong>Refresh</strong> and <strong>Clear all</strong>.
            </li>
          </ul>
          <p>
            History is persisted to a SQLite file — survives restarts, survives
            crashes.
          </p>

          <h4>Plugins</h4>
          <p>
            Read-only list of every plugin registered with this build: name,
            execution hooks, description, full name, and weight (lower weight
            runs earlier). Use this to understand what <code>@@DEFAULT</code>{" "}
            actually means, or to craft a custom plugin selector string.
          </p>

          <h4>Databases</h4>
          <p>
            Two kinds of data live here. First, the <strong>embedded test
            databases</strong> — CSV files of web-vulnerability signatures,
            outdated-version matchers, favicon hashes, server banners, and so
            on — with row counts for each. Second, the{" "}
            <strong>vulnerability database</strong> (CVE + CPE match + EPSS
            probabilities + fix versions). The <em>Update</em> button downloads
            fresh NVD and EPSS data. See{" "}
            <a href="#troubleshooting" onClick={(e) => { e.preventDefault(); jumpTo("troubleshooting"); }}>
              troubleshooting
            </a>{" "}
            if the update fails.
          </p>

          <h4>SCA — Software Composition Analysis</h4>
          <p>Four tabs:</p>
          <ul>
            <li>
              <strong>Dependency Analysis:</strong> point at a directory that
              contains manifest files (<code>package.json</code>,{" "}
              <code>Cargo.toml</code>, <code>requirements.txt</code>, etc.) or a
              pre-built SBOM. The scan extracts component-version pairs and
              cross-references them against the vulnerability database.
            </li>
            <li>
              <strong>Binary Analysis:</strong> point at a single binary or a
              folder. The engine extracts embedded version strings (and,
              optionally, the contents of archives) and looks them up.
            </li>
            <li>
              <strong>Results:</strong> findings table plus an EPSS-threshold
              filter so you can hide issues below a given exploit probability.
            </li>
            <li>
              <strong>VulnDB:</strong> same update controls as the Databases
              view, surfaced here for convenience.
            </li>
          </ul>

          <h4>Settings</h4>
          <p>
            Theme (system / light / dark), font size (small → xlarge), reset to
            defaults, and a button to re-trigger the welcome tour on next app
            launch.
          </p>

          <h4>Help</h4>
          <p>You're reading it.</p>
        </section>

        {/* ------------------------------------------------------------------ */}
        <section id="scenarios">
          <h3>Scenario recipes</h3>
          <p>
            Concrete, end-to-end walkthroughs for common tasks. Each one assumes
            you're starting from the Dashboard unless stated otherwise.
          </p>

          <h4>1. Quick passive audit of a public URL</h4>
          <ol className="numbered">
            <li>Enter the URL in <em>Host / URL</em>.</li>
            <li>
              Leave tuning empty, leave plugins at <code>@@DEFAULT</code>.
            </li>
            <li>Leave active fuzzing <em>off</em>.</li>
            <li>Press <strong>Start scan</strong>.</li>
            <li>
              When the toast says "Scan complete", click <strong>Export CSV</strong>
              above the findings table to save a copy.
            </li>
          </ol>
          <p>
            This touches only standard HTTP probes — it does not submit forms or
            inject payloads. Safe for targets you have permission to fingerprint.
          </p>

          <h4>2. Hunt SQL injection in a specific application</h4>
          <ol className="numbered">
            <li>
              Switch to <strong>Active Fuzzing → Run</strong>.
            </li>
            <li>Enter the application's root URL.</li>
            <li>
              Pick a <em>Scope</em>: <code>domain</code> for the whole host,{" "}
              <code>folder</code> to confine to a subtree, <code>page</code> to
              test only the URL you entered.
            </li>
            <li>Set crawl depth 3–5 and max URLs ~500 to start.</li>
            <li>
              In the SQL Injection block, start with Level 1 / Risk 1, techniques{" "}
              <code>BEUST</code>, DBMS auto-detect.
            </li>
            <li>
              Leave <em>Enumerate</em> unchecked for the first run — you want to
              confirm the injection exists before pulling data.
            </li>
            <li>Press <strong>Start active fuzzing</strong>.</li>
            <li>
              If a finding comes back, re-run with <em>Enumerate → Databases</em>
              ticked to fingerprint the schema. Only escalate to risk 2/3 on
              systems you own.
            </li>
          </ol>
          <p className="callout">
            Active fuzzing sends real payloads. Only use it against targets you
            own or have written permission to test. The crawler can generate
            thousands of requests on a large site.
          </p>

          <h4>3. Scan a project folder for vulnerable dependencies</h4>
          <ol className="numbered">
            <li>Switch to <strong>SCA → Dependency Analysis</strong>.</li>
            <li>Click <em>Browse…</em> next to <em>Scan directory</em>.</li>
            <li>Pick your project's root folder.</li>
            <li>
              Optionally set an EPSS threshold (e.g. 0.1) to skip issues with
              low exploit probability.
            </li>
            <li>
              Leave <em>Show fixes</em> on so you can see which versions to
              upgrade to.
            </li>
            <li>Press <strong>Start</strong>.</li>
            <li>
              Findings appear in the <em>Results</em> tab. Use the{" "}
              <em>Source → SCA</em> filter chip to hide anything that isn't a
              component match.
            </li>
          </ol>

          <h4>4. Compare results against an earlier scan</h4>
          <p>
            There is no dedicated diff view yet. The practical approach today:
          </p>
          <ol className="numbered">
            <li>Open <strong>History</strong>, find the earlier run.</li>
            <li>Click <strong>Re-run</strong>; the same parameters go back in.</li>
            <li>
              After it finishes, export the new findings as JSON, and compare
              against an earlier JSON export (any diff tool works).
            </li>
          </ol>

          <h4>5. Build a preset for scans you repeat</h4>
          <ol className="numbered">
            <li>Configure the Dashboard form exactly how you want it.</li>
            <li>
              At the top of the form, next to the <em>Preset</em> dropdown,
              click <strong>Save as…</strong> and give it a name (e.g.{" "}
              <em>"QA environment — weekly"</em>).
            </li>
            <li>
              Next time, pick the name from the dropdown and the whole form
              repopulates. Edit anything you like before starting.
            </li>
            <li>
              <strong>Delete</strong> removes the selected preset; there's no
              undo, so pay attention.
            </li>
          </ol>

          <h4>6. Share findings with a colleague</h4>
          <ol className="numbered">
            <li>
              Finish the scan. Apply whatever filters you want the recipient to
              see — source, severity, and search all narrow the export.
            </li>
            <li>
              Click <strong>Export JSON</strong> (for tool-to-tool handoff) or{" "}
              <strong>Export CSV</strong> (for spreadsheets / tickets).
            </li>
            <li>
              The file is written with a timestamped name like{" "}
              <code>corvex-findings-20260417-104233.json</code> to your browser's
              default Downloads folder.
            </li>
          </ol>
        </section>

        {/* ------------------------------------------------------------------ */}
        <section id="scan-form">
          <h3>Scan form reference</h3>
          <p>
            The Dashboard form has a lot of fields. Most have an ⓘ help tip
            inline. This is a quick index.
          </p>

          <h4>Target</h4>
          <dl className="kv">
            <dt>Host / URL</dt>
            <dd>
              Full URL or bare host. Accepts optional port and path. Validated
              client-side — the Start button stays disabled if the shape is
              wrong.
            </dd>
            <dt>Ports</dt>
            <dd>
              Comma-separated list, optionally with ranges:{" "}
              <code>80,443,8000-8100</code>. Leave empty to use the default set.
            </dd>
            <dt>Force SSL</dt>
            <dd>Assume HTTPS even if the host didn't include a scheme.</dd>
            <dt>Follow redirects</dt>
            <dd>
              Off by default — many scan tests care about the raw redirect
              response. Turn on to chase 301/302s.
            </dd>
            <dt>Timeout (s), Concurrency</dt>
            <dd>
              Per-request timeout and the max in-flight HTTP requests per host.
              Defaults 15 s / 8 are a reasonable starting point.
            </dd>
          </dl>

          <h4>Tuning and plugins</h4>
          <dl className="kv">
            <dt>Tuning</dt>
            <dd>
              A chip picker for categories <code>0–9</code> and{" "}
              <code>a–e</code>. Empty runs everything. <code>x</code> inverts —
              instead of "include only these", it means "exclude these".
            </dd>
            <dt>Plugins</dt>
            <dd>
              Select-all UI over the plugin registry. <code>@@DEFAULT</code>{" "}
              resolves to the default-on subset. Uncheck individual plugins to
              exclude them from the default set, or pick a narrow bespoke list.
            </dd>
            <dt>Evasion</dt>
            <dd>
              String of flags <code>1–9</code> plus letter <code>A</code>. Each
              flag applies a URI transform (random encoding, directory
              self-reference, etc.). Combine multiple in one string.
            </dd>
          </dl>

          <h4>Port scanning, DNS enumeration</h4>
          <dl className="kv">
            <dt>Port scanning</dt>
            <dd>
              Adds a TCP connect scan before web tests. Discovered HTTP services
              are auto-added as scan targets; other services get basic banner
              checks.
            </dd>
            <dt>Port range</dt>
            <dd>
              Same syntax as <em>Ports</em>. Only honored when port scanning is
              enabled.
            </dd>
            <dt>DNS subdomain brute-force</dt>
            <dd>
              Runs in addition to automatic DNS record + zone-transfer checks.
              Uses a built-in wordlist.
            </dd>
          </dl>

          <h4>Active fuzzing</h4>
          <dl className="kv">
            <dt>Scope</dt>
            <dd>
              <code>domain</code> (single host), <code>subdomains</code>,{" "}
              <code>folder</code> (only within the URL's path prefix), or{" "}
              <code>page</code> (the exact URL and nothing more).
            </dd>
            <dt>Crawl depth</dt>
            <dd>BFS depth of link following. 3 is a safe default.</dd>
            <dt>Max URLs</dt>
            <dd>Hard cap on the number of pages visited. The scan stops early if this trips.</dd>
            <dt>SQLi Level (1–5), Risk (1–3)</dt>
            <dd>
              Level expands which injection points are tested (params → cookies
              → headers → path). Risk controls how destructive the payloads
              are; only risk 3 uses UPDATE/INSERT/DELETE or file / OS-command
              payloads.
            </dd>
            <dt>Techniques</dt>
            <dd>
              <code>B</code>oolean, <code>E</code>rror, <code>U</code>nion,{" "}
              <code>S</code>tacked, <code>T</code>ime. They run in priority
              order and short-circuit on the first confirmation.
            </dd>
            <dt>DBMS</dt>
            <dd>
              Pick one to skip fingerprinting, or <em>Auto-detect</em>.
            </dd>
            <dt>Tamper modules</dt>
            <dd>
              Comma-separated names of WAF-bypass transforms (e.g.{" "}
              <code>space2comment,randomcase</code>). Chained left-to-right on
              every payload.
            </dd>
            <dt>Enumerate</dt>
            <dd>
              Post-detection data pulls — databases, tables, columns, users,
              password hashes, full-table dump, file-read, OS-command. The last
              two require risk 3.
            </dd>
          </dl>

          <h4>Output</h4>
          <dl className="kv">
            <dt>Format</dt>
            <dd>
              <code>txt</code>, <code>json</code>, <code>csv</code>,{" "}
              <code>htm</code>, <code>xml</code>, <code>sql</code>. Only
              affects the optional file output — the UI always streams findings.
            </dd>
            <dt>Output file</dt>
            <dd>
              Engine-side report path. Separate from the UI export buttons
              (those serialize the filtered view at click time).
            </dd>
          </dl>

          <h4>Misc</h4>
          <dl className="kv">
            <dt>Auth</dt>
            <dd>
              <code>user:pass</code> or <code>user:pass:realm</code>. Scheme is
              auto-detected from the challenge.
            </dd>
            <dt>Custom User-Agent</dt>
            <dd>Overrides the default UA string.</dd>
          </dl>
        </section>

        {/* ------------------------------------------------------------------ */}
        <section id="interface-tips">
          <h3>Interface tips</h3>
          <ul>
            <li>
              <strong>Findings search:</strong> the box above the findings table
              matches against message, URI, ID, plugin, CVE, component, and
              host. Case-insensitive substring.
            </li>
            <li>
              <strong>Filter chips:</strong> three rows — source (All Src / Web
              / SCA), type (signature / active / fingerprint), severity. All
              three stack, so "Web + active + HIGH" shows only active findings
              from web plugins at HIGH severity. Filter state persists across
              view switches and app restarts.
            </li>
            <li>
              <strong>Severity mix bar:</strong> hover any segment for exact
              count and percentage. The strip is proportional, so a lone
              CRITICAL row can look very wide in a small result set.
            </li>
            <li>
              <strong>Log "Follow" checkbox:</strong> on by default. The panel
              auto-scrolls to the bottom as new lines arrive. It pauses
              automatically if you scroll up — re-enable by ticking the box or
              scrolling back to the bottom.
            </li>
            <li>
              <strong>Presets:</strong> stored per-install. Export CSV/JSON does
              not include them — to move presets between machines, copy the
              <code>corvexScanPresets</code> key from the webview's localStorage.
            </li>
            <li>
              <strong>Toasts:</strong> scan start-fail, done, cancel, and error
              all emit a bottom-right toast that self-dismisses in ~4.5 seconds.
              Click × to dismiss immediately.
            </li>
            <li>
              <strong>Titlebar:</strong> custom frame — use the three controls
              at the far right to minimize, maximize, and close. The window is
              draggable from the blank titlebar area.
            </li>
          </ul>
        </section>

        {/* ------------------------------------------------------------------ */}
        <section id="data-storage">
          <h3>Data & storage</h3>
          <p>
            Everything the app persists is local — nothing is sent anywhere
            unless you explicitly trigger an update (NVD/EPSS fetch) or scan a
            remote host.
          </p>
          <h4>Files on disk</h4>
          <dl className="kv">
            <dt>History database</dt>
            <dd>
              SQLite, one row per scan. On Windows it lives at{" "}
              <code>%APPDATA%\dev.fazminnizam.corvex-rust\history.sqlite</code>.
              The app folder is the same one Tauri creates automatically for
              app data.
            </dd>
            <dt>Vulnerability database</dt>
            <dd>
              A separate SQLite file maintained by the Update action in the
              Databases view. Holds CVE records, CPE matches, EPSS probabilities,
              and fix versions. If <em>Available</em> reads <em>No</em> in the
              VulnDB summary, run <strong>Update</strong> once to populate it.
            </dd>
          </dl>
          <h4>In the webview's localStorage</h4>
          <dl className="kv">
            <dt><code>corvexSidebarCollapsed</code></dt>
            <dd>0 / 1 — sidebar rail state.</dd>
            <dt><code>corvexTheme</code>, <code>corvexFontSize</code></dt>
            <dd>Settings-view preferences.</dd>
            <dt><code>corvexFindingsFilter</code>, <code>corvexFindingsSevFilter</code>, <code>corvexFindingsSourceFilter</code>, <code>corvexFindingsQuery</code></dt>
            <dd>Persisted filter / search state on the findings table.</dd>
            <dt><code>corvexScanPresets</code></dt>
            <dd>Named form snapshots from the Dashboard preset dropdown.</dd>
            <dt><code>corvexActiveFuzzForm</code></dt>
            <dd>Last-used values in the Active Fuzzing → Run form.</dd>
            <dt><code>corvexTourSeen</code></dt>
            <dd>Flag preventing the welcome tour from auto-appearing after first launch.</dd>
          </dl>
        </section>

        {/* ------------------------------------------------------------------ */}
        <section id="glossary">
          <h3>Glossary</h3>
          <dl className="kv">
            <dt>Passive scan</dt>
            <dd>
              Probes that read what the server exposes — headers, standard
              paths, banners, signature matches. Does not submit forms or inject
              payloads.
            </dd>
            <dt>Active scan / active fuzzing</dt>
            <dd>
              Crawls to find parameters, then injects crafted payloads into
              them. Invasive — may modify data at higher risk levels.
            </dd>
            <dt>Plugin</dt>
            <dd>
              A unit of scan behavior that registers for one or more hook points
              (recon, scan, prefetch, postfetch, active). The Plugins view lists
              all plugins this build knows about.
            </dd>
            <dt>Tuning categories</dt>
            <dd>
              Each test in the embedded databases is tagged with a category
              (0–9, a–e). Setting <em>Tuning</em> filters which categories run.
            </dd>
            <dt>Evasion flags</dt>
            <dd>
              URI transforms that mangle the request to try to sneak past WAFs /
              IDSes. Combine multiple flags in one string.
            </dd>
            <dt>Tamper module</dt>
            <dd>
              Payload-level obfuscation applied during SQL-injection fuzzing —
              whitespace substitution, case randomization, encoding tricks, and
              so on.
            </dd>
            <dt>CVE</dt>
            <dd>
              Common Vulnerabilities and Exposures — an identifier like{" "}
              <code>CVE-2021-44228</code> for a specific published vulnerability.
            </dd>
            <dt>CVSS</dt>
            <dd>
              Common Vulnerability Scoring System — a 0–10 severity rating
              derived from exploitability and impact metrics.
            </dd>
            <dt>EPSS</dt>
            <dd>
              Exploit Prediction Scoring System — a 0–1 probability that a given
              CVE will be exploited in the wild in the next 30 days. Useful for
              prioritization when CVSS alone produces too much noise.
            </dd>
            <dt>SCA — Software Composition Analysis</dt>
            <dd>
              Looking at an application's third-party components (from
              manifests, SBOMs, or embedded strings) and mapping them to known
              vulnerabilities.
            </dd>
            <dt>SBOM</dt>
            <dd>
              Software Bill of Materials. A structured list of every component
              and version that ships with an application. CycloneDX and SPDX
              are the two main formats.
            </dd>
            <dt>DBMS</dt>
            <dd>
              Database Management System. The SQL-injection engine has
              backend-specific payloads for MySQL, PostgreSQL, MSSQL, Oracle,
              SQLite, MariaDB, DB2, and Firebird.
            </dd>
          </dl>
        </section>

        {/* ------------------------------------------------------------------ */}
        <section id="limitations">
          <h3>Known limitations</h3>
          <p>Deliberate, up-front honesty — things the app does not do today:</p>
          <ul>
            <li>
              <strong>Not every active fuzzing module is ready.</strong> The
              SQL-injection family is fully wired (error / boolean / time /
              union / stacked, with eight DBMS backends and enumeration). XSS,
              LFI, command injection, CRLF, open redirect, XXE, SSTI, SSRF,
              file-upload, subdomain takeover, and canned CVE chains
              (Log4Shell, Spring4Shell) are listed in the Fuzzing view as{" "}
              <em>planned</em> — they do not run yet.
            </li>
            <li>
              <strong>No pause / resume.</strong> Cancel is the only way to
              stop a running scan, and it's a full stop — you cannot continue
              from where you were.
            </li>
            <li>
              <strong>No built-in diff view.</strong> To compare scans, re-run
              from History and diff the exported JSON files yourself.
            </li>
            <li>
              <strong>No triage workflow.</strong> You cannot mark findings as
              false-positive / accepted-risk inside the app. All results come
              back fresh on every scan.
            </li>
            <li>
              <strong>No scheduler.</strong> Scans are manual. Keep the app
              open if you want a scan to complete — closing the window
              interrupts it.
            </li>
            <li>
              <strong>No multi-target batch view.</strong> One scan at a time.
              You can re-run from History, but there is no "scan this list of
              hosts in parallel" UI.
            </li>
            <li>
              <strong>Keyboard shortcuts are minimal.</strong> The onboarding
              tour supports Arrow Left / Arrow Right and Escape. No
              app-wide shortcuts yet.
            </li>
            <li>
              <strong>Form-based login, OAST callbacks, and client
              certificates</strong> are not wired through the UI. The engine
              knows about them but the form has no field to set them from here.
            </li>
            <li>
              <strong>No executive / PDF report.</strong> Text, JSON, CSV, XML,
              HTML and SQL output are available via the Dashboard's{" "}
              <em>Output file</em>; there is no bundled rich-PDF export.
            </li>
          </ul>
        </section>

        {/* ------------------------------------------------------------------ */}
        <section id="troubleshooting">
          <h3>Troubleshooting</h3>

          <h4>Databases view says the vulnerability database is unavailable</h4>
          <p>
            Click <strong>Update</strong> in the Databases view (or the
            <em> VulnDB</em> tab of SCA). The first update downloads the full
            NVD catalog and can take a while. If it fails, set an{" "}
            <code>NVD_API_KEY</code> environment variable before launching the
            app — NIST throttles unauthenticated callers heavily.
          </p>

          <h4>NVD update fails with "rate limited" or similar</h4>
          <p>
            Same fix — set <code>NVD_API_KEY</code> and restart the app. You can
            get a free key from{" "}
            <code>nvd.nist.gov/developers/request-an-api-key</code> (the app
            does not call this URL on your behalf — sign up manually).
          </p>

          <h4>Port scan finishes with zero results</h4>
          <p>
            Most likely the target's firewall is dropping traffic, or the range
            you set is entirely closed. Try a short confirmed-open range like{" "}
            <code>80,443,22</code> to verify the scanner works, then widen.
            Increasing timeout can also help on very-high-latency hosts.
          </p>

          <h4>Scan starts but findings stay at zero</h4>
          <ul>
            <li>Check the log panel for connection errors.</li>
            <li>
              Confirm you didn't invert tuning — a leading <code>x</code> in the
              Tuning field means <em>exclude these</em>, so <code>x1</code>{" "}
              actually turns off category 1 and runs everything else.
            </li>
            <li>
              Some targets legitimately have no hits against the standard plugin
              set. Try enabling active fuzzing, or loosen plugins to a specific
              focused subset.
            </li>
          </ul>

          <h4>Form won't let me press Start</h4>
          <p>
            There's a validation error somewhere. Scroll through the form — any
            field with a red message underneath is the culprit. Common causes:
            missing host, malformed port range, or an out-of-range evasion flag.
          </p>

          <h4>Re-run is disabled on History rows</h4>
          <p>
            Either a scan is already running (cancel it first), or the row's
            status is <em>Running</em> — the app treats an in-progress history
            entry as unsafe to duplicate.
          </p>

          <h4>Log panel stopped scrolling</h4>
          <p>
            The <em>Follow</em> checkbox above the log got unticked (or you
            scrolled up, which pauses follow-mode automatically). Re-tick it, or
            scroll back to the bottom and follow-mode re-engages.
          </p>

          <h4>Presets dropdown is empty after reinstalling</h4>
          <p>
            Presets are stored in the webview's local storage, not in the
            app-data folder. Reinstalling the app — or wiping the webview data —
            clears them. If you rely on a preset, export its details by hand
            until an import / export feature exists.
          </p>

          <h4>The welcome tour never re-appears after I reset it</h4>
          <p>
            Settings → <em>Restart welcome tour</em> clears the "seen" flag,
            but the tour only checks on app start. Close and reopen the app.
          </p>
        </section>
      </div>
    </div>
  );
}
