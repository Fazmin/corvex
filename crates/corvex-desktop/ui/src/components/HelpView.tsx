import { useEffect, useRef, useState } from "react";

interface Section {
  id: string;
  title: string;
}

const SECTIONS: Section[] = [
  { id: "getting-started", title: "Getting started" },
  { id: "views", title: "Views" },
  { id: "service-probing", title: "Service probing" },
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
              see the stats strip, the scan form on the left, and an empty
              findings table on the right. The log panel and resize handle
              stay hidden until a scan actually starts.
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
              <strong>Watch progress at a glance.</strong> An animated{" "}
              <em>Scanning</em> indicator appears at the top of the dashboard
              with a Stop button inline. A small pulsing dot also appears next
              to the Dashboard entry in the sidebar, so you know a run is in
              flight even if you've navigated away to another view.
            </li>
            <li>
              <strong>Watch the results stream in.</strong> Findings appear in
              the table as they're discovered. The stats strip updates every
              ~750 ms. The log panel now opens below the findings table so you
              can read engine traffic; toggle <em>Follow</em> off to scroll back.
            </li>
            <li>
              <strong>When the scan finishes,</strong> a toast pops in the
              bottom-right. The findings table is exportable (CSV / JSON
              buttons) and the run is saved to History.
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
              <strong>Severity strip:</strong> sits between the Findings table
              and the Log panel. Five small colour-coded chips (CRITICAL / HIGH
              / MEDIUM / LOW / INFO) showing counts. On the Dashboard the chips
              are clickable — pick one to filter the table to that severity,
              click the active chip or <em>All</em> to clear. No more duplicate
              "All Sev" row above the table.
            </li>
            <li>
              <strong>Findings table:</strong> one row per finding. Click a row
              to expand details (CVE, CVSS, EPSS, component, references, fix
              version). A purple <em>SCA</em> pill marks software-composition
              findings; teal <em>Web</em> marks everything else. Drag the thin
              bar below the table to resize it up or down; the size persists.
            </li>
            <li>
              <strong>Log panel:</strong> raw engine messages at TRACE / DEBUG /
              INFO / WARN / ERROR levels. Capped at the last 500 lines. Only
              visible once a scan has started in the current session.
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
            The main scan cockpit for web-vulnerability scans. The scan form
            supports roughly 30 fields covering HTTP basics (host, ports, SSL,
            redirects, timeout, concurrency), tuning, plugin selection,
            evasion flags, port scanning, DNS subdomain brute-force, active
            fuzzing with crawl controls, and a SQL-injection sub-section that
            reveals when active fuzzing is on.
          </p>
          <p>
            Layout (top to bottom): optional <em>Scanning…</em> indicator while
            a run is in flight, four stat cards, the scan form on the left, a
            scrollable findings table on the right with a draggable resize
            handle below it, the minimal severity strip (which doubles as the
            severity filter), and the log panel — the log only appears once a
            scan actually starts, and the resize handle hides with it so an
            idle dashboard fits the viewport cleanly.
          </p>
          <p className="callout">
            For port discovery and TLS-stack fingerprinting on arbitrary IPs,
            hostnames, CIDR blocks, or IP ranges, use the dedicated{" "}
            <strong>Probing</strong> view in the sidebar — that's where Rapid /
            Deep scan modes and JARM live.
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

          <h4>Probing</h4>
          <p>
            Dedicated view for port discovery, TLS-stack fingerprinting, and
            service identification. Seven tabs:
          </p>
          <ul>
            <li>
              <strong>Run</strong> — paste one or more targets, pick a scan
              mode, and press Start. Results stream in: a live hosts table, an
              open-ports table with product / version / CPE columns, and an
              error list for any entries that failed to resolve. Navigate away
              during a run — the results keep filling up in the background and
              a pulse dot on the sidebar Probing entry signals work is still
              underway.
            </li>
            <li>
              <strong>Configure</strong> — scan-mode default, default port
              range, JARM toggle, and the list of additional probe files.
              Values here become the starting point for new runs on this tab
              and the Dashboard's port-scan fields.
            </li>
            <li>
              <strong>Scan modes</strong> — detailed breakdown of Rapid vs Deep
              (connect timeout, concurrency, per-host cap, probe fleet, output
              shape).
            </li>
            <li>
              <strong>Probe families</strong> — what scripted probes, static
              TOML probes, Recog fingerprint matching, and JARM each do, with
              examples. Lists show the actual probes registered in this build.
            </li>
            <li>
              <strong>Datasets</strong> — compact "loaded now" counts. Full
              provenance lives on the Databases view's Probing tab.
            </li>
            <li>
              <strong>JARM</strong> — what JARM actually identifies, how the
              62-character hash is built, the cost per TLS port, and a look-up
              tool where you can paste a hash from anywhere and see the same
              decomposition popover used inline on scan results.
            </li>
            <li>
              <strong>Directive format</strong> — syntax reference for Layer-3
              drop-in probe files (<code>Probe</code>, <code>match</code>,{" "}
              <code>softmatch</code>, <code>ports</code>, <code>sslports</code>,
              fallback chains, delimiter styles, template backrefs).
            </li>
          </ul>
          <p className="callout">
            See the dedicated <a href="#service-probing" onClick={(e) => { e.preventDefault(); jumpTo("service-probing"); }}>Service probing</a> section
            below for end-to-end walk-throughs and examples.
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
            The single "what's bundled?" view. Four tabs:
          </p>
          <ul>
            <li>
              <strong>Web signatures</strong> — the 14 embedded Corvex web
              databases (tests, outdated matchers, favicon hashes, server
              banners, realms, variables, dictionary, 404 signatures, …) with
              live row counts.
            </li>
            <li>
              <strong>Probing</strong> — scripted-probe count, declarative
              probes from <code>probes.toml</code>, Recog fingerprint sets and
              total fingerprint count, plus any Layer-3 extras currently merged
              in. Provenance card names Recog (BSD-2-Clause, shipped under
              {" "}<code>THIRD_PARTY_LICENSES.md</code>), in-house probe
              authorship, the known-JARM table, and the layer-3 trust model.
            </li>
            <li>
              <strong>SCA / VulnDB</strong> — CVE count, CPE matches, EPSS
              scores, fix records, and the last-refresh timestamps for NVD and
              EPSS. The <em>Update</em> action itself lives on the SCA view
              under its VulnDB tab; Databases shows the numbers.
            </li>
            <li>
              <strong>Fuzzing</strong> — summary of the fuzz catalog (modules,
              SQLi techniques, tamper payloads, DBMS backends, enumeration
              targets). The per-technique explainers stay in the Fuzzing view
              where they're useful next to the Run form; Databases only shows
              the totals.
            </li>
          </ul>
          <p>
            Each non-Web tab ends with a jump button that takes you to the
            related feature view if you want operational controls.
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
              <strong>VulnDB:</strong> the <em>Update</em> button lives here —
              downloads fresh NVD and EPSS data into the local vulnerability
              database. A compact one-line count strip shows current totals
              (CVEs, CPE matches, EPSS, fixes, last-refresh dates). The fuller
              breakdown and provenance now lives on Databases → SCA / VulnDB.
            </li>
          </ul>

          <h4>Settings</h4>
          <p>
            Theme (system / light / dark), font size (small → xlarge), reset
            to defaults, and a button to re-trigger the welcome tour on next
            app launch. Probing configuration (scan-mode default, JARM toggle,
            additional probe files) lives on the <strong>Probing</strong>{" "}
            view's Configure tab so it sits next to the run controls that
            consume it.
          </p>

          <h4>Help</h4>
          <p>You're reading it.</p>
        </section>

        {/* ------------------------------------------------------------------ */}
        <section id="service-probing">
          <h3>Service probing</h3>
          <p>
            The Probing view covers everything that happens at the TCP and TLS
            layer before HTTP takes over — port discovery, service
            identification, and TLS-stack fingerprinting. It runs independently
            of the web-scan pipeline, so a Probing run doesn't trigger plugins,
            crawlers, or active fuzzing.
          </p>

          <h4>Target forms</h4>
          <p>
            The Targets textarea on the Run tab accepts one entry per line or
            comma-separated within a line. Each entry is parsed independently
            — a malformed entry shows up in the error list without aborting
            the rest.
          </p>
          <dl className="kv">
            <dt>Single IP</dt>
            <dd>
              <code>10.0.0.7</code> or <code>::1</code>. IPv4 and IPv6 literals
              are both accepted.
            </dd>
            <dt>Hostname</dt>
            <dd>
              <code>example.com</code> — resolved via DNS. First A/AAAA record
              wins. The display label in results preserves the original
              hostname.
            </dd>
            <dt>CIDR block (IPv4)</dt>
            <dd>
              <code>192.168.1.0/24</code>. Network and broadcast addresses are
              skipped for prefixes narrower than <code>/31</code>; a{" "}
              <code>/31</code> or <code>/32</code> keeps both endpoints.
              Expansion is capped at 65,536 hosts per entry to prevent an
              accidental <code>/8</code> sweep.
            </dd>
            <dt>Full IP range</dt>
            <dd>
              <code>10.0.0.5-10.0.0.40</code>. Inclusive on both ends; reversed
              ranges are rejected with a clear error.
            </dd>
            <dt>Short last-octet range</dt>
            <dd>
              <code>192.168.1.10-40</code>. Equivalent to{" "}
              <code>192.168.1.10-192.168.1.40</code>, useful for sweeping a
              known band inside a subnet.
            </dd>
            <dt>Comma list</dt>
            <dd>
              <code>10.0.0.1, 10.0.0.2-5, example.com</code>. Each element goes
              through the parser independently and the results concatenate.
            </dd>
          </dl>

          <h4>Scan modes</h4>
          <dl className="kv">
            <dt>Rapid</dt>
            <dd>
              TCP connect sweep only. 300 ms connect timeout, up to 2,000
              simultaneous connects (500 per host), no TLS handshake, no
              probes. Best for "which ports are open?" questions across a
              wide range. Full 1-65535 coverage on a local subnet finishes in
              seconds.
            </dd>
            <dt>Deep</dt>
            <dd>
              2.5 s connect timeout, 256 simultaneous connects (64 per host),
              TLS handshake on every open port, scripted + declarative probe
              chain with a ~4 s budget per port, plus optional JARM. Produces
              service, product, version, vendor, CPE, OS hint, and the
              negotiated TLS version / cipher / ALPN. HTTPS on non-standard
              ports is detected through the real handshake.
            </dd>
          </dl>

          <h4>Probe families</h4>
          <p>Deep mode runs four kinds of probes against each open port:</p>
          <ul>
            <li>
              <strong>Scripted probes</strong> — Rust modules written from
              public protocol specs. This build ships modules for TLS, HTTP,
              SSH, MySQL, PostgreSQL, SMB, RDP, and LDAP. Each opens its own
              connection, runs a multi-step exchange, and emits typed
              evidence.
            </li>
            <li>
              <strong>Declarative probes</strong> — entries in{" "}
              <code>probes.toml</code>: a payload, a port list, and the
              fingerprint sets to match the response against. Simpler than
              scripted probes but enough for banner-style protocols (FTP, SMTP,
              POP3, IMAP, Redis, Memcached, VNC, Elasticsearch, Docker, etcd,
              DNS version.bind, and so on).
            </li>
            <li>
              <strong>Recog fingerprints</strong> — Rapid7's open-source
              BSD-2-Clause regex database bundled under{" "}
              <code>data/recog/*.xml</code>. Each fingerprint is a regex plus
              a list of params that lift capture groups into named output
              fields (<code>service.product</code>, <code>service.version</code>,{" "}
              <code>service.cpe23</code>, <code>os.product</code>, …).
            </li>
            <li>
              <strong>JARM</strong> — 10 crafted TLS Client Hellos per
              TLS-capable port, with each probe varying the offered versions,
              cipher list, cipher order, GREASE, extension order, and ALPN.
              The result is a 62-character string identifying the TLS stack
              (OpenSSL vs BoringSSL vs SChannel vs rustls, plus configured
              cipher preferences).
            </li>
          </ul>

          <h4>Running a probe</h4>
          <ol className="numbered">
            <li>Open the Probing view from the sidebar.</li>
            <li>
              On the <strong>Run</strong> tab, paste your targets, pick a scan
              mode, set a port range (full <code>1-65535</code> is fine in
              Rapid; narrow it in Deep unless you're willing to wait several
              seconds per open port).
            </li>
            <li>
              In Deep mode, decide whether to tick <em>Collect JARM</em> —
              adds up to 10 extra TCP sessions per TLS-capable port with an
              800 ms budget each.
            </li>
            <li>
              Host concurrency defaults to 8. Each target still uses the
              mode's internal concurrency, so 8 × 256 in Deep means up to
              2,048 sockets in flight at peak.
            </li>
            <li>
              Press <strong>Start probing</strong>. The live hosts table, open
              ports table, and completion banner fill in as events arrive.
              Navigate between tabs or sidebar views — the run keeps going in
              the background and the Probing nav entry pulses until it
              finishes.
            </li>
            <li>
              After completion, form values <em>stay</em>. Press{" "}
              <strong>New probe</strong> to clear results and reset form
              defaults from the Configure tab.
            </li>
          </ol>

          <h4>Reading JARM results</h4>
          <p>
            Every JARM hash in the open-ports table renders as a compact
            clickable badge (<code>JARM 009c03…dc2b</code>). Click it for a
            popover that:
          </p>
          <ul>
            <li>Shows the full 62-character hash plus a copy button.</li>
            <li>
              Looks the hash up against the bundled known-fingerprint table
              (<code>crates/corvex-sonar/data/jarm_known.toml</code>). If the
              hash matches, the popover shows the name / notes / confidence
              tier. Otherwise it tells you how to append an entry so the next
              time the same stack appears it auto-annotates.
            </li>
            <li>
              Decomposes the hash into its two canonical halves — the first
              30 chars of per-probe version + cipher data, and the last 32
              chars of an extensions-order SHA-256 digest.
            </li>
            <li>
              Explains what JARM actually identifies so you don't over-read a
              match (it clusters TLS stacks, not necessarily applications).
            </li>
          </ul>
          <p className="callout">
            The bundled JARM look-up table starts as a curated seed. It grows
            by you appending entries you recognise — this build doesn't make
            strong claims about any specific stack out of the box.
          </p>

          <h4>Layer-3 drop-in probe files</h4>
          <p>
            If you want Corvex to run probes from your own files at startup,
            add absolute paths (one per line) on the Configure tab under{" "}
            <em>Additional probe files</em>. The format uses the established
            directive grammar documented under Probing → Directive format:
          </p>
          <pre style={{
            padding: 12,
            background: "var(--panel-alt)",
            borderRadius: 6,
            fontFamily: "var(--mono, monospace)",
            fontSize: "calc(var(--font-base) - 2px)",
            overflowX: "auto",
          }}>{`# myapp.probes
Probe TCP MyHttpGet q|GET / HTTP/1.0\\r\\n\\r\\n|
rarity 1
ports 80,8080
sslports 443,8443
totalwaitms 4000
match myapp m|^HTTP/1\\.[01] \\d+.*\\r\\nServer: MyApp/(\\d+\\.\\d+)|i p/MyApp/ v/$1/ cpe:/a:acme:myapp:$1:*:*:*:*:*:*:*/`}</pre>
          <p>
            Files are parsed once per path-set per process, cached in memory,
            and never redistributed by Corvex. Failed regex compiles are
            dropped with a debug-level log; they don't stop the rest of the
            file from loading. Supported directives: <code>Probe</code>,{" "}
            <code>match</code>, <code>softmatch</code>, <code>ports</code>,{" "}
            <code>sslports</code>, <code>totalwaitms</code>,{" "}
            <code>tcpwrappedms</code>, <code>rarity</code>,{" "}
            <code>fallback</code>, <code>Exclude</code> (parsed and stored;
            probe-level <code>ports</code>/<code>sslports</code> are what the
            engine currently uses — global Exclude isn't enforced).
          </p>
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

          <h4>6. Sweep a subnet for open ports</h4>
          <ol className="numbered">
            <li>
              Switch to <strong>Probing → Run</strong>.
            </li>
            <li>
              Paste the subnet into <em>Targets</em>, e.g.{" "}
              <code>192.168.1.0/24</code>. Multiple subnets / single hosts /
              ranges can share the field — one entry per line.
            </li>
            <li>
              Pick <strong>Rapid</strong> as the scan mode.
            </li>
            <li>
              Set a broad port range — <code>1-65535</code> is reasonable on a
              local network.
            </li>
            <li>
              Leave host concurrency at 8. Press <strong>Start probing</strong>.
            </li>
            <li>
              Watch hosts flip from <em>running</em> to <em>done</em> with open
              counts in the Hosts table. The Open ports table accumulates each
              host's results inline — you don't need to wait for the whole
              sweep to finish to start reading.
            </li>
            <li>
              Any CIDR entry wider than <code>/16</code> caps at 65,536 hosts
              per entry — no accidental /8 sweeps.
            </li>
          </ol>

          <h4>7. Identify services on a known host</h4>
          <ol className="numbered">
            <li>
              Probing → Run. Enter the host as a single IP or hostname.
            </li>
            <li>
              Pick <strong>Deep</strong>.
            </li>
            <li>
              Narrow the port range to whatever came back from an earlier Rapid
              sweep — Deep spends up to 4 s per open port, so the full 65k
              range can take a while.
            </li>
            <li>
              Start. Each open port gets a TLS handshake attempt and every
              matching probe runs; results fill in with{" "}
              <strong>service · product · version · CPE</strong> columns.
              HTTPS on non-standard ports (8888, 9443, …) is detected through
              the real handshake, not just the port number.
            </li>
            <li>
              If a port shows just a raw JARM hash with no other info, click
              the badge — the popover shows decomposition and whether the
              hash matches the bundled known-fingerprint table.
            </li>
          </ol>

          <h4>8. Fingerprint a cluster of TLS endpoints with JARM</h4>
          <ol className="numbered">
            <li>
              Probing → Run. Targets can be a CIDR block, hostname list, or
              comma-separated mix.
            </li>
            <li>
              Scan mode <strong>Deep</strong>, and tick{" "}
              <em>Collect JARM</em>.
            </li>
            <li>
              Set a narrow TLS-focused port range:{" "}
              <code>443,8443,9443,4443,993,465</code> keeps the cost
              manageable (JARM adds up to 10 extra TCP sessions × 800 ms per
              TLS port).
            </li>
            <li>
              After completion, copy hashes you see repeated across hosts —
              these are the cluster markers. Append them to{" "}
              <code>crates/corvex-sonar/data/jarm_known.toml</code> with a
              short label, rebuild, and subsequent scans auto-annotate the
              cluster.
            </li>
          </ol>

          <h4>9. Extend probe coverage with your own file</h4>
          <ol className="numbered">
            <li>
              Write a probe file using the directive syntax under Probing →
              Directive format. The worked example on that tab is a good
              starting point.
            </li>
            <li>
              Save to an absolute path — e.g.{" "}
              <code>C:\Users\you\probes\myapp.txt</code>.
            </li>
            <li>
              Probing → Configure, paste the path into <em>Additional probe
              files</em>, one per line.
            </li>
            <li>
              Back on the Run tab (or on the Dashboard's port-scan fields),
              start a <strong>Deep</strong> scan. The first run of the
              process parses and compiles the file; subsequent scans hit the
              cache.
            </li>
            <li>
              Check Probing → Datasets or Databases → Probing for counts —
              the extra probes / fingerprints are reported separately from the
              bundled set so you can tell what your file contributed.
            </li>
          </ol>

          <h4>10. Share findings with a colleague</h4>
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
              Adds a TCP connect scan before web tests. Discovered HTTP
              services are auto-added as scan targets; other services get
              basic banner checks. The scan uses the same engine that powers
              the Probing view — see that view for Rapid vs Deep tuning, JARM,
              and Layer-3 probe files.
            </dd>
            <dt>Port range</dt>
            <dd>
              Same syntax as <em>Ports</em>. Pre-populated from the default you
              save on Probing → Configure. Only honored when port scanning is
              enabled.
            </dd>
            <dt>Scan mode</dt>
            <dd>
              <code>Rapid</code> (default, just open/closed) or{" "}
              <code>Deep</code> (adds TLS handshake + service fingerprinting
              with product / version / CPE).
            </dd>
            <dt>Collect JARM</dt>
            <dd>
              Only relevant in Deep mode. Adds up to 10 extra TCP sessions per
              TLS-capable port to produce a TLS-stack fingerprint. Off by
              default.
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
              <strong>Findings search:</strong> the box above the findings
              table matches against message, URI, ID, plugin, CVE, component,
              and host. Case-insensitive substring.
            </li>
            <li>
              <strong>Filter chips (Dashboard):</strong> one compact row for
              classification (All / Signature / Active / Fingerprint) and
              source (All Src / Web / SCA) separated by a thin divider.
              Severity is <em>not</em> in the chip row — it's the severity
              strip below the table. Filters stack, so "Web + Active + HIGH"
              shows only active findings from web plugins at HIGH severity.
              Filter state persists across view switches and app restarts.
            </li>
            <li>
              <strong>Severity strip as filter:</strong> the minimal coloured
              row between Findings and Log. Each chip is a toggle — click a
              severity to filter the table, click the active chip (or{" "}
              <em>All</em>) to clear. The Active Fuzzing view's embedded
              findings table still uses its own dedicated severity chip row
              because it has no strip underneath.
            </li>
            <li>
              <strong>Findings panel resize:</strong> once a scan has started
              (log is visible), a thin horizontal bar sits between the
              findings table and the severity strip. Drag it to grow or
              shrink the findings area. Clamped to 160–1200 px. The chosen
              size persists in <code>corvexFindingsHeight</code>; remove that
              key to return to the responsive default.
            </li>
            <li>
              <strong>Scan indicator banner:</strong> while a dashboard scan
              runs, an animated card with a Stop button pins to the top of
              the dashboard. Same style on the Probing view's Run tab, but
              there the chips show live host / port / elapsed metrics because
              there's no stats bar above.
            </li>
            <li>
              <strong>Sidebar pulse dot:</strong> a small accent-coloured dot
              appears next to the Dashboard nav entry while a web scan runs,
              and next to the Probing entry while a probe run is in flight.
              Visible even after you've navigated to another view.
            </li>
            <li>
              <strong>Log "Follow" checkbox:</strong> on by default. The panel
              auto-scrolls to the bottom as new lines arrive. It pauses
              automatically if you scroll up — re-enable by ticking the box
              or scrolling back to the bottom.
            </li>
            <li>
              <strong>Presets:</strong> stored per-install. Export CSV / JSON
              does not include them — to move presets between machines, copy
              the <code>corvexScanPresets</code> key from the webview's
              localStorage.
            </li>
            <li>
              <strong>Toasts:</strong> scan start-fail, done, cancel, and
              error all emit a bottom-right toast that self-dismisses in
              ~4.5 seconds. Click × to dismiss immediately.
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
            <dt>
              <code>corvexFindingsFilter</code>,{" "}
              <code>corvexFindingsSourceFilter</code>,{" "}
              <code>corvexFindingsSevFilter</code>,{" "}
              <code>corvexFindingsQuery</code>
            </dt>
            <dd>
              Persisted filter / search state on the findings table.{" "}
              <code>corvexFindingsSevFilter</code> is shared between the
              Dashboard's severity strip and the Active Fuzzing findings
              table.
            </dd>
            <dt><code>corvexFindingsHeight</code></dt>
            <dd>
              Explicit pixel height of the Findings panel after the user has
              dragged the resize handle. Absent = responsive{" "}
              <code>clamp()</code> default.
            </dd>
            <dt><code>corvexScanPresets</code></dt>
            <dd>Named form snapshots from the Dashboard preset dropdown.</dd>
            <dt><code>corvexActiveFuzzForm</code></dt>
            <dd>Last-used values in the Active Fuzzing → Run form.</dd>
            <dt><code>corvexProbingDefaults</code></dt>
            <dd>
              Scan-mode / ports-range / JARM defaults saved on the Probing
              view's Configure tab. Read by both the Probing Run tab and the
              Dashboard's port-scan fields when they mount.
            </dd>
            <dt><code>corvexExtraProbeFiles</code></dt>
            <dd>
              Absolute paths (JSON array) to additional Layer-3 probe files
              configured on the Probing view. Merged into the running
              fingerprint database on startup.
            </dd>
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
            <dt>Rapid / Deep scan mode</dt>
            <dd>
              Probing view modes. <em>Rapid</em> is a fast TCP connect sweep
              — open/closed only, no probes, no TLS. <em>Deep</em> adds a TLS
              handshake + scripted and declarative probes with Recog
              fingerprint matching + optional JARM, producing product /
              version / CPE details per open port.
            </dd>
            <dt>Recog</dt>
            <dd>
              Open-source fingerprint database (Rapid7, BSD-2-Clause). Each
              fingerprint is a regex plus params that map capture groups to
              named fields (<code>service.product</code>,{" "}
              <code>service.version</code>, <code>service.cpe23</code>, …).
              Corvex bundles a curated subset and applies it to responses
              captured by its probes. The licence notice ships with the binary
              as <code>THIRD_PARTY_LICENSES.md</code>.
            </dd>
            <dt>JARM</dt>
            <dd>
              A 62-character hash that identifies a remote TLS stack by
              sending 10 crafted Client Hellos with varying TLS versions,
              cipher lists, cipher orders, GREASE, extension orders, and
              ALPN sets, then digesting the per-probe negotiated
              (version, cipher) tuples plus a SHA-256 of the extension
              ordering. Useful for clustering hosts behind the same
              load balancer / CDN / malware stack.
            </dd>
            <dt>CIDR / subnet range</dt>
            <dd>
              Compact notation for a range of IP addresses. Probing accepts
              IPv4 CIDRs like <code>192.168.1.0/24</code>, full IP ranges
              like <code>10.0.0.5-10.0.0.40</code>, and short last-octet
              ranges like <code>192.168.1.10-40</code>. Each expansion is
              capped at 65,536 hosts per entry as a safety net.
            </dd>
            <dt>Layer-3 probe file</dt>
            <dd>
              An external, user-supplied file containing additional probes in
              the Corvex directive format. Configured per-install under
              Probing → Configure, loaded at process startup, merged into
              the bundled probe database in memory. Never redistributed by
              Corvex — it reads what you drop in.
            </dd>
            <dt>CPE</dt>
            <dd>
              Common Platform Enumeration — NIST-standard identifier for a
              specific product / version, e.g.{" "}
              <code>cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*</code>.
              Probe fingerprints emit CPE strings so the result cross-links
              directly to the vulnerability database.
            </dd>
          </dl>
        </section>

        {/* ------------------------------------------------------------------ */}
        <section id="limitations">
          <h3>Known limitations</h3>
          <p>Deliberate, up-front honesty — things the app does not do today:</p>
          <ul>
            <li>
              <strong>Most active fuzzing modules ship today.</strong> The
              SQL-injection family is fully wired (error / boolean / time /
              union / stacked, with eight DBMS backends + enumeration). In
              addition, Corvex now runs eight response-based active modules
              during the Active hook: reflected XSS, open redirect, CRLF
              header injection, LFI (path-traversal with system-file marker
              matching), OS command injection (marker-echo + time-based
              sleep), SSTI (six template engines with integer-product
              detection), in-band XXE (XML-accepting endpoints), and
              Spring4Shell (non-destructive CVE-2022-22965 confirmation).
              <br />
              <br />
              Still listed as <em>planned</em> because they need
              infrastructure that isn't in this build yet: stored XSS (no
              cross-page recheck in the crawler), SSRF and Log4Shell (need
              an OAST callback service to confirm out-of-band hits),
              file upload (needs a multipart upload + post-upload probe
              cycle), and subdomain takeover (needs a DNS-side enumerator
              surfacing CNAMEs).
            </li>
            <li>
              <strong>Bundled JARM known-fingerprint table is a seed.</strong>{" "}
              Ships with an illustrative placeholder only — no hashes are
              hard-coded. Every JARM hash you see will report{" "}
              <em>no matching entry</em> until you populate{" "}
              <code>crates/corvex-sonar/data/jarm_known.toml</code> with
              hashes you've captured yourself.
            </li>
            <li>
              <strong>Probing is IPv4-focused for range expansion.</strong>{" "}
              Single IPv6 literals and hostnames resolve fine, but CIDR and
              dash-range expansion only covers IPv4.
            </li>
            <li>
              <strong>Layer-3 Exclude directive is parsed, not enforced.</strong>{" "}
              Global exclude lists in user-supplied probe files are stored but
              not applied; per-probe <code>ports</code> / <code>sslports</code>
              {" "}control which ports get which probe.
            </li>
            <li>
              <strong>No pause / resume.</strong> Cancel is the only way to
              stop a running scan, and it's a full stop — you cannot continue
              from where you were. This applies to both web scans and probe
              runs.
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
              <strong>Probe runs are not in History.</strong> Standalone
              Probing runs stream results live and persist while the app is
              open, but they are not saved to the History view. Use{" "}
              <em>New probe</em> to reset or export open-port results through
              screenshots / clipboard for now.
            </li>
            <li>
              <strong>No multi-target batch view for web scans.</strong> One
              web scan at a time on the Dashboard. Probing supports multiple
              targets in one run; web scanning does not.
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

          <h4>Probing Run tab shows "done" but no open ports</h4>
          <p>
            Same causes as above — closed range or firewall. Re-run with
            Rapid mode and <code>80,443,22</code> against a host you know is
            alive to confirm the runner works end-to-end, then widen. If Rapid
            finds ports but Deep finds none, the per-port probe budget may be
            timing out on a slow network — raise the budget by adjusting
            defaults, or narrow the range so each port gets the full ~4 s
            window.
          </p>

          <h4>CIDR or dash-range expansion produces nothing</h4>
          <p>
            Look at the Target errors panel on the Run tab. Common causes:
            reversed range (<code>10.0.0.5-10.0.0.3</code>), IPv6 CIDR (not
            supported in this build), mistyped prefix. A CIDR broader than{" "}
            <code>/16</code> is capped at 65,536 hosts per entry — split it
            into multiple narrower ranges if you really want to cover more.
          </p>

          <h4>JARM column shows no "known match"</h4>
          <p>
            Expected for almost every host out of the box — the bundled
            known-fingerprint table ships with only a commented-out
            placeholder. Capture hashes from hosts whose stacks you recognise,
            append them to{" "}
            <code>crates/corvex-sonar/data/jarm_known.toml</code>, and rebuild.
            Subsequent scans will auto-annotate.
          </p>

          <h4>Extra probe files aren't showing up in results</h4>
          <ul>
            <li>
              Check the path is absolute (<code>C:\...</code> on Windows,
              <code>/...</code> on macOS / Linux). Relative paths silently fail
              to resolve on Windows because the app's working directory is
              app-data.
            </li>
            <li>
              Check Probing → Datasets or Databases → Probing — the "Extra
              probe files loaded" counter should be non-zero when a scan
              starts with a configured path.
            </li>
            <li>
              Failed regexes in the file are dropped at startup with a
              debug-level log message. Set <code>RUST_LOG=sonar=debug</code>{" "}
              before launching to see the drop count.
            </li>
            <li>
              Files are cached per path-set for the life of the process.
              Editing the file without restarting the app does nothing —
              close and reopen the app after changes.
            </li>
          </ul>

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
