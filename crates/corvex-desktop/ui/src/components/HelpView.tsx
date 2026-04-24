import { useEffect, useMemo, useRef, useState } from "react";
import {
  nucleiTemplateList,
  type NucleiTemplateEntry,
} from "../api";

interface Section {
  id: string;
  title: string;
}

const SECTIONS: Section[] = [
  { id: "getting-started", title: "Getting started" },
  { id: "views", title: "Views" },
  { id: "proxy", title: "Proxy, Intercept, Replay & Checks" },
  { id: "service-probing", title: "Service probing" },
  { id: "recon", title: "Recon" },
  { id: "scenarios", title: "Scenario recipes" },
  { id: "scan-form", title: "Scan form reference" },
  { id: "interface-tips", title: "Interface tips" },
  { id: "data-storage", title: "Data & storage" },
  { id: "nuclei-catalog", title: "Bundled Nuclei templates" },
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
            The single "what's bundled?" view. Five tabs:
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
            <li>
              <strong>Nuclei templates</strong> — supported vs skipped counts,
              pinned upstream tag + commit, per-severity breakdown for
              supported templates, skipped-bucket breakdown (with a tooltip
              for each reason — unsupported feature, DSL helper, interactsh,
              non-HTTP protocol, parse error), top tags across the supported
              set, and whether the Tier-2 extras cache is populated. The
              provenance card names ProjectDiscovery (MIT), explains the
              filter policy (severity critical/high plus the <code>kev</code>
              tag), and lists the on-disk load roots actually being used.
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

          <h4>Proxy</h4>
          <p>
            An interactive HTTP(S) proxy with a live Traffic log, request
            Intercept queue, request Replay editor, and OWASP-categorised
            Checks. Unlike the Dashboard (which sends its own requests) the
            Proxy view sits between your browser and real targets — point your
            browser at <code>127.0.0.1:8888</code>, install the local
            certificate authority once, and every page you load lands in the
            Traffic tab in real time. See the dedicated{" "}
            <button
              type="button"
              className="help-inline-link"
              onClick={() => {
                const el = document.getElementById("proxy");
                el?.scrollIntoView({ behavior: "smooth", block: "start" });
              }}
            >
              Proxy, Intercept, Replay &amp; Checks
            </button>{" "}
            section below for the full walkthrough.
          </p>

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
        <section id="proxy">
          <h3>Proxy, Intercept, Replay &amp; Checks</h3>
          <p>
            The Proxy is an intercepting HTTP/HTTPS proxy built into the app.
            It captures every request your browser makes, stores them locally,
            and layers four interactive tools on top:{" "}
            <strong>Traffic</strong> (live log), <strong>Intercept</strong>{" "}
            (pause &amp; edit before forwarding), <strong>Replay</strong>{" "}
            (resend any captured request with edits), and{" "}
            <strong>Checks</strong> (run OWASP Top 10 analyzers against your
            traffic). A fifth tab, <strong>Settings</strong>, holds the
            first-time setup guide.
          </p>

          <h4>How it fits together</h4>
          <p>
            A single mental model covers the whole feature:
          </p>
          <ol className="numbered">
            <li>
              Your browser is configured to send all traffic to{" "}
              <code>127.0.0.1:8888</code>.
            </li>
            <li>
              corvex terminates the TLS connection using its local certificate
              authority (CA), decrypts the request, logs it to the{" "}
              <strong>Traffic</strong> tab, and forwards it to the real
              server.
            </li>
            <li>
              If <strong>Intercept</strong> mode is on, the request pauses
              here and waits for you to forward / edit / drop it before it
              goes out.
            </li>
            <li>
              The server's response comes back; corvex logs it, runs the
              enabled passive <strong>Checks</strong> against it, then hands
              the response to the browser. From the browser's perspective
              nothing unusual happened.
            </li>
            <li>
              You can right-click any captured request → <strong>Send to
              Replay</strong> to resend it (edited or not), or{" "}
              <strong>Send to Checks</strong> to queue it for active probes.
            </li>
          </ol>

          <h4>One-time setup (do this before first use)</h4>
          <p>
            Nothing works until the browser trusts the local CA. The Proxy
            tab's <strong>Settings</strong> sub-tab has the guided flow, but
            here's the short version:
          </p>
          <ol className="numbered">
            <li>
              Open <strong>Proxy → Settings → Certificate authority</strong>.
              Click <em>Show CA certificate</em> and save the PEM block to a
              file called <code>corvex-ca.crt</code>.
            </li>
            <li>
              Install it into your OS trust store:
              <ul>
                <li>
                  <strong>Windows:</strong>{" "}
                  <code>certutil -addstore -user Root corvex-ca.crt</code>
                </li>
                <li>
                  <strong>macOS:</strong>{" "}
                  <code>
                    security add-trusted-cert -d -r trustRoot -k
                    ~/Library/Keychains/login.keychain corvex-ca.crt
                  </code>{" "}
                  — then open Keychain Access and flip the entry to{" "}
                  <em>Always Trust</em>.
                </li>
                <li>
                  <strong>Linux (Debian/Ubuntu):</strong>{" "}
                  <code>sudo cp corvex-ca.crt /usr/local/share/ca-certificates/</code>{" "}
                  then{" "}
                  <code>sudo update-ca-certificates</code>.
                </li>
              </ul>
            </li>
            <li>
              Point your browser at the proxy. Firefox has its own trust
              store and its own proxy settings — see <em>Proxy → Settings →
              Browser setup</em> for per-browser walkthroughs covering
              Firefox, Chrome / Edge / Brave, Safari, <code>curl</code>,{" "}
              <code>wget</code>, and PowerShell.
            </li>
          </ol>
          <p className="callout">
            The CA is generated once on first app launch and stored under
            your app-data directory. Re-installing corvex does not invalidate
            it — you only go through the OS trust step once per machine per
            browser.
          </p>

          <h4>Starting the proxy</h4>
          <p>
            In the Proxy toolbar, the listen address defaults to{" "}
            <code>127.0.0.1:8888</code> (loopback-only for safety). Click{" "}
            <strong>Start</strong>. The status pill flips to{" "}
            <em>Running</em>. Clicking the button again stops the listener;
            pending intercepts are auto-released and any open connections
            drain cleanly.
          </p>
          <p>
            To capture traffic from a phone or another machine on your LAN,
            change the listen address to your LAN IP (e.g.{" "}
            <code>192.168.1.10:8888</code>), install the CA on the target
            device, and set the device's Wi-Fi proxy to the same host:port.
            Only do this on trusted networks — the proxy does not
            authenticate clients.
          </p>

          <h4>Traffic tab — inspecting captured requests</h4>
          <p>
            Every in- and out-of-scope request lands here as a row. Columns:
            row number, HTTP method, response status, URL, response size,
            duration. Click any row to expand an inline detail panel showing
            origin, host:port, MIME type, and scope classification.
          </p>
          <p>
            Two actions live in the expanded panel:
          </p>
          <ul>
            <li>
              <strong>Send to Replay</strong> — switches to the Replay tab
              with this request pre-loaded into the editor.
            </li>
            <li>
              <strong>Send to Checks</strong> — queues this request as a
              target for the Checks tab's active-probe runner.
            </li>
            <li>
              <strong>Send to Fuzzer</strong> — jumps to the{" "}
              <em>Active Fuzzing</em> view with the captured URL
              pre-filled in the Target field and scope forced to{" "}
              <code>page</code>, so the fuzzer hits exactly that
              endpoint instead of crawling the whole origin. Your other
              form settings (SQLi level, techniques, tamper modules,
              enumerate targets) are preserved from the last run — only
              the target and scope change.
            </li>
          </ul>
          <p>
            <strong>Spec import.</strong> The{" "}
            <strong>Import spec</strong> button in the proxy toolbar
            reads an OpenAPI 3 (<code>.json</code>) or Postman v2.1
            collection (<code>.json</code>) and drops one synthetic
            Traffic row per documented endpoint — method, URL
            (composed from <code>servers[0].url</code> for OpenAPI or
            <code>item.request.url.raw</code> for Postman), example
            headers, example request body where the spec provides
            one. Imported rows carry origin <code>imported</code> so
            you can tell them apart from real browser traffic. From
            there, the usual Traffic-row flow works: expand a row,
            Send to Replay to edit and fire it, Send to Checks to
            queue active probes, or Send to Fuzzer to hammer it. The
            rows have no response until you fire one via Replay — the
            import is a seed, not a simulator.
          </p>
          <p>
            <strong>HAR export.</strong> An <strong>Export HAR</strong>{" "}
            button in the proxy toolbar writes the current session's
            traffic log to an HTTP Archive 1.2 file (
            <code>.har</code>, JSON). Every row becomes one HAR entry
            with method, URL, headers, query string, POST body,
            status, response headers, and response body. Bodies that
            aren't valid UTF-8 are stored with{" "}
            <code>encoding: "base64"</code> per the HAR v1.2 spec, so
            binary downloads survive the round-trip. The exporter
            streams directly to disk — a 5,000-row session exports
            without buffering the whole document in memory. The
            resulting file can be loaded into browser DevTools
            (Network tab → "Import HAR…"), Fiddler, Charles, or
            Wireshark for comparison or long-term archival.
          </p>
          <p>
            <strong>Retention.</strong> Each session keeps a ring
            buffer of its most recent exchanges — default{" "}
            <code>5,000</code> rows per session. When the listener is
            running and a session crosses the cap, the writer evicts
            the oldest rows (and their cascaded scan findings /
            WebSocket frames / spilled body blobs) on the next flush
            (~250 ms cadence). Sessions that have already ended are
            never touched by retention — whatever size they were at
            Stop is what they stay. Tune or disable the cap under{" "}
            <em>Settings → Retention</em>; a value of <code>0</code> is
            the explicit "unlimited" sentinel. Useful when you need the
            full history for a long audit run; revert to a cap before
            the next day of browsing so <code>history.sqlite</code>{" "}
            doesn't grow past what your app-data directory can spare.
          </p>
          <p>
            <strong>Body size &amp; storage.</strong> Captured bodies
            under <code>512 KB</code> live inline in{" "}
            <code>history.sqlite</code>; anything larger spills to a
            sibling blob directory (<code>proxy_blobs/&lt;session&gt;/&lt;
            exchange&gt;.&#123;req,res&#125;</code>) so the DB stays
            small. The detail-pane read path is transparent — spilled
            bodies load from disk when you expand a row. Exchanges
            where either side exceeded the <code>32 MB</code> hard cap
            get a <code>trunc</code> badge next to the method; the
            first 32 MB were stored, the rest was forwarded to the peer
            but not recorded. For UI responsiveness the detail pane
            caps the body it renders at <code>1 MB</code> per side — the
            on-disk blob still holds the full (up to 32 MB) copy, it's
            just that Replay loads only the preview.
          </p>
          <p>
            <strong>WebSocket rows</strong> carry a blue{" "}
            <code>ws</code> badge next to the method. Expanding one
            shows the captured handshake fields plus a{" "}
            <em>WebSocket frames</em> panel underneath the Send-to-X
            actions. The panel has two halves: a list of every frame
            that crossed the wire (direction arrow, opcode, sequence
            number, text or hex preview, payload size), and a detail
            pane that shows the full UTF-8 decode or a hex+ASCII dump
            when you click one. Frames stream in live — new ones
            appear as the connection continues. If the upstream
            negotiated <code>permessage-deflate</code> or any other
            extension, an "extension active" warning appears; payloads
            are captured as-is and text previews may look like
            gibberish because they're compressed.
          </p>
          <p>
            <strong>Example.</strong> You browse{" "}
            <code>https://juice-shop.example/api/Users/6</code>. A row
            appears: <code>GET</code> · <code>200</code> ·{" "}
            <code>/api/Users/6</code> · 312 B · 84 ms. Expand it, click{" "}
            <strong>Send to Replay</strong>, change the trailing{" "}
            <code>6</code> to <code>7</code>, click Send — you see the
            response for a different user's profile as a new row in the
            Traffic log linked back to the original.
          </p>

          <h4>Intercept tab — pause, edit, forward</h4>
          <p>
            Intercept is off by default (pass-through). Turn it on from the
            mode row:
          </p>
          <ul>
            <li>
              <strong>Off</strong> — nothing pauses.
            </li>
            <li>
              <strong>Request</strong> — pauses before the request goes
              upstream. Most common mode when testing.
            </li>
            <li>
              <strong>Response</strong> — pauses after the upstream server
              replies, before the response reaches the browser. You edit
              the status line, headers, or body on the wire — useful for
              simulating error states, flipping feature-flag JSON, or
              stripping security headers to test how the client copes.
            </li>
            <li>
              <strong>Both</strong> — pauses at both sides. Each exchange
              hits the Pending queue twice: once with the{" "}
              <code>→ req</code> badge on the way out, once with the{" "}
              <code>← resp</code> badge on the way back.
            </li>
          </ul>
          <p>
            Only <em>in-scope</em> requests pause — browser background
            traffic (analytics, telemetry) is logged but never interrupts
            you. Scope rules are authored in Settings; the default is
            "capture everything, intercept none" until you add rules.
          </p>
          <p>
            When an exchange pauses, a row appears in the <em>Pending</em>{" "}
            queue on the left. The phase badge tells you which side is
            frozen: an amber <code>→ req</code> means the request is held
            before going upstream; a blue <code>← resp</code> means the
            upstream reply is held before reaching the client. Click the
            row and the right pane fills with the raw HTTP/1 bytes ready
            for editing. Three buttons wait at the bottom (their labels
            re-phrase based on phase — e.g.{" "}
            <strong>Forward request</strong> vs{" "}
            <strong>Forward response</strong>):
          </p>
          <ul>
            <li>
              <strong>Forward</strong> — send the bytes as-is. (The button
              re-labels to <strong>Forward edited…</strong> the moment you
              touch the editor.)
            </li>
            <li>
              <strong>Drop</strong> — refuse the exchange. On the request
              phase the browser receives a <code>502 Bad Gateway</code>;
              on the response phase the browser also receives a{" "}
              <code>502</code> — the upstream's real reply is discarded.
            </li>
            <li>
              <strong>Drop all</strong> (above the queue) — release every
              pending intercept with Forward. Useful when switching mode
              back to Off.
            </li>
          </ul>
          <p>
            <strong>Example 1 — edit a request.</strong> A login form
            submits <code>POST /auth/login</code> with a JSON body:
          </p>
          <pre className="help-cmd">
{`POST /auth/login HTTP/1.1
Host: target.example
Content-Type: application/json
Content-Length: 43

{"email":"alice@x.com","password":"hunter2"}`}
          </pre>
          <p>
            Change <code>hunter2</code> to <code>' OR 1=1 --</code> in the
            editor, click <strong>Forward edited request</strong>. The
            backend re-parses your bytes and sends them upstream. If the
            parse fails (e.g. you accidentally deleted the blank line
            between headers and body), the exchange is released with the
            original bytes and a warning is logged instead of silently
            corrupting the wire request.
          </p>
          <p>
            <strong>Example 2 — edit a response.</strong> Set mode to{" "}
            <strong>Response</strong>, load{" "}
            <code>https://httpbin.org/get</code> in your browser. The
            upstream reply pauses with a <code>← resp</code> badge:
          </p>
          <pre className="help-cmd">
{`HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 17

{"ok":true}`}
          </pre>
          <p>
            Rewrite the status line to{" "}
            <code>HTTP/1.1 403 Forbidden</code>, swap the body for{" "}
            <code>{`{"error":"denied"}`}</code>, update{" "}
            <code>Content-Length</code> to match (17 bytes → 18), click{" "}
            <strong>Forward edited response</strong>. The browser sees a
            403 as if the server sent it — the real server never knows.
            Handy for probing how a client handles error paths you can't
            trigger naturally (quota exceeded, auth expired, upstream
            outage). Same mechanics work for injecting debug headers,
            stripping <code>Content-Security-Policy</code> to test CSP
            fallbacks, or flipping a feature-flag JSON boolean before the
            SPA renders.
          </p>
          <p className="callout">
            Safety net: if you walk away, every pending intercept
            auto-forwards after 5 minutes so upstream sockets don't leak.
            <code>Connection: close</code> is forced on every forwarded
            request — don't worry about keep-alive semantics. Edited
            bytes that fail to parse as valid HTTP fall back to the
            original (warning logged), so a typo won't silently corrupt
            the stream.
          </p>

          <h4>Settings · Scope rules — what gets paused and checked</h4>
          <p>
            Scope decides which exchanges active features touch. The
            Traffic log always captures everything; scope gates
            intercept, replay, and active Checks so incidental background
            traffic (analytics beacons, favicon fetches, tabs from other
            apps) never interrupts you. Rules live under{" "}
            <em>Proxy → Settings → Scope rules</em> and persist across
            restarts in <code>history.sqlite</code>.
          </p>
          <p>
            Two lists, evaluated in order:
          </p>
          <ul>
            <li>
              <strong>Exclude</strong> — matches always win. Any request
              matching an exclude rule is marked out-of-scope, even if an
              include rule would otherwise cover it.
            </li>
            <li>
              <strong>Include</strong> — if empty, every non-excluded
              request is in-scope (the default "log all" behaviour).
              Otherwise, only requests matching at least one include rule
              count.
            </li>
          </ul>
          <p>
            Each rule has three fields:
          </p>
          <ul>
            <li>
              <strong>Host</strong> — exact match (
              <code>api.example.com</code>) or leading wildcard (
              <code>*.example.com</code> matches the apex and any
              sub-domain). Blank matches any host.
            </li>
            <li>
              <strong>Path regex</strong> — Rust regex evaluated against
              the request path (without query string). Blank matches any
              path. A malformed regex fails closed — the rule never
              matches rather than silently widening scope.
            </li>
            <li>
              <strong>Port</strong> — single port filter. Blank matches
              any port.
            </li>
          </ul>
          <p>
            <strong>Example — narrow scope for a bug-bounty target.</strong>{" "}
            You're testing <code>app.acme.test</code> and don't want your
            other open tabs spamming the Intercept queue. Add one include
            rule:
          </p>
          <pre className="help-cmd">
{`Host:       *.acme.test
Path regex: (blank)
Port:       (blank)`}
          </pre>
          <p>
            Save. The instant a new request comes in, only the Acme hosts
            pause. A few minutes later you notice the site's analytics
            beacon (<code>metrics.acme.test/collect</code>) keeps pausing
            and getting in the way — add an exclude rule:
          </p>
          <pre className="help-cmd">
{`Host:       metrics.acme.test
Path regex: ^/collect
Port:       (blank)`}
          </pre>
          <p>
            Save again. Metrics beacons now pass through without pausing;
            the rest of <code>*.acme.test</code> still funnels into
            Intercept. In the Traffic log, each row's <em>Scope</em> field
            reads <code>in</code>, <code>out</code>, or{" "}
            <code>excluded</code> so you can see what scope decided at
            the time — updates only apply to new requests, so anything
            already sitting in the Pending queue keeps its original
            classification.
          </p>
          <p className="callout">
            Save is explicit: your in-progress edits don't apply until you
            click <strong>Save scope rules</strong>. Path regexes are
            validated at Save time, so a bad pattern surfaces as an error
            instead of fail-closing every future match.
          </p>

          <h4>Replay tab — resend with edits</h4>
          <p>
            Replay takes a captured request as a base and lets you send
            variants of it on demand, without the browser or the intercept
            queue in the loop. Each replay runs through the same low-level
            HTTP client the scanner uses, so you control the wire exactly.
          </p>
          <p>
            Workflow:
          </p>
          <ol className="numbered">
            <li>
              On the Traffic tab, expand any row → <strong>Send to
              Replay</strong>. The Replay tab loads the full raw request
              (request line + headers + blank line + body) into the left
              pane.
            </li>
            <li>
              Edit anything. Change the method, tweak a header, add a query
              parameter, modify the body. Keep the blank line between
              headers and body intact.
            </li>
            <li>
              Click <strong>Send</strong> (or <strong>Send (edited)</strong>{" "}
              when the editor is dirty). The right pane shows status,
              duration, response headers, and body.
            </li>
            <li>
              Every replay is captured as its own row in the Traffic log
              with origin <em>replay</em>, linked back to the parent. You
              can replay a replay, stack edits, and compare length /
              status deltas.
            </li>
          </ol>
          <p>
            <strong>Example — IDOR probe.</strong> Base request:{" "}
            <code>GET /api/orders/1042</code> returning a 2.4 KB JSON body.
            In Replay, change <code>1042</code> to <code>1043</code>, send.
            If the response is another 2.4 KB body (different order ID),
            the endpoint may be missing an access-control check. If it's a
            403, access control is enforced.
          </p>

          <h4>Checks tab — OWASP analyzers</h4>
          <p>
            The Checks tab runs analyzers against traffic and shows their
            findings. Two kinds:
          </p>
          <ul>
            <li>
              <strong>Passive</strong> — run automatically on every in-scope
              captured response. No extra network traffic; they inspect
              what's already there.
            </li>
            <li>
              <strong>Active</strong> — send probe requests on demand
              against targets you queue. Run them only against systems you
              own or have permission to test.
            </li>
          </ul>
          <p>
            The <strong>Library</strong> pane on the left lists every
            available check grouped by OWASP Top 10 category (A01..A10).
            Each row is a checkbox with a severity badge, kind (passive /
            active), name, and description. A sticky search bar at the top
            filters across name, stable id, category, kind, and description
            — type <code>sqli</code>, <code>xss</code>, or <code>A03</code>{" "}
            to narrow a library of thousands down to just the relevant
            rows. Tick <em>Enabled only</em> to see just what you've
            selected.
          </p>
          <p>
            Bundled coded checks ship out of the box:
          </p>
          <ul>
            <li>
              <strong>Missing Security Headers (A05, passive)</strong> — one
              finding per missing CSP / HSTS (on HTTPS) /
              X-Content-Type-Options / X-Frame-Options (satisfied by{" "}
              <code>CSP: frame-ancestors</code>) / Referrer-Policy /
              Permissions-Policy.
            </li>
            <li>
              <strong>Verbose Errors / Stack Traces (A05, passive)</strong>{" "}
              — regex bank covering Java, PHP, .NET, Node.js, Python,
              Laravel Whoops, Django DEBUG, Flask Werkzeug, Ruby.
            </li>
            <li>
              <strong>Version Disclosure (A06, passive)</strong> — extracts
              product + version from Server / X-Powered-By / X-AspNet-Version
              headers and HTML <code>&lt;meta name=generator&gt;</code>.
            </li>
            <li>
              <strong>Insecure Cookie Flags (A02, passive)</strong> — one
              finding per Set-Cookie missing Secure (on HTTPS), HttpOnly, or
              SameSite.
            </li>
            <li>
              <strong>Stack Fingerprint (A06, passive)</strong> — identifies
              the web framework, server, and language behind every response
              using a Wappalyzer-compatible matcher. Emits one Info finding
              listing every detected product with its version where the
              regex captured one.
            </li>
            <li>
              <strong>Banner CVE Cross-Reference (A03, passive)</strong> —
              for every Stack Fingerprint detection that captured a
              version (e.g. <code>nginx 1.18.0</code>,{" "}
              <code>WordPress 6.2.1</code>, <code>Apache Tomcat 9.0.45</code>),
              queries the local vulndb for matching CVEs and emits one
              finding per CVE with severity derived from the CVSS v3.1
              base score (Critical ≥ 9.0, High ≥ 7.0, Medium ≥ 4.0, Low
              &gt; 0). Evidence carries the CPE vendor/product, CVSS
              score + vector, EPSS score if known, and the NVD
              description. Needs the vulndb populated — open{" "}
              <em>Databases → Vulnerabilities</em> and click{" "}
              <strong>Refresh now</strong> if the check is quiet on
              obvious banners. Bare banners without a version (e.g.{" "}
              <code>Server: nginx</code>) are deliberately skipped — NVD
              range matching needs a concrete version.
            </li>
            <li>
              <strong>Reflected XSS (A03, active)</strong> — injects a
              unique canary into each query parameter across several
              context-breakers (attribute break, script break, svg
              onload). Reports a parameter only when the payload survives
              unencoded in the response.
            </li>
            <li>
              <strong>Error-based SQL Injection (A03, active)</strong> —
              sends boundary-breaking payloads (<code>'</code>,{" "}
              <code>"</code>, <code>')</code>, <code>' OR '1'='1</code>)
              per parameter and matches responses against the existing
              corvex SQLi error-signature bank.
            </li>
            <li>
              <strong>Boolean-blind SQL Injection (A05, active)</strong>{" "}
              — sends paired probes that differ by a single truth value
              (<code>AND 1=1</code> vs <code>AND 1=2</code>) across four
              SQL boundaries (numeric, single-quote, double-quote,
              paren-quote). Uses the same trigram page-similarity math
              as sqlmap: a TRUE probe that matches the baseline page
              while a FALSE probe diverges — and the two probes differ
              from each other — is a confirmed injection. Works against
              apps that suppress database errors entirely. Preserves
              the original parameter value so the app's own parser
              still accepts the input shape.
            </li>
            <li>
              <strong>Time-based Blind SQL Injection (A05, active)</strong>
              {" "}— injects per-DBMS sleep calls ({" "}
              <code>SLEEP(n)</code> for MySQL/MariaDB,{" "}
              <code>pg_sleep(n)</code> for PostgreSQL,{" "}
              <code>WAITFOR DELAY</code> for MSSQL,{" "}
              <code>DBMS_PIPE.RECEIVE_MESSAGE</code> for Oracle) and
              times the response. Uses a <em>two-shot oracle</em>:
              first a 4-second probe, then a 7-second confirmation —
              only findings that clear both thresholds against a
              measured baseline are emitted. Catches injection on
              endpoints where the response content never varies with
              input (stored-proc wrappers, logged-only queries, DELETE
              / UPDATE paths that return "ok" regardless). Each probe
              intentionally stalls the server's SQL thread, so the
              check bails out of a parameter after one confirmed hit.
            </li>
            <li>
              <strong>Nuclei Templates — active execution (A03,
              active)</strong> — fires the HTTP-protocol subset of
              the bundled Nuclei catalogue against the target's base
              URL. Each template sends its own requests (the passive
              Nuclei row only evaluates matchers against already-
              captured responses, so a template whose finding
              depends on <code>/wp-admin/admin-ajax.php?action=...</code>
              {" "}or a specific CVE path you've never browsed will
              stay silent there and fire here). Default filter:
              Critical / High severity plus templates tagged{" "}
              <code>kev</code>, <code>rce</code>,{" "}
              <code>auth-bypass</code>, <code>ssrf</code>,{" "}
              <code>sqli</code>, <code>lfi</code> / <code>rfi</code>,{" "}
              <code>xxe</code>, <code>command-injection</code>,{" "}
              <code>fileupload</code>, <code>deserialization</code>,{" "}
              <code>takeover</code>. Hard cap 300 templates per
              target to keep runs bounded. Set{" "}
              <code>NUCLEI_ACTIVE_INCLUDE_ALL=1</code> in the
              environment before launching the app to drop the
              filter.
            </li>
            <li>
              <strong>Hidden Parameter Discovery (A05, active)</strong>
              {" "}— fuzzes a curated ~220-word wordlist (debug flags,
              admin access toggles, HTTP method overrides, feature
              flags, callback handlers, redirect targets, file
              pointers, SSRF-shaped URLs, auth tokens, id aliases,
              pagination, CMS / framework hooks) one parameter at a
              time. Two-pass probing: first a random canary to catch
              reflection (truthy-branch bugs), then <code>1</code> as
              a fallback for strict-equality checks like{" "}
              <code>if (param == "1")</code>. Hits are corroborated
              with a control probe (bogus parameter name, "how much
              does the endpoint naturally jitter?") so random content
              doesn't trip the detector. Every discovered parameter
              is a new attack surface for SQLi / SSRF / XSS / Open
              Redirect — run this first on an unfamiliar target.
            </li>
            <li>
              <strong>Server-Side Request Forgery (SSRF) (A10,
              active)</strong> — substitutes each URL-shaped query
              parameter with cloud-metadata endpoints (AWS IMDSv1,
              GCP <code>metadata.google.internal</code>, Azure IMDS,
              DigitalOcean) and loopback URLs (
              <code>http://127.0.0.1/</code>,{" "}
              <code>http://localhost/</code>, decimal-IP{" "}
              <code>http://2130706433/</code> for filter bypass).
              Confirms a hit via distinctive body markers —{" "}
              <code>ami-id</code>, <code>AccessKeyId</code>,{" "}
              <code>computeMetadata</code>,{" "}
              <code>Welcome to nginx</code>, <code>It works!</code>,{" "}
              <code>Connection refused</code> — and suppresses false
              positives by requiring the marker to be absent from the
              baseline response. AWS / GCP / Azure metadata hits are
              Critical; DigitalOcean + loopback hits are High. Blind
              SSRF still needs an OOB server and will light up when
              active-Nuclei lands.
            </li>
            <li>
              <strong>Open Redirect (A01, active)</strong> — substitutes
              URL-shaped parameter values with the RFC 2606 sentinel{" "}
              <code>corvex-redirect-canary.invalid</code>; reports any
              endpoint that redirects to it.
            </li>
          </ul>
          <p>
            Bundled <strong>Nuclei templates</strong> (~6,000) are also
            exposed here, one row per template, OWASP-categorised by the
            classifier (SQLi → A03, SSRF → A10, CVE tags → A06, etc.).
            These run passively against captured responses whose request
            path matches the template's base path — no extra requests go
            out.
          </p>

          <h4>Running active checks</h4>
          <ol className="numbered">
            <li>
              From the Traffic tab, expand rows you want to probe and
              click <strong>Send to Checks</strong>. They appear under{" "}
              <em>Targets</em> on the Checks tab.
            </li>
            <li>
              In the Library pane, tick the active checks you want to run
              (e.g. <em>Reflected XSS</em>, <em>Error-based SQLi</em>).
            </li>
            <li>
              Click <strong>Run N active check(s) on M target(s)</strong>.
            </li>
            <li>
              Findings stream into the right pane as they're produced. Each
              finding has a severity stripe, title, check id, and a short
              description. The evidence JSON (matched payload, reflected
              canary, captured version, etc.) is stored alongside the
              finding for later inspection.
            </li>
          </ol>

          <h4>Stack fingerprinting — the Wappalyzer dataset</h4>
          <p>
            Stack fingerprints power two things: the <em>Stack Fingerprint
            </em> passive finding you'll see on most exchanges, and the{" "}
            <em>Banner CVE Cross-Reference</em> check, which turns
            every versioned detection into a CVE lookup against the
            local vulndb. The engine follows the Wappalyzer technology
            schema — a battle-tested format that describes products as
            regex patterns against HTTP headers, cookies, response
            HTML, meta tags, URL paths, and implied-by relationships.
          </p>
          <p>
            Out of the box the project ships with a large upstream
            technology dataset (thousands of fingerprints across CMSes,
            e-commerce platforms, analytics, JS libraries, web servers,
            CDNs and more) plus a small hand-curated seed as a safety net.
            Managing, refreshing, and auditing that dataset lives under
            its own help section — this page only covers how detection
            flows through the Checks pipeline.
          </p>
          <p>
            <strong>Example — what a detection looks like.</strong> Browse{" "}
            <code>https://shop.example/</code>. The Stack Fingerprint check
            emits an Info finding like:
          </p>
          <pre className="help-cmd">
{`Stack detected: Cloudflare, nginx 1.24.0, PHP 8.2.4,
                WordPress 6.4.2, jQuery 3.7.1, Bootstrap 5.3.2`}
          </pre>
          <p>
            The evidence JSON records how each tech was matched (header,
            cookie, HTML pattern, URL) so you can audit false positives.
          </p>

          <h4>Settings tab — first-time setup guide</h4>
          <p>
            Instead of a single wall of configuration, Settings is broken
            into five chipped sub-sections:
          </p>
          <ol className="numbered">
            <li>
              <strong>Overview</strong> — jump-links to the three setup
              steps.
            </li>
            <li>
              <strong>Certificate authority</strong> — export the CA PEM,
              show the stored path, and per-OS install commands.
            </li>
            <li>
              <strong>Browser setup</strong> — full walkthroughs for Firefox
              (manual proxy + Authorities import), Chromium browsers
              (FoxyProxy / SwitchyOmega and system-wide fallback), Safari
              (System Settings → Network → Proxies), plus copy-pasteable{" "}
              <code>curl</code>, <code>wget</code>, POSIX <code>http_proxy</code>{" "}
              env vars, and PowerShell <code>$env:HTTPS_PROXY</code>.
            </li>
            <li>
              <strong>Verify</strong> — step-by-step smoke check.
            </li>
            <li>
              <strong>Troubleshooting</strong> — five common failure modes
              (cert warnings, loopback bypass, 502 hangs, CA not ready, port
              collision) and the fixes.
            </li>
          </ol>

          <h4>Where the data lives</h4>
          <p>
            All proxy data is stored in the same SQLite database the rest of
            the app uses (<code>history.sqlite</code> in the app-data dir):
          </p>
          <ul>
            <li>
              <code>proxy_sessions</code> — one row per{" "}
              <em>Start → Stop</em> cycle.
            </li>
            <li>
              <code>exchanges</code> — captured request/response pairs with
              headers, bodies, timings, scope, intercept flags.
            </li>
            <li>
              <code>scan_runs</code> — active-check run metadata.
            </li>
            <li>
              <code>exchange_scan_findings</code> — findings linked back to
              their parent exchange.
            </li>
          </ul>
          <p>
            The CA certificate + private key live under{" "}
            <code>&lt;app-data&gt;/proxy/ca/ca.pem</code> and{" "}
            <code>ca.key</code> (0600 on Unix). Never share the private key.
          </p>

          <h4>Safety notes</h4>
          <ul>
            <li>
              Listen address defaults to loopback. Only change it to a LAN
              address on trusted networks — the proxy doesn't authenticate
              clients and your CA would become trusted on any machine that
              routes through it.
            </li>
            <li>
              Active checks send actual payloads (<code>' OR 1=1</code>,
              <code>&lt;svg/onload=</code> canaries, redirect sentinels) to
              target servers. Only run them against systems you own or have
              written permission to test.
            </li>
            <li>
              HTTPS MITM works only against targets that rely on the OS/
              browser trust store. Apps with <em>certificate pinning</em>{" "}
              (many mobile banking apps) will reject the minted leaf cert —
              this is by design and not something trusting the CA can fix.
            </li>
          </ul>
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
        <section id="recon">
          <h3>Recon</h3>
          <p>
            The <strong>Recon</strong> view in the sidebar takes a domain and
            expands it into the hosts, subdomains, and DNS records that belong
            to it — the step that usually happens in a separate terminal
            before an audit gets serious. Two modes, both driven from the
            same form:
          </p>
          <h4>Passive discovery</h4>
          <p>
            Three keyless public sources are queried concurrently. No request
            ever touches the target itself; each source is a third-party
            aggregator of certificate-transparency logs or historic passive
            DNS, so the only network traffic is corvex ↔ source.
          </p>
          <ul>
            <li>
              <strong>crt.sh</strong> — Certificate Transparency search. The
              canonical high-yield source; every TLS certificate issued for
              the domain or a subdomain shows up here.
            </li>
            <li>
              <strong>AlienVault OTX</strong> — community passive-DNS feed.
              Good coverage for hosts that ever resolved in the wild.
            </li>
            <li>
              <strong>CertSpotter</strong> — a second CT source with a
              different lookback window; often surfaces short-lived
              staging/preprod certs crt.sh missed.
            </li>
          </ul>
          <p>
            Results stream into the{" "}
            <em>Subdomains</em> grid live, with a chip per source showing
            how many hosts it contributed. If one source is rate-limited or
            down, the other two still land results — partial failures never
            abort the run.
          </p>

          <h4>Active mode</h4>
          <p>
            Tick <strong>Active mode</strong> to pair passive discovery with
            actual DNS traffic against the domain's authoritative servers.
            Runs in order:
          </p>
          <ol className="numbered">
            <li>
              <strong>Record enumeration</strong> — A, AAAA, MX, NS, TXT, SOA,
              CNAME for the seed domain. Every record that comes back lands in
              the DNS records panel.
            </li>
            <li>
              <strong>Zone transfer (AXFR)</strong> — attempted against every
              authoritative NS. Almost always refused on modern DNS; when it
              isn't, you've found a misconfiguration and the rows surface
              straight into Subdomains with <code>zone-transfer</code> as the
              source tag.
            </li>
            <li>
              <strong>Wildcard probe</strong> — resolves a 32-char random
              subdomain. If the domain wildcards (catch-all record), the
              returned IPs are recorded and used to filter brute-force
              results that would otherwise be false positives.
            </li>
            <li>
              <strong>Wordlist brute-force</strong> — resolves{" "}
              <code>{`{prefix}.{domain}`}</code> for every prefix in the
              wordlist, up to the configured concurrency (default 500). A
              built-in ~200-entry wordlist of common names ships bundled;
              point at a larger list (e.g. SecLists{" "}
              <code>subdomains-top1million</code>) via the Browse button.
            </li>
            <li>
              <strong>Address resolution</strong> — each discovered host is
              resolved to its current A/AAAA so the grid can show IPs
              alongside the source attribution.
            </li>
          </ol>
          <p className="callout">
            Active mode fires real DNS queries against the target's NS —
            that's the only phase where traffic touches infrastructure the
            target operates. Keep wordlists and concurrency reasonable, and
            only run against assets you're authorised to test.
          </p>

          <h4>Cross-tool integrations</h4>
          <p>
            Every discovered host carries three per-row actions:
          </p>
          <ul>
            <li>
              <strong>Scope</strong> — appends an include rule for the host
              to the Proxy → Settings → Scope rules list, so Intercept pauses
              exchanges from that host as soon as they flow through the
              proxy. A bulk "Add all N to Proxy scope" button at the bottom
              of the grid does the same thing for everything on screen.
            </li>
            <li>
              <strong>Checks</strong> — injects a synthetic{" "}
              <code>GET /</code> exchange for the host into the currently-
              running proxy session. The row lands in the Traffic tab with
              origin <code>imported</code>, ready for Send to Checks /
              Send to Fuzzer like any captured exchange. Requires an active
              proxy session.
            </li>
            <li>
              <strong>Fuzzer</strong> — hands the host URL to the Active
              Fuzzing view (same pipe as Traffic row's Send to Fuzzer);
              scope defaults to <code>page</code> so the fuzzer hits exactly
              that endpoint.
            </li>
          </ul>

          <h4>History</h4>
          <p>
            Every recon run is persisted to <code>history.sqlite</code>.
            Click the <strong>History</strong> tab at the top of the view to
            browse past runs — subdomains + records + sources + wildcard
            state all rehydrate. Delete a run to cascade-drop its findings.
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

          <h4>11. Capture and audit a login flow through the proxy</h4>
          <p>
            When the target does a real login in a real browser, you see
            every redirect, every cookie, and every CSRF token the way the
            app would hand them out. This is useful for documenting the
            auth flow, grabbing a real session cookie for Replay, or
            seeding the Checks tab with post-login URLs that need an
            authenticated session.
          </p>
          <ol className="numbered">
            <li>
              Switch to the <strong>Proxy</strong> view. If the status
              pill says <em>Stopped</em>, click <strong>Start</strong>.
            </li>
            <li>
              In your browser, set the HTTP(S) proxy to{" "}
              <code>127.0.0.1:8888</code> and make sure the corvex CA is
              trusted (see{" "}
              <em>Proxy, Intercept, Replay &amp; Checks → One-time setup
              </em>{" "}
              if this is your first run).
            </li>
            <li>
              Visit the app's login page, type credentials, submit. The
              browser may redirect once or twice before landing on the
              dashboard.
            </li>
            <li>
              Back in corvex, open the <strong>Traffic</strong> tab. You'll
              see a row for every request — the login <code>POST</code>,
              the 302 redirects, the follow-up <code>GET</code>s, the
              static assets.
            </li>
            <li>
              Click the login <code>POST</code> row to expand it. You'll
              see method, status, and host. Click <strong>Send to
              Replay</strong> — the full raw request (including any
              <code>Cookie</code> header and submitted form body) loads
              into the Replay editor.
            </li>
            <li>
              Click any post-login page (dashboard, profile, account
              settings) in the Traffic tab, expand, click{" "}
              <strong>Send to Checks</strong>. They queue up on the
              Checks tab with the real session cookie attached.
            </li>
          </ol>

          <h4>
            12. Tamper with a request on the wire using Intercept
          </h4>
          <p>
            The classic authorization-bypass probe — edit a submitted
            form value <em>after</em> the browser's client-side JavaScript
            has validated it but before the server sees it.
          </p>
          <ol className="numbered">
            <li>
              In the Proxy view, open the <strong>Intercept</strong> tab
              and set the mode chip to <strong>Request</strong>.
            </li>
            <li>
              Go back to your browser and trigger the action you want to
              tamper with — for example a "change account email" form or
              a cart checkout POST.
            </li>
            <li>
              The browser hangs waiting for the response. In corvex, a
              new row appears in the Intercept <em>Pending</em> queue.
              Click it.
            </li>
            <li>
              The editor on the right shows the raw HTTP/1 bytes:
              <pre className="help-cmd">
{`POST /api/account HTTP/1.1
Host: target.example
Content-Type: application/json
Cookie: session=abc123...
Content-Length: 52

{"email":"alice@corp.com","role":"user"}`}
              </pre>
              Change <code>"role":"user"</code> to{" "}
              <code>"role":"admin"</code>. Keep the blank line between
              headers and body intact.
            </li>
            <li>
              The Forward button auto-relabels to <strong>Forward
              edited</strong>. Click it. corvex re-parses your bytes,
              forwards the modified request upstream, and returns the
              real response to the browser.
            </li>
            <li>
              If the server accepted it, check the Traffic tab — the
              edited request shows up with the{" "}
              <em>request-edited</em> intercept flag set. If the server
              rejected it (403 / 400), you've confirmed the role check
              is server-side.
            </li>
          </ol>
          <p className="callout">
            Forgotten an intercept? Every paused request auto-forwards
            after 5 minutes so upstream sockets don't leak. Hit{" "}
            <strong>Drop all</strong> above the queue to release
            everything pending in one go.
          </p>

          <h4>
            13. Hunt reflected XSS across an app with proxy-driven
            targets
          </h4>
          <p>
            Unlike the Dashboard's Active Fuzzing (which crawls), this
            scenario uses your real browser as the crawler: you click
            through the app, corvex captures every endpoint, then active
            checks run only against what you actually visited.
          </p>
          <ol className="numbered">
            <li>
              Start the Proxy and browse the app end-to-end — every
              search box, every filter, every profile form. The Traffic
              tab populates with one row per request.
            </li>
            <li>
              Open the <strong>Checks</strong> tab. In the library
              search, type <code>xss</code>. Tick{" "}
              <em>Reflected XSS (active)</em>.
            </li>
            <li>
              On the Traffic tab, expand any <code>GET</code> with a
              query string (search results, filter pages) and click{" "}
              <strong>Send to Checks</strong>. Repeat for every
              interesting endpoint — they pile up in the Targets list.
            </li>
            <li>
              Back on the Checks tab, click{" "}
              <strong>Run 1 active check(s) on N target(s)</strong>. A
              canary token like <code>cvxXSS7f3ad019</code> is injected
              into each query parameter across several context-breakers
              (<code>&lt;svg/onload=</code>, <code>"&gt;&lt;script&gt;</code>,
              attribute breaks, etc.).
            </li>
            <li>
              Findings stream into the panel on the right. A High-severity
              <em>Reflected XSS</em> finding names the parameter, the
              payload that landed, and the reflection context. Clean
              parameters silently contribute nothing.
            </li>
          </ol>

          <h4>14. SQL-injection probe against a specific parameter</h4>
          <p>
            Same workflow as above but with the error-based SQLi check,
            reusing corvex's DBMS error-signature bank.
          </p>
          <ol className="numbered">
            <li>
              Capture the target request through the proxy — for example
              a search form submit:{" "}
              <code>GET /search?q=hello&amp;page=1</code>.
            </li>
            <li>
              Expand the row, <strong>Send to Checks</strong>.
            </li>
            <li>
              On the Checks tab, search <code>sqli</code>, tick{" "}
              <em>Error-based SQL Injection (active)</em>, Run.
            </li>
            <li>
              corvex sends one baseline request (unmodified) plus six
              boundary-probe variants per parameter:{" "}
              <code>'</code>, <code>"</code>, <code>')</code>,{" "}
              <code>")</code>, <code>' OR '1'='1</code>,{" "}
              <code>" OR "1"="1</code>. A finding fires only when the
              probe response contains a DBMS error signature the baseline
              didn't — suppresses pre-existing error pages.
            </li>
            <li>
              The evidence JSON names the param, payload, detected DBMS
              (MySQL / PostgreSQL / MSSQL / Oracle / SQLite …) and every
              matched signature string.
            </li>
          </ol>

          <h4>15. Replay an IDOR probe to compare two object IDs</h4>
          <p>
            When access-control checks are missing, changing a numeric
            ID in a URL lets you read another user's data. Replay makes
            this a two-click check.
          </p>
          <ol className="numbered">
            <li>
              While logged in as your test user, visit a per-object
              resource — for example the JSON API behind a profile page:
              <code>GET /api/orders/1042</code>.
            </li>
            <li>
              In the Traffic tab, expand that row →{" "}
              <strong>Send to Replay</strong>. The full request (with
              session cookies) loads into the editor.
            </li>
            <li>
              Edit the <em>request line only</em> — change{" "}
              <code>/api/orders/1042</code> to{" "}
              <code>/api/orders/1043</code>. Leave every header alone
              so the session cookie still goes out.
            </li>
            <li>
              Click <strong>Send (edited)</strong>. The response pane
              shows the raw result.
            </li>
            <li>
              Compare: a 200 with a different-sized body = suspicious
              (you probably just read another user's data). A 403 = the
              access-control check is working. Every replay is itself
              captured as a new Traffic row with origin <em>replay</em>{" "}
              linked back to the parent, so you can stack variants and
              compare deltas.
            </li>
          </ol>

          <h4>16. Find missing security headers across a site</h4>
          <p>
            Zero-effort passive audit. You don't tick any checks or
            queue targets — just browse the app with the proxy on.
          </p>
          <ol className="numbered">
            <li>Start the Proxy. Browse the site normally.</li>
            <li>
              Switch to the <strong>Checks</strong> tab. The{" "}
              <em>Findings</em> pane on the right fills in real time as
              passive checks run on every response.
            </li>
            <li>
              Type <code>header</code> into the library search to see
              the <em>Missing Security Headers</em> check — one Low
              finding per missing CSP / HSTS / X-Content-Type-Options /
              X-Frame-Options / Referrer-Policy / Permissions-Policy. If
              a CSP is present and already covers{" "}
              <code>frame-ancestors</code>, X-Frame-Options is
              deliberately not flagged.
            </li>
            <li>
              Passive <em>Verbose Errors</em>, <em>Version Disclosure</em>,{" "}
              <em>Insecure Cookie Flags</em>, and{" "}
              <em>Stack Fingerprint</em> findings also appear without any
              further action — they run on every in-scope response.
            </li>
          </ol>

          <h4>
            17. Narrow scope to one target so background noise stops
            cluttering Intercept
          </h4>
          <p>
            You just started intercepting and every tab, every favicon,
            every analytics beacon from every open window is piling up in
            the Pending queue. Fix: configure scope rules so only the
            target you're testing is in-scope; everything else flows
            through the Traffic log without ever pausing.
          </p>
          <ol className="numbered">
            <li>
              In the Proxy view, open <strong>Settings →{" "}
              <em>4. Scope rules</em></strong>. Both lists start empty —
              that's the "log all, intercept all" default.
            </li>
            <li>
              Click <strong>+ Add include rule</strong>. Fill in the host
              field with <code>*.acme.test</code> (leading wildcard
              matches any sub-domain plus the apex). Leave path and port
              blank.
            </li>
            <li>
              Click <strong>Save scope rules</strong>. The banner flips
              to "Saved — applies to new requests." Rules live in{" "}
              <code>history.sqlite</code>, so they survive a restart.
            </li>
            <li>
              Back on the Traffic tab, newly-captured rows show a{" "}
              <em>Scope</em> field in the expanded detail. Requests
              matching the include rule read <code>in</code>; everything
              else reads <code>out</code>. Out-of-scope rows are still
              captured and visible — they just never pause the browser.
            </li>
            <li>
              Turn on Intercept → Request (or Both). Only the Acme hosts
              pause now. Go back to Settings and add an{" "}
              <strong>exclude</strong> rule for{" "}
              <code>metrics.acme.test</code> with path regex{" "}
              <code>^/collect</code> to suppress the site's own telemetry
              without taking the whole host out of scope.
            </li>
          </ol>
          <p className="callout">
            Scope decisions are captured at the moment each request is
            classified. Editing rules only affects new requests —
            exchanges already waiting in the Pending queue keep their
            original classification. Clearing the Pending queue with{" "}
            <strong>Drop all</strong> is the clean way to reset after a
            scope change.
          </p>

          <h4>
            18. Simulate an error response without touching the server
          </h4>
          <p>
            Your SPA probably has a "session expired" or "quota exceeded"
            error branch that's hard to trigger from the outside. The
            response-phase intercept lets you hand the browser any
            response you want — the real server never knows you tampered
            with its reply.
          </p>
          <ol className="numbered">
            <li>
              In the Intercept tab, set mode to <strong>Response</strong>.
              If this is noisy, first narrow scope (scenario 17) so only
              the target app's responses pause.
            </li>
            <li>
              Trigger the action you want to test in the browser — e.g.
              loading a profile page, calling{" "}
              <code>GET /api/me</code>.
            </li>
            <li>
              The upstream reply pauses with a blue{" "}
              <code>← resp</code> badge. Click it. The editor shows:
              <pre className="help-cmd">
{`HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 42

{"id":42,"email":"alice@acme.test"}`}
              </pre>
            </li>
            <li>
              Rewrite the status line to{" "}
              <code>HTTP/1.1 401 Unauthorized</code>. Replace the body
              with <code>{`{"error":"token_expired"}`}</code>. Update{" "}
              <code>Content-Length</code> to match the new body length
              (the upstream's 42-byte JSON becomes a 27-byte one). The
              blank line between headers and body is mandatory.
            </li>
            <li>
              Click <strong>Forward edited response</strong>. The
              browser's fetch promise resolves with a 401, and the SPA
              runs whatever its "session expired" handler does — ideally
              kicking you to the login page. The Traffic row records the
              intercepted reply with the <em>response-edited</em> flag so
              you can compare the original upstream bytes vs what the
              client actually consumed.
            </li>
          </ol>
          <p>
            Same pattern works for: stripping{" "}
            <code>Content-Security-Policy</code> to test the CSP
            fallback, flipping a feature-flag JSON boolean before the SPA
            renders, injecting{" "}
            <code>X-Debug-*</code> headers the real server would never
            send, or returning <code>429 Too Many Requests</code> to
            exercise client-side backoff logic.
          </p>

          <h4>
            19. Drop a response to simulate upstream failure mid-flight
          </h4>
          <p>
            Another use of response-phase intercept: the request leaves
            your browser cleanly, the server processes it (maybe writes
            to the DB), but the reply never arrives. Great for surfacing
            double-submit bugs or checking whether optimistic UI recovers
            gracefully when a confirmation never comes back.
          </p>
          <ol className="numbered">
            <li>
              Set Intercept mode to <strong>Response</strong>.
            </li>
            <li>
              Fire off the action you want to half-complete — e.g. a{" "}
              <code>POST /api/orders</code> that creates a record.
            </li>
            <li>
              When the upstream reply pauses, select it and click{" "}
              <strong>Drop response</strong>. The browser receives a{" "}
              <code>502 Bad Gateway</code>; the server's original{" "}
              <code>201 Created</code> is discarded.
            </li>
            <li>
              Check the app: did it show a generic error, or did it
              offer to retry? If it retried blindly, you may have just
              found a double-submit bug (two orders from one click).
              Check the server-side record to confirm the write landed
              despite the dropped response.
            </li>
          </ol>

          <h4>
            20. Send a captured endpoint straight into the Active Fuzzer
          </h4>
          <p>
            The Checks tab is tuned for surgical single-check runs
            against a hand-picked target. The Active Fuzzer is the
            heavier artillery: SQL-injection engine with five
            techniques, 50 tamper modules, LFI, CRLF, SSTI, CMD-injection,
            XXE, open-redirect, plus Nuclei templates. When you spot a
            suspicious parameter while browsing through the proxy,{" "}
            <strong>Send to Fuzzer</strong> skips the "copy URL, switch
            view, paste it back" dance.
          </p>
          <ol className="numbered">
            <li>
              Browse the target app with the proxy running. Let the
              Traffic tab fill with real requests.
            </li>
            <li>
              Spot an endpoint worth hammering — e.g.{" "}
              <code>GET /api/orders?status=open&amp;user=42</code>.
              Expand that row.
            </li>
            <li>
              Click <strong>Send to Fuzzer →</strong>. The view switches
              to <em>Active Fuzzing</em>. A banner at the top of the Run
              tab reads{" "}
              <em>
                Seeded from Intercept → [your URL] · scope forced to{" "}
                page
              </em>
              . The Target URL field is pre-filled with the full URL
              including the query string, and the form's other settings
              (SQLi level, techniques, tamper modules, enumerate
              targets) are preserved from your last run.
            </li>
            <li>
              Tune for the attack class you care about. SQL injection:
              leave scope on <code>page</code>, set Level = 2 / Risk = 1,
              techniques BEUT (Boolean + Error + Union + Time), DBMS on
              auto-detect. For a wider sweep: raise to Level 3 / Risk 2
              and enable enumerate{" "}
              <code>dbs,tables,columns</code>.
            </li>
            <li>
              Click <strong>Start active fuzzing</strong>. The fuzzer
              treats the seeded URL as a single-page target (no
              crawling) and tests every query parameter with the
              enabled modules. Findings stream into the table below
              live; the stats bar shows request count and elapsed time.
            </li>
            <li>
              When done, the run shows up in History with origin{" "}
              <em>active</em>. The captured Traffic row that seeded it
              stays untouched — the fuzzer fires its own requests and
              captures its own exchanges, so original and fuzzed
              traffic are cleanly separable in the log.
            </li>
          </ol>
          <p className="callout">
            Scope always defaults to <code>page</code> when seeded from
            Traffic, so the fuzzer won't crawl sideways into unrelated
            endpoints. If you actually want a wider run, change it to{" "}
            <code>folder</code>, <code>domain</code>, or{" "}
            <code>subdomains</code> before hitting Start. Only test
            targets you own or have authorization for — active fuzzing
            sends hundreds to thousands of probe requests per endpoint.
          </p>

          <h4>
            21. Audit a WebSocket-driven feature (chat, live dashboard,
            collaborative editor)
          </h4>
          <p>
            WebSockets are where a lot of modern app logic hides —
            messaging, live-update streams, presence / typing
            indicators, signalling for WebRTC. The Traffic tab captures
            every frame crossing the proxy, so you can audit message
            formats, authorization checks, and broadcast scopes without
            a standalone WS tool.
          </p>
          <ol className="numbered">
            <li>
              Start the proxy and open the app. When your browser
              upgrades to WebSocket, a row appears in Traffic with a
              blue <code>ws</code> badge, status{" "}
              <code>101 Switching Protocols</code>, and the upgrade
              URL (<code>ws://</code> or <code>wss://</code> depending
              on the scheme).
            </li>
            <li>
              Expand the row. Below the Send-to-X actions, a{" "}
              <em>WebSocket frames</em> panel renders every frame in
              capture order. Amber <code>→</code> rows are
              browser-sent, blue <code>←</code> rows are server-sent.
              Opcode badges label the frame type (<code>text</code>{" "}
              JSON/text, <code>binary</code> BSON/protobuf/custom,{" "}
              <code>ping</code> / <code>pong</code> keepalives,{" "}
              <code>close</code> shutdown).
            </li>
            <li>
              Click any frame to open the detail pane. Text frames
              decode as UTF-8; binary frames render as a hex + ASCII
              dump, 16 bytes per row, so you can eyeball framing headers
              and magic numbers.
            </li>
            <li>
              Trigger the interesting action in the app — send a chat
              message, join a room, toggle a permission. Watch the
              corresponding frames stream in live. Compare the request
              frame you sent with the broadcast frames the server fans
              out: does the server echo your message to just the target
              user, or to everyone in the room including users who
              shouldn't see it (IDOR-over-WebSocket)? Does an admin-only
              action round-trip through a permission check, or does the
              server blindly trust the message?
            </li>
            <li>
              For authorization bugs, replay the frame sequence as a
              different user — log in as User A, observe the frame a
              privileged action produces, then log in as User B and
              send the same frame verbatim (using a raw WS client like{" "}
              <code>wscat</code> or a browser DevTools snippet). If the
              server accepts it, the check was client-side only.
            </li>
          </ol>
          <p className="callout">
            Frames exceeding 16 MB are forwarded raw but captured as
            zero-byte placeholders to protect the proxy from a runaway
            binary stream. Extensions like{" "}
            <code>permessage-deflate</code> compress payloads — the
            frames panel flags this with an "extension active" badge,
            and text previews will look like gibberish because we don't
            decompress them. For those sessions, treat payloads as
            opaque binary or temporarily disable the extension in the
            client to get readable captures.
          </p>

          <h4>
            22. Cap a long audit session so history.sqlite doesn't
            balloon
          </h4>
          <p>
            Leaving the proxy running overnight while a CI bot or a
            crawler pounds the app is a fast way to pile up hundreds of
            thousands of captured exchanges. Retention keeps the ring
            trimmed to whatever size fits your workflow — each session
            reuses its cap and older rows get evicted automatically.
          </p>
          <ol className="numbered">
            <li>
              Open <em>Proxy → Settings → 5. Retention</em>. The
              current cap is shown as the active chip (default{" "}
              <code>5,000</code>).
            </li>
            <li>
              Pick a preset (<code>1K</code>, <code>5K</code>,{" "}
              <code>20K</code>, <code>100K</code>, or{" "}
              <strong>Unlimited</strong>) or type a custom value into
              the number field. Values over <code>1,000,000</code> are
              clamped on save.
            </li>
            <li>
              Click <strong>Save retention policy</strong>. The writer
              picks up the new cap on its next flush (at most 250 ms
              later); you don't need to restart the proxy session.
            </li>
            <li>
              Start a long-running capture. Once the session passes the
              cap, the oldest rows vanish from the Traffic tab on their
              own as new traffic arrives — you'll see the list stay at
              the configured size while the counter in the toolbar keeps
              climbing (that counter tracks total captures this session,
              not current live rows).
            </li>
            <li>
              Completed sessions (anything from an earlier Start / Stop
              cycle, or ones you flip through via History) are{" "}
              <em>never</em> retouched — retention only evicts from the
              currently-running session. To trim old sessions, delete
              them from the History view instead.
            </li>
          </ol>
          <p className="callout">
            Setting the cap to <code>0</code> disables eviction
            entirely. Handy when you genuinely need every exchange for
            an audit report, but watch{" "}
            <code>history.sqlite</code> size (it lives under the app
            data dir) — a dense session can grow at ~1 MB per 1,000
            exchanges on top of the blob-spill directory for bodies
            over 512 KB.
          </p>

          <h4>
            23. Export a session to HAR for handoff or offline analysis
          </h4>
          <p>
            HAR (HTTP Archive) is the lingua franca browsers, intercept
            proxies, and DevTools all understand. Exporting a corvex
            session as HAR lets you hand a captured flow to a
            teammate, attach it to a bug report, or load it into
            DevTools' Network tab for side-by-side comparison — without
            giving anyone access to the live proxy.
          </p>
          <ol className="numbered">
            <li>
              Start the proxy and browse the target app. The Traffic
              tab fills with rows; let the interesting flow finish.
              (Export works while the session is still running —
              you'll snapshot the current state.)
            </li>
            <li>
              Click <strong>Export HAR</strong> in the proxy toolbar,
              next to Start/Stop. A native file-save dialog opens with
              a default filename like{" "}
              <code>corvex-session-a1b2c3d4.har</code>.
            </li>
            <li>
              Pick a location and confirm. The exporter streams
              directly to disk — even a 5,000-row session with a few
              hundred MB of bodies lands in seconds without stalling
              the listener. A status line under the toolbar shows the
              entry count and file size once the write completes.
            </li>
            <li>
              Open the resulting file in any HAR-aware tool. In Chrome
              / Edge DevTools: <em>Network tab → right-click → Import
              HAR…</em>. In Firefox: <em>Network → Import HAR…</em>.
              In Charles or Fiddler: <em>File → Import</em>. Each tool
              renders the captured requests as if they'd happened in
              that tool's own live capture.
            </li>
            <li>
              Bodies that round-trip cleanly as UTF-8 show up as plain
              text in DevTools; binary bodies (images, compressed
              payloads) are base64-encoded per the HAR 1.2 spec and
              DevTools decodes them transparently in the Preview pane.
              Every HAR entry also carries a{" "}
              <code>_corvexId</code> field tying it back to the
              original exchange id in <code>history.sqlite</code>.
            </li>
          </ol>
          <p className="callout">
            The HAR write is session-scoped: one button click = the
            current session only. Exports aren't affected by retention
            — you get every row that's still present in{" "}
            <code>history.sqlite</code> at the moment you click the
            button, not the subset retention has trimmed to. To archive
            a long-running session before eviction chews through older
            rows, export periodically.
          </p>

          <h4>
            24. Seed Checks targets from an OpenAPI or Postman spec
          </h4>
          <p>
            When the dev team hands you an OpenAPI document or a
            Postman collection for the API you're about to audit, you
            don't have to click every endpoint in a browser to surface
            them. Import the spec and every documented route becomes a
            synthetic Traffic row, ready for the full Send-to-X flow.
          </p>
          <ol className="numbered">
            <li>
              Click <strong>Start</strong> in the proxy toolbar first —
              imported rows attach to the currently-running session.
              You don't need to point any browser at the proxy yet;
              the import path doesn't involve network traffic.
            </li>
            <li>
              Click <strong>Import spec</strong> next to Export HAR. A
              native open-file dialog appears; pick the spec file.
              OpenAPI <code>.json</code> and Postman v2.1{" "}
              <code>.json</code> are both recognised — the parser
              detects the format from the file's shape and picks the
              right branch.
            </li>
            <li>
              The status line under the toolbar confirms how many
              endpoints imported, e.g.{" "}
              <em>
                Imported 47 openapi3 endpoint(s) from swagger.json
              </em>
              . Skipped items (folders, URL-less Postman requests)
              are called out separately.
            </li>
            <li>
              Switch to the <strong>Traffic</strong> tab — the
              imported rows appear with origin <code>imported</code>,
              no response (yet), and URLs derived from the spec's{" "}
              <code>servers[0].url</code> (OpenAPI) or{" "}
              <code>url.raw</code> (Postman). Example path and query
              parameters are filled in from the spec's{" "}
              <code>example</code> / <code>schema.example</code>{" "}
              fields so the URL is fireable as-is; where the spec
              provided no example, a placeholder like{" "}
              <code>example</code> or <code>1</code> lands instead.
            </li>
            <li>
              Expand any imported row and click{" "}
              <strong>Send to Checks</strong> to queue it for active
              probes, <strong>Send to Replay</strong> to edit the
              request and fire it against the real upstream, or{" "}
              <strong>Send to Fuzzer</strong> to hammer every
              parameter. Responses from those flows land as new rows
              linked back to the imported parent.
            </li>
          </ol>
          <p className="callout">
            Imported rows have no response until you fire one — they
            document what the API <em>says</em> it does, not what it
            actually returns. Use Replay to execute a few representative
            imports, confirm the spec still matches reality, then fan
            out to Checks / Fuzzer against the confirmed set. Postman
            collections that use <code>{`{{variable}}`}</code> tokens
            substitute <code>example</code> on import so the URL parses;
            edit in Replay before firing if the real value matters.
          </p>

          <h4>
            25. Turn a version banner into a CVE list (Banner-CVE
            cross-reference)
          </h4>
          <p>
            Outdated middleware — nginx 1.14, Apache 2.4.49, WordPress
            5.8, Tomcat 8.5.31 — is one of the highest-signal findings
            in any web assessment, but only if you spot the version
            banner <em>and</em> remember which CVEs affect it. This
            scenario turns that into zero-effort passive work: browse
            the site once, and every unpatched banner becomes a ranked
            list of CVEs with CVSS scores and EPSS probabilities.
          </p>
          <ol className="numbered">
            <li>
              <strong>Confirm the vulndb is populated.</strong> Open{" "}
              <em>Databases → Vulnerabilities</em>. If the "CVEs loaded"
              counter is zero (or the "last NVD update" timestamp is
              blank/stale), click <strong>Refresh now</strong>. The
              first populate is a ~200 MB pull from NVD and takes a few
              minutes; subsequent refreshes are incremental. A missing
              or empty vulndb silently disables this check — nothing
              breaks, but no CVE findings come out.
            </li>
            <li>
              Start the proxy and browse the target app normally. No
              special configuration — <em>Banner CVE Cross-Reference
              </em> is a passive check that runs automatically on every
              in-scope response.
            </li>
            <li>
              Switch to the <strong>Checks</strong> tab. The{" "}
              <em>Findings</em> pane fills in real time. Each CVE
              finding is titled like{" "}
              <code>nginx 1.18.0 affected by CVE-2021-23017</code> and
              severity-coloured from the CVSS v3.1 base score:
              Critical ≥ 9.0, High ≥ 7.0, Medium ≥ 4.0, Low &gt; 0.
            </li>
            <li>
              Click a finding to expand its evidence. The JSON records{" "}
              <code>product</code>, <code>version</code>,{" "}
              <code>cpe_vendor</code>, <code>cpe_product</code>,{" "}
              <code>cvss_v31_score</code>, <code>cvss_v31_vector</code>,
              EPSS score + percentile when present, and the NVD
              description trimmed to 500 chars. Use the CPE to
              cross-reference against vendor advisories.
            </li>
            <li>
              <strong>Triage tip.</strong> Sort the Findings pane by
              severity, then by EPSS percentile (high-EPSS first). EPSS
              reflects real-world exploitation probability in the next
              30 days — a CVSS 7.5 with EPSS 0.94 should jump the
              queue ahead of a CVSS 9.8 with EPSS 0.02. Stack
              Fingerprint itself still emits one Info finding per
              exchange listing the full detected stack, so you can
              always see which banners were checked even when no CVEs
              landed.
            </li>
            <li>
              <strong>False-positive guard.</strong> A banner can lie:
              a CDN or reverse proxy may emit{" "}
              <code>Server: nginx/1.18.0</code> while the real origin
              runs 1.24.0. Before filing, confirm the banner against
              the origin (Send to Replay, strip the CDN host, re-fire)
              or check for an explicit{" "}
              <code>Server</code> override in the server config.
            </li>
          </ol>
          <p className="callout">
            The check is deliberately quiet about versionless banners
            (<code>Server: nginx</code>, <code>Apache</code> without a
            version) — NVD CPE ranges need a concrete version to match
            accurately, and "maybe vulnerable" findings poison the
            dashboard. If you need a versionless product to still be
            flagged, pair this with the <em>Version Disclosure</em>{" "}
            passive check (it fires on the same banners and at least
            tells you a version is being leaked). Findings are capped
            at 25 per exchange so a page that pulls in a dozen
            outdated JS libs can't flood the feed; the full count is
            recorded in the <code>total_cves_for_banner</code> evidence
            field.
          </p>

          <h4>
            26. Confirm a suspicious parameter with boolean-blind SQLi
          </h4>
          <p>
            The Error-based SQLi check catches the obvious cases where
            the app leaks a MySQL / Postgres / MSSQL error. Modern
            apps increasingly swallow those errors — a 500 turns into
            a friendly "something went wrong" page and detection goes
            quiet. Boolean-blind SQLi fires where error-based does
            not: it asks the database a true/false question and reads
            the answer from the <em>shape of the response</em>, not
            the error text.
          </p>
          <ol className="numbered">
            <li>
              Browse the app with the proxy on and exercise any
              request that carries a parameter you suspect feeds a
              WHERE clause — <code>GET /order?id=5</code>,{" "}
              <code>GET /profile?username=alice</code>, pagination{" "}
              <code>?page=3</code>, filters{" "}
              <code>?status=open</code>.
            </li>
            <li>
              Expand the row in Traffic and click{" "}
              <strong>Send to Checks</strong>. It joins the Targets
              list on the Checks tab.
            </li>
            <li>
              In the Checks library, type <code>blind</code> into
              the search. Tick <em>Boolean-blind SQL Injection</em>{" "}
              (and <em>Error-based SQL Injection</em> if you want
              both signals at once).
            </li>
            <li>
              Click <strong>Run N active check(s)</strong>. For each
              parameter, the runner fires three requests per SQL
              boundary (baseline, <code>AND 1=1</code>,{" "}
              <code>AND 1=2</code>) across four context boundaries
              — numeric, single-quote, double-quote, paren-quote.
              The first boundary that produces a confirmed diff
              wins; the rest of the boundaries for that parameter
              are skipped.
            </li>
            <li>
              Click the resulting finding to inspect evidence. The
              JSON carries the boundary that fired, the full
              true/false payloads, and three ratios:{" "}
              <code>ratio_true_vs_baseline</code> (should be ≥ 0.90),
              {" "}<code>ratio_false_vs_baseline</code> (should be
              ≤ 0.80), and <code>ratio_true_vs_false</code> (the
              true/false gap must be ≥ 0.05). These are the same
              page-similarity numbers sqlmap prints — if a finding
              looks off, cross-check against sqlmap.
            </li>
            <li>
              <strong>Confirm manually in Replay.</strong> Send the
              original request to Replay. Duplicate it twice, tacking{" "}
              <code>' AND '1'='1-- -</code> onto the parameter in one
              copy and <code>' AND '1'='2-- -</code> in the other.
              If the first comes back with the original content and
              the second comes back empty or errorful, the finding
              is real.
            </li>
          </ol>
          <p className="callout">
            The check uses <code>remove_dynamic_content</code> from{" "}
            <code>corvex_core::sqli::detection</code> to strip CSRF
            tokens, timestamps, session IDs, UUIDs and cache-busters
            before comparing bodies — so a nonce-heavy HTML page
            doesn't trigger a false negative. Endpoints that echo the
            raw query string into the response are still a blind spot
            (TRUE will look close to FALSE); prefer Error-based or
            Time-based on those.
          </p>

          <h4>
            27. Catch silent SQL injection with time-based blind SQLi
          </h4>
          <p>
            There's a narrow class of injectable endpoints where
            neither error-based nor boolean-blind work: the
            application logs the query but returns a constant response
            ("Operation queued"), or the statement is an INSERT /
            UPDATE / DELETE whose effect isn't visible on the same
            round-trip. Time-based blind SQLi fires there by stalling
            the server's SQL thread for a chosen number of seconds and
            watching the clock.
          </p>
          <ol className="numbered">
            <li>
              Send the suspect request to Checks (scenario 20 covers
              the Send-to-X flow). Time-based works best on endpoints
              where the baseline latency is low and consistent — API
              endpoints that return quickly, background-queue
              submission endpoints, "like" / "favourite" / "archive"
              buttons.
            </li>
            <li>
              In the Checks library, search <code>time</code>. Tick{" "}
              <em>Time-based Blind SQL Injection</em>. Click{" "}
              <strong>Run</strong>.
            </li>
            <li>
              Per parameter the runner times a baseline request, then
              iterates the four SQL boundaries × the big-four DBMS
              payloads (MySQL/MariaDB, PostgreSQL, MSSQL, Oracle).
              The first probe adds ~4 seconds; a passing probe
              triggers a 7-second confirmation. Only findings that
              clear both thresholds are reported. Expect ≈ 1 second
              of active work per parameter when nothing fires and
              ≈ 11 seconds on the parameter that does.
            </li>
            <li>
              Open the finding. The evidence carries{" "}
              <code>baseline_ms</code>,{" "}
              <code>first_elapsed_ms</code>,{" "}
              <code>confirm_elapsed_ms</code>, and the{" "}
              <code>thresholds</code> block so you can see the
              timing call. A typical confirmed hit looks like:
              baseline 45 ms, first ~4,100 ms, confirm ~7,200 ms —
              the confirmation probe adds three seconds over the
              first probe, matching the 3-second bump in delay.
            </li>
            <li>
              <strong>Validate from Replay.</strong> Send the
              finding's <code>confirm_payload</code> verbatim and
              watch the total time in the Replay response pane. If
              it reliably sits near the injected sleep duration, it's
              real. If the time is variable or drops back to
              baseline on repeat, investigate whether an upstream
              proxy is responsible (Cloudflare rate-limiting can
              produce slow-then-fast patterns that mimic SLEEP).
            </li>
          </ol>
          <p className="callout">
            Time-based probes intentionally block SQL threads on the
            target — treat this as an <em>active</em> attack that
            briefly consumes a database connection per probe. Only
            run against systems you own or have written authorization
            for. The check stops after the first confirmed hit per
            parameter to keep total stall time bounded; you won't
            get a matrix of "also fires on boundary X with DBMS Y"
            findings on the same parameter.
          </p>

          <h4>
            28. Find cloud-credential-leak SSRF through a "fetch URL"
            feature
          </h4>
          <p>
            "Fetch-this-URL-for-me" features — preview generators,
            PDF renderers, webhook endpoints, avatar importers, RSS
            aggregators — are the classic SSRF shape. When the
            application fetches a URL an attacker controls, the
            attacker can redirect it inward: at{" "}
            <code>http://169.254.169.254/</code> on AWS to steal IAM
            credentials, at <code>http://127.0.0.1/</code> to reach
            unauthenticated admin UIs bound to loopback. The SSRF
            check probes exactly these targets and confirms with
            body markers that can only have come from inside the
            target's own network.
          </p>
          <ol className="numbered">
            <li>
              Browse the app and trigger anything that looks like a
              URL fetch —{" "}
              <code>POST /webhook?url=https://example.com</code>,{" "}
              <code>GET /preview?u=https://blog.example/post/1</code>,
              a profile avatar upload that accepts a URL, an
              image-to-PDF converter. The request you want to probe
              is the <em>one whose parameter carries the target URL
              </em>, not the response.
            </li>
            <li>
              Expand the row in Traffic. Click{" "}
              <strong>Send to Checks</strong>.
            </li>
            <li>
              In the Checks library, type <code>ssrf</code>. Tick{" "}
              <em>Server-Side Request Forgery (SSRF)</em>. Hit{" "}
              <strong>Run</strong>.
            </li>
            <li>
              For every parameter whose value looks URL-shaped
              (scheme, leading slash, host-shaped string, or a
              recognisable TLD like <code>.com</code> /{" "}
              <code>.net</code> / <code>.io</code>), the runner
              swaps the value for each of ~8 probe URLs and watches
              the response for distinctive markers —{" "}
              <code>AccessKeyId</code> for AWS credentials,{" "}
              <code>ami-id</code> for AWS metadata listings,{" "}
              <code>computeMetadata</code> for GCP,{" "}
              <code>Welcome to nginx</code> for a loopback default
              page. Probes are filtered against the baseline body so
              an app that always renders a footer containing
              "Apache" doesn't trigger false positives.
            </li>
            <li>
              Findings split by severity:{" "}
              <strong>Critical</strong> — AWS / GCP / Azure
              metadata leaks (the attacker is minutes away from
              cloud-API credentials);{" "}
              <strong>High</strong> — DigitalOcean metadata or any
              loopback hit (the attacker can pivot to every
              internal HTTP service on the target box). The
              evidence JSON names the probe label (
              <code>aws-imds</code>, <code>aws-imds-creds</code>,{" "}
              <code>gcp-meta</code>, <code>azure-meta</code>,{" "}
              <code>digitalocean-meta</code>,{" "}
              <code>loopback-ipv4</code>,{" "}
              <code>loopback-ipv4-int</code>,{" "}
              <code>localhost</code>) and lists the markers that
              matched.
            </li>
            <li>
              <strong>Escalate manually.</strong> On a confirmed
              AWS-IMDS finding, send the finding's payload to Replay,
              change the target path to{" "}
              <code>/latest/meta-data/iam/security-credentials/</code>{" "}
              to list attached IAM roles, then follow up with{" "}
              <code>/latest/meta-data/iam/security-credentials/&lt;role&gt;</code>
              {" "}to grab a set of temporary STS credentials. For
              the GCP variant, pivot to{" "}
              <code>/computeMetadata/v1/instance/service-accounts/default/token</code>
              {" "}for an OAuth access token. The initial finding is
              the anchor; the real impact comes from the follow-up.
            </li>
          </ol>
          <p className="callout">
            The check is marker-based and catches the most common
            SSRF classes reliably, but it is not complete: blind
            SSRF (where the server makes the request but never
            reflects the response) stays silent here. For blind
            variants, wait for the active-Nuclei engine and its
            Interactsh OOB support, or pair this check with a
            standalone callback server (<code>burpcollaborator</code>
            {" / "}<code>interactsh-client</code>) and a manually
            crafted probe. Header-based SSRF (injecting into{" "}
            <code>X-Forwarded-For</code>, <code>Referer</code>,{" "}
            <code>X-Original-URL</code>) is also deferred — the
            current check only probes query parameters with
            URL-shaped values.
          </p>

          <h4>
            29. Surface hidden parameters so every other active check
            has more to probe
          </h4>
          <p>
            Every injection check — SQLi, SSRF, XSS, Open Redirect —
            can only fuzz parameters it can see. If the app accepts{" "}
            <code>?admin=1</code> but nobody's ever sent{" "}
            <code>admin</code> through the proxy, it's invisible.
            Hidden-parameter discovery brute-forces ~220 common
            parameter names against the target and reports the ones
            the server reacts to, giving the other checks more to
            work with. Run this <em>first</em> on an unfamiliar
            target — then loop back and re-run SQLi / SSRF / XSS
            against the now-augmented parameter set.
          </p>
          <ol className="numbered">
            <li>
              Browse the app and <strong>Send to Checks</strong> any
              endpoint you want to examine. The check works on
              GETs; POST-body discovery is a future extension.
            </li>
            <li>
              In the Checks library, type <code>hidden</code>. Tick{" "}
              <em>Hidden Parameter Discovery</em>. Click{" "}
              <strong>Run</strong>.
            </li>
            <li>
              Each candidate is probed with two values in sequence: a
              random canary (maximises odds of hitting a reflection)
              then a plain <code>1</code> if the canary didn't fire
              (catches strict-equality admin flags). A control probe
              with a bogus parameter name runs first to measure the
              endpoint's natural response jitter — only diffs that
              exceed that jitter count.
            </li>
            <li>
              Expand each finding. The evidence JSON names the{" "}
              <code>class</code> the parameter belongs to (
              <code>admin-access</code>, <code>debug</code>,{" "}
              <code>method-override</code>, <code>feature-flag</code>,{" "}
              <code>redirect-target</code>, <code>ssrf-shaped</code>,
              ...) so you can triage by impact class — admin-access
              and method-override are near-immediate escalation
              candidates; pagination finds are usually a SQLi
              precursor. The{" "}
              <code>value_that_matched</code> field tells you which
              probe triggered the signal so you can reproduce the
              exact request in Replay.
            </li>
            <li>
              <strong>Pivot.</strong> A hit on{" "}
              <code>admin</code>, <code>is_admin</code>,{" "}
              <code>role</code>: set it in Replay, fire the request,
              compare content against the public view. A hit on{" "}
              <code>url</code>, <code>fetch</code>,{" "}
              <code>callback_url</code>: re-run the SSRF check with
              the same target URL — Hidden Params doesn't test the
              URL-fetch pathway itself. A hit on{" "}
              <code>sort</code>, <code>order_by</code>,{" "}
              <code>id</code>, <code>uid</code>: re-run SQLi checks
              (error-based, boolean-blind, time-based) — these are
              very commonly SQL-injectable.
            </li>
            <li>
              <strong>Narrow with method override.</strong> A
              finding on <code>_method</code>,{" "}
              <code>X-HTTP-Method-Override</code>, or{" "}
              <code>http_method</code> means the app honours method
              spoofing. Send the request to Replay, change the
              method parameter to <code>DELETE</code> or{" "}
              <code>PUT</code>, and see if the endpoint now performs
              a destructive action it shouldn't from a{" "}
              <code>GET</code>-originated request. Great CSRF-bypass
              signal.
            </li>
          </ol>
          <p className="callout">
            The request budget is roughly <em>wordlist + 2</em> in
            the best case (every hit on the first canary) and
            <em> 2×wordlist + 2</em> in the worst case (nothing
            fires on the canary, every probe retries with{" "}
            <code>1</code>). On a 50 ms-per-request endpoint that's
            roughly 25 seconds — on a chatty WordPress admin it can
            stretch to a minute. The check is disabled in the Checks
            library unless you explicitly tick it; it's too
            expensive to run automatically on every target. Blind
            spots: apps that compare to specific non-<code>1</code>
            {" "}values (e.g. <code>mode == "debug"</code>), apps
            that require POST / JSON bodies, apps that hash-verify
            the query string before processing. Those need manual
            probe crafting after the first pass narrows the surface.
          </p>

          <h4>
            30. Fire path-specific Nuclei templates against a target
            (active Nuclei)
          </h4>
          <p>
            The passive Nuclei path matches templates against traffic
            you've already captured, so it only covers endpoints you
            actually browsed. Templates written for specific paths —{" "}
            <code>/wp-admin/admin-ajax.php</code>,{" "}
            <code>/server-status</code>,{" "}
            <code>/actuator/env</code>,{" "}
            <code>/.git/config</code>, per-CVE URLs — stay silent
            until something requests that path. Active Nuclei fixes
            that: it fires each template's own HTTP requests against
            the target's base URL, exactly how the upstream Nuclei
            CLI does, while sharing corvex's Checks pipeline for
            findings storage and severity mapping.
          </p>
          <ol className="numbered">
            <li>
              Send a request to Checks — any request for the target
              host will do since the active Nuclei check operates on
              the base URL, not the specific path. Scenario 20
              covers <strong>Send to Checks</strong>.
            </li>
            <li>
              In the Checks library, type <code>nuclei-active</code>
              {" "}into the search and tick{" "}
              <em>Nuclei Templates (active execution)</em>. This is
              a single umbrella row — it dispatches to the full
              bundle filtered by severity and KEV tags. Click{" "}
              <strong>Run</strong>.
            </li>
            <li>
              For each eligible template (Critical / High severity
              or tagged <code>kev</code>, <code>rce</code>,{" "}
              <code>auth-bypass</code>, <code>ssrf</code>,{" "}
              <code>sqli</code>, <code>lfi</code>, <code>rfi</code>,{" "}
              <code>xxe</code>, <code>command-injection</code>,{" "}
              <code>fileupload</code>, <code>deserialization</code>,{" "}
              <code>takeover</code>), the runner executes every{" "}
              <code>http:</code> request block in the template
              against the target's base URL. The Executor respects
              each template's <code>stop-at-first-match</code>{" "}
              flag and the per-template request cap (64 by
              default), and caps total in-flight HTTP requests at
              8 across the whole run.
            </li>
            <li>
              Findings land with check id{" "}
              <code>nuclei-active:&lt;template-id&gt;</code> so
              they're clearly distinguishable from the passive
              Nuclei row (<code>nuclei:&lt;template-id&gt;</code>).
              Each evidence JSON includes{" "}
              <code>last_request_method</code>,{" "}
              <code>last_request_uri</code>,{" "}
              <code>last_response_status</code>,{" "}
              <code>matched_at</code>, and any values the
              template's extractor captured (version strings,
              paths, error messages).
            </li>
            <li>
              <strong>Widen the filter.</strong> A full-bundle
              sweep (every Low / Info / Medium template, without
              the tag gate) can surface valuable informational
              findings — open dashboards, exposed debug endpoints,
              misconfigured servers — but the request budget
              explodes by ~10×. Set the env var{" "}
              <code>NUCLEI_ACTIVE_INCLUDE_ALL=1</code> before
              launching the app, then re-run the check. The hard
              cap of 300 templates per target still applies as a
              safety net.
            </li>
            <li>
              <strong>Triage.</strong> Sort findings by severity,
              then by template id prefix — CVE-tagged templates
              point at known vulnerabilities (confirm against the
              NVD URL in the bundled template), while topic-tagged
              templates (<code>exposures/</code>,{" "}
              <code>misconfiguration/</code>,{" "}
              <code>takeovers/</code>) describe operational risk
              that may not have a CVE assigned. Pair with scenario
              25 (Banner-CVE) to cross-reference banner-leaked
              versions against the CVEs a Nuclei hit mentions.
            </li>
          </ol>
          <p className="callout">
            Active Nuclei and the per-template passive descriptors
            (<code>nuclei:&lt;id&gt;</code>) share the same
            template store — refreshing the bundle from{" "}
            <em>Databases → Nuclei templates → Expand coverage</em>
            {" "}updates both paths in the same pass. Blind SSRF
            templates (ones that rely on Interactsh / OOB callbacks)
            are still skipped at load; their finding path needs the
            Interactsh support that's called out in the Deferred
            list. A template that hits during active execution but
            never triggered on passive traffic is <em>expected
            behaviour</em> — that gap is exactly the problem this
            check was built to close.
          </p>

          <h4>
            31. Go from a single domain to a scoped audit in two minutes
          </h4>
          <p>
            The Recon view compresses the "what belongs to this target?"
            step into a single click. Passive sources land a fast first
            cut; active mode expands it; cross-tool actions push the
            results into the rest of the app without any copy-paste.
          </p>
          <ol className="numbered">
            <li>
              Open the sidebar's <strong>Recon</strong> view. Type the
              target domain (e.g. <code>hackerone.com</code>). Leave all
              three passive sources ticked; skip active mode for a
              low-impact first pass.
            </li>
            <li>
              Click <strong>Start recon</strong>. Source chips turn into
              running badges; within seconds the Subdomains table fills
              with hosts attributed to crt.sh / AlienVault OTX /
              CertSpotter. Unresolved hosts (no live A/AAAA) still show
              up — the source tag is meaningful on its own.
            </li>
            <li>
              Skim the table for interesting hosts — staging, admin,
              internal, api, pay, legacy anything. Tick Active mode and
              rerun if you need the DNS record cluster (A/MX/NS/TXT/SOA)
              or want the built-in wordlist to flush out hosts the
              passive sources missed.
            </li>
            <li>
              Click <strong>Scope</strong> on any row (or{" "}
              <strong>Add all to Proxy scope</strong> at the bottom) to
              append matching include rules to the proxy's scope list.
              Flip to Proxy → Settings → Scope rules to confirm. Now
              when you browse, only traffic to those hosts pauses in
              Intercept.
            </li>
            <li>
              With the proxy session running, click{" "}
              <strong>Checks</strong> on the hosts you want to audit —
              corvex synthesises a <code>GET /</code> exchange per host
              (origin <em>imported</em>) and drops it in the Traffic
              tab, ready for Send to Checks / Send to Fuzzer just like a
              real capture.
            </li>
            <li>
              Need fuzzing? Hit <strong>Fuzzer</strong> on a row — the
              Active Fuzzing view opens with the host pre-filled, scope
              forced to <code>page</code>.
            </li>
          </ol>
          <p className="callout">
            Recon results are persisted per run. Use the History tab
            inside Recon to compare a passive sweep today with the
            active run you did last week, or to hand a collaborator a
            snapshot by forwarding <code>history.sqlite</code>.
          </p>
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
              The <em>Select all</em> / <em>Deselect all</em> shortcuts at the
              top of the list flip the entire registry in one click:
              {" "}<em>Select all</em> sets <code>@@ALL</code> (every plugin
              including opt-in extras like <code>nuclei</code>,{" "}
              <code>dictionary</code>, <code>siebel</code>), while{" "}
              <em>Deselect all</em> expands to{" "}
              <code>@@DEFAULT;-p1;-p2;…;-pN</code> — every checkbox off so you
              can cherry-pick one or two plugins for a focused run.
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
            <dt>Bundled Nuclei templates</dt>
            <dd>
              A filtered subset of the ProjectDiscovery nuclei-templates
              library ships with the app under{" "}
              <code>program/databases/nuclei/</code> (severity{" "}
              <em>critical</em> / <em>high</em> / <em>medium</em> plus the
              {" "}<code>kev</code> tag). The sibling{" "}
              <code>MANIFEST.toml</code> pins the upstream release tag and
              per-file commit SHA; the live counts in Databases → Nuclei
              templates read from this directory. In a packaged build the
              same tree lands under the installer's resources dir next to
              the app binary. Templates are MIT-licensed; per-template
              author attribution is preserved in every finding.
            </dd>
            <dt>Tier-2 Nuclei extras cache</dt>
            <dd>
              Optional full-library cache maintained outside the shipped
              bundle. When present it merges on top of the Tier-1 bundle at
              scan time. On Windows the expected path is{" "}
              <code>%APPDATA%\corvex\nuclei-templates\</code>; Databases →
              Nuclei templates shows whether a cache is in place.
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
        <section id="nuclei-catalog">
          <h3>Bundled Nuclei templates</h3>
          <p>
            Every template currently on disk under{" "}
            <code>program/databases/nuclei/</code> (plus the Tier-2 extras
            cache when present). A <em>supported</em> template will run
            during an active-phase scan; a <em>skipped</em> one is parsed
            but not executed because it uses a v1-unsupported feature
            (e.g. <code>raw:</code> requests, unknown DSL helpers,
            interactsh). The list is loaded on first expand so it doesn't
            slow down the rest of the Help view.
          </p>
          <NucleiCatalog />
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
            <dt>Banner CVE cross-reference</dt>
            <dd>
              A passive Checks entry (<code>banner-cve</code>, OWASP A03)
              that pairs Stack Fingerprint detections with the local
              vulndb. For every banner that captured a version, it emits
              one finding per matching CVE with severity mapped from the
              CVSS v3.1 base score. Silent when the vulndb is missing
              or the banner lacks a version — see scenario 25 for a
              worked example.
            </dd>
            <dt>Boolean-blind SQLi</dt>
            <dd>
              Active Checks entry (<code>boolean-blind-sqli</code>,
              OWASP A05) that confirms SQL injection even when the app
              hides database errors. Sends paired{" "}
              <code>AND 1=1</code> / <code>AND 1=2</code> probes across
              four boundary contexts (numeric, single-quote,
              double-quote, paren-quote) and compares response
              similarity against a baseline using a trigram page ratio.
              Finding includes the boundary that fired and three
              similarity ratios for audit.
            </dd>
            <dt>Time-based blind SQLi</dt>
            <dd>
              Active Checks entry (<code>time-based-sqli</code>, OWASP
              A05) that proves SQL injection by stalling the server's
              SQL thread for a measured number of seconds. Uses a
              two-shot oracle (4-second probe, 7-second confirmation)
              and per-DBMS sleep payloads (
              <code>SLEEP</code>, <code>pg_sleep</code>,{" "}
              <code>WAITFOR DELAY</code>,{" "}
              <code>DBMS_PIPE.RECEIVE_MESSAGE</code>). See scenario 27
              for the triage playbook.
            </dd>
            <dt>SSRF — Server-Side Request Forgery</dt>
            <dd>
              Attack class where the server fetches a URL on an
              attacker's behalf, letting the attacker reach networks
              (cloud metadata at <code>169.254.169.254</code>, services
              bound to <code>127.0.0.1</code>) that are not directly
              reachable from the internet. Active Checks entry{" "}
              <code>ssrf</code> (OWASP A10) probes cloud-metadata and
              loopback targets via URL-shaped query parameters and
              confirms on distinctive body markers (AWS IAM keys, GCP
              access tokens, default server landing pages). See
              scenario 28.
            </dd>
            <dt>Hidden-parameter discovery</dt>
            <dd>
              Active Checks entry (<code>hidden-params</code>, OWASP
              A05) that fuzzes a ~220-word wordlist of common
              parameter names (admin flags, debug toggles, feature
              flags, HTTP method overrides, callback handlers,
              redirect targets, URL fetchers, auth tokens, id
              aliases, pagination, CMS hooks) against the target.
              Uses a two-pass oracle: random canary for reflection,
              fallback to <code>1</code> for strict-equality checks.
              Scenario 29 covers the recipe.
            </dd>
            <dt>Active Nuclei execution</dt>
            <dd>
              Umbrella active check (<code>nuclei-active</code>,
              OWASP A03) that runs the HTTP-protocol subset of
              bundled Nuclei templates against the target's base
              URL. Unlike the passive per-template rows (
              <code>nuclei:&lt;id&gt;</code>), this one actually
              sends the template's requests and evaluates matchers
              on the response. Default filter: Critical / High
              severity plus KEV tags; widen with the env var{" "}
              <code>NUCLEI_ACTIVE_INCLUDE_ALL=1</code>. See scenario
              30.
            </dd>
            <dt>IMDS — Instance Metadata Service</dt>
            <dd>
              The HTTP endpoint cloud providers expose to their VMs so
              apps can retrieve instance info and temporary
              credentials. AWS lives at{" "}
              <code>http://169.254.169.254/latest/meta-data/</code>;
              GCP at <code>http://metadata.google.internal/</code>;
              Azure at{" "}
              <code>http://169.254.169.254/metadata/instance</code>.
              Only reachable from inside the instance, which is why
              SSRF against an IMDS endpoint confirms the
              vulnerability beyond doubt.
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
            <dt>Nuclei templates</dt>
            <dd>
              Community-maintained YAML vulnerability templates
              (ProjectDiscovery, MIT). A filtered subset — severity{" "}
              <em>critical</em> / <em>high</em> / <em>medium</em> plus the
              {" "}<code>kev</code> tag — ships bundled under{" "}
              <code>program/databases/nuclei/</code> and is executed by the
              {" "}<code>nuclei</code> plugin during the active phase. Live
              counts, pinned upstream tag, per-severity and per-tag
              breakdowns, and the skipped-bucket reasons are visible under
              Databases → Nuclei templates. Each finding preserves the
              template id, per-template <code>info.author</code> credit, and
              any CVE / CWE classification; overlap with native plugins like
              {" "}<code>spring4shell</code> / <code>shellshock</code> is
              suppressed by{" "}
              <code>program/databases/nuclei/overlap.toml</code> so the same
              vulnerability isn't reported twice on one origin. When a CVE id
              is present and a matching record lives in the local VulnDB, the
              finding is enriched with CVSS / EPSS / description from that
              record rather than emitted as two separate entries. Full MIT
              notice with pinned upstream tag + commit in{" "}
              <code>THIRD_PARTY_LICENSES.md</code>.
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

          <h4>Proxy &amp; traffic interception</h4>
          <dl className="kv">
            <dt>Proxy (MITM)</dt>
            <dd>
              A local HTTP/1 listener that sits between a browser and the
              real servers it wants to reach. "MITM" stands for
              man-in-the-middle — the proxy decrypts TLS with its own
              certificate, logs the request, forwards it to the real
              origin, then re-encrypts the response on the way back.
              Everything happens on loopback by default
              (<code>127.0.0.1:8888</code>).
              <br />
              <em>Example:</em> your browser thinks it's talking to{" "}
              <code>https://shop.example/</code>. It's actually talking
              to corvex, which is talking to <code>shop.example</code> on
              its behalf.
            </dd>

            <dt>Certificate Authority (CA)</dt>
            <dd>
              A self-signed root certificate that corvex generates on
              first launch and uses to mint per-site leaf certificates
              during interception. The browser only trusts the CA if you
              install it in the OS trust store; without that, HTTPS pages
              show a cert warning and the MITM fails.
              <br />
              <em>Where:</em> CA cert + key live under{" "}
              <code>&lt;app-data&gt;/proxy/ca/</code>. Export the cert
              via <em>Proxy → Settings → Certificate authority</em>.
            </dd>

            <dt>SNI leaf certificate</dt>
            <dd>
              The per-host cert the proxy generates on the fly when your
              browser opens a connection. The browser tells corvex which
              hostname it wants via SNI (Server Name Indication), and
              corvex mints a short-lived cert for exactly that hostname,
              signed by the local CA. Cached for 512 hosts per session.
            </dd>

            <dt>CONNECT tunnel</dt>
            <dd>
              The HTTP method a browser uses to ask a proxy to open a
              raw TCP tunnel for HTTPS. The browser sends{" "}
              <code>CONNECT shop.example:443 HTTP/1.1</code>; corvex
              replies <code>200 Connection Established</code>, then
              terminates TLS on that tunnel so it can see the plain
              request.
            </dd>

            <dt>Exchange</dt>
            <dd>
              One request/response pair captured through the proxy. Has a
              ULID-style ID, a session ID, timing info, scope
              classification, and intercept flags. Every row in the
              Traffic tab is an Exchange. Replayed or check-generated
              requests become their own Exchanges linked back to the
              parent.
            </dd>

            <dt>Scope</dt>
            <dd>
              A classification applied to every Exchange: in-scope,
              out-of-scope, or excluded. The traffic log captures
              everything either way, but <em>interactive features</em>{" "}
              (Intercept, Replay edits, active Checks) only act on
              in-scope exchanges. Scope rules live under{" "}
              <em>Proxy → Settings → Scope rules</em>, persist in{" "}
              <code>history.sqlite</code> across restarts, and default
              to "everything is in scope" until you add
              includes/excludes.
            </dd>

            <dt>Scope rule</dt>
            <dd>
              One row in the include or exclude list. Matches on host
              (exact or leading-wildcard like{" "}
              <code>*.example.com</code>), optional path regex, and
              optional port. Exclude matches always win over includes.
              Malformed path regexes are rejected at Save time rather
              than silently fail-closing future matches.
            </dd>

            <dt>Intercept mode</dt>
            <dd>
              A four-state toggle on the Intercept tab: <em>Off</em>{" "}
              (pass-through), <em>Request</em> (pause before the request
              goes upstream), <em>Response</em> (pause after the
              upstream reply, before it reaches the client),{" "}
              <em>Both</em>. Only in-scope exchanges pause; the rest
              pass through silently.
            </dd>

            <dt>Intercept phase (request / response)</dt>
            <dd>
              Which side of the exchange is paused. Rows in the Pending
              queue carry a phase badge: amber <code>→ req</code> means
              the request is held before leaving the listener; blue{" "}
              <code>← resp</code> means the upstream's reply is held
              before delivery to the client. A Both-mode exchange shows
              up twice in the queue over its lifetime.
            </dd>

            <dt>Recon (passive / active)</dt>
            <dd>
              Top-level sidebar view that expands a single domain into
              hosts, subdomains, and DNS records. <em>Passive</em> mode
              queries three keyless public sources (crt.sh, AlienVault
              OTX, CertSpotter) — no traffic touches the target.
              <em> Active</em> mode layers on DNS record enumeration,
              zone-transfer attempts, and wildcard-aware wordlist
              brute-force against the target's authoritative
              nameservers. Results stream live into a grid with per-row
              actions: push to the Proxy scope, inject a synthetic
              Exchange into the active proxy session for Checks, or
              seed the Active Fuzzer. Every run is persisted under{" "}
              <code>recon_runs</code> / <code>recon_findings</code> in
              <code> history.sqlite</code>.
            </dd>

            <dt>Wildcard DNS filtering</dt>
            <dd>
              A catch-all DNS record (<code>*.example.com</code>) makes
              every imaginable subdomain "resolve" to the same IP,
              which would turn every wordlist brute-force into
              thousands of false positives. Before brute-forcing, the
              Recon runner resolves a 32-char random subdomain; if that
              answers, the returned IPs are captured and any brute
              result whose IPs match the wildcard set is dropped.
              Listed in the Recon status line so you can see it firing.
            </dd>

            <dt>Spec import (OpenAPI / Postman)</dt>
            <dd>
              A seeding flow for the Traffic tab. Reads an OpenAPI 3
              <code> .json</code> document (detected by its top-level{" "}
              <code>openapi</code> field) or a Postman v2.1 collection
              (detected by <code>info.schema</code>) and creates one
              synthetic Exchange per documented endpoint — method,
              URL, headers, example request body — with origin{" "}
              <code>imported</code>. The rows appear with no response
              in the Traffic tab until you drive them through Replay.
              Purpose: jump from a spec handoff to a checkable target
              list without clicking every endpoint in a browser first.
              YAML specs aren't supported in v1; convert to JSON with
              <code> swagger-cli bundle</code> or a similar tool first.
            </dd>

            <dt>HAR (HTTP Archive)</dt>
            <dd>
              A JSON file format for captured HTTP sessions. Browsers,
              DevTools, and intercept proxies (Charles, Fiddler,
              Burp-compatible tools) all read and write HAR 1.2. The
              <strong> Export HAR</strong> button in the proxy toolbar
              streams the current session to a <code>.har</code> file:
              one entry per exchange with method, URL, headers, query,
              POST body, status, response headers, and response body.
              Binary bodies ride as{" "}
              <code>encoding: "base64"</code>. A custom{" "}
              <code>_corvexId</code> field on each entry preserves the
              exchange id for cross-referencing with the corvex DB.
            </dd>

            <dt>Retention / ring buffer</dt>
            <dd>
              Per-session cap on how many exchanges the proxy keeps
              around. Configured under{" "}
              <em>Proxy → Settings → Retention</em>. When a running
              session exceeds the cap, the writer deletes the oldest
              rows (and their cascaded scan findings, WebSocket
              frames, and spilled body blobs) every flush tick so the
              visible list stays at the target size. <code>0</code> is
              the explicit "unlimited" sentinel. Completed sessions
              are never retouched — retention is a budget for live
              capture only.
            </dd>

            <dt>Body spill / truncation</dt>
            <dd>
              A capture policy for large request and response bodies.
              Up to <code>512 KB</code> is stored inline in SQLite;
              beyond that, the body is written to a sibling blob file
              (<code>&lt;app-data&gt;/proxy_blobs/</code>) so{" "}
              <code>history.sqlite</code> stays compact. Anything over
              <code>32 MB</code> is forwarded byte-for-byte to the peer
              but only the first 32 MB are recorded — the exchange
              picks up a <code>body-truncated</code> tag so the UI can
              warn you. Prevents a malicious or runaway upstream from
              OOMing the proxy while still letting normal downloads
              stream through.
            </dd>

            <dt>WebSocket frame</dt>
            <dd>
              One message in a WebSocket conversation. The proxy
              captures the RFC 6455 opcode (<code>text</code>,{" "}
              <code>binary</code>, <code>close</code>, <code>ping</code>,{" "}
              <code>pong</code>, or a fragmented <code>cont</code>{" "}
              continuation), the FIN bit, the direction (client →
              upstream or upstream → client), and the payload. Frames
              are forwarded byte-for-byte — capture is observation-only
              in v1, no editing. Upstream-negotiated extensions like{" "}
              <code>permessage-deflate</code> are flagged on the parent
              exchange; payloads for those connections are stored as the
              raw compressed bytes and decode as binary in the viewer.
            </dd>

            <dt>Pending intercept</dt>
            <dd>
              A paused Exchange waiting for your verdict. Each one has a
              oneshot channel on the backend — once you click Forward /
              Forward edited / Drop, the exchange continues (or is
              refused with 502). Auto-forwarded after 5 minutes if
              ignored so upstream sockets don't leak. Edited bytes that
              fail to re-parse as valid HTTP fall back to the original
              (warning logged) so a typo can't silently corrupt the
              wire.
            </dd>

            <dt>Replay</dt>
            <dd>
              Resending any captured Exchange with optional edits. Unlike
              the browser, Replay bypasses the listener and goes through
              corvex's low-level HTTP client so you control the wire
              exactly. Each Replay creates a child Exchange linked back
              to the original.
            </dd>
          </dl>

          <h4>Checks &amp; findings</h4>
          <dl className="kv">
            <dt>Check</dt>
            <dd>
              An analyzer that looks at an Exchange and emits zero or
              more findings. Two kinds:{" "}
              <em>passive</em> (inspects what's already captured — runs
              for free on every in-scope response) and <em>active</em>{" "}
              (sends additional probe requests on demand).
            </dd>

            <dt>Passive check</dt>
            <dd>
              Cheap, synchronous, side-effect-free. Examples shipped:
              Missing Security Headers, Verbose Errors, Version
              Disclosure, Insecure Cookie Flags, Stack Fingerprint, plus
              every bundled Nuclei template that can be evaluated
              without extra requests.
            </dd>

            <dt>Active check</dt>
            <dd>
              Sends crafted requests and interprets the responses.
              Examples shipped: Reflected XSS (canary + context
              breakers), Error-based SQLi (boundary probes + DBMS
              signature bank), Open Redirect (RFC 2606 sentinel host).
              Run these only against systems you own or have written
              permission to test.
            </dd>

            <dt>Finding</dt>
            <dd>
              A single issue raised by one check against one Exchange.
              Has a stable check id, severity (Info / Low / Medium /
              High / Critical), title, description, and a free-form
              evidence JSON blob (matched payload, captured version,
              reflected canary, etc.). Persisted to{" "}
              <code>exchange_scan_findings</code>.
            </dd>

            <dt>OWASP Top 10 (2021)</dt>
            <dd>
              The industry-standard taxonomy for web vulnerabilities.
              corvex groups every Check by category:{" "}
              <code>A01</code> Broken Access Control,{" "}
              <code>A02</code> Cryptographic Failures,{" "}
              <code>A03</code> Injection,{" "}
              <code>A04</code> Insecure Design,{" "}
              <code>A05</code> Security Misconfiguration,{" "}
              <code>A06</code> Vulnerable &amp; Outdated Components,{" "}
              <code>A07</code> Identification &amp; Auth Failures,{" "}
              <code>A08</code> Software &amp; Data Integrity Failures,{" "}
              <code>A09</code> Logging &amp; Monitoring Failures,{" "}
              <code>A10</code> Server-Side Request Forgery. Used to
              group the Checks library in the UI.
            </dd>

            <dt>Canary</dt>
            <dd>
              A unique token injected into a parameter so a matching
              reflection in the response is unambiguously caused by your
              probe and not by pre-existing content. Example:{" "}
              <code>cvxXSS7f3ad019</code>. The Reflected XSS check pairs
              it with context-breakers like{" "}
              <code>"&gt;&lt;svg/onload=cvxXSS7f3ad019&gt;</code>.
            </dd>

            <dt>Sentinel host</dt>
            <dd>
              The Open Redirect check substitutes URL-shaped parameter
              values with <code>corvex-redirect-canary.invalid</code> —
              an RFC 2606 reserved TLD that provably can't resolve to a
              real server. If the target redirects to this host in its{" "}
              <code>Location</code> header, the check is certain the
              redirect was user-controlled without any network risk.
            </dd>

            <dt>Context breaker</dt>
            <dd>
              A payload template designed to break out of the HTML
              context it lands in. For attribute-context:{" "}
              <code>"&gt;&lt;svg/onload=…&gt;</code>. For script-context:{" "}
              <code>&lt;/script&gt;&lt;…&gt;</code>. Reflected XSS
              rotates through several so a single parameter gets tested
              against every likely rendering path.
            </dd>

            <dt>Stack fingerprint</dt>
            <dd>
              The detected web framework / server / language stack
              behind a response. Example:{" "}
              <em>nginx 1.24.0, PHP 8.2.4, WordPress 6.4.2, jQuery
              3.7.1</em>. Runs on every in-scope response as a passive
              check; feeds future CVE cross-referencing work.
            </dd>

            <dt>Wappalyzer schema</dt>
            <dd>
              The industry-standard fingerprint format corvex uses to
              describe a technology: regex patterns against HTTP
              headers, cookies, HTML body, <code>&lt;meta&gt;</code>{" "}
              tags, and URL paths, plus "implied-by" relationships
              (WordPress implies PHP). The engine is schema-compatible
              so upstream datasets can drop in; management of that data
              lives in its own help section.
            </dd>

            <dt>Nuclei template</dt>
            <dd>
              A YAML file from the{" "}
              <code>projectdiscovery/nuclei-templates</code> project
              that describes a vulnerability as a path + a set of
              matchers (word, regex, status, DSL). corvex bundles
              thousands; the Checks tab surfaces each one as a
              togglable library entry, classified into an OWASP
              category by tag heuristic.
            </dd>
          </dl>
        </section>

        {/* ------------------------------------------------------------------ */}
        <section id="limitations">
          <h3>Known limitations</h3>
          <p>Deliberate, up-front honesty — things the app does not do today:</p>
          <ul>
            <li>
              <strong>Nuclei engine v1 coverage is partial.</strong> The
              bundled subset currently runs about one-third of its templates
              against targets; the rest are classified at load time with a
              structured reason visible under Databases → Nuclei templates.
              Dominant gaps: the <code>raw:</code> HTTP-request block (full
              wire requests instead of path-based, roughly 2,000 templates),
              DSL helpers outside the v1 allowlist (~200), templates that
              require a real Interactsh out-of-band server (~65, parse-stubbed
              but never matched), and non-HTTP protocols
              (<code>network</code>, <code>dns</code>, <code>ssl</code>,{" "}
              <code>code</code>, <code>headless</code>). Each of these is a
              targeted v1.1 / v2 lift.
            </li>
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

/* ====================================================================== */
/* NucleiCatalog — expandable, filter-enabled list of every template on   */
/* disk. Fetches from the nuclei_template_list IPC command on first open, */
/* then lets the user narrow the list with a substring match against id,  */
/* name, tags, CVEs, authors, or skip reason.                             */
/* ====================================================================== */

type SevFilter = "all" | "critical" | "high" | "medium" | "low" | "info";
type SupportFilter = "all" | "supported" | "skipped";

function NucleiCatalog() {
  const [opened, setOpened] = useState(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [rows, setRows] = useState<NucleiTemplateEntry[]>([]);
  const [query, setQuery] = useState("");
  const [sev, setSev] = useState<SevFilter>("all");
  const [support, setSupport] = useState<SupportFilter>("all");

  const onToggle = (e: React.SyntheticEvent<HTMLDetailsElement>) => {
    const isOpen = e.currentTarget.open;
    setOpened(isOpen);
    if (isOpen && rows.length === 0 && !loading && !err) {
      setLoading(true);
      nucleiTemplateList()
        .then((list) => {
          setRows(list);
          setLoading(false);
        })
        .catch((e: unknown) => {
          setErr(
            typeof e === "string"
              ? e
              : e instanceof Error
              ? e.message
              : "unknown"
          );
          setLoading(false);
        });
    }
  };

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows.filter((r) => {
      if (sev !== "all" && r.severity !== sev) return false;
      if (support === "supported" && !r.supported) return false;
      if (support === "skipped" && r.supported) return false;
      if (!q) return true;
      if (r.id.toLowerCase().includes(q)) return true;
      if (r.name.toLowerCase().includes(q)) return true;
      if (r.tags.some((t) => t.toLowerCase().includes(q))) return true;
      if (r.cve_ids.some((c) => c.toLowerCase().includes(q))) return true;
      if (r.authors.some((a) => a.toLowerCase().includes(q))) return true;
      if (r.path.toLowerCase().includes(q)) return true;
      if ((r.skip_reason ?? "").toLowerCase().includes(q)) return true;
      return false;
    });
  }, [rows, query, sev, support]);

  const supportedTotal = rows.filter((r) => r.supported).length;
  const skippedTotal = rows.length - supportedTotal;

  const summary = rows.length
    ? `Show full list (${rows.length.toLocaleString()} templates — ${supportedTotal.toLocaleString()} supported, ${skippedTotal.toLocaleString()} skipped)`
    : "Show full list";

  return (
    <details onToggle={onToggle}>
      <summary
        style={{
          cursor: "pointer",
          padding: "6px 10px",
          border: "1px solid var(--border)",
          borderRadius: 6,
          marginTop: 6,
          marginBottom: 10,
          display: "inline-block",
        }}
      >
        {summary}
      </summary>

      {opened && loading && (
        <div className="empty" style={{ marginTop: 8 }}>
          Loading template metadata…
        </div>
      )}

      {opened && err && (
        <div className="empty" style={{ marginTop: 8 }}>
          Failed to load template list: {err}
        </div>
      )}

      {opened && !loading && !err && rows.length > 0 && (
        <>
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: 8,
              marginTop: 6,
              marginBottom: 8,
              alignItems: "center",
            }}
          >
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by id / name / tag / CVE / author / skip reason…"
              style={{
                flex: "1 1 260px",
                padding: "4px 8px",
                fontSize: "calc(var(--font-base) - 1px)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                background: "var(--panel)",
                color: "var(--fg)",
              }}
            />
            <select
              value={sev}
              onChange={(e) => setSev(e.target.value as SevFilter)}
              style={{ padding: "3px 6px" }}
            >
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            <select
              value={support}
              onChange={(e) => setSupport(e.target.value as SupportFilter)}
              style={{ padding: "3px 6px" }}
            >
              <option value="all">Supported + skipped</option>
              <option value="supported">Supported only</option>
              <option value="skipped">Skipped only</option>
            </select>
            <span
              className="sub"
              style={{ fontFamily: "monospace", fontSize: "calc(var(--font-base) - 2px)" }}
            >
              showing {filtered.length.toLocaleString()} of{" "}
              {rows.length.toLocaleString()}
            </span>
          </div>

          <div
            style={{
              maxHeight: 520,
              overflow: "auto",
              border: "1px solid var(--border)",
              borderRadius: 4,
              contentVisibility: "auto",
            }}
          >
            <table
              className="findings-table"
              style={{ fontSize: "calc(var(--font-base) - 2px)", width: "100%" }}
            >
              <thead>
                <tr>
                  <th style={{ width: "34%" }}>ID</th>
                  <th style={{ width: "10%" }}>Severity</th>
                  <th style={{ width: "20%" }}>Tags</th>
                  <th style={{ width: "18%" }}>CVE(s)</th>
                  <th style={{ width: "18%" }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 1000).map((r) => (
                  <tr key={r.id + r.path} title={r.name || r.path}>
                    <td style={{ fontFamily: "monospace" }}>{r.id}</td>
                    <td>
                      {r.severity ? (
                        <span
                          className={`sev-pill sev-${r.severity}`}
                          style={{
                            fontSize: "calc(var(--font-base) - 3px)",
                            textTransform: "uppercase",
                          }}
                        >
                          {r.severity}
                        </span>
                      ) : (
                        <span className="sub">—</span>
                      )}
                    </td>
                    <td style={{ fontFamily: "monospace" }}>
                      {r.tags.slice(0, 4).join(", ")}
                      {r.tags.length > 4 ? ` +${r.tags.length - 4}` : ""}
                    </td>
                    <td style={{ fontFamily: "monospace" }}>
                      {r.cve_ids.join(", ") || <span className="sub">—</span>}
                    </td>
                    <td>
                      {r.supported ? (
                        <span style={{ color: "var(--success)" }}>supported</span>
                      ) : (
                        <span
                          style={{ color: "var(--warning)" }}
                          title={r.skip_reason ?? ""}
                        >
                          {r.skip_reason ?? "skipped"}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filtered.length > 1000 && (
              <div
                className="sub"
                style={{ padding: "6px 10px", textAlign: "center" }}
              >
                Showing the first 1,000 of {filtered.length.toLocaleString()}.
                Tighten the filter to narrow the list.
              </div>
            )}
          </div>
        </>
      )}
    </details>
  );
}
