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
          </ul>
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
              <strong>Response</strong> — pauses after the server replies,
              before the response reaches the browser. Handler arrives with
              Phase 4.
            </li>
            <li>
              <strong>Both</strong> — pauses at both sides.
            </li>
          </ul>
          <p>
            Only <em>in-scope</em> requests pause — browser background
            traffic (analytics, telemetry) is logged but never interrupts
            you. Scope rules are authored in Settings; the default is
            "capture everything, intercept none" until you add rules.
          </p>
          <p>
            When a request pauses, a row appears in the <em>Pending</em>{" "}
            queue on the left (method, URL, phase). Click it and the right
            pane fills with the raw HTTP/1 bytes ready for editing. Three
            buttons wait at the bottom:
          </p>
          <ul>
            <li>
              <strong>Forward</strong> — send the bytes as-is. (The button
              re-labels to <strong>Forward edited</strong> the moment you
              touch the editor.)
            </li>
            <li>
              <strong>Drop</strong> — refuse the request. The browser
              receives a <code>502 Bad Gateway</code>.
            </li>
            <li>
              <strong>Drop all</strong> (above the queue) — release every
              pending intercept with Forward. Useful when switching mode
              back to Off.
            </li>
          </ul>
          <p>
            <strong>Example of an edit.</strong> A login form submits{" "}
            <code>POST /auth/login</code> with a JSON body:
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
            editor, click <strong>Forward edited</strong>. The backend
            re-parses your bytes and sends them upstream. If the parse
            fails (e.g. you accidentally deleted the blank line between
            headers and body), the exchange stays paused and the UI shows a
            parse error instead of silently corrupting the wire request.
          </p>
          <p className="callout">
            Safety net: if you walk away, every pending intercept
            auto-forwards after 5 minutes so upstream sockets don't leak.
            <code>Connection: close</code> is forced on every forwarded
            request — don't worry about keep-alive semantics.
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
            </em> passive finding you'll see on most exchanges, and (in a
            follow-up iteration) the Banner-CVE cross-reference. The engine
            follows the Wappalyzer technology schema — a battle-tested
            format that describes products as regex patterns against HTTP
            headers, cookies, response HTML, meta tags, URL paths, and
            implied-by relationships.
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
              in-scope exchanges. Scope rules live under Settings and
              default to "everything is in scope" until you add
              includes/excludes.
            </dd>

            <dt>Intercept mode</dt>
            <dd>
              A four-state toggle on the Intercept tab: <em>Off</em>{" "}
              (pass-through), <em>Request</em> (pause before the request
              goes upstream), <em>Response</em> (pause before the
              response reaches the browser), <em>Both</em>. Only
              in-scope exchanges pause; the rest pass through silently.
            </dd>

            <dt>Pending intercept</dt>
            <dd>
              A paused Exchange waiting for your verdict. Each one has a
              oneshot channel on the backend — once you click Forward /
              Forward edited / Drop, the request continues (or is
              refused with 502). Auto-forwarded after 5 minutes if
              ignored so upstream sockets don't leak.
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
