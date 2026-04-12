/**
 * Shows the active-fuzzing module inventory: which fuzzers ship with
 * this build, their injection types, payload classes, and status.
 */

interface FuzzerModule {
  name: string;
  category: "injection" | "fingerprint" | "cve";
  status: "ready" | "planned";
  description: string;
  injectionTypes: string[];
  payloads: string;
}

const MODULES: FuzzerModule[] = [
  // ---- Core injection -------------------------------------------------------
  {
    name: "xss_reflected",
    category: "injection",
    status: "planned",
    description: "Injects canary strings into every parameter and checks if they appear unescaped in the response body (HTML context, attribute context, JS context).",
    injectionTypes: ["Query", "Body", "Cookie"],
    payloads: "Escalating: plain canary, \"><svg/onload=, script injection, attribute escape",
  },
  {
    name: "xss_stored",
    category: "injection",
    status: "planned",
    description: "Submits a canary into forms, then re-crawls the site looking for the canary reflected on other pages.",
    injectionTypes: ["Body"],
    payloads: "Unique per-scan canary token",
  },
  {
    name: "sqli_error",
    category: "injection",
    status: "ready",
    description: "Injects quote characters and SQL fragments, scans responses for database error messages (MySQL, PostgreSQL, MSSQL, SQLite, Oracle, MariaDB, DB2, Firebird). Extracts version data via EXTRACTVALUE/UPDATEXML/CAST.",
    injectionTypes: ["Query", "Body"],
    payloads: "', \", \\, ' OR '1'='1, EXTRACTVALUE, UPDATEXML, CAST",
  },
  {
    name: "sqli_boolean",
    category: "injection",
    status: "ready",
    description: "Differential analysis: injects TRUE vs FALSE conditions and compares response body via trigram page-ratio. Double-confirms with secondary boolean pair.",
    injectionTypes: ["Query", "Body"],
    payloads: "1 AND 1=1 vs 1 AND 1=2, ' AND '1'='1 vs ' AND '1'='2",
  },
  {
    name: "sqli_time",
    category: "injection",
    status: "ready",
    description: "Time-based blind SQLi: injects SLEEP/WAITFOR/pg_sleep payloads and measures round-trip time. Confirms with doubled delay. Supports 8+ DBMS backends.",
    injectionTypes: ["Query", "Body"],
    payloads: "SLEEP(n), WAITFOR DELAY, pg_sleep(n), DBMS_PIPE.RECEIVE_MESSAGE, BENCHMARK",
  },
  {
    name: "sqli_union",
    category: "injection",
    status: "ready",
    description: "UNION query-based: determines column count via ORDER BY, finds visible columns via marker injection, extracts data (version, database, user) through visible column.",
    injectionTypes: ["Query", "Body"],
    payloads: "ORDER BY n, UNION ALL SELECT NULL,..., marker canary injection",
  },
  {
    name: "sqli_stacked",
    category: "injection",
    status: "ready",
    description: "Stacked queries: tests semicolon-separated statement support via time-based confirmation. Primarily MSSQL/PostgreSQL. Requires risk >= 2.",
    injectionTypes: ["Query", "Body"],
    payloads: "; WAITFOR DELAY, ; SELECT pg_sleep(n), ; SELECT SLEEP(n)",
  },
  {
    name: "sqli_enumerate",
    category: "injection",
    status: "ready",
    description: "Post-detection enumeration: extracts databases, tables, columns, users, password hashes. Supports boolean binary-search and UNION extraction across 8+ DBMS.",
    injectionTypes: [],
    payloads: "information_schema, pg_database, sysdatabases, all_tables, sqlite_master",
  },
  {
    name: "sqli_exploit",
    category: "injection",
    status: "ready",
    description: "Post-exploitation: file read (LOAD_FILE, pg_read_file), file write (INTO OUTFILE, COPY TO), OS command execution (xp_cmdshell, COPY TO PROGRAM). Requires risk 3.",
    injectionTypes: [],
    payloads: "LOAD_FILE, INTO OUTFILE, xp_cmdshell, COPY TO PROGRAM, UDF injection",
  },
  {
    name: "lfi_active",
    category: "injection",
    status: "planned",
    description: "Injects LFI traversal paths into discovered parameters (not just db_tests templates). Reuses the @LFI() payload generator.",
    injectionTypes: ["Query", "Body", "PathSegment"],
    payloads: "../../../etc/hosts, ..\\Windows\\win.ini (depth + platform aware)",
  },
  {
    name: "cmd_injection",
    category: "injection",
    status: "planned",
    description: "Injects OS command separators and sleep payloads, detects via timing (like time-based SQLi) or output matching.",
    injectionTypes: ["Query", "Body", "Header"],
    payloads: ";sleep 5, |sleep 5, `sleep 5`, $(sleep 5)",
  },
  {
    name: "crlf",
    category: "injection",
    status: "planned",
    description: "Injects CRLF sequences to split HTTP headers. Detects by looking for a canary Set-Cookie header in the response.",
    injectionTypes: ["Query"],
    payloads: "%0D%0ASet-Cookie:corvex=1",
  },
  {
    name: "open_redirect",
    category: "injection",
    status: "planned",
    description: "Injects external URLs into common redirect parameters (url, redirect, next, returnUrl). Checks 3xx Location header.",
    injectionTypes: ["Query"],
    payloads: "https://attacker.test/redirect-canary",
  },
  // ---- Advanced injection ---------------------------------------------------
  {
    name: "xxe",
    category: "injection",
    status: "planned",
    description: "Crafts XML payloads with ENTITY declarations targeting local files. Sends to XML-accepting endpoints.",
    injectionTypes: ["Body (XML)"],
    payloads: "<!ENTITY xxe SYSTEM \"file:///etc/hosts\">",
  },
  {
    name: "ssti",
    category: "injection",
    status: "planned",
    description: "Server-Side Template Injection: injects arithmetic expressions ({{7*7}}) for Jinja2, Twig, ERB, Velocity, Freemarker, Handlebars.",
    injectionTypes: ["Query", "Body"],
    payloads: "{{7*7}}, ${7*7}, #{7*7}, <% 7*7 %>",
  },
  {
    name: "ssrf",
    category: "injection",
    status: "planned",
    description: "Injects internal URLs (metadata endpoint, localhost) into parameters to detect server-side request forgery.",
    injectionTypes: ["Query", "Body"],
    payloads: "http://169.254.169.254/latest/meta-data/, http://127.0.0.1/",
  },
  {
    name: "file_upload",
    category: "injection",
    status: "planned",
    description: "Uploads a webshell disguised as an image, then requests it back to check if server-side execution occurred.",
    injectionTypes: ["Body (multipart)"],
    payloads: ".php/.jsp/.asp disguised as .jpg",
  },
  // ---- Fingerprinting -------------------------------------------------------
  {
    name: "cms",
    category: "fingerprint",
    status: "planned",
    description: "Detects CMS platforms (WordPress, Drupal, Joomla, SPIP, Magento) via known paths and meta generator tags.",
    injectionTypes: [],
    payloads: "/wp-login.php, /user/login, /administrator/, <meta name=\"generator\">",
  },
  {
    name: "tech",
    category: "fingerprint",
    status: "planned",
    description: "Technology fingerprinting via response headers, cookies, meta tags, script sources, and body patterns. CVE correlation.",
    injectionTypes: [],
    payloads: "db_technologies database (header regex, cookie, meta tag, URL, body)",
  },
  {
    name: "subdomain_takeover",
    category: "fingerprint",
    status: "planned",
    description: "Checks DNS CNAME records against known takeover fingerprints (GitHub Pages, S3, Heroku, Azure, etc.).",
    injectionTypes: [],
    payloads: "db_takeover fingerprint regexes",
  },
  // ---- CVE chains -----------------------------------------------------------
  {
    name: "log4shell",
    category: "cve",
    status: "planned",
    description: "Injects ${jndi:ldap://...} into headers and parameters to detect Log4j RCE (CVE-2021-44228).",
    injectionTypes: ["Header", "Query", "Body"],
    payloads: "${jndi:ldap://<canary>/a}",
  },
  {
    name: "spring4shell",
    category: "cve",
    status: "planned",
    description: "POSTs the CVE-2022-22965 classLoader manipulation payload and checks for JSP write confirmation.",
    injectionTypes: ["Body"],
    payloads: "class.module.classLoader.resources.context.parent.pipeline.first.pattern",
  },
];

const STATUS_COLORS: Record<string, string> = {
  ready: "var(--success)",
  planned: "var(--warning)",
};

const CATEGORY_LABELS: Record<string, string> = {
  injection: "Injection",
  fingerprint: "Fingerprint",
  cve: "CVE Chain",
};

export function FuzzingView() {
  const grouped = {
    injection: MODULES.filter((m) => m.category === "injection"),
    fingerprint: MODULES.filter((m) => m.category === "fingerprint"),
    cve: MODULES.filter((m) => m.category === "cve"),
  };

  return (
    <div className="history-view" style={{ overflow: "auto" }}>
      <div className="history-header">
        <div>
          <h2
            style={{
              margin: 0,
              fontSize: 13,
              color: "var(--fg)",
              textTransform: "none",
              letterSpacing: 0,
            }}
          >
            Active fuzzer modules ({MODULES.length})
          </h2>
          <div className="sub" style={{ marginTop: 4 }}>
            The active engine crawls the target, extracts forms and
            parameters, then runs these modules against every discovered
            injection point. Enable via the "Active fuzzing" checkbox on
            the Dashboard or <code>--active</code> on the CLI.
          </div>
        </div>
      </div>

      {(["injection", "fingerprint", "cve"] as const).map((cat) => (
        <div key={cat} style={{ marginBottom: 20 }}>
          <h3
            style={{
              fontSize: 12,
              fontWeight: 600,
              color: "var(--muted)",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              margin: "12px 0 8px 0",
            }}
          >
            {CATEGORY_LABELS[cat]} ({grouped[cat].length})
          </h3>
          <div style={{ overflowX: "auto" }}>
            <table className="findings-table" style={{ tableLayout: "auto" }}>
              <colgroup>
                <col style={{ width: "18%" }} />
                <col style={{ width: "8%" }} />
                <col style={{ width: "auto" }} />
                <col style={{ width: "22%" }} />
                <col style={{ width: "22%" }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Module</th>
                  <th>Status</th>
                  <th>Description</th>
                  <th>Injection types</th>
                  <th>Payloads</th>
                </tr>
              </thead>
              <tbody>
                {grouped[cat].map((m) => (
                  <tr key={m.name}>
                    <td>
                      <code>{m.name}</code>
                    </td>
                    <td>
                      <span
                        className="badge"
                        style={{
                          color: STATUS_COLORS[m.status],
                          borderColor: STATUS_COLORS[m.status],
                        }}
                      >
                        {m.status}
                      </span>
                    </td>
                    <td style={{ whiteSpace: "normal" }}>{m.description}</td>
                    <td>
                      {m.injectionTypes.length > 0
                        ? m.injectionTypes.map((t) => (
                            <span
                              key={t}
                              className="badge"
                              style={{ marginRight: 4, marginBottom: 2, display: "inline-block" }}
                            >
                              {t}
                            </span>
                          ))
                        : "—"}
                    </td>
                    <td style={{ whiteSpace: "normal", fontSize: 11 }}>
                      <code>{m.payloads}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </div>
  );
}
