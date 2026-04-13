/**
 * Shows the active-fuzzing module inventory: which fuzzers ship with
 * this build, their injection types, payload classes, and status.
 * Includes detailed reference sections for the SQL injection engine.
 */

import { useState } from "react";

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
    description: "Injects boundary characters (' \" \\ ) )) and SQL fragments, then scans the response for 48 database error patterns across 8 DBMS backends. When an error is detected, the DBMS is fingerprinted and data extraction is attempted via EXTRACTVALUE (MySQL), UPDATEXML (MySQL), CAST/CONVERT (MSSQL/PostgreSQL), or CTXSYS.DRITHSX.SN (Oracle). Typically requires only 1-3 requests per parameter. Highest priority technique.",
    injectionTypes: ["Query", "Body"],
    payloads: "', \", \\, ), ')), ' OR '1'='1, EXTRACTVALUE(1,CONCAT(0x7e,VERSION())), CAST(@@VERSION AS INT), UPDATEXML(1,CONCAT(0x7e,VERSION()),1)",
  },
  {
    name: "sqli_boolean",
    category: "injection",
    status: "ready",
    description: "Sends paired true/false SQL conditions (e.g. AND 1=1 vs AND 1=2) and compares the response bodies using trigram page-ratio analysis. If the true condition produces the same page as the baseline but the false condition produces a different page, the parameter is injectable. Confirms every detection with a secondary boolean pair (AND 2>1 vs AND 2<1) to reduce false positives. Supports AND-based (risk 1) and OR-based (risk 2) payloads at multiple nesting levels (' AND, ') AND, ')) AND).",
    injectionTypes: ["Query", "Body"],
    payloads: "' AND '1'='1 / ' AND '1'='2, ') AND ('1'='1 / ') AND ('1'='2, 1 AND 1=1 / 1 AND 1=2, AND 2>1 / AND 2<1",
  },
  {
    name: "sqli_time",
    category: "injection",
    status: "ready",
    description: "Injects DBMS-specific time delay payloads and measures response time against a baseline median (3 samples). If the response exceeds baseline + delay * 0.8, tentatively marks as vulnerable, then confirms with a doubled delay checking for proportional time increase. Works when there is zero visible difference in the response body. Supports OAST DNS callbacks for out-of-band confirmation when --oast is set. Slowest technique due to intentional delays. Request timeout is automatically extended to accommodate the injected delay.",
    injectionTypes: ["Query", "Body"],
    payloads: "MySQL: SLEEP(n), BENCHMARK(5000000,SHA1('test')) | PostgreSQL: pg_sleep(n) | MSSQL: WAITFOR DELAY '0:0:n' | Oracle: DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),n) | SQLite: LIKE('A',UPPER(HEX(RANDOMBLOB(n00000000/2))))",
  },
  {
    name: "sqli_union",
    category: "injection",
    status: "ready",
    description: "Determines column count via binary-search ORDER BY probing (ORDER BY 1, 2, 4, 8... up to 50), then falls back to UNION SELECT NULL,NULL,... if ORDER BY doesn't work. Once the column count is known, injects a unique marker string into each column position to find which one is reflected in the response. Then extracts VERSION(), DATABASE(), and CURRENT_USER() through the visible column. Handles DBMS-specific syntax: Oracle requires FROM DUAL, MSSQL uses TOP 1, DB2 requires FROM SYSIBM.SYSDUMMY1. Most powerful technique for direct data extraction.",
    injectionTypes: ["Query", "Body"],
    payloads: "' ORDER BY n--, ' UNION ALL SELECT NULL,...,NULL--, ' UNION ALL SELECT NULL,...,'q6zq9qMARKERq6zq9q',...,NULL--, CONCAT(marker,VERSION(),marker)",
  },
  {
    name: "sqli_stacked",
    category: "injection",
    status: "ready",
    description: "Tests whether the database driver supports multiple SQL statements separated by semicolons (piggy-backing). Uses time-based confirmation: injects '; WAITFOR DELAY' (MSSQL), '; SELECT pg_sleep()' (PostgreSQL), or '; SELECT SLEEP()' (MySQL) and measures response time. Stacked queries enable INSERT/UPDATE/DELETE and direct OS command execution. Only effective when the application uses a database driver that supports multi-statement execution. Requires risk >= 2.",
    injectionTypes: ["Query", "Body"],
    payloads: "'; WAITFOR DELAY '0:0:n'--, '; SELECT pg_sleep(n)--, '); SELECT SLEEP(n)--, 1; WAITFOR DELAY '0:0:n'--",
  },
  {
    name: "sqli_enumerate",
    category: "injection",
    status: "ready",
    description: "Post-detection database enumeration using whichever technique confirmed the injection. UNION-based extraction is fastest (direct query substitution). Boolean-blind uses character-by-character binary search via ASCII/ORD bisection (~8 requests per character). Time-blind uses the same binary search but with timing instead of response differences. Supports: database/schema listing, table enumeration, column discovery, user accounts, password hashes (mysql.user, pg_shadow, sys.sql_logins, dba_users), and privilege mapping. DBMS-specific catalog queries for MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MariaDB, DB2, and Firebird.",
    injectionTypes: [],
    payloads: "information_schema.schemata, information_schema.tables, information_schema.columns, pg_database, master..sysdatabases, all_tables, all_tab_columns, sqlite_master, PRAGMA table_info(), syscat.tables, RDB$RELATIONS",
  },
  {
    name: "sqli_exploit",
    category: "injection",
    status: "ready",
    description: "Post-exploitation capabilities requiring risk 3. File read: MySQL LOAD_FILE(), PostgreSQL pg_read_file(), MSSQL OPENROWSET(BULK, SINGLE_CLOB), Oracle UTL_FILE.GET_RAW(). File write: MySQL SELECT INTO OUTFILE, PostgreSQL COPY TO, MSSQL xp_cmdshell echo. OS command execution: MSSQL xp_cmdshell (auto-enables via sp_configure if disabled), PostgreSQL COPY TO PROGRAM (>= 9.3), MySQL UDF sys_exec() via shared library, Oracle DBMS_SCHEDULER.CREATE_JOB. All exploitation functions emit warnings before execution and are gated behind risk level 3.",
    injectionTypes: [],
    payloads: "LOAD_FILE('/etc/passwd'), SELECT '...' INTO OUTFILE '/path', EXEC xp_cmdshell 'cmd', COPY (SELECT '') TO PROGRAM 'cmd', SELECT sys_exec('cmd'), DBMS_SCHEDULER.CREATE_JOB(...)",
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

/* ---- Reference data for the detail panels ---- */

const TECHNIQUES = [
  {
    code: "E",
    name: "Error-based",
    priority: 1,
    requests: "1-3 per parameter",
    description:
      "Injects boundary characters and SQL fragments, then scans the HTTP response for known database error messages. Corvex matches against 48 regex patterns covering 8 DBMS backends. When an error is found, the DBMS is fingerprinted automatically.",
    how: "Sends probes like ', \", \\, ), ')) into each parameter. If the response contains an error string (e.g. \"You have an error in your SQL syntax\" for MySQL, \"ORA-01756\" for Oracle), the parameter is confirmed injectable. At level >= 2, the engine attempts data extraction using error-leaking functions.",
    extraction:
      "MySQL: EXTRACTVALUE(1,CONCAT(0x7e,VERSION())), UPDATEXML() | MSSQL: CAST(@@VERSION AS INT), CONVERT() | PostgreSQL: CAST(version() AS INT) | Oracle: CTXSYS.DRITHSX.SN(), UTL_INADDR.GET_HOST_NAME()",
    dbms: "All 8 backends",
  },
  {
    code: "B",
    name: "Boolean-based blind",
    priority: 2,
    requests: "3-6 per parameter",
    description:
      "Detects injection by comparing how the application responds to logically true vs false SQL conditions. No error messages are needed \u2014 only a measurable difference in the response body.",
    how: "Sends a true payload (e.g. ' AND '1'='1) and compares the response to the baseline using trigram page-ratio analysis (0.0-1.0 similarity). Then sends a false payload (' AND '1'='2). If the true response matches the baseline (ratio > 0.9) but the false response differs (ratio < 0.6), the parameter is injectable. Every positive is double-confirmed with a secondary pair (AND 2>1 vs AND 2<1).",
    extraction:
      "Character-by-character binary search using ASCII/ORD bisection: AND ASCII(SUBSTRING(version(),1,1))>64 \u2014 approximately 8 requests per character extracted.",
    dbms: "All 8 backends (DBMS-specific comparison functions: LENGTH/LEN, MID/SUBSTRING)",
  },
  {
    code: "T",
    name: "Time-based blind",
    priority: 3,
    requests: "6+ per parameter (includes baseline + confirmation)",
    description:
      "Last-resort technique for when there is absolutely no visible difference in the response. Injects time delay payloads and measures whether the response takes significantly longer than normal.",
    how: "First measures baseline response time (median of 3 requests). Then injects a delay payload (e.g. AND SLEEP(5)). If the response takes longer than baseline + delay\u00d70.8, tentatively marks as vulnerable. Confirms by injecting a doubled delay (SLEEP(10)) and checking that the response time increases proportionally. Request timeout is automatically extended.",
    extraction:
      "Same binary-search as boolean-blind, but uses timing instead of page content: AND IF(ASCII(SUBSTRING(version(),1,1))>64,SLEEP(5),0). Approximately 8 requests per character, each taking delay seconds.",
    dbms: "MySQL: SLEEP(), BENCHMARK() | PostgreSQL: pg_sleep() | MSSQL: WAITFOR DELAY | Oracle: DBMS_PIPE.RECEIVE_MESSAGE() | SQLite: RANDOMBLOB CPU burn",
  },
  {
    code: "U",
    name: "UNION query-based",
    priority: 4,
    requests: "10-30 per parameter",
    description:
      "The most powerful technique for direct data extraction. Appends a UNION SELECT statement to the original query to inject attacker-controlled output into the page.",
    how: "Step 1: Determine column count via binary-search ORDER BY (ORDER BY 1, 2, 4, 8...) or fallback UNION SELECT NULL,NULL,... probing (up to 50 columns). Step 2: Find visible column by injecting a unique marker string into each column position and checking if it appears in the response. Step 3: Replace the marker with SQL expressions (VERSION(), DATABASE(), CURRENT_USER()) to extract data directly.",
    extraction:
      "Direct substitution: UNION ALL SELECT NULL,CONCAT(marker,version(),marker),NULL FROM DUAL. Output appears directly in the response body. Handles DBMS-specific syntax \u2014 Oracle: FROM DUAL, DB2: FROM SYSIBM.SYSDUMMY1, Firebird: FROM RDB$DATABASE.",
    dbms: "All 8 backends (DBMS-specific FROM clause, string concatenation, type casting)",
  },
  {
    code: "S",
    name: "Stacked queries",
    priority: 5,
    requests: "6+ per parameter",
    description:
      "Tests whether the database driver supports executing multiple SQL statements separated by semicolons. This enables INSERT, UPDATE, DELETE, and direct OS command execution. Requires risk >= 2.",
    how: "Injects a semicolon followed by a time-delay statement (e.g. '; WAITFOR DELAY '0:0:5'-- for MSSQL, '; SELECT pg_sleep(5)-- for PostgreSQL). Measures response time against baseline. Confirms with doubled delay. Only effective when the application's database driver supports multi-statement execution \u2014 primarily MSSQL (always), PostgreSQL (usually), MySQL (sometimes, depends on API).",
    extraction:
      "Once confirmed, can execute arbitrary SQL: INSERT/UPDATE for data modification, xp_cmdshell for OS commands (MSSQL), COPY TO PROGRAM (PostgreSQL), or DBMS_SCHEDULER (Oracle).",
    dbms: "MSSQL (always), PostgreSQL (usually), MySQL/MariaDB (driver-dependent)",
  },
];

const TAMPER_MODULES = [
  {
    category: "Space replacement",
    count: 8,
    modules: [
      { name: "space2comment", desc: "Replace spaces with /**/" },
      { name: "space2hash", desc: "MySQL: replace space with #\\n" },
      { name: "space2dash", desc: "Replace spaces with --\\n" },
      { name: "space2mssqlblank", desc: "MSSQL: random blank chars (%01-%0F)" },
      { name: "space2mssqlhash", desc: "MSSQL: %23\\n" },
      { name: "space2morehash", desc: "MySQL >=5.1: #\\n with versioned comments" },
      { name: "space2plus", desc: "Replace spaces with +" },
      { name: "space2randomblank", desc: "Random whitespace: %09, %0A, %0C, %0D" },
    ],
  },
  {
    category: "Encoding",
    count: 10,
    modules: [
      { name: "charencode", desc: "URL-encode all non-alphanumeric characters" },
      { name: "chardoubleencode", desc: "Double URL-encode (encode the % signs)" },
      { name: "charunicodeencode", desc: "Unicode URL-encode (%u0041 for A)" },
      { name: "base64encode", desc: "Base64-encode the entire payload" },
      { name: "htmlencode", desc: "HTML entity encoding (&#65; for A)" },
      { name: "overlongutf8", desc: "Overlong 2-byte UTF-8 for ASCII chars" },
      { name: "percentage", desc: "MSSQL: insert % between chars (SE%LE%CT)" },
      { name: "unionalltounion", desc: "Replace UNION ALL SELECT with UNION SELECT" },
      { name: "unmagicquotes", desc: "Bypass PHP magic_quotes with %BF%27" },
      { name: "hex2char", desc: "Replace 0xNN hex literals with CHAR(NN)" },
    ],
  },
  {
    category: "Keyword obfuscation",
    count: 12,
    modules: [
      { name: "randomcase", desc: "Randomize SQL keyword casing (sElEcT)" },
      { name: "randomcomments", desc: "Insert /**/ inside keywords (SEL/**/ECT)" },
      { name: "versionedkeywords", desc: "MySQL: /*!50000 UNION*/ versioned comments" },
      { name: "versionedmorekeywords", desc: "Extended versioned comments for more keywords" },
      { name: "halfversionedmorekeywords", desc: "Opening /*!... without closing comment" },
      { name: "informationschemacomment", desc: "Add /**/ after information_schema" },
      { name: "capitalletters", desc: "Uppercase all SQL keywords" },
      { name: "lowercase", desc: "Lowercase all SQL keywords" },
      { name: "concat2concatws", desc: "Replace CONCAT() with CONCAT_WS('',)" },
      { name: "commalesslimit", desc: "LIMIT N,M to LIMIT M OFFSET N" },
      { name: "commalessmid", desc: "MID(a,b,c) to MID(a FROM b FOR c)" },
      { name: "commentbeforeparentheses", desc: "Add /**/ before every (" },
    ],
  },
  {
    category: "Comparison & logic",
    count: 8,
    modules: [
      { name: "between", desc: "Replace > with NOT BETWEEN 0 AND" },
      { name: "greatest", desc: "Replace > with GREATEST() equivalent" },
      { name: "least", desc: "Replace < with LEAST() equivalent" },
      { name: "equaltolike", desc: "Replace = with LIKE" },
      { name: "ifnull2casewhenisnull", desc: "IFNULL to CASE WHEN IS NULL" },
      { name: "ifnull2ifisnull", desc: "IFNULL to IF(ISNULL(),...)" },
      { name: "bluecoat", desc: "= to LIKE + space to %09 (BlueCoat bypass)" },
      { name: "modsecurityversioned", desc: "Wrap entire payload in /*!...*/  (ModSecurity)" },
    ],
  },
  {
    category: "Injection prefix/suffix",
    count: 7,
    modules: [
      { name: "apostrophemask", desc: "Replace ' with UTF-8 fullwidth %EF%BC%87" },
      { name: "apostrophenullencode", desc: "Replace ' with %00%27 (null byte)" },
      { name: "appendnullbyte", desc: "Append %00 to the payload" },
      { name: "nonrecursivereplacement", desc: "Double keywords: SELSELECTECT (filter bypass)" },
      { name: "symboliclogical", desc: "AND/OR to &&/|| (symbolic operators)" },
      { name: "misunion", desc: "Replace UNION with -.1UNION" },
      { name: "dunion", desc: "Replace UNION with DUNION" },
    ],
  },
  {
    category: "Advanced / DBMS-specific",
    count: 5,
    modules: [
      { name: "sp_password", desc: "MSSQL: append sp_password to hide from T-SQL logs" },
      { name: "schemasplit", desc: "Split FROM schema.table into subquery" },
      { name: "luanginx", desc: "Lua-Nginx WAF bypass via \\r\\n injection" },
      { name: "sleep2getlock", desc: "MySQL: replace SLEEP() with GET_LOCK()" },
      { name: "substr2mid", desc: "Replace SUBSTR/SUBSTRING with MID()" },
    ],
  },
];

const DBMS_DETAILS = [
  { name: "MySQL", errors: "SQL syntax.*?MySQL, Warning.*?mysqli_, You have an error in your SQL syntax, Unknown column, com.mysql.jdbc", sleep: "SLEEP(n), BENCHMARK()", concat: "CONCAT(a,b)", catalog: "information_schema.schemata / .tables / .columns", fileOps: "LOAD_FILE(), INTO OUTFILE", osCmd: "UDF sys_exec() via shared lib" },
  { name: "PostgreSQL", errors: "PostgreSQL.*?ERROR, Warning.*?pg_, Npgsql., PG::SyntaxError, ERROR: syntax error at or near", sleep: "pg_sleep(n)", concat: "a || b", catalog: "pg_database, information_schema.tables / .columns", fileOps: "pg_read_file(), COPY TO", osCmd: "COPY TO PROGRAM (>= 9.3)" },
  { name: "MSSQL", errors: "Driver.*?SQL Server, OLE DB.*?SQL Server, ODBC SQL Server Driver, Msg \\d+.*Level \\d+", sleep: "WAITFOR DELAY '0:0:n'", concat: "a + b", catalog: "master..sysdatabases, information_schema.tables / .columns", fileOps: "OPENROWSET(BULK), xp_cmdshell echo", osCmd: "xp_cmdshell (sp_configure auto-enable)" },
  { name: "Oracle", errors: "ORA-\\d{4,5}, Oracle error, Oracle.*?Driver, quoted string not properly terminated", sleep: "DBMS_PIPE.RECEIVE_MESSAGE()", concat: "a || b", catalog: "all_tables, all_tab_columns (owner-based)", fileOps: "UTL_FILE.GET_RAW()", osCmd: "DBMS_SCHEDULER.CREATE_JOB" },
  { name: "SQLite", errors: "SQLite/JQLite, Warning.*?sqlite_, [SQLITE_ERROR], near \"...\": syntax error", sleep: "RANDOMBLOB CPU burn", concat: "a || b", catalog: "sqlite_master, PRAGMA table_info()", fileOps: "N/A", osCmd: "load_extension() if enabled" },
  { name: "MariaDB", errors: "MariaDB server version (+ MySQL patterns)", sleep: "SLEEP(n)", concat: "CONCAT(a,b)", catalog: "Same as MySQL", fileOps: "LOAD_FILE(), INTO OUTFILE", osCmd: "UDF sys_exec()" },
  { name: "DB2", errors: "CLI Driver.*?DB2, DB2 SQL error, SQLCODE=-\\d+, com.ibm.db2.jcc", sleep: "Heavy query join", concat: "a || b", catalog: "syscat.schemata / syscat.tables / syscat.columns", fileOps: "N/A", osCmd: "N/A" },
  { name: "Firebird", errors: "Dynamic SQL Error, Warning.*?ibase_, org.firebirdsql.jdbc", sleep: "Heavy query join", concat: "a || b", catalog: "RDB$RELATIONS, RDB$RELATION_FIELDS", fileOps: "N/A", osCmd: "N/A" },
];

const ENUMERATE_TARGETS = [
  { flag: "dbs", label: "Databases", desc: "List all database/schema names on the server", risk: 1, queries: "MySQL: information_schema.schemata | PostgreSQL: pg_database | MSSQL: master..sysdatabases | Oracle: DISTINCT owner FROM all_tables | SQLite: 'main' | DB2: syscat.schemata" },
  { flag: "tables", label: "Tables", desc: "List all tables in the current (or specified) database", risk: 1, queries: "information_schema.tables, all_tables, sqlite_master, syscat.tables, RDB$RELATIONS" },
  { flag: "columns", label: "Columns", desc: "List columns for each discovered table", risk: 1, queries: "information_schema.columns, all_tab_columns, PRAGMA table_info(), syscat.columns, RDB$RELATION_FIELDS" },
  { flag: "users", label: "Users", desc: "Enumerate database user accounts", risk: 1, queries: "mysql.user, pg_user, master..syslogins, all_users, RDB$USER_PRIVILEGES" },
  { flag: "passwords", label: "Password hashes", desc: "Extract password hashes from system tables", risk: 1, queries: "mysql.user (authentication_string), pg_shadow (passwd), sys.sql_logins (password_hash), dba_users (password)" },
  { flag: "dump", label: "Table dump", desc: "Extract full row data from discovered tables", risk: 1, queries: "SELECT * with LIMIT/OFFSET pagination (boolean-blind: ~8 requests per character)" },
  { flag: "file-read", label: "File read", desc: "Read arbitrary files from the server filesystem", risk: 3, queries: "MySQL: LOAD_FILE() | PostgreSQL: pg_read_file() | MSSQL: OPENROWSET(BULK, SINGLE_CLOB) | Oracle: UTL_FILE.GET_RAW()" },
  { flag: "os-cmd", label: "OS command", desc: "Execute operating system commands on the server", risk: 3, queries: "MSSQL: xp_cmdshell | PostgreSQL: COPY TO PROGRAM | MySQL: UDF sys_exec() | Oracle: DBMS_SCHEDULER" },
];

type DetailTab = "modules" | "techniques" | "tamper" | "dbms" | "enumerate";

export function FuzzingView() {
  const [tab, setTab] = useState<DetailTab>("modules");

  const grouped = {
    injection: MODULES.filter((m) => m.category === "injection"),
    fingerprint: MODULES.filter((m) => m.category === "fingerprint"),
    cve: MODULES.filter((m) => m.category === "cve"),
  };

  const readyCount = MODULES.filter((m) => m.status === "ready").length;
  const totalTamper = TAMPER_MODULES.reduce((s, c) => s + c.count, 0);

  const tabs: { key: DetailTab; label: string }[] = [
    { key: "modules", label: `Modules (${MODULES.length})` },
    { key: "techniques", label: `Techniques (${TECHNIQUES.length})` },
    { key: "tamper", label: `Tamper (${totalTamper})` },
    { key: "dbms", label: `DBMS (${DBMS_DETAILS.length})` },
    { key: "enumerate", label: `Enumerate (${ENUMERATE_TARGETS.length})` },
  ];

  return (
    <div className="history-view" style={{ overflow: "auto" }}>
      <div className="history-header">
        <div>
          <h2 style={{ margin: 0, fontSize: "var(--font-base)", color: "var(--fg)", textTransform: "none", letterSpacing: 0 }}>
            Active Fuzzing
          </h2>
          <div className="sub" style={{ marginTop: 4, lineHeight: 1.6 }}>
            {readyCount} ready, {MODULES.length - readyCount} planned modules.{" "}
            The SQL injection engine provides {TECHNIQUES.length} detection techniques, {totalTamper} tamper modules, {DBMS_DETAILS.length} DBMS backends, and {ENUMERATE_TARGETS.length} enumeration targets.{" "}
            Enable via the "Active fuzzing" checkbox on the Dashboard or <code>--active</code> on the CLI.
          </div>
        </div>
      </div>

      {/* ---- Tab bar ---- */}
      <div style={{ display: "flex", gap: 2, marginBottom: 12, borderBottom: "1px solid var(--border)", paddingBottom: 0 }}>
        {tabs.map((t) => (
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
              borderBottom: tab === t.key ? "2px solid var(--accent)" : "2px solid transparent",
              marginBottom: -1,
              transition: "color 0.15s, border-color 0.15s",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ---- Modules tab ---- */}
      {tab === "modules" && (
        <>
          {(["injection", "fingerprint", "cve"] as const).map((cat) => (
            <div key={cat} style={{ marginBottom: 20 }}>
              <h3 style={{ fontSize: "calc(var(--font-base) - 1px)", fontWeight: 600, color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.06em", margin: "12px 0 8px 0" }}>
                {CATEGORY_LABELS[cat]} ({grouped[cat].length})
              </h3>
              <div style={{ overflowX: "auto" }}>
                <table className="findings-table" style={{ tableLayout: "auto" }}>
                  <colgroup>
                    <col style={{ width: "15%" }} />
                    <col style={{ width: "7%" }} />
                    <col style={{ width: "auto" }} />
                    <col style={{ width: "15%" }} />
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
                        <td><code>{m.name}</code></td>
                        <td>
                          <span className="badge" style={{ color: STATUS_COLORS[m.status], borderColor: STATUS_COLORS[m.status] }}>
                            {m.status}
                          </span>
                        </td>
                        <td style={{ whiteSpace: "normal" }}>{m.description}</td>
                        <td>
                          {m.injectionTypes.length > 0
                            ? m.injectionTypes.map((t) => (
                                <span key={t} className="badge" style={{ marginRight: 4, marginBottom: 2, display: "inline-block" }}>{t}</span>
                              ))
                            : "\u2014"}
                        </td>
                        <td style={{ whiteSpace: "normal", fontSize: 11 }}><code>{m.payloads}</code></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </>
      )}

      {/* ---- Techniques tab ---- */}
      {tab === "techniques" && (
        <div>
          <div className="sub" style={{ marginBottom: 12 }}>
            Techniques run in priority order and short-circuit once a parameter is confirmed at high confidence. Lower priority number = runs first.
          </div>
          {TECHNIQUES.map((t) => (
            <div key={t.code} style={{ marginBottom: 20, padding: "14px 16px", background: "var(--panel)", borderRadius: "var(--radius)", border: "1px solid var(--border)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                <span style={{ background: "var(--accent-soft)", color: "var(--accent)", fontFamily: "var(--mono)", fontSize: "var(--font-base)", fontWeight: 700, width: 28, height: 28, borderRadius: 6, display: "flex", alignItems: "center", justifyContent: "center" }}>{t.code}</span>
                <div>
                  <div style={{ fontWeight: 600, color: "var(--fg)", fontSize: 13 }}>{t.name}</div>
                  <div style={{ fontSize: "calc(var(--font-base) - 3px)", color: "var(--muted)" }}>Priority {t.priority} &middot; ~{t.requests}</div>
                </div>
              </div>
              <p style={{ margin: "0 0 8px 0", color: "var(--fg)", fontSize: "calc(var(--font-base) - 2px)", lineHeight: 1.6 }}>{t.description}</p>
              <div style={{ fontSize: "calc(var(--font-base) - 2px)", lineHeight: 1.6 }}>
                <div style={{ marginBottom: 6 }}>
                  <span style={{ color: "var(--accent)", fontWeight: 600 }}>How it works: </span>
                  <span style={{ color: "var(--muted-strong)" }}>{t.how}</span>
                </div>
                <div style={{ marginBottom: 6 }}>
                  <span style={{ color: "var(--accent)", fontWeight: 600 }}>Data extraction: </span>
                  <span style={{ color: "var(--muted-strong)" }}>{t.extraction}</span>
                </div>
                <div>
                  <span style={{ color: "var(--accent)", fontWeight: 600 }}>DBMS support: </span>
                  <span style={{ color: "var(--muted-strong)" }}>{t.dbms}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ---- Tamper tab ---- */}
      {tab === "tamper" && (
        <div>
          <div className="sub" style={{ marginBottom: 12 }}>
            Tamper modules transform SQL payloads before injection to bypass WAFs, input filters, and intrusion detection systems.
            Chain multiple modules via <code>--tamper space2comment,randomcase,between</code>. Modules apply left-to-right.
          </div>
          {TAMPER_MODULES.map((cat) => (
            <div key={cat.category} style={{ marginBottom: 16 }}>
              <h3 style={{ fontSize: "calc(var(--font-base) - 1px)", fontWeight: 600, color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.06em", margin: "0 0 8px 0" }}>
                {cat.category} ({cat.count})
              </h3>
              <div style={{ overflowX: "auto" }}>
                <table className="findings-table" style={{ tableLayout: "auto" }}>
                  <colgroup>
                    <col style={{ width: "30%" }} />
                    <col style={{ width: "70%" }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th>Module</th>
                      <th>Transform</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cat.modules.map((m) => (
                      <tr key={m.name}>
                        <td><code>{m.name}</code></td>
                        <td style={{ whiteSpace: "normal" }}>{m.desc}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ---- DBMS tab ---- */}
      {tab === "dbms" && (
        <div>
          <div className="sub" style={{ marginBottom: 12 }}>
            Each backend has tailored error fingerprints, time-delay functions, string concatenation syntax, catalog queries, file I/O vectors, and OS command execution methods.
            Use <code>--sqli-dbms mysql</code> to force a specific backend, or leave on auto-detect.
          </div>
          {DBMS_DETAILS.map((db) => (
            <div key={db.name} style={{ marginBottom: 16, padding: "12px 16px", background: "var(--panel)", borderRadius: "var(--radius)", border: "1px solid var(--border)" }}>
              <div style={{ fontWeight: 600, color: "var(--fg)", fontSize: "var(--font-base)", marginBottom: 8 }}>{db.name}</div>
              <div style={{ display: "grid", gridTemplateColumns: "110px 1fr", gap: "4px 12px", fontSize: "calc(var(--font-base) - 2px)", lineHeight: 1.6 }}>
                <span style={{ color: "var(--accent)", fontWeight: 600 }}>Error patterns</span>
                <span style={{ color: "var(--muted-strong)", overflowWrap: "break-word" }}>{db.errors}</span>
                <span style={{ color: "var(--accent)", fontWeight: 600 }}>Sleep function</span>
                <span style={{ color: "var(--muted-strong)" }}>{db.sleep}</span>
                <span style={{ color: "var(--accent)", fontWeight: 600 }}>Concatenation</span>
                <span style={{ color: "var(--muted-strong)" }}>{db.concat}</span>
                <span style={{ color: "var(--accent)", fontWeight: 600 }}>Catalog tables</span>
                <span style={{ color: "var(--muted-strong)", overflowWrap: "break-word" }}>{db.catalog}</span>
                <span style={{ color: "var(--accent)", fontWeight: 600 }}>File operations</span>
                <span style={{ color: "var(--muted-strong)" }}>{db.fileOps}</span>
                <span style={{ color: "var(--accent)", fontWeight: 600 }}>OS commands</span>
                <span style={{ color: "var(--muted-strong)" }}>{db.osCmd}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ---- Enumerate tab ---- */}
      {tab === "enumerate" && (
        <div>
          <div className="sub" style={{ marginBottom: 12 }}>
            Post-detection extraction using whichever technique confirmed the injection. UNION-based is fastest (direct query substitution).
            Boolean-blind uses ASCII binary search (~8 requests/char). Time-blind is slowest (each bit costs delay seconds).
            Enable via <code>--sqli-enumerate dbs,tables,columns</code> or checkboxes in the scan form.
          </div>
          {ENUMERATE_TARGETS.map((e) => (
            <div key={e.flag} style={{ marginBottom: 14, padding: "12px 16px", background: "var(--panel)", borderRadius: "var(--radius)", border: "1px solid var(--border)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <code style={{ color: "var(--accent)", fontSize: 12 }}>{e.flag}</code>
                <span style={{ fontWeight: 600, color: "var(--fg)", fontSize: 12 }}>{e.label}</span>
                {e.risk >= 3 && (
                  <span className="badge" style={{ color: "var(--danger)", borderColor: "var(--danger)", fontSize: "calc(var(--font-base) - 4px)" }}>risk 3</span>
                )}
              </div>
              <p style={{ margin: "0 0 6px 0", fontSize: "calc(var(--font-base) - 2px)", color: "var(--fg)", lineHeight: 1.5 }}>{e.desc}</p>
              <div style={{ fontSize: "calc(var(--font-base) - 3px)", color: "var(--muted-strong)", lineHeight: 1.6, overflowWrap: "break-word" }}>
                <span style={{ color: "var(--accent)", fontWeight: 600 }}>Queries: </span>{e.queries}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
