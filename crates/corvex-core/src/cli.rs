//! CLI argument model.
//!
//! Mirrors every flag from the Perl CLI help in
//! [../../../program/plugins/corvex_core.plugin](../../../program/plugins/corvex_core.plugin).
//! Single-dash long flags (`-host`, `-Tuning`) are kept to match Corvex's UX.

use clap::Parser;
use std::path::PathBuf;

/// Corvex - web vulnerability scanner (Rust port).
#[derive(Debug, Clone, Parser)]
#[command(
    name = "corvex",
    version,
    about = "Rust port of the Corvex web vulnerability scanner",
    disable_help_flag = true,
    // Corvex uses "-host" not "--host". allow_hyphen_values is handled per-arg.
    arg_required_else_help = false
)]
pub struct Cli {
    /// Show help
    #[arg(long = "Help", short = 'H', action = clap::ArgAction::Help)]
    pub help: Option<bool>,

    /// Target host or URL
    #[arg(long = "host", short = 'h', value_name = "HOST")]
    pub host: Option<String>,

    /// Alias for -host
    #[arg(long = "url", value_name = "URL")]
    pub url: Option<String>,

    /// Target port(s), comma-separated
    #[arg(long = "port", short = 'p', value_name = "PORT[,PORT...]")]
    pub port: Option<String>,

    /// Force SSL
    #[arg(long = "ssl", default_value_t = false)]
    pub ssl: bool,

    /// Disable SSL
    #[arg(long = "nossl", default_value_t = false)]
    pub nossl: bool,

    /// Force IPv4
    #[arg(long = "ipv4", short = '4', default_value_t = false)]
    pub ipv4: bool,

    /// Force IPv6
    #[arg(long = "ipv6", short = '6', default_value_t = false)]
    pub ipv6: bool,

    /// Test IPv6 connectivity and exit
    #[arg(long = "check6", default_value_t = false)]
    pub check6: bool,

    /// Skip DNS lookup
    #[arg(long = "nolookup", default_value_t = false)]
    pub nolookup: bool,

    /// Tuning categories (0-9, a-f, x for exclude)
    #[arg(long = "Tuning", short = 'T', value_name = "CODES")]
    pub tuning: Option<String>,

    /// Plugin list (macros allowed: @@ALL, @@NONE, @@DEFAULT, @@EXTRAS)
    #[arg(long = "Plugins", value_name = "LIST")]
    pub plugins: Option<String>,

    /// Output format(s), comma-separated
    #[arg(long = "Format", short = 'F', value_name = "FMT")]
    pub format: Option<String>,

    /// Report output file
    #[arg(long = "output", short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Display verbosity flags
    #[arg(long = "Display", short = 'D', value_name = "FLAGS")]
    pub display: Option<String>,

    /// Evasion technique flags (1-9, A-Z)
    #[arg(long = "evasion", short = 'e', value_name = "FLAGS")]
    pub evasion: Option<String>,

    /// Database/filename mutation
    #[arg(long = "mutate", value_name = "OPTS")]
    pub mutate: Option<String>,

    /// Mutate options string
    #[arg(long = "mutate-options", value_name = "STRING")]
    pub mutate_options: Option<String>,

    /// Pause between requests (seconds, may be fractional)
    #[arg(long = "Pause", short = 'P', value_name = "SECS")]
    pub pause: Option<f64>,

    /// Per-request timeout (seconds)
    #[arg(long = "timeout", value_name = "SECS")]
    pub timeout: Option<u64>,

    /// Max scan time per host (seconds)
    #[arg(long = "maxtime", value_name = "SECS")]
    pub maxtime: Option<u64>,

    /// Custom User-Agent
    #[arg(long = "useragent", value_name = "UA")]
    pub useragent: Option<String>,

    /// Virtual host header
    #[arg(long = "vhost", value_name = "VHOST")]
    pub vhost: Option<String>,

    /// Add a header (NAME:VALUE), repeatable
    #[arg(long = "Add-header", value_name = "HDR", action = clap::ArgAction::Append)]
    pub add_header: Vec<String>,

    /// Authentication credentials user[:pass[:realm]]
    #[arg(long = "id", value_name = "ID")]
    pub id: Option<String>,

    /// Client cert key file
    #[arg(long = "key", value_name = "FILE")]
    pub key: Option<PathBuf>,

    /// Client cert file
    #[arg(long = "RSAcert", value_name = "FILE")]
    pub rsacert: Option<PathBuf>,

    /// Use proxy (optional URL, else use corvex.conf settings)
    #[arg(long = "useproxy", value_name = "PROXY", num_args = 0..=1, default_missing_value = "")]
    pub useproxy: Option<String>,

    /// Save responses to directory
    #[arg(long = "Save", value_name = "DIR")]
    pub save: Option<PathBuf>,

    /// Root directory prefix for all tests
    #[arg(long = "root", value_name = "/PATH")]
    pub root: Option<String>,

    /// Remove trailing slash on URIs
    #[arg(long = "noslash", default_value_t = false)]
    pub noslash: bool,

    /// Follow redirects
    #[arg(long = "followredirects", default_value_t = false)]
    pub followredirects: bool,

    /// Custom 404 signature
    #[arg(long = "404string", value_name = "STRING")]
    pub four04_string: Option<String>,

    /// Custom 404 status code
    #[arg(long = "404code", value_name = "CODE")]
    pub four04_code: Option<u16>,

    /// Force CGI directory list
    #[arg(long = "Cgidirs", short = 'C', value_name = "DIRS")]
    pub cgidirs: Option<String>,

    /// Additional user databases
    #[arg(long = "Userdbs", value_name = "DBFILE")]
    pub userdbs: Option<PathBuf>,

    /// Force platform profile
    #[arg(long = "Platform", value_name = "P")]
    pub platform: Option<String>,

    /// Non-interactive mode
    #[arg(long = "nointeractive", default_value_t = false)]
    pub nointeractive: bool,

    /// Don't send cookies
    #[arg(long = "nocookies", default_value_t = false)]
    pub nocookies: bool,

    /// Ask before each test
    #[arg(long = "ask", value_name = "WHEN")]
    pub ask: Option<String>,

    /// Generic option passthrough
    #[arg(long = "Option", value_name = "KV", action = clap::ArgAction::Append)]
    pub option: Vec<String>,

    /// Check databases and exit
    #[arg(long = "dbcheck", default_value_t = false)]
    pub dbcheck: bool,

    /// List available plugins and exit
    #[arg(long = "list-plugins", default_value_t = false)]
    pub list_plugins: bool,

    /// Skip update check
    #[arg(long = "nocheck", default_value_t = false)]
    pub nocheck: bool,

    /// Print version and exit
    #[arg(long = "Version", default_value_t = false)]
    pub version_flag: bool,

    /// Alternate config file
    #[arg(long = "config", value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Max concurrent in-flight requests per host (Rust-port addition)
    #[arg(long = "max-concurrent-requests", value_name = "N", default_value_t = 8)]
    pub max_concurrent_requests: usize,

    /// Max hosts scanned in parallel (Rust-port addition)
    #[arg(long = "max-concurrent-hosts", value_name = "N", default_value_t = 4)]
    pub max_concurrent_hosts: usize,

    // ---- Active fuzzing flags ------------------------------------------------

    /// Enable active fuzzing (crawler + injection probes). Implies --crawl.
    #[arg(long = "active", default_value_t = false)]
    pub active: bool,

    /// Enable the crawler (auto-discovers pages + forms). Implicit if --active.
    #[arg(long = "crawl", default_value_t = false)]
    pub crawl: bool,

    /// Max link-following depth for the crawler (default 3)
    #[arg(long = "crawl-depth", value_name = "N")]
    pub crawl_depth: Option<u32>,

    /// Hard cap on URLs the crawler will visit (default 500)
    #[arg(long = "max-urls", value_name = "N")]
    pub max_urls: Option<u32>,

    /// Scope restriction: domain | subdomains | folder | page
    #[arg(long = "scope", value_name = "SCOPE")]
    pub scope: Option<String>,

    /// Exclude URLs matching this regex (repeatable)
    #[arg(long = "exclude-pattern", value_name = "REGEX", action = clap::ArgAction::Append)]
    pub exclude_pattern: Vec<String>,

    /// Seed the crawl from an OpenAPI / Swagger spec file
    #[arg(long = "openapi", value_name = "FILE")]
    pub openapi: Option<PathBuf>,

    /// POST to this URL to obtain a session cookie before scanning
    #[arg(long = "form-login", value_name = "URL")]
    pub form_login: Option<String>,

    /// Form login POST body (key=value pairs, repeatable)
    #[arg(long = "form-login-data", value_name = "KV", action = clap::ArgAction::Append)]
    pub form_login_data: Vec<String>,

    /// Import cookies from a Chrome / Firefox SQLite cookie DB
    #[arg(long = "cookie-jar", value_name = "FILE")]
    pub cookie_jar: Option<PathBuf>,

    /// Resume a previously suspended scan session
    #[arg(long = "resume", value_name = "SESSION_ID")]
    pub resume: Option<String>,

    /// Out-of-band callback host for blind vulnerability detection
    #[arg(long = "oast", value_name = "URL")]
    pub oast: Option<String>,

    // ---- SQL injection flags ------------------------------------------------

    /// SQLi testing level (1-5). Higher levels test more injection points.
    /// 1=GET/POST params, 2=+cookies, 3=+User-Agent/Referer, 4=+other headers, 5=all
    #[arg(long = "sqli-level", value_name = "N", default_value_t = 1)]
    pub sqli_level: u8,

    /// SQLi risk level (1-3). Controls payload destructiveness.
    /// 1=safe/read-only, 2=+OR-based, 3=+UPDATE/INSERT/file-write/os-cmd
    #[arg(long = "sqli-risk", value_name = "N", default_value_t = 1)]
    pub sqli_risk: u8,

    /// SQLi techniques to test. String of chars: B=boolean, E=error, U=union, S=stacked, T=time
    #[arg(long = "sqli-techniques", value_name = "BEUST", default_value = "BEUST")]
    pub sqli_techniques: String,

    /// Force a specific DBMS for SQLi (mysql, postgresql, mssql, oracle, sqlite, mariadb, db2, firebird)
    #[arg(long = "sqli-dbms", value_name = "DBMS")]
    pub sqli_dbms: Option<String>,

    /// Seconds for time-based blind SQLi delay (default 5)
    #[arg(long = "sqli-time-delay", value_name = "SECS", default_value_t = 5)]
    pub sqli_time_delay: u32,

    /// SQL payload tamper modules (comma-separated). Run --list-tampers to see all.
    #[arg(long = "tamper", value_name = "MODULES")]
    pub tamper: Option<String>,

    /// Second-order SQLi: check injection results on this URL
    #[arg(long = "sqli-second-url", value_name = "URL")]
    pub sqli_second_url: Option<String>,

    /// Force injection prefix (e.g. ")" or "1 AND")
    #[arg(long = "sqli-prefix", value_name = "PREFIX")]
    pub sqli_prefix: Option<String>,

    /// Force injection suffix (e.g. "-- -" or "#")
    #[arg(long = "sqli-suffix", value_name = "SUFFIX")]
    pub sqli_suffix: Option<String>,

    /// Post-detection enumeration targets (comma-separated):
    /// dbs,tables,columns,users,dump,passwords,file-read,file-write,os-cmd
    #[arg(long = "sqli-enumerate", value_name = "WHAT")]
    pub sqli_enumerate: Option<String>,

    // ---- Port scanning flags ---------------------------------------------------

    /// Enable port scanning before web tests
    #[arg(long = "portscan", default_value_t = false)]
    pub portscan: bool,

    /// Port range to scan (default "1-1000", supports "80,443,8080" or "1-65535")
    #[arg(long = "ports-range", value_name = "RANGE", default_value = "1-1000")]
    pub ports_range: String,

    /// Concurrent port scan connections (default 200)
    #[arg(long = "portscan-threads", value_name = "N", default_value_t = 200)]
    pub portscan_threads: usize,

    /// Enable service banner grabbing on open ports
    /// (deprecated — prefer `--scan-mode deep`; kept for backwards compatibility).
    #[arg(long = "service-detect", hide = true, default_value_t = false)]
    pub service_detect: bool,

    /// Port-scan mode: "rapid" (fast sweep, open/closed only) or
    /// "deep" (TLS handshake + service fingerprinting with product, version, CPE).
    #[arg(long = "scan-mode", value_name = "MODE", default_value = "rapid")]
    pub scan_mode: String,

    /// Enable JARM TLS-stack fingerprinting in deep mode (opt-in, adds cost).
    #[arg(long = "jarm", default_value_t = false)]
    pub jarm: bool,

    /// Additional service-probe files (Layer-3 drop-in, directive format).
    /// Repeat the flag to add multiple files.
    #[arg(long = "service-probes", value_name = "PATH")]
    pub service_probes: Vec<PathBuf>,

    // ---- DNS enumeration flags ------------------------------------------------

    /// Enable DNS subdomain brute-force discovery
    #[arg(long = "dns-brute", default_value_t = false)]
    pub dns_brute: bool,

    /// Custom subdomain wordlist file (one prefix per line)
    #[arg(long = "dns-wordlist", value_name = "FILE")]
    pub dns_wordlist: Option<PathBuf>,

    /// Parallel DNS resolution threads for brute-force (default 50)
    #[arg(long = "dns-threads", value_name = "N", default_value_t = 50)]
    pub dns_threads: usize,

    // ---- Vulnerability database flags ----------------------------------------

    /// Vulnerability database update mode: now, daily, never, latest (default: daily)
    #[arg(long = "vulndb-update", value_name = "MODE", default_value = "daily")]
    pub vulndb_update: String,

    /// Custom path for the vulnerability database file
    #[arg(long = "vulndb-path", value_name = "PATH")]
    pub vulndb_path: Option<PathBuf>,

    /// NVD API key (or set NVD_API_KEY env var)
    #[arg(long = "nvd-api-key", value_name = "KEY")]
    pub nvd_api_key: Option<String>,

    /// Export vulnerability database to JSON file
    #[arg(long = "vulndb-export", value_name = "FILE")]
    pub vulndb_export: Option<PathBuf>,

    /// Import vulnerability database from JSON file
    #[arg(long = "vulndb-import", value_name = "FILE")]
    pub vulndb_import: Option<PathBuf>,

    // ---- SCA (Software Composition Analysis) flags ---------------------------

    /// Scan a directory for dependency manifest files
    #[arg(long = "scan-dir", value_name = "PATH")]
    pub scan_dir: Option<PathBuf>,

    /// Parse an SBOM file (CycloneDX or SPDX) for component analysis
    #[arg(long = "sbom-input", value_name = "FILE")]
    pub sbom_input: Option<PathBuf>,

    /// Generate an SBOM from scan results
    #[arg(long = "sbom-output", value_name = "FILE")]
    pub sbom_output: Option<PathBuf>,

    /// SBOM output format: cyclonedx-json, cyclonedx-xml, spdx-json, spdx-tv
    #[arg(long = "sbom-format", value_name = "FMT", default_value = "cyclonedx-json")]
    pub sbom_format: String,

    /// Filter CVEs by minimum EPSS probability (0.0-1.0)
    #[arg(long = "epss-threshold", value_name = "PROB")]
    pub epss_threshold: Option<f32>,

    /// Filter CVEs by minimum EPSS percentile (0-100)
    #[arg(long = "epss-percentile", value_name = "N")]
    pub epss_percentile: Option<f32>,

    /// Include available fix information in output
    #[arg(long = "show-fixes", default_value_t = false)]
    pub show_fixes: bool,

    // ---- Binary analysis flags -----------------------------------------------

    /// Scan a binary file or directory for vulnerable components
    #[arg(long = "binary-scan", value_name = "PATH")]
    pub binary_scan: Option<PathBuf>,

    /// Recursively scan directories for binary analysis
    #[arg(long = "binary-recursive", default_value_t = false)]
    pub binary_recursive: bool,

    /// Extract and scan archive files (ZIP, TAR, DEB, RPM)
    #[arg(long = "binary-extract", default_value_t = false)]
    pub binary_extract: bool,

    // ---- VEX / Triage flags --------------------------------------------------

    /// Import a VEX document for triage filtering
    #[arg(long = "vex-input", value_name = "FILE")]
    pub vex_input: Option<PathBuf>,

    /// Export a VEX document from triage data
    #[arg(long = "vex-output", value_name = "FILE")]
    pub vex_output: Option<PathBuf>,

    /// VEX output format: cyclonedx, openvex
    #[arg(long = "vex-format", value_name = "FMT", default_value = "cyclonedx")]
    pub vex_format: String,

    /// Show only CVEs with these triage statuses (comma-separated)
    #[arg(long = "triage-filter", value_name = "LIST")]
    pub triage_filter: Option<String>,

    /// Set triage status for a CVE (CVE-ID=STATUS), repeatable
    #[arg(long = "triage-set", value_name = "CVE=STATUS", action = clap::ArgAction::Append)]
    pub triage_set: Vec<String>,

    // ---- Report merging flags ------------------------------------------------

    /// Save scan report with a tag for later merging
    #[arg(long = "save-report", value_name = "TAG")]
    pub save_report: Option<String>,

    /// Merge saved reports by tags (comma-separated)
    #[arg(long = "merge-reports", value_name = "TAGS")]
    pub merge_reports: Option<String>,

    /// Diff two saved reports by tags (TAG1,TAG2)
    #[arg(long = "diff-reports", value_name = "TAGS")]
    pub diff_reports: Option<String>,

    // ---- Phase 2d cutover flags ----------------------------------------------

    /// Run scan via the unified rules.sqlite path only. Disables the legacy
    /// TestsPlugin (bincode db_tests) and widens RulesPlugin's source filter
    /// to include all sources (Nikto + ZAP + Burp). Use this to validate the
    /// new path against a target you've already baselined.
    #[arg(long = "rules-only", default_value_t = false)]
    pub rules_only: bool,

    /// Run scan via the legacy TestsPlugin only. Disables RulesPlugin so
    /// behaviour exactly matches pre-Phase-2 builds. Use this as the parity
    /// baseline for `--rules-only` comparisons.
    #[arg(long = "legacy-only", default_value_t = false)]
    pub legacy_only: bool,

    // ---- Config generation flags ---------------------------------------------

    /// Generate a template config file in the given format: toml, yaml
    #[arg(long = "generate-config", value_name = "FMT")]
    pub generate_config: Option<String>,
}

impl Cli {
    /// Parse from process argv, tolerating Corvex's short (single-dash) long flags.
    pub fn parse_from_env() -> Self {
        Self::parse()
    }

    /// Resolve the effective host: -host wins, else -url.
    pub fn effective_host(&self) -> Option<&str> {
        self.host.as_deref().or(self.url.as_deref())
    }
}
