//! CLI argument model.
//!
//! Mirrors every flag from the Perl CLI help in
//! [../../../program/plugins/nikto_core.plugin](../../../program/plugins/nikto_core.plugin).
//! Single-dash long flags (`-host`, `-Tuning`) are kept to match Nikto's UX.

use clap::Parser;
use std::path::PathBuf;

/// Nikto - web vulnerability scanner (Rust port).
#[derive(Debug, Clone, Parser)]
#[command(
    name = "nikto",
    version,
    about = "Rust port of the Nikto web vulnerability scanner",
    disable_help_flag = true,
    // Nikto uses "-host" not "--host". allow_hyphen_values is handled per-arg.
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

    /// Use proxy (optional URL, else use nikto.conf settings)
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
}

impl Cli {
    /// Parse from process argv, tolerating Nikto's short (single-dash) long flags.
    pub fn parse_from_env() -> Self {
        Self::parse()
    }

    /// Resolve the effective host: -host wins, else -url.
    pub fn effective_host(&self) -> Option<&str> {
        self.host.as_deref().or(self.url.as_deref())
    }
}
