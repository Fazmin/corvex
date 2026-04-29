//! `ScanParams` — the JSON shape the frontend sends to `scan_start`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use corvex_core::cli::Cli;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanParams {
    pub host: String,
    #[serde(default)]
    pub ports: Option<String>,
    #[serde(default)]
    pub ssl: bool,
    #[serde(default)]
    pub nossl: bool,
    #[serde(default)]
    pub ipv4: bool,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub nolookup: bool,
    #[serde(default)]
    pub tuning: Option<String>,
    #[serde(default)]
    pub plugins: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub output: Option<PathBuf>,
    #[serde(default)]
    pub evasion: Option<String>,
    #[serde(default)]
    pub add_header: Vec<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub useproxy: Option<String>,
    #[serde(default)]
    pub vhost: Option<String>,
    #[serde(default)]
    pub useragent: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub pause_secs: Option<f64>,
    #[serde(default)]
    pub maxtime_secs: Option<u64>,
    #[serde(default)]
    pub max_concurrent_requests: Option<usize>,
    #[serde(default)]
    pub max_concurrent_hosts: Option<usize>,
    #[serde(default)]
    pub follow_redirects: bool,
    #[serde(default)]
    pub userdbs: Option<PathBuf>,
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub four04_string: Option<String>,
    #[serde(default)]
    pub four04_code: Option<u16>,

    // ---- Active fuzzing flags ------------------------------------------------
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub crawl_depth: Option<u32>,
    #[serde(default)]
    pub max_urls: Option<u32>,
    #[serde(default)]
    pub exclude_pattern: Vec<String>,

    // ---- Port scanning flags ----------------------------------------------------
    #[serde(default)]
    pub portscan: bool,
    #[serde(default)]
    pub ports_range: Option<String>,
    #[serde(default)]
    pub scan_mode: Option<String>,
    #[serde(default)]
    pub jarm: bool,
    #[serde(default)]
    pub extra_probe_files: Vec<String>,

    // ---- DNS enumeration flags ------------------------------------------------
    #[serde(default)]
    pub dns_brute: bool,

    // ---- SQL injection flags ------------------------------------------------
    #[serde(default)]
    pub sqli_level: Option<u8>,
    #[serde(default)]
    pub sqli_risk: Option<u8>,
    #[serde(default)]
    pub sqli_techniques: Option<String>,
    #[serde(default)]
    pub sqli_dbms: Option<String>,
    #[serde(default)]
    pub sqli_time_delay: Option<u32>,
    #[serde(default)]
    pub tamper: Option<String>,
    #[serde(default)]
    pub sqli_enumerate: Option<String>,

    // ---- SCA (Software Composition Analysis) flags ---------------------------
    #[serde(default)]
    pub scan_dir: Option<String>,
    #[serde(default)]
    pub sbom_input: Option<String>,
    #[serde(default)]
    pub sbom_output: Option<String>,
    #[serde(default)]
    pub sbom_format: Option<String>,
    #[serde(default)]
    pub epss_threshold: Option<f32>,
    #[serde(default)]
    pub show_fixes: bool,

    // ---- Binary analysis flags -----------------------------------------------
    #[serde(default)]
    pub binary_scan: Option<String>,
    #[serde(default)]
    pub binary_recursive: bool,
    #[serde(default)]
    pub binary_extract: bool,
}

impl ScanParams {
    pub fn into_cli(self) -> Cli {
        Cli {
            help: None,
            host: Some(self.host),
            url: None,
            port: self.ports,
            ssl: self.ssl,
            nossl: self.nossl,
            ipv4: self.ipv4,
            ipv6: self.ipv6,
            check6: false,
            nolookup: self.nolookup,
            tuning: self.tuning,
            plugins: self.plugins,
            format: self.format,
            output: self.output,
            display: None,
            evasion: self.evasion,
            mutate: None,
            mutate_options: None,
            pause: self.pause_secs,
            timeout: self.timeout_secs,
            maxtime: self.maxtime_secs,
            useragent: self.useragent,
            vhost: self.vhost,
            add_header: self.add_header,
            id: self.id,
            key: None,
            rsacert: None,
            useproxy: self.useproxy,
            save: None,
            root: self.root,
            noslash: false,
            followredirects: self.follow_redirects,
            four04_string: self.four04_string,
            four04_code: self.four04_code,
            cgidirs: None,
            userdbs: self.userdbs,
            platform: None,
            nointeractive: true,
            nocookies: false,
            ask: None,
            option: Vec::new(),
            dbcheck: false,
            list_plugins: false,
            nocheck: true,
            version_flag: false,
            config: None,
            max_concurrent_requests: self.max_concurrent_requests.unwrap_or(8),
            max_concurrent_hosts: self.max_concurrent_hosts.unwrap_or(4),
            active: self.active,
            crawl: self.active,
            crawl_depth: self.crawl_depth,
            max_urls: self.max_urls,
            scope: self.scope,
            exclude_pattern: self.exclude_pattern,
            openapi: None,
            form_login: None,
            form_login_data: Vec::new(),
            cookie_jar: None,
            resume: None,
            oast: None,
            portscan: self.portscan,
            ports_range: self.ports_range.unwrap_or_else(|| "1-1000".to_string()),
            portscan_threads: 200,
            service_detect: false,
            scan_mode: self
                .scan_mode
                .unwrap_or_else(|| "rapid".to_string()),
            jarm: self.jarm,
            service_probes: self
                .extra_probe_files
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            dns_brute: self.dns_brute,
            dns_wordlist: None,
            dns_threads: 50,
            sqli_level: self.sqli_level.unwrap_or(1),
            sqli_risk: self.sqli_risk.unwrap_or(1),
            sqli_techniques: self.sqli_techniques.unwrap_or_else(|| "BEUST".to_string()),
            sqli_dbms: self.sqli_dbms,
            sqli_time_delay: self.sqli_time_delay.unwrap_or(5),
            tamper: self.tamper,
            sqli_second_url: None,
            sqli_prefix: None,
            sqli_suffix: None,
            sqli_enumerate: self.sqli_enumerate,
            // SCA / VulnDB fields
            vulndb_update: "daily".to_string(),
            vulndb_path: None,
            nvd_api_key: None,
            vulndb_export: None,
            vulndb_import: None,
            scan_dir: self.scan_dir.map(PathBuf::from),
            sbom_input: self.sbom_input.map(PathBuf::from),
            sbom_output: self.sbom_output.map(PathBuf::from),
            sbom_format: self.sbom_format.unwrap_or_else(|| "cyclonedx-json".to_string()),
            epss_threshold: self.epss_threshold,
            epss_percentile: None,
            show_fixes: self.show_fixes,
            // Binary analysis
            binary_scan: self.binary_scan.map(PathBuf::from),
            binary_recursive: self.binary_recursive,
            binary_extract: self.binary_extract,
            // VEX / Triage — not exposed in desktop UI for now
            vex_input: None,
            vex_output: None,
            vex_format: "cyclonedx".to_string(),
            triage_filter: None,
            triage_set: Vec::new(),
            // Report merging — not in desktop UI
            save_report: None,
            merge_reports: None,
            diff_reports: None,
            generate_config: None,
            // Unified rules cutover flags — desktop uses the default
            // (rules-only) path; the legacy / side-by-side toggles are
            // CLI-only knobs for parity validation. Leaving all three
            // false picks up the post-Phase-2d.0 default behaviour
            // (RulesPlugin owns every source, TestsPlugin no-ops).
            rules_only: false,
            legacy_only: false,
            side_by_side: false,
        }
    }
}
