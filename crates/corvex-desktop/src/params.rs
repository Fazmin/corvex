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
        }
    }
}
