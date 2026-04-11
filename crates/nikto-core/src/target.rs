//! `Mark` — the per-target state bag (= Perl `%mark`).

use crate::error::{NiktoError, Result};
use crate::http::cookies::CookieJar;
use crate::http::tls::SslInfo;
use dns_lookup::lookup_host;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Unix,
    Windows,
    All,
}

impl Platform {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "windows" | "win" => Platform::Windows,
            "unix" | "nix" | "linux" => Platform::Unix,
            _ => Platform::All,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Realm {
    pub auth_type: String,
    pub realm: String,
    pub user: Option<String>,
    pub pass: Option<String>,
}

#[derive(Debug)]
pub struct HostCounters {
    pub total_vulns: AtomicU64,
    pub total_errors: AtomicU64,
    pub failures: AtomicU64,
}

impl Default for HostCounters {
    fn default() -> Self {
        Self {
            total_vulns: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        }
    }
}

impl HostCounters {
    pub fn incr_vulns(&self) {
        self.total_vulns.fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_errors(&self) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_failures(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn vulns(&self) -> u64 {
        self.total_vulns.load(Ordering::Relaxed)
    }
    pub fn errors(&self) -> u64 {
        self.total_errors.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub struct Mark {
    pub ident: String,
    pub hostname: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub ssl: bool,
    pub root: String,
    pub vhost: Option<String>,
    pub platform: Platform,
    pub banner: Option<String>,
    pub ssl_info: Option<SslInfo>,
    pub cookie_jar: CookieJar,
    pub realms: HashMap<String, Realm>,
    pub counters: HostCounters,
    pub start_time: SystemTime,
    pub test_ok: bool,
    pub errmsg: Option<String>,
    pub messages: Vec<String>,
    pub has_vhost: bool,
}

impl Mark {
    pub fn new(ident: String, hostname: String, port: u16, ssl: bool, root: String) -> Self {
        Self {
            ident,
            hostname,
            ip: None,
            port,
            ssl,
            root,
            vhost: None,
            platform: Platform::All,
            banner: None,
            ssl_info: None,
            cookie_jar: CookieJar::default(),
            realms: HashMap::new(),
            counters: HostCounters::default(),
            start_time: SystemTime::now(),
            test_ok: true,
            errmsg: None,
            messages: Vec::new(),
            has_vhost: false,
        }
    }

    pub fn display_name(&self) -> String {
        match (&self.ip, self.port) {
            (Some(ip), p) => format!("{} ({}:{})", self.hostname, ip, p),
            (None, p) => format!("{}:{}", self.hostname, p),
        }
    }
}

/// Parse -host/-port combinations into a list of Marks.
///
/// Accepted forms for `host_arg`:
///   - `example.com`
///   - `https://example.com[:port]/path`
///   - `host1,host2`
pub fn set_targets(
    host_arg: &str,
    ports: Option<&str>,
    force_ssl: bool,
    root: Option<&str>,
) -> Result<Vec<Mark>> {
    let mut marks = Vec::new();
    let port_list: Vec<u16> = match ports {
        Some(s) => s
            .split(',')
            .filter_map(|p| p.trim().parse::<u16>().ok())
            .collect(),
        None => Vec::new(),
    };

    for raw in host_arg.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (host, port, ssl, path) = parse_host(raw)?;
        let ssl = ssl || force_ssl;
        let effective_root = root.map(|s| s.to_string()).unwrap_or_else(|| path.clone());

        if !port_list.is_empty() {
            for p in &port_list {
                let ssl_guess = if *p == 443 { true } else { ssl };
                marks.push(Mark::new(
                    format!("{host}:{p}"),
                    host.clone(),
                    *p,
                    ssl_guess,
                    effective_root.clone(),
                ));
            }
        } else {
            let final_port = port.unwrap_or(if ssl { 443 } else { 80 });
            marks.push(Mark::new(
                format!("{host}:{final_port}"),
                host,
                final_port,
                ssl,
                effective_root,
            ));
        }
    }

    Ok(marks)
}

fn parse_host(s: &str) -> Result<(String, Option<u16>, bool, String)> {
    // Support full URLs, bare hosts, host:port.
    if s.contains("://") {
        let u = Url::parse(s).map_err(|e| NiktoError::other(format!("parse {s}: {e}")))?;
        let host = u
            .host_str()
            .ok_or_else(|| NiktoError::other(format!("no host in {s}")))?
            .to_string();
        let port = u.port();
        let ssl = u.scheme().eq_ignore_ascii_case("https");
        let mut path = u.path().to_string();
        if path.is_empty() {
            path = "/".to_string();
        }
        return Ok((host, port, ssl, path));
    }
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return Ok((h.to_string(), Some(port), false, "/".to_string()));
        }
    }
    Ok((s.to_string(), None, false, "/".to_string()))
}

/// Resolve hostname -> IP. Uses a blocking resolver in a spawn_blocking.
pub async fn resolve(hostname: &str) -> Result<IpAddr> {
    let h = hostname.to_string();
    let res = tokio::task::spawn_blocking(move || lookup_host(&h))
        .await
        .map_err(|e| NiktoError::Dns(e.to_string()))?
        .map_err(|e| NiktoError::Dns(e.to_string()))?;
    res.into_iter()
        .next()
        .ok_or_else(|| NiktoError::Dns(format!("no addresses for {hostname}")))
}
