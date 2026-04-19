//! TCP port scanner with two modes:
//!
//! * `ScanMode::Rapid` — fast sweep (short timeout, high concurrency,
//!   open/closed only, no probes, no TLS).
//! * `ScanMode::Deep` — per-port TLS handshake attempt and scripted/static
//!   probing via `corvex-sonar` to extract product, version, and CPE.
//!
//! Discovered HTTP/HTTPS services (including HTTPS on non-standard ports in
//! Deep mode) feed back into the web-scan pipeline via new `Mark` entries
//! created in [`crate::scan`].

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use corvex_sonar::{ScanMode, ScanTuning, SonarOpts};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

pub use corvex_sonar::{ScanMode as SonarScanMode, TlsMeta};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone, Default)]
pub struct ServiceInfo {
    pub name: String,
    pub banner: String,
    pub version: Option<String>,
    pub tls: bool,
    pub product: Option<String>,
    pub vendor: Option<String>,
    pub info: Option<String>,
    pub cpe: Vec<String>,
    pub jarm: Option<String>,
    pub tls_meta: Option<TlsMeta>,
}

#[derive(Debug, Clone)]
pub struct OpenPort {
    pub port: u16,
    pub state: PortState,
    pub service: Option<ServiceInfo>,
}

#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub host: String,
    pub ip: IpAddr,
    pub open_ports: Vec<OpenPort>,
}

pub fn parse_port_range(s: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start.trim().parse().unwrap_or(1);
            let end: u16 = end.trim().parse().unwrap_or(start);
            for p in start..=end {
                ports.push(p);
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports
}

pub async fn tcp_scan(
    ip: IpAddr,
    host: &str,
    port_list: &[u16],
    mode: ScanMode,
    tuning: ScanTuning,
    opts: SonarOpts,
) -> PortScanResult {
    let sem = Arc::new(Semaphore::new(tuning.concurrency.max(1)));
    let mut handles = Vec::new();
    let connect_timeout = Duration::from_millis(tuning.connect_timeout_ms.max(1));

    for &port in port_list {
        let sem = sem.clone();
        let addr = SocketAddr::new(ip, port);
        let host = host.to_string();
        let tuning = tuning;
        let opts = opts.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await;
            let connect = match timeout(connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => s,
                _ => return None,
            };
            drop(connect);

            if !tuning.run_probes {
                return Some(OpenPort {
                    port,
                    state: PortState::Open,
                    service: None,
                });
            }

            let db = corvex_sonar::db::sonar_db();
            let match_opt = corvex_sonar::identify(
                &db,
                &host,
                addr.ip(),
                port,
                mode,
                &opts,
                tuning.connect_timeout_ms,
                tuning.probe_budget_ms,
                tuning.tls_handshake,
            )
            .await;

            let service = match_opt.map(|m| ServiceInfo {
                name: m.service.clone(),
                banner: m
                    .info
                    .clone()
                    .unwrap_or_default(),
                version: m.version.clone(),
                tls: m.over_tls,
                product: m.product.clone(),
                vendor: m.vendor.clone(),
                info: m.info.clone(),
                cpe: m.cpe.clone(),
                jarm: m.jarm.clone(),
                tls_meta: m.tls.clone(),
            });

            Some(OpenPort {
                port,
                state: PortState::Open,
                service,
            })
        });
        handles.push(handle);
    }

    let mut open_ports = Vec::new();
    for h in handles {
        if let Ok(Some(op)) = h.await {
            open_ports.push(op);
        }
    }
    open_ports.sort_by_key(|p| p.port);

    PortScanResult {
        host: host.to_string(),
        ip,
        open_ports,
    }
}

pub fn is_http_service(name: &str) -> bool {
    matches!(name, "http" | "https")
}
