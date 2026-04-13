//! TCP port scanner with service detection via banner grabbing.
//!
//! Runs as a pre-phase before the plugin lifecycle. Discovered HTTP/HTTPS
//! services can spawn additional `Mark` entries; non-HTTP services are
//! reported as findings directly.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// State of a scanned port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// Detected service information from banner grabbing.
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub banner: String,
    pub version: Option<String>,
    pub tls: bool,
}

/// A single open port result.
#[derive(Debug, Clone)]
pub struct OpenPort {
    pub port: u16,
    pub state: PortState,
    pub service: Option<ServiceInfo>,
}

/// Full port scan result for one host.
#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub host: String,
    pub ip: IpAddr,
    pub open_ports: Vec<OpenPort>,
}

/// Parse a port range string like "1-1000", "80,443,8080", or "1-65535".
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

/// Perform a TCP connect scan against `ip` on all ports in `port_list`,
/// with `max_concurrent` parallel connections and a per-port `timeout_ms`
/// millisecond timeout.
pub async fn tcp_scan(
    ip: IpAddr,
    host: &str,
    port_list: &[u16],
    max_concurrent: usize,
    timeout_ms: u64,
    service_detect: bool,
) -> PortScanResult {
    let sem = Arc::new(Semaphore::new(max_concurrent));
    let mut handles = Vec::new();
    let connect_timeout = Duration::from_millis(timeout_ms);
    let banner_timeout = Duration::from_millis(2000);

    for &port in port_list {
        let sem = sem.clone();
        let addr = SocketAddr::new(ip, port);
        let host = host.to_string();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await;
            // Try TCP connect
            match timeout(connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(mut stream)) => {
                    let service = if service_detect {
                        grab_banner(&mut stream, port, &host, banner_timeout).await
                    } else {
                        None
                    };
                    Some(OpenPort {
                        port,
                        state: PortState::Open,
                        service,
                    })
                }
                Ok(Err(_)) => None,   // Connection refused → closed
                Err(_) => None,        // Timeout → filtered (not reported)
            }
        });
        handles.push(handle);
    }

    let mut open_ports = Vec::new();
    for h in handles {
        if let Ok(Some(op)) = h.await {
            open_ports.push(op);
        }
    }

    // Sort by port number
    open_ports.sort_by_key(|p| p.port);

    PortScanResult {
        host: host.to_string(),
        ip,
        open_ports,
    }
}

/// Grab a banner from an open TCP connection by reading initial bytes.
async fn grab_banner(
    stream: &mut TcpStream,
    port: u16,
    _host: &str,
    read_timeout: Duration,
) -> Option<ServiceInfo> {
    let mut buf = [0u8; 1024];
    let banner = match timeout(read_timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            String::from_utf8_lossy(&buf[..n]).to_string()
        }
        _ => String::new(),
    };

    let (name, version) = identify_service(port, &banner);
    let tls = matches!(port, 443 | 8443 | 993 | 995 | 465 | 636);

    Some(ServiceInfo {
        name,
        banner: banner.chars().take(200).collect(),
        version,
        tls,
    })
}

/// Identify the service from port number and/or banner content.
fn identify_service(port: u16, banner: &str) -> (String, Option<String>) {
    let lower = banner.to_ascii_lowercase();

    // Banner-based detection first
    if lower.starts_with("ssh-") {
        let version = banner.split_whitespace().next().map(|s| s.to_string());
        return ("ssh".into(), version);
    }
    if lower.starts_with("220") && (lower.contains("ftp") || lower.contains("filezilla") || lower.contains("vsftpd") || lower.contains("proftpd")) {
        let version = extract_version_from_banner(banner);
        return ("ftp".into(), version);
    }
    if lower.starts_with("220") && (lower.contains("smtp") || lower.contains("mail") || lower.contains("postfix") || lower.contains("exim")) {
        let version = extract_version_from_banner(banner);
        return ("smtp".into(), version);
    }
    if lower.starts_with("+ok") || lower.starts_with("-err") {
        return ("pop3".into(), None);
    }
    if lower.starts_with("* ok") && lower.contains("imap") {
        return ("imap".into(), None);
    }
    if lower.contains("mysql") {
        return ("mysql".into(), extract_version_from_banner(banner));
    }
    if lower.contains("postgresql") || lower.contains("postgres") {
        return ("postgresql".into(), None);
    }
    if lower.contains("redis") {
        return ("redis".into(), extract_version_from_banner(banner));
    }
    if lower.contains("mongodb") || lower.contains("mongod") {
        return ("mongodb".into(), None);
    }
    if lower.starts_with("http/") || lower.contains("<!doctype") || lower.contains("<html") {
        return ("http".into(), None);
    }
    if lower.contains("rfb ") {
        return ("vnc".into(), extract_version_from_banner(banner));
    }

    // Port-based fallback
    let name = match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 587 => "smtp",
        53 => "dns",
        80 | 8080 | 8000 | 8888 => "http",
        110 => "pop3",
        111 => "rpcbind",
        143 => "imap",
        443 | 8443 => "https",
        445 => "smb",
        465 => "smtps",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 | 5901 => "vnc",
        6379 => "redis",
        8161 => "activemq",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "unknown",
    };

    (name.into(), None)
}

fn extract_version_from_banner(banner: &str) -> Option<String> {
    // Grab the first line, trim status codes
    let first_line = banner.lines().next().unwrap_or("");
    let cleaned = first_line
        .trim_start_matches(|c: char| c.is_ascii_digit() || c == ' ' || c == '-');
    if cleaned.len() > 3 {
        Some(cleaned.trim().chars().take(80).collect())
    } else {
        None
    }
}

/// Well-known HTTP port check.
pub fn is_http_service(name: &str) -> bool {
    matches!(name, "http" | "https")
}
