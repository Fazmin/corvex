//! Deep TLS/SSL security analysis — cipher enumeration, protocol version
//! testing, and known vulnerability detection.
//!
//! Uses the existing OpenSSL bindings directly for full control over
//! protocol negotiation.

use openssl::ssl::{SslConnector, SslMethod, SslVersion, SslVerifyMode};
use std::net::IpAddr;
use tokio::task;

use crate::error::Result;

/// A TLS vulnerability finding.
#[derive(Debug, Clone)]
pub struct TlsVulnerability {
    pub name: String,
    pub cve: Option<String>,
    pub description: String,
    pub severity: &'static str,
}

/// Results of deep TLS analysis.
#[derive(Debug, Clone, Default)]
pub struct TlsAuditResult {
    pub protocols_supported: Vec<String>,
    pub vulnerabilities: Vec<TlsVulnerability>,
}

/// Test which TLS protocol versions a server supports by attempting
/// connections with each version.
pub async fn probe_protocols(
    host: String,
    ip: IpAddr,
    port: u16,
) -> Result<Vec<String>> {
    let probes: Vec<(&str, Option<SslVersion>, Option<SslVersion>)> = vec![
        ("TLSv1.3", Some(SslVersion::TLS1_3), Some(SslVersion::TLS1_3)),
        ("TLSv1.2", Some(SslVersion::TLS1_2), Some(SslVersion::TLS1_2)),
        ("TLSv1.1", Some(SslVersion::TLS1_1), Some(SslVersion::TLS1_1)),
        ("TLSv1.0", Some(SslVersion::TLS1), Some(SslVersion::TLS1)),
    ];

    let mut supported = Vec::new();

    for (name, min, max) in probes {
        let host = host.clone();
        let name = name.to_string();

        let ok = task::spawn_blocking(move || {
            try_protocol_connect(&host, ip, port, min, max)
        })
        .await
        .unwrap_or(false);

        if ok {
            supported.push(name);
        }
    }

    Ok(supported)
}

fn try_protocol_connect(
    host: &str,
    ip: IpAddr,
    port: u16,
    min_version: Option<SslVersion>,
    max_version: Option<SslVersion>,
) -> bool {
    let mut builder = match SslConnector::builder(SslMethod::tls()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    builder.set_verify(SslVerifyMode::NONE);
    if let Some(min) = min_version {
        let _ = builder.set_min_proto_version(Some(min));
    }
    if let Some(max) = max_version {
        let _ = builder.set_max_proto_version(Some(max));
    }
    let _ = builder.set_cipher_list("ALL:COMPLEMENTOFALL:@SECLEVEL=0");

    let connector = builder.build();
    let addr = format!("{ip}:{port}");

    match std::net::TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| std::net::SocketAddr::new(ip, port)),
        std::time::Duration::from_secs(5),
    ) {
        Ok(tcp) => {
            let ssl = connector.configure();
            match ssl {
                Ok(config) => config.into_ssl(host).ok().and_then(|ssl| {
                    openssl::ssl::SslStream::new(ssl, tcp).ok().and_then(|mut s| {
                        s.connect().ok()
                    })
                }).is_some(),
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

/// Analyze protocol support for known vulnerabilities.
pub fn check_protocol_vulns(protocols: &[String]) -> Vec<TlsVulnerability> {
    let mut vulns = Vec::new();
    let protos: Vec<String> = protocols.iter().map(|p| p.to_ascii_uppercase()).collect();

    // SSLv3 — POODLE
    if protos.iter().any(|p| p.contains("SSLV3")) {
        vulns.push(TlsVulnerability {
            name: "POODLE".into(),
            cve: Some("CVE-2014-3566".into()),
            description: "SSLv3 is supported — vulnerable to POODLE attack.".into(),
            severity: "HIGH",
        });
    }

    // TLS 1.0 — BEAST
    if protos.iter().any(|p| p == "TLSV1.0" || p == "TLSV1") {
        vulns.push(TlsVulnerability {
            name: "BEAST".into(),
            cve: Some("CVE-2011-3389".into()),
            description: "TLS 1.0 is supported — may be vulnerable to BEAST attack with CBC ciphers.".into(),
            severity: "MEDIUM",
        });
    }

    // TLS 1.1 — deprecated
    if protos.iter().any(|p| p == "TLSV1.1") {
        vulns.push(TlsVulnerability {
            name: "TLS 1.1 Deprecated".into(),
            cve: None,
            description: "TLS 1.1 is supported — deprecated per RFC 8996.".into(),
            severity: "LOW",
        });
    }

    // No TLS 1.2 or 1.3 support
    let has_modern = protos.iter().any(|p| p == "TLSV1.2" || p == "TLSV1.3");
    if !has_modern && !protos.is_empty() {
        vulns.push(TlsVulnerability {
            name: "No Modern TLS".into(),
            cve: None,
            description: "Server does not support TLS 1.2 or 1.3 — only deprecated protocols available.".into(),
            severity: "HIGH",
        });
    }

    vulns
}
