//! Report TLS handshake + certificate metadata as findings once per host,
//! with a TLS grade (A–F) based on protocol version and cipher strength.
//!
//! The HTTP client extracts the cert/cipher/protocol on the initial fetch
//! and stashes them in `mark.ssl_info`. This plugin fires on the Recon hook
//! and emits a summary finding so every report sink sees it.

use async_trait::async_trait;
use corvex_core::error::Result;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "ssl",
    full_name: "SSL/TLS",
    description: "Report TLS certificate, cipher, and protocol information with grade.",
    weight: 10,
    default: true,
    extra: false,
    hooks: &[HookKind::Recon],
};

#[derive(Default)]
pub struct SslPlugin;

/// Compute a TLS grade based on protocol and cipher.
///
/// Grading rules (simplified SSL Labs-style):
///   A — TLS 1.2+ with strong cipher (AES-GCM, ChaCha20, AES-256)
///   B — TLS 1.2 with acceptable cipher (AES-CBC)
///   C — TLS 1.1 or weak cipher (3DES, RC4)
///   D — TLS 1.0
///   F — SSLv3 or SSLv2
fn tls_grade(protocol: Option<&str>, cipher: Option<&str>) -> (char, Severity) {
    let proto = protocol.unwrap_or("").to_ascii_uppercase();
    let ciph = cipher.unwrap_or("").to_ascii_uppercase();

    // Protocol check — floor the grade
    let proto_grade: u8 = if proto.contains("TLSV1.3") {
        5 // A+
    } else if proto.contains("TLSV1.2") {
        4 // A
    } else if proto.contains("TLSV1.1") {
        2 // C
    } else if proto.contains("TLSV1.0") || proto.contains("TLSV1") {
        1 // D
    } else if proto.contains("SSLV3") || proto.contains("SSLV2") {
        0 // F
    } else {
        3 // Unknown — assume B
    };

    // Cipher check — may lower the grade
    let cipher_grade: u8 = if ciph.contains("GCM")
        || ciph.contains("CHACHA20")
        || ciph.contains("AES256")
        || ciph.contains("AES_256")
    {
        5 // Excellent
    } else if ciph.contains("AES128") || ciph.contains("AES_128") || ciph.contains("AES") {
        4 // Good
    } else if ciph.contains("CBC") {
        3 // Acceptable (may be vulnerable to BEAST/Lucky13)
    } else if ciph.contains("3DES") || ciph.contains("DES-CBC3") {
        1 // Weak (Sweet32)
    } else if ciph.contains("RC4") || ciph.contains("NULL") || ciph.contains("EXPORT") {
        0 // Insecure
    } else {
        3 // Unknown — assume acceptable
    };

    let final_grade = proto_grade.min(cipher_grade);

    let (grade, severity) = match final_grade {
        5 | 4 => ('A', Severity::Info),
        3 => ('B', Severity::Low),
        2 => ('C', Severity::Medium),
        1 => ('D', Severity::Medium),
        _ => ('F', Severity::High),
    };

    (grade, severity)
}

/// Check for known weak cipher patterns and return findings.
fn check_cipher_weaknesses(cipher: &str) -> Vec<(String, Severity)> {
    let ciph = cipher.to_ascii_uppercase();
    let mut issues = Vec::new();

    if ciph.contains("RC4") {
        issues.push((
            "Cipher uses RC4 which is cryptographically broken.".into(),
            Severity::High,
        ));
    }
    if ciph.contains("3DES") || ciph.contains("DES-CBC3") {
        issues.push((
            "Cipher uses 3DES (64-bit block) — vulnerable to Sweet32 attacks.".into(),
            Severity::Medium,
        ));
    }
    if ciph.contains("NULL") {
        issues.push((
            "NULL cipher detected — data is transmitted unencrypted.".into(),
            Severity::Critical,
        ));
    }
    if ciph.contains("EXPORT") {
        issues.push((
            "EXPORT-grade cipher detected — vulnerable to FREAK/Logjam.".into(),
            Severity::High,
        ));
    }
    if ciph.contains("CBC") && !ciph.contains("3DES") {
        issues.push((
            "CBC mode cipher in use — may be susceptible to BEAST/Lucky13 padding attacks.".into(),
            Severity::Low,
        ));
    }

    issues
}

#[async_trait]
impl Plugin for SslPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_recon(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let info = {
            let m = mark.lock().await;
            m.ssl_info.clone()
        };
        let info = match info {
            Some(i) => i,
            None => return Ok(()),
        };

        let mut findings: Vec<ReportItem> = Vec::new();

        // ---- SSL info summary ----
        let mut parts: Vec<String> = Vec::new();
        if let Some(p) = &info.protocol {
            parts.push(format!("Protocol: {p}"));
        }
        if let Some(c) = &info.cipher {
            parts.push(format!("Cipher: {c}"));
        }
        if let Some(s) = &info.cert_subject {
            parts.push(format!("Subject: {s}"));
        }
        if let Some(s) = &info.cert_issuer {
            parts.push(format!("Issuer: {s}"));
        }
        if !info.cert_alt_names.is_empty() {
            parts.push(format!("SAN: {}", info.cert_alt_names.join(", ")));
        }
        if let Some(s) = &info.cert_not_after {
            parts.push(format!("Not After: {s}"));
        }

        if !parts.is_empty() {
            findings.push(ReportItem {
                corvex_id: "SSL-INFO".into(),
                method: "GET".into(),
                uri: "/".into(),
                message: parts.join(" | "),
                refs: String::new(),
                data: String::new(),
                plugin: INFO.name.to_string(),
                ..Default::default()
            });
        }

        // ---- TLS grade ----
        let (grade, grade_severity) =
            tls_grade(info.protocol.as_deref(), info.cipher.as_deref());

        findings.push(ReportItem {
            corvex_id: format!("SSL-GRADE-{grade}"),
            method: "GET".into(),
            uri: "/".into(),
            message: format!(
                "TLS grade: {grade} (protocol: {}, cipher: {})",
                info.protocol.as_deref().unwrap_or("unknown"),
                info.cipher.as_deref().unwrap_or("unknown"),
            ),
            refs: String::new(),
            data: String::new(),
            plugin: INFO.name.to_string(),
            severity: grade_severity,
            ..Default::default()
        });

        // ---- Protocol-level warnings ----
        if let Some(proto) = &info.protocol {
            let upper = proto.to_ascii_uppercase();
            if upper.contains("SSLV3") {
                findings.push(ReportItem {
                    corvex_id: "SSL-SSLV3".into(),
                    method: "GET".into(),
                    uri: "/".into(),
                    message: "SSLv3 is in use — vulnerable to POODLE (CVE-2014-3566).".into(),
                    refs: "CVE-2014-3566".into(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                    severity: Severity::High,
                    cve: Some("CVE-2014-3566".into()),
                    cvss: Some(3.4),
                });
            }
            if upper.contains("TLSV1.0") || (upper == "TLSV1" && !upper.contains("TLSV1.")) {
                findings.push(ReportItem {
                    corvex_id: "SSL-TLS10".into(),
                    method: "GET".into(),
                    uri: "/".into(),
                    message: "TLS 1.0 is in use — deprecated and vulnerable to BEAST.".into(),
                    refs: String::new(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                    severity: Severity::Medium,
                    ..Default::default()
                });
            }
            if upper.contains("TLSV1.1") {
                findings.push(ReportItem {
                    corvex_id: "SSL-TLS11".into(),
                    method: "GET".into(),
                    uri: "/".into(),
                    message: "TLS 1.1 is in use — deprecated since RFC 8996.".into(),
                    refs: String::new(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                    severity: Severity::Low,
                    ..Default::default()
                });
            }
        }

        // ---- Cipher weakness checks ----
        if let Some(cipher) = &info.cipher {
            for (msg, sev) in check_cipher_weaknesses(cipher) {
                findings.push(ReportItem {
                    corvex_id: "SSL-CIPHER-WEAK".into(),
                    method: "GET".into(),
                    uri: "/".into(),
                    message: msg,
                    refs: String::new(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                    severity: sev,
                    ..Default::default()
                });
            }
        }

        if !findings.is_empty() {
            ctx.emit(mark, findings).await;
        }
        Ok(())
    }
}
