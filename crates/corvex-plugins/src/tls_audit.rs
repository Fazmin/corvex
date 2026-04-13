//! Deep TLS/SSL security analysis plugin.
//!
//! Probes the server with separate connections per protocol version to
//! enumerate support and detect known TLS vulnerabilities.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::info;

use corvex_core::error::Result;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;
use corvex_core::tls_audit;

static INFO: PluginInfo = PluginInfo {
    name: "tls_audit",
    full_name: "TLS Security Audit",
    description: "Deep TLS protocol/cipher enumeration and vulnerability detection.",
    weight: 12,
    default: true,
    extra: false,
    hooks: &[HookKind::Recon],
};

#[derive(Default)]
pub struct TlsAuditPlugin;

#[async_trait]
impl Plugin for TlsAuditPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_recon(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let (hostname, ip, port, ssl) = {
            let m = mark.lock().await;
            (m.hostname.clone(), m.ip, m.port, m.ssl)
        };

        // Only run on SSL/TLS targets
        if !ssl {
            return Ok(());
        }
        let ip = match ip {
            Some(ip) => ip,
            None => return Ok(()),
        };

        info!(target: "tls_audit", "probing TLS protocols for {}:{}", hostname, port);

        let mut findings: Vec<ReportItem> = Vec::new();

        // Probe supported protocols
        let protocols = tls_audit::probe_protocols(hostname.clone(), ip, port).await?;

        if !protocols.is_empty() {
            findings.push(ReportItem {
                corvex_id: "TLS-PROTOCOLS".into(),
                method: "TLS".into(),
                uri: format!("{}:{}", hostname, port),
                message: format!(
                    "Supported TLS protocols: {}",
                    protocols.join(", ")
                ),
                refs: String::new(),
                data: protocols.join("\n"),
                plugin: INFO.name.to_string(),
                ..Default::default()
            });
        }

        // Check for protocol-level vulnerabilities
        let vulns = tls_audit::check_protocol_vulns(&protocols);
        for vuln in &vulns {
            let severity = match vuln.severity {
                "CRITICAL" => Severity::Critical,
                "HIGH" => Severity::High,
                "MEDIUM" => Severity::Medium,
                "LOW" => Severity::Low,
                _ => Severity::Info,
            };
            findings.push(ReportItem {
                corvex_id: format!("TLS-VULN-{}", vuln.name.to_ascii_uppercase().replace(' ', "-")),
                method: "TLS".into(),
                uri: format!("{}:{}", hostname, port),
                message: vuln.description.clone(),
                refs: vuln.cve.clone().unwrap_or_default(),
                data: String::new(),
                plugin: INFO.name.to_string(),
                severity,
                cve: vuln.cve.clone(),
                ..Default::default()
            });
        }

        if !findings.is_empty() {
            ctx.emit(mark, findings).await;
        }

        Ok(())
    }
}
