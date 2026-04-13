//! Network service vulnerability checks — tests non-HTTP services
//! discovered during port scanning.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::info;

use corvex_core::error::Result;
use corvex_core::netservice;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;

static INFO: PluginInfo = PluginInfo {
    name: "netservices",
    full_name: "Network Service Checks",
    description: "Vulnerability checks for non-HTTP services (FTP, SMTP, SSH, SNMP, Telnet).",
    weight: 40,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct NetServicesPlugin;

/// Well-known service ports to check when port scanning is not enabled.
const DEFAULT_SERVICE_PORTS: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (161, "snmp"),
];

#[async_trait]
impl Plugin for NetServicesPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_scan(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let ip = {
            let m = mark.lock().await;
            m.ip
        };
        let ip = match ip {
            Some(ip) => ip,
            None => return Ok(()),
        };

        // Only run if port scanning was enabled (we need discovered ports)
        // or do a quick probe on default service ports
        if !ctx.cli.portscan {
            return Ok(());
        }

        let mut findings: Vec<ReportItem> = Vec::new();

        // Check well-known service ports
        for &(port, service) in DEFAULT_SERVICE_PORTS {
            if ctx.is_cancelled() {
                break;
            }

            match service {
                "ftp" => {
                    if let Ok(result) = netservice::check_ftp_anon(ip, port).await {
                        if let Some(msg) = &result.finding {
                            findings.push(make_finding(port, service, msg, "MEDIUM", &result.banner));
                        }
                        if !result.banner.is_empty() {
                            findings.push(make_banner_finding(port, service, &result.banner));
                        }
                    }
                }
                "ssh" => {
                    if let Ok(result) = netservice::check_ssh(ip, port).await {
                        if let Some(msg) = &result.finding {
                            findings.push(make_finding(port, service, msg, result.severity, &result.banner));
                        }
                        if !result.banner.is_empty() {
                            findings.push(make_banner_finding(port, service, &result.banner));
                        }
                    }
                }
                "telnet" => {
                    // Quick connect check to see if telnet is open
                    if let Ok(_) = tokio::net::TcpStream::connect(
                        std::net::SocketAddr::new(ip, port)
                    ).await {
                        let result = netservice::check_telnet(port);
                        if let Some(msg) = &result.finding {
                            findings.push(make_finding(port, service, msg, result.severity, ""));
                        }
                    }
                }
                "smtp" => {
                    if let Ok(result) = netservice::check_smtp_relay(ip, port).await {
                        if let Some(msg) = &result.finding {
                            findings.push(make_finding(port, service, msg, result.severity, &result.banner));
                        }
                        if !result.banner.is_empty() {
                            findings.push(make_banner_finding(port, service, &result.banner));
                        }
                    }
                }
                "snmp" => {
                    if let Ok(result) = netservice::check_snmp_community(ip, port).await {
                        if let Some(msg) = &result.finding {
                            findings.push(make_finding(port, service, msg, result.severity, ""));
                        }
                    }
                }
                _ => {}
            }
        }

        if !findings.is_empty() {
            info!(target: "netservices", "found {} network service findings", findings.len());
            ctx.emit(mark, findings).await;
        }

        Ok(())
    }
}

fn make_finding(port: u16, service: &str, message: &str, severity: &str, _banner: &str) -> ReportItem {
    let sev = match severity {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    };
    ReportItem {
        corvex_id: format!("NETSVC-{}-{}", service.to_ascii_uppercase(), port),
        method: "TCP".into(),
        uri: format!(":{port}"),
        message: message.to_string(),
        refs: String::new(),
        data: String::new(),
        plugin: INFO.name.to_string(),
        severity: sev,
        ..Default::default()
    }
}

fn make_banner_finding(port: u16, service: &str, banner: &str) -> ReportItem {
    ReportItem {
        corvex_id: format!("NETSVC-BANNER-{}-{}", service.to_ascii_uppercase(), port),
        method: "TCP".into(),
        uri: format!(":{port}"),
        message: format!("{} service banner: {}", service, banner.trim()),
        refs: String::new(),
        data: String::new(),
        plugin: INFO.name.to_string(),
        ..Default::default()
    }
}
