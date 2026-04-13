//! DNS enumeration plugin — record lookups, SPF analysis, optional
//! subdomain brute-force discovery.
//!
//! Runs in the Recon phase (weight 5 = early, before other recon plugins)
//! so discovered subdomains can inform the rest of the scan.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::info;

use corvex_core::dns;
use corvex_core::error::Result;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;

static INFO: PluginInfo = PluginInfo {
    name: "dns_enum",
    full_name: "DNS Enumeration",
    description:
        "DNS record lookups, SPF analysis, zone transfer check, and optional subdomain brute-force.",
    weight: 5,
    default: true,
    extra: false,
    hooks: &[HookKind::Recon],
};

#[derive(Default)]
pub struct DnsEnumPlugin;

/// Extract the base domain from a hostname. Strips leading `www.` or
/// similar prefixes but keeps at least two labels.
fn base_domain(hostname: &str) -> String {
    let h = hostname.trim_end_matches('.');
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() <= 2 {
        return h.to_string();
    }
    // Use the last two labels as the domain
    labels[labels.len() - 2..].join(".")
}

#[async_trait]
impl Plugin for DnsEnumPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_recon(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let hostname = {
            let m = mark.lock().await;
            m.hostname.clone()
        };

        // Skip IP-only targets
        if hostname.parse::<std::net::IpAddr>().is_ok() {
            return Ok(());
        }

        let domain = base_domain(&hostname);
        info!(target: "dns_enum", "enumerating DNS for {domain}");

        let mut findings: Vec<ReportItem> = Vec::new();

        // ---- Record lookups ----
        match dns::lookup_records(&domain).await {
            Ok(records) => {
                if !records.is_empty() {
                    let summary: Vec<String> = records
                        .iter()
                        .map(|r| format!("{} {} {}", r.record_type, r.name, r.value))
                        .collect();

                    findings.push(ReportItem {
                        corvex_id: "DNS-RECORDS".into(),
                        method: "DNS".into(),
                        uri: domain.clone(),
                        message: format!(
                            "Found {} DNS records for {domain}.",
                            records.len()
                        ),
                        refs: String::new(),
                        data: summary.join("\n"),
                        plugin: INFO.name.to_string(),
                        ..Default::default()
                    });

                    // SPF analysis
                    let spf_issues = dns::check_spf_issues(&records);
                    for issue in &spf_issues {
                        findings.push(ReportItem {
                            corvex_id: "DNS-SPF".into(),
                            method: "DNS".into(),
                            uri: domain.clone(),
                            message: issue.clone(),
                            refs: String::new(),
                            data: String::new(),
                            plugin: INFO.name.to_string(),
                            severity: Severity::Medium,
                            ..Default::default()
                        });
                    }

                    // Check for MX pointing to external providers (informational)
                    let mx_records: Vec<&dns::DnsRecord> = records
                        .iter()
                        .filter(|r| r.record_type == "MX")
                        .collect();
                    if !mx_records.is_empty() {
                        let mx_list: Vec<String> =
                            mx_records.iter().map(|r| r.value.clone()).collect();
                        findings.push(ReportItem {
                            corvex_id: "DNS-MX".into(),
                            method: "DNS".into(),
                            uri: domain.clone(),
                            message: format!(
                                "Mail servers: {}",
                                mx_list.join(", ")
                            ),
                            refs: String::new(),
                            data: String::new(),
                            plugin: INFO.name.to_string(),
                            ..Default::default()
                        });
                    }
                }
            }
            Err(e) => {
                info!(target: "dns_enum", "DNS lookup failed for {domain}: {e}");
            }
        }

        // ---- Zone transfer attempt ----
        match dns::try_zone_transfer(&domain).await {
            Ok(records) if !records.is_empty() => {
                findings.push(ReportItem {
                    corvex_id: "DNS-AXFR".into(),
                    method: "DNS".into(),
                    uri: domain.clone(),
                    message: format!(
                        "DNS zone transfer (AXFR) succeeded! Retrieved {} records. This is a serious misconfiguration.",
                        records.len()
                    ),
                    refs: String::new(),
                    data: records.iter().map(|r| format!("{} {}", r.record_type, r.value)).collect::<Vec<_>>().join("\n"),
                    plugin: INFO.name.to_string(),
                    severity: Severity::High,
                    ..Default::default()
                });
            }
            _ => {}
        }

        // ---- Reverse DNS ----
        let ip = {
            let m = mark.lock().await;
            m.ip
        };
        if let Some(ip) = ip {
            if let Ok(Some(rdns)) = dns::reverse_lookup(ip).await {
                if rdns.trim_end_matches('.') != hostname {
                    findings.push(ReportItem {
                        corvex_id: "DNS-RDNS".into(),
                        method: "DNS".into(),
                        uri: domain.clone(),
                        message: format!(
                            "Reverse DNS for {} resolves to {rdns} (differs from target hostname {hostname}).",
                            ip
                        ),
                        refs: String::new(),
                        data: String::new(),
                        plugin: INFO.name.to_string(),
                        ..Default::default()
                    });
                }
            }
        }

        // ---- Subdomain brute-force ----
        if ctx.cli.dns_brute {
            let wordlist: Vec<String> = if let Some(path) = &ctx.cli.dns_wordlist {
                // Load from custom file
                match std::fs::read_to_string(path) {
                    Ok(content) => content
                        .lines()
                        .map(|l| l.trim().to_string())
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .collect(),
                    Err(e) => {
                        info!(target: "dns_enum", "failed to read wordlist {}: {e}", path.display());
                        ctx.dbs.subdomains.prefixes.clone()
                    }
                }
            } else {
                ctx.dbs.subdomains.prefixes.clone()
            };

            info!(
                target: "dns_enum",
                "brute-forcing {} subdomain prefixes for {domain} (threads: {})",
                wordlist.len(),
                ctx.cli.dns_threads
            );

            match dns::brute_subdomains(&domain, &wordlist, ctx.cli.dns_threads).await {
                Ok(found) if !found.is_empty() => {
                    info!(target: "dns_enum", "discovered {} subdomains", found.len());
                    findings.push(ReportItem {
                        corvex_id: "DNS-SUBDOMAINS".into(),
                        method: "DNS".into(),
                        uri: domain.clone(),
                        message: format!(
                            "Discovered {} subdomains via brute-force.",
                            found.len()
                        ),
                        refs: String::new(),
                        data: found.join("\n"),
                        plugin: INFO.name.to_string(),
                        severity: Severity::Info,
                        ..Default::default()
                    });
                }
                Ok(_) => {
                    info!(target: "dns_enum", "no subdomains found via brute-force");
                }
                Err(e) => {
                    info!(target: "dns_enum", "subdomain brute-force failed: {e}");
                }
            }
        }

        if !findings.is_empty() {
            ctx.emit(mark, findings).await;
        }

        Ok(())
    }
}
