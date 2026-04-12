//! SQL Injection Scanner Plugin
//!
//! Active-phase plugin that detects and exploits SQL injection
//! vulnerabilities using five detection techniques across 8+ DBMS
//! backends, with ~50 tamper/WAF-bypass modules.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::info;

use corvex_core::crawler::CrawlGraph;
use corvex_core::error::Result;
use corvex_core::fuzzer::param::FuzzTarget;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::ReportItem;
use corvex_core::scan::ScanCtx;
use corvex_core::sqli::config::SqliConfig;
use corvex_core::sqli::dbms::Dbms;
use corvex_core::sqli::enumerate;
use corvex_core::sqli::exploit;
use corvex_core::sqli::tamper::TamperChain;
use corvex_core::sqli::technique::{
    boolean, error, stacked, time, union_query, Confidence, SqliFinding,
};
use corvex_core::target::Mark;

fn sqli_item(method: &str, uri: &str, message: String, refs: &str) -> Vec<ReportItem> {
    vec![ReportItem {
        corvex_id: String::new(),
        method: method.to_string(),
        uri: uri.to_string(),
        message,
        refs: refs.to_string(),
        data: String::new(),
        plugin: "sqli".to_string(),
    }]
}

static INFO: PluginInfo = PluginInfo {
    name: "sqli",
    full_name: "SQL Injection Scanner",
    description: "Active SQL injection detection and exploitation: error-based, boolean blind, time-based blind, UNION query, stacked queries across 8+ DBMS backends with ~50 WAF-bypass tamper modules.",
    weight: 50,
    default: false,
    extra: false,
    hooks: &[HookKind::Active],
};

#[derive(Default)]
pub struct SqliPlugin;

#[async_trait]
impl Plugin for SqliPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_active(
        &self,
        ctx: &ScanCtx,
        mark: Arc<Mutex<Mark>>,
        graph: Arc<CrawlGraph>,
    ) -> Result<()> {
        // Build config from CLI flags
        let config = SqliConfig {
            level: ctx.cli.sqli_level,
            risk: ctx.cli.sqli_risk,
            techniques: ctx.cli.sqli_techniques.clone(),
            dbms: ctx
                .cli
                .sqli_dbms
                .as_deref()
                .and_then(Dbms::from_str_loose),
            time_delay: ctx.cli.sqli_time_delay,
            tamper: ctx
                .cli
                .tamper
                .as_deref()
                .map(|s| s.split(',').map(|t| t.trim().to_string()).collect())
                .unwrap_or_default(),
            second_url: ctx.cli.sqli_second_url.clone(),
            prefix: ctx.cli.sqli_prefix.clone(),
            suffix: ctx.cli.sqli_suffix.clone(),
            enumerate: ctx.cli.sqli_enumerate.clone(),
        };

        let tamper = if config.tamper.is_empty() {
            TamperChain::default()
        } else {
            TamperChain::from_names(&config.tamper.join(","))
        };

        info!(
            "sqli plugin: level={} risk={} techniques={} tamper={} dbms={:?}",
            config.level,
            config.risk,
            config.techniques,
            tamper.len(),
            config.dbms,
        );

        let mut all_findings: Vec<SqliFinding> = Vec::new();

        // Iterate all crawled pages
        for page in &graph.pages {
            if ctx.is_cancelled() {
                break;
            }

            let targets = FuzzTarget::from_crawled(page);
            if targets.is_empty() {
                continue;
            }

            for target in &targets {
                if ctx.is_cancelled() {
                    break;
                }

                if target.points.is_empty() {
                    continue;
                }

                info!(
                    "sqli: testing {} ({} injection points)",
                    target.url,
                    target.points.len()
                );

                // Run techniques in priority order
                let mut findings = Vec::new();

                // Error-based (fastest, most reliable)
                if config.has_technique('E') {
                    let f =
                        error::detect(ctx, mark.clone(), target, &config, &tamper)
                            .await?;
                    findings.extend(f);
                }

                // Boolean-based blind
                if config.has_technique('B') {
                    // Skip params already confirmed by error-based
                    let confirmed: Vec<String> = findings
                        .iter()
                        .filter(|f| f.confidence >= Confidence::High)
                        .map(|f| f.parameter.clone())
                        .collect();

                    let f = boolean::detect(
                        ctx,
                        mark.clone(),
                        target,
                        &config,
                        &tamper,
                    )
                    .await?;

                    findings.extend(
                        f.into_iter()
                            .filter(|f| !confirmed.contains(&f.parameter)),
                    );
                }

                // Time-based blind
                if config.has_technique('T') {
                    let confirmed: Vec<String> = findings
                        .iter()
                        .filter(|f| f.confidence >= Confidence::High)
                        .map(|f| f.parameter.clone())
                        .collect();

                    let f = time::detect(
                        ctx,
                        mark.clone(),
                        target,
                        &config,
                        &tamper,
                    )
                    .await?;

                    findings.extend(
                        f.into_iter()
                            .filter(|f| !confirmed.contains(&f.parameter)),
                    );
                }

                // UNION query-based
                if config.has_technique('U') {
                    let confirmed: Vec<String> = findings
                        .iter()
                        .filter(|f| f.confidence >= Confidence::High)
                        .map(|f| f.parameter.clone())
                        .collect();

                    let f = union_query::detect(
                        ctx,
                        mark.clone(),
                        target,
                        &config,
                        &tamper,
                    )
                    .await?;

                    findings.extend(
                        f.into_iter()
                            .filter(|f| !confirmed.contains(&f.parameter)),
                    );
                }

                // Stacked queries
                if config.has_technique('S') {
                    let confirmed: Vec<String> = findings
                        .iter()
                        .filter(|f| f.confidence >= Confidence::High)
                        .map(|f| f.parameter.clone())
                        .collect();

                    let f = stacked::detect(
                        ctx,
                        mark.clone(),
                        target,
                        &config,
                        &tamper,
                    )
                    .await?;

                    findings.extend(
                        f.into_iter()
                            .filter(|f| !confirmed.contains(&f.parameter)),
                    );
                }

                // Emit findings as report items
                for finding in &findings {
                    let msg = format!(
                        "SQL injection ({}, {}, confidence: {}): parameter '{}' is injectable. DBMS: {}{}",
                        finding.technique,
                        finding.injection_point.name(),
                        finding.confidence,
                        finding.parameter,
                        finding.dbms,
                        finding
                            .extracted_data
                            .as_ref()
                            .map(|d| format!(". Extracted: {d}"))
                            .unwrap_or_default(),
                    );

                    ctx.emit(
                        mark.clone(),
                        sqli_item(&target.method, &target.url, msg, "CWE-89"),
                    )
                    .await;
                }

                // Enumeration phase (if requested)
                if config.enumerate.is_some() {
                    for finding in &findings {
                        if ctx.is_cancelled() {
                            break;
                        }

                        if finding.confidence < Confidence::Medium {
                            continue;
                        }

                        info!(
                            "sqli: enumerating via {} on parameter '{}'",
                            finding.technique, finding.parameter
                        );

                        let enum_result = enumerate::enumerate(
                            ctx,
                            mark.clone(),
                            target,
                            finding,
                            &config,
                            &tamper,
                        )
                        .await?;

                        // Emit enumeration results
                        if !enum_result.databases.is_empty() {
                            ctx.emit(
                                mark.clone(),
                                sqli_item("SQLI", &target.url, format!("Databases found: {}", enum_result.databases.join(", ")), "CWE-89"),
                            ).await;
                        }
                        if !enum_result.tables.is_empty() {
                            ctx.emit(
                                mark.clone(),
                                sqli_item("SQLI", &target.url, format!("Tables found: {}", enum_result.tables.join(", ")), "CWE-89"),
                            ).await;
                        }
                        if !enum_result.users.is_empty() {
                            ctx.emit(
                                mark.clone(),
                                sqli_item("SQLI", &target.url, format!("Users found: {}", enum_result.users.join(", ")), "CWE-89"),
                            ).await;
                        }
                        if !enum_result.password_hashes.is_empty() {
                            for (user, hash) in &enum_result.password_hashes {
                                ctx.emit(
                                    mark.clone(),
                                    sqli_item("SQLI", &target.url, format!("Password hash: {user}:{hash}"), "CWE-89"),
                                ).await;
                            }
                        }
                    }
                }

                // Exploitation phase (file read/write, OS cmd)
                let enum_targets = config.enumerate_targets();
                for finding in &findings {
                    if ctx.is_cancelled() {
                        break;
                    }

                    if finding.confidence < Confidence::High {
                        continue;
                    }

                    if enum_targets.contains(&"file-read") {
                        // Try reading /etc/passwd or equivalent
                        let test_file = if cfg!(windows) {
                            "C:\\Windows\\win.ini"
                        } else {
                            "/etc/passwd"
                        };
                        let result = exploit::file_read(
                            ctx,
                            mark.clone(),
                            target,
                            finding,
                            test_file,
                            &config,
                            &tamper,
                        )
                        .await?;

                        if result.success {
                            let msg = format!(
                                "File read successful: {}{}",
                                test_file,
                                result.data.as_ref()
                                    .map(|d| format!(" (content: {}...)", &d[..d.len().min(100)]))
                                    .unwrap_or_default(),
                            );
                            ctx.emit(mark.clone(), sqli_item("SQLI", &target.url, msg, "CWE-89")).await;
                        }
                    }

                    if enum_targets.contains(&"os-cmd") {
                        let result = exploit::os_command(
                            ctx,
                            mark.clone(),
                            target,
                            finding,
                            "id",
                            &config,
                            &tamper,
                        )
                        .await?;

                        if result.success {
                            let msg = format!(
                                "OS command execution successful{}",
                                result.data.as_ref()
                                    .map(|d| format!(": {d}"))
                                    .unwrap_or_default(),
                            );
                            ctx.emit(mark.clone(), sqli_item("SQLI", &target.url, msg, "CWE-78")).await;
                        }
                    }
                }

                all_findings.extend(findings);
            }
        }

        if !all_findings.is_empty() {
            info!(
                "sqli: {} total findings across {} techniques",
                all_findings.len(),
                all_findings
                    .iter()
                    .map(|f| f.technique)
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
            );
        }

        Ok(())
    }
}
