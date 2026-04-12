//! Stacked queries (piggy-back) SQL injection detection.
//!
//! Tests whether the target supports multiple SQL statements separated
//! by semicolons, primarily using time-based confirmation. Works best
//! against MSSQL and PostgreSQL.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::error::Result;
use crate::fuzzer::param::FuzzTarget;
use crate::scan::ScanCtx;
use crate::target::Mark;

use super::{Confidence, SqliFinding, Technique};
use crate::sqli::config::SqliConfig;
use crate::sqli::dbms::Dbms;
use crate::sqli::payloads;
use crate::sqli::tamper::TamperChain;

/// Timing factor for stacked query confirmation.
const TIMING_FACTOR: f64 = 0.8;

/// Run stacked queries detection on all injection points.
/// This technique requires risk >= 2 since stacked queries can execute
/// data-modifying statements.
pub async fn detect(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    config: &SqliConfig,
    tamper: &TamperChain,
) -> Result<Vec<SqliFinding>> {
    let mut findings = Vec::new();

    // Stacked queries are risky — require risk >= 2
    if config.risk < 2 {
        return Ok(findings);
    }

    let (host, port, ssl) = {
        let m = mark.lock().await;
        (m.hostname.clone(), m.port, m.ssl)
    };

    // Measure baseline timing
    let baseline_time = measure_baseline(ctx, mark.clone(), target, &host, port, ssl).await?;
    let delay = config.time_delay;

    let dbms_list = match config.dbms {
        Some(d) if d.supports_stacked() => vec![d],
        Some(_) => return Ok(findings), // DBMS doesn't support stacked queries
        None => vec![Dbms::MSSQL, Dbms::PostgreSQL, Dbms::MySQL],
    };

    for (pi, point) in target.points.iter().enumerate() {
        if ctx.is_cancelled() {
            break;
        }

        let mut detected = false;

        for dbms in &dbms_list {
            if ctx.is_cancelled() || detected {
                break;
            }

            let stacked_pls = payloads::stacked_probes(*dbms, delay, config.level);

            for payload in &stacked_pls {
                if ctx.is_cancelled() || detected {
                    break;
                }

                let tampered = if tamper.is_empty() {
                    payload.clone()
                } else {
                    tamper.apply(payload, Some(*dbms))
                };

                let form = None;
                let mut req = target.inject(pi, &tampered, &host, port, form);
                req.ssl = ssl;
                req.timeout_secs = (delay as u64 + 15).max(req.timeout_secs);

                let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let expected_min = baseline_time
                    + Duration::from_secs_f64(delay as f64 * TIMING_FACTOR);

                if resp.elapsed >= expected_min {
                    // Confirm with doubled delay
                    let confirmed = confirm_stacked(
                        ctx,
                        mark.clone(),
                        target,
                        pi,
                        *dbms,
                        delay * 2,
                        baseline_time,
                        config,
                        tamper,
                        &host,
                        port,
                        ssl,
                    )
                    .await?;

                    findings.push(SqliFinding {
                        technique: Technique::StackedQueries,
                        dbms: *dbms,
                        parameter: point.name().to_string(),
                        injection_point: point.clone(),
                        payload: tampered.clone(),
                        url: target.url.clone(),
                        extracted_data: None,
                        confidence: if confirmed {
                            Confidence::High
                        } else {
                            Confidence::Medium
                        },
                    });
                    detected = true;
                }
            }
        }
    }

    Ok(findings)
}

async fn measure_baseline(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<Duration> {
    let mut times = Vec::with_capacity(3);
    for _ in 0..3 {
        if ctx.is_cancelled() {
            break;
        }
        let mut req = crate::http::request::Request::new(host, port, &target.method, "/");
        req.uri = extract_path(&target.url);
        req.ssl = ssl;
        if let Ok(resp) = ctx.nfetch(mark.clone(), &mut req).await {
            times.push(resp.elapsed);
        }
    }
    if times.is_empty() {
        return Ok(Duration::from_secs(1));
    }
    times.sort();
    Ok(times[times.len() / 2])
}

async fn confirm_stacked(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    dbms: Dbms,
    confirm_delay: u32,
    baseline_time: Duration,
    config: &SqliConfig,
    tamper: &TamperChain,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<bool> {
    let confirm_payloads = payloads::stacked_probes(dbms, confirm_delay, config.level);
    if let Some(payload) = confirm_payloads.first() {
        let tampered = if tamper.is_empty() {
            payload.clone()
        } else {
            tamper.apply(payload, Some(dbms))
        };

        let form = None;
        let mut req = target.inject(point_idx, &tampered, host, port, form);
        req.ssl = ssl;
        req.timeout_secs = (confirm_delay as u64 + 15).max(req.timeout_secs);

        if let Ok(resp) = ctx.nfetch(mark.clone(), &mut req).await {
            let expected_min = baseline_time
                + Duration::from_secs_f64(confirm_delay as f64 * TIMING_FACTOR);
            return Ok(resp.elapsed >= expected_min);
        }
    }
    Ok(false)
}

fn extract_path(url: &str) -> String {
    url::Url::parse(url)
        .map(|u| {
            let mut s = u.path().to_string();
            if let Some(q) = u.query() {
                s.push('?');
                s.push_str(q);
            }
            s
        })
        .unwrap_or_else(|_| "/".to_string())
}
