//! Time-based blind SQL injection detection.
//!
//! Injects SLEEP/WAITFOR/pg_sleep payloads and measures response time
//! to detect blind SQL injection when no visible output difference exists.

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

/// Number of baseline requests to establish normal response time.
const BASELINE_SAMPLES: usize = 3;
/// Tolerance factor: response must exceed baseline + (delay * factor).
const TIMING_FACTOR: f64 = 0.8;

/// Run time-based blind detection on all injection points.
pub async fn detect(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    config: &SqliConfig,
    tamper: &TamperChain,
) -> Result<Vec<SqliFinding>> {
    let mut findings = Vec::new();
    let (host, port, ssl) = {
        let m = mark.lock().await;
        (m.hostname.clone(), m.port, m.ssl)
    };

    // Establish baseline response time
    let baseline_time = measure_baseline(ctx, mark.clone(), target, &host, port, ssl).await?;
    let delay = config.time_delay;

    let dbms_list = match config.dbms {
        Some(d) => vec![d],
        None => vec![
            Dbms::MySQL,
            Dbms::PostgreSQL,
            Dbms::MSSQL,
            Dbms::Oracle,
            Dbms::SQLite,
        ],
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

            let time_pls = payloads::time_payloads(*dbms, delay, config.level);

            for payload in &time_pls {
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
                // Ensure timeout is long enough to capture the delay
                req.timeout_secs = (delay as u64 + 15).max(req.timeout_secs);

                let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let expected_min = baseline_time
                    + Duration::from_secs_f64(delay as f64 * TIMING_FACTOR);

                if resp.elapsed >= expected_min {
                    // Tentative detection — confirm with doubled delay
                    let confirmed = confirm_time(
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

                    let confidence = if confirmed {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    };

                    findings.push(SqliFinding {
                        technique: Technique::TimeBlind,
                        dbms: *dbms,
                        parameter: point.name().to_string(),
                        injection_point: point.clone(),
                        payload: tampered.clone(),
                        url: target.url.clone(),
                        extracted_data: None,
                        confidence,
                    });
                    detected = true;
                }
            }
        }
    }

    Ok(findings)
}

/// Measure baseline response time by sending multiple requests and taking
/// the median duration.
async fn measure_baseline(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<Duration> {
    let mut times = Vec::with_capacity(BASELINE_SAMPLES);

    for _ in 0..BASELINE_SAMPLES {
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
    Ok(times[times.len() / 2]) // median
}

/// Confirmation with doubled delay to verify proportional response time increase.
async fn confirm_time(
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
    let confirm_payloads = payloads::time_payloads(dbms, confirm_delay, config.level);

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
