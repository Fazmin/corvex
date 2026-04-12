//! Boolean-based blind SQL injection detection.
//!
//! Injects true/false SQL conditions and compares response bodies
//! using page ratio analysis to detect injectable parameters.

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::error::Result;
use crate::fuzzer::param::FuzzTarget;
use crate::scan::ScanCtx;
use crate::target::Mark;

use super::{Confidence, SqliFinding, Technique};
use crate::sqli::config::SqliConfig;
use crate::sqli::dbms::Dbms;
use crate::sqli::detection;
use crate::sqli::payloads;
use crate::sqli::tamper::TamperChain;

/// Similarity threshold: responses with ratio above this are "same page".
const SAME_PAGE_THRESHOLD: f64 = 0.90;
/// Responses with ratio below this against baseline are "different page".
const DIFF_PAGE_THRESHOLD: f64 = 0.60;

/// Run boolean-based blind detection on all injection points.
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

    // Get baseline response
    let baseline_body = {
        let mut req = crate::http::request::Request::new(&host, port, &target.method, "/");
        req.uri = extract_path(&target.url);
        req.ssl = ssl;
        match ctx.nfetch(mark.clone(), &mut req).await {
            Ok(r) => r.body,
            Err(_) => return Ok(findings),
        }
    };
    let baseline_clean =
        detection::remove_dynamic_content(&String::from_utf8_lossy(&baseline_body));

    let dbms_list = match config.dbms {
        Some(d) => vec![d],
        None => vec![
            Dbms::MySQL,
            Dbms::PostgreSQL,
            Dbms::MSSQL,
            Dbms::Oracle,
            Dbms::SQLite,
            Dbms::MariaDB,
            Dbms::DB2,
            Dbms::Firebird,
            Dbms::Unknown,
        ],
    };

    let pairs = {
        let mut all_pairs = Vec::new();
        for dbms in &dbms_list {
            all_pairs.extend(payloads::boolean_pairs(*dbms, config.level, config.risk));
        }
        // Deduplicate
        all_pairs.sort_by(|a, b| a.0.cmp(&b.0));
        all_pairs.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
        all_pairs
    };

    for (pi, point) in target.points.iter().enumerate() {
        if ctx.is_cancelled() {
            break;
        }

        let mut confirmed = false;

        for (true_payload, false_payload) in &pairs {
            if ctx.is_cancelled() || confirmed {
                break;
            }

            let true_p = if tamper.is_empty() {
                true_payload.clone()
            } else {
                tamper.apply(true_payload, config.dbms)
            };
            let false_p = if tamper.is_empty() {
                false_payload.clone()
            } else {
                tamper.apply(false_payload, config.dbms)
            };

            // Send TRUE condition
            let form = None;
            let mut true_req = target.inject(pi, &true_p, &host, port, form);
            true_req.ssl = ssl;
            let true_resp = match ctx.nfetch(mark.clone(), &mut true_req).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let true_clean = detection::remove_dynamic_content(&true_resp.body_str());

            // Send FALSE condition
            let mut false_req = target.inject(pi, &false_p, &host, port, form);
            false_req.ssl = ssl;
            let false_resp = match ctx.nfetch(mark.clone(), &mut false_req).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let false_clean = detection::remove_dynamic_content(&false_resp.body_str());

            // Compare: true should match baseline, false should differ
            let true_ratio = detection::page_ratio(
                baseline_clean.as_bytes(),
                true_clean.as_bytes(),
            );
            let false_ratio = detection::page_ratio(
                baseline_clean.as_bytes(),
                false_clean.as_bytes(),
            );

            if true_ratio >= SAME_PAGE_THRESHOLD && false_ratio <= DIFF_PAGE_THRESHOLD {
                // Primary detection successful — confirm with second pair
                let confidence = if pairs.len() > 1 {
                    // Attempt confirmation with a different pair
                    let confirm_result = confirm_boolean(
                        ctx,
                        mark.clone(),
                        target,
                        pi,
                        &baseline_clean,
                        config,
                        tamper,
                        &host,
                        port,
                        ssl,
                    )
                    .await?;
                    if confirm_result {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    }
                } else {
                    Confidence::Medium
                };

                findings.push(SqliFinding {
                    technique: Technique::BooleanBlind,
                    dbms: config.dbms.unwrap_or(Dbms::Unknown),
                    parameter: point.name().to_string(),
                    injection_point: point.clone(),
                    payload: format!("{true_payload} / {false_payload}"),
                    url: target.url.clone(),
                    extracted_data: None,
                    confidence,
                });
                confirmed = true;
            }
        }
    }

    Ok(findings)
}

/// Confirmation check using alternative boolean pair.
async fn confirm_boolean(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    baseline_clean: &str,
    config: &SqliConfig,
    tamper: &TamperChain,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<bool> {
    // Use a simple numeric confirmation pair
    let confirm_true = "AND 2>1";
    let confirm_false = "AND 2<1";

    let true_p = if tamper.is_empty() {
        confirm_true.to_string()
    } else {
        tamper.apply(confirm_true, config.dbms)
    };
    let false_p = if tamper.is_empty() {
        confirm_false.to_string()
    } else {
        tamper.apply(confirm_false, config.dbms)
    };

    let form = None;
    let mut true_req = target.inject(point_idx, &true_p, host, port, form);
    true_req.ssl = ssl;
    let true_resp = match ctx.nfetch(mark.clone(), &mut true_req).await {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };

    let mut false_req = target.inject(point_idx, &false_p, host, port, form);
    false_req.ssl = ssl;
    let false_resp = match ctx.nfetch(mark.clone(), &mut false_req).await {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };

    let true_clean = detection::remove_dynamic_content(&true_resp.body_str());
    let false_clean = detection::remove_dynamic_content(&false_resp.body_str());

    let true_ratio = detection::page_ratio(baseline_clean.as_bytes(), true_clean.as_bytes());
    let false_ratio = detection::page_ratio(baseline_clean.as_bytes(), false_clean.as_bytes());

    Ok(true_ratio >= SAME_PAGE_THRESHOLD && false_ratio <= DIFF_PAGE_THRESHOLD)
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
