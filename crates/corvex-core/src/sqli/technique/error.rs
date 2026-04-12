//! Error-based SQL injection detection.
//!
//! Injects boundary probes and SQL fragments, scanning responses for
//! database error messages. When errors are found, attempts data
//! extraction via DBMS-specific error functions.

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::error::Result;
use crate::fuzzer::param::FuzzTarget;
use crate::scan::ScanCtx;
use crate::target::Mark;

use super::{Confidence, SqliFinding, Technique};
use crate::sqli::config::SqliConfig;
use crate::sqli::dbms::{self, Dbms};
use crate::sqli::detection;
use crate::sqli::payloads;
use crate::sqli::tamper::TamperChain;

/// Run error-based detection on all injection points of a fuzz target.
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

    // Get baseline response (no injection) for comparison
    let baseline_req = {
        let mut req = crate::http::request::Request::new(&host, port, &target.method, "/");
        req.uri = extract_path(&target.url);
        req.ssl = ssl;
        req
    };
    let baseline = match ctx.nfetch(mark.clone(), &mut baseline_req.clone()).await {
        Ok(r) => r,
        Err(_) => return Ok(findings),
    };
    let baseline_errors = detection::error_matches(&baseline.body_str());

    let probes = payloads::boundary_probes(config.level);

    for (pi, point) in target.points.iter().enumerate() {
        if ctx.is_cancelled() {
            break;
        }

        let mut _detected_dbms: Option<Dbms> = config.dbms;

        for probe in &probes {
            if ctx.is_cancelled() {
                break;
            }

            let payload = if tamper.is_empty() {
                probe.clone()
            } else {
                tamper.apply(probe, config.dbms)
            };

            let form = None; // TODO: pass form descriptor for POST body fields
            let mut req = target.inject(pi, &payload, &host, port, form);
            req.ssl = ssl;

            let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let body = resp.body_str();
            let errors = detection::error_matches(&body);

            // Filter out errors that were already in the baseline
            let new_errors: Vec<_> = errors
                .iter()
                .filter(|e| {
                    !baseline_errors
                        .iter()
                        .any(|be| be.dbms == e.dbms && be.description == e.description)
                })
                .collect();

            if !new_errors.is_empty() {
                let best = dbms::best_dbms(
                    &new_errors.iter().map(|e| (*e).clone()).collect::<Vec<_>>(),
                );
                _detected_dbms = Some(best);

                findings.push(SqliFinding {
                    technique: Technique::ErrorBased,
                    dbms: best,
                    parameter: point.name().to_string(),
                    injection_point: point.clone(),
                    payload: payload.clone(),
                    url: target.url.clone(),
                    extracted_data: None,
                    confidence: Confidence::High,
                });

                // Attempt data extraction at level >= 2
                if config.level >= 2 {
                    if let Some(data) = attempt_error_extraction(
                        ctx,
                        mark.clone(),
                        target,
                        pi,
                        best,
                        config,
                        tamper,
                        &host,
                        port,
                        ssl,
                    )
                    .await?
                    {
                        if let Some(last) = findings.last_mut() {
                            last.extracted_data = Some(data);
                        }
                    }
                }

                // Found vulnerability for this point, skip remaining probes
                break;
            }
        }
    }

    Ok(findings)
}

/// Attempt to extract data using error-based techniques.
async fn attempt_error_extraction(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    dbms: Dbms,
    _config: &SqliConfig,
    tamper: &TamperChain,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<Option<String>> {
    // Try to extract version() as a proof of exploitation
    let version_expr = dbms.version_fn();
    let extraction_payloads = payloads::error_extraction_payloads(dbms, version_expr);

    for payload in &extraction_payloads {
        if ctx.is_cancelled() {
            break;
        }

        let tampered = if tamper.is_empty() {
            payload.clone()
        } else {
            tamper.apply(payload, Some(dbms))
        };

        let form = None;
        let mut req = target.inject(point_idx, &tampered, host, port, form);
        req.ssl = ssl;

        let resp = match ctx.nfetch(mark.clone(), &mut req).await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let body = resp.body_str();

        // Look for version strings in error messages
        // Common patterns: data appears after ~ (0x7e) in EXTRACTVALUE/UPDATEXML
        if let Some(start) = body.find('~') {
            let after = &body[start + 1..];
            if let Some(end) = after.find('~') {
                let data = &after[..end];
                if !data.is_empty() && data.len() < 200 {
                    return Ok(Some(data.to_string()));
                }
            }
        }

        // For CAST-based extraction, look for conversion error message with data
        // e.g., "Conversion failed when converting the nvarchar value 'Microsoft SQL Server...' to data type int"
        if let Some(start) = body.find("nvarchar value '") {
            let after = &body[start + 16..];
            if let Some(end) = after.find('\'') {
                let data = &after[..end];
                if !data.is_empty() && data.len() < 500 {
                    return Ok(Some(data.to_string()));
                }
            }
        }

        // PostgreSQL CAST error pattern
        if let Some(start) = body.find("invalid input syntax for") {
            let after = &body[start..];
            if let Some(q_start) = after.find('"') {
                let after_q = &after[q_start + 1..];
                if let Some(q_end) = after_q.find('"') {
                    let data = &after_q[..q_end];
                    if !data.is_empty() && data.len() < 500 {
                        return Ok(Some(data.to_string()));
                    }
                }
            }
        }
    }

    Ok(None)
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
