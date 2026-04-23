//! Tauri command surface for the proxy and Checks feature.
//!
//! Commands are thin adapters over the [`corvex_proxy::ProxyState`]
//! handle registered during Tauri setup. The command module focuses on
//! serialization and error mapping — the underlying logic lives in the
//! `corvex-proxy` crate so it can be reused from tests and, later, a
//! CLI entry point.

use std::sync::Arc;

use corvex_proxy::{
    run_replay, Exchange, ExchangeId, ExchangeSummary, InterceptMode, InterceptVerdict,
    PendingIntercept, ProxyConfig, ProxyState, ProxyStatus, ReplayInput, ScopeRules, SessionId,
    StoredFinding,
};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::check_bridge::CheckBridge;
use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize)]
pub struct ExchangeDetail {
    pub id: String,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
    pub status: Option<u16>,
    pub request_headers: Vec<(String, String)>,
    pub request_body_base64: Option<String>,
    pub response_headers: Vec<(String, String)>,
    pub response_body_base64: Option<String>,
    pub started_at_unix: i64,
    pub duration_ms: Option<u64>,
}

#[tauri::command]
pub async fn proxy_status(state: State<'_, Arc<ProxyState>>) -> AppResult<ProxyStatus> {
    Ok(state.status().await)
}

#[tauri::command]
pub async fn proxy_start(
    state: State<'_, Arc<ProxyState>>,
    config: Option<ProxyConfig>,
) -> AppResult<SessionId> {
    let cfg = config.unwrap_or_default();
    state
        .start(cfg)
        .await
        .map_err(|e| AppError::Other(format!("proxy_start: {e}")))
}

#[tauri::command]
pub async fn proxy_stop(state: State<'_, Arc<ProxyState>>) -> AppResult<()> {
    state
        .stop()
        .await
        .map_err(|e| AppError::Other(format!("proxy_stop: {e}")))
}

#[tauri::command]
pub async fn proxy_export_ca_pem(
    state: State<'_, Arc<ProxyState>>,
) -> AppResult<ExportedCa> {
    let authority = state.authority();
    let pem = authority
        .cert_pem()
        .map_err(|e| AppError::Other(format!("cert_pem: {e}")))?;
    Ok(ExportedCa {
        path: authority.cert_path().to_string_lossy().into_owned(),
        pem: String::from_utf8_lossy(&pem).into_owned(),
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportedCa {
    pub path: String,
    pub pem: String,
}

#[tauri::command]
pub async fn exchanges_list(
    state: State<'_, Arc<ProxyState>>,
    session: SessionId,
    limit: Option<usize>,
    offset: Option<usize>,
) -> AppResult<Vec<ExchangeSummary>> {
    let limit = limit.unwrap_or(200).clamp(1, 2000);
    let offset = offset.unwrap_or(0);
    let db = state.db().clone();
    let session_copy = session;
    let rows = tauri::async_runtime::spawn_blocking(move || {
        db.list_exchanges(&session_copy, limit, offset)
    })
    .await
    .map_err(|e| AppError::Other(format!("join: {e}")))?
    .map_err(|e| AppError::Other(format!("list_exchanges: {e}")))?;
    Ok(rows)
}

#[tauri::command]
pub async fn exchange_get(
    state: State<'_, Arc<ProxyState>>,
    id: ExchangeId,
) -> AppResult<Option<ExchangeDetail>> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let db = state.db().clone();
    let row = tauri::async_runtime::spawn_blocking(move || db.get_exchange_raw(&id))
        .await
        .map_err(|e| AppError::Other(format!("join: {e}")))?
        .map_err(|e| AppError::Other(format!("get_exchange: {e}")))?;
    let Some(stored) = row else { return Ok(None) };

    let req_headers: indexmap::IndexMap<String, String> =
        bincode::deserialize(&stored.req_headers)
            .map_err(|e| AppError::Other(format!("decode req headers: {e}")))?;
    let res_headers: indexmap::IndexMap<String, String> = stored
        .res_headers
        .as_deref()
        .map(bincode::deserialize)
        .transpose()
        .map_err(|e| AppError::Other(format!("decode res headers: {e}")))?
        .unwrap_or_default();

    Ok(Some(ExchangeDetail {
        id: id.to_string(),
        method: stored.method,
        scheme: stored.scheme,
        host: stored.host,
        port: stored.port,
        path: stored.path,
        query: stored.query,
        status: stored.status,
        request_headers: req_headers.into_iter().collect(),
        request_body_base64: stored.req_body.as_deref().map(|b| B64.encode(b)),
        response_headers: res_headers.into_iter().collect(),
        response_body_base64: stored.res_body.as_deref().map(|b| B64.encode(b)),
        started_at_unix: stored.started_at,
        duration_ms: stored.duration_ms,
    }))
}

/// Wake-path signature for when the listener eventually emits live
/// exchanges on the broadcast channel: we'll forward each summary to
/// the frontend as a `proxy://exchange-new` event. This shim exists
/// now so the listener can plug in without touching the command
/// surface.
#[allow(dead_code)]
pub fn exchange_summary_payload(ex: &Exchange) -> ExchangeSummary {
    ex.summary()
}

// --- Scope rules -------------------------------------------------------

#[tauri::command]
pub async fn scope_get(state: State<'_, Arc<ProxyState>>) -> AppResult<ScopeRules> {
    Ok(state.scope_snapshot().await)
}

#[tauri::command]
pub async fn scope_set(
    state: State<'_, Arc<ProxyState>>,
    rules: ScopeRules,
) -> AppResult<()> {
    // Validate any path regexes up front so a malformed rule is caught
    // at Save time instead of silently fail-closing every match later.
    for rule in rules.include.iter().chain(rules.exclude.iter()) {
        if let Some(pat) = &rule.path_regex {
            if !pat.is_empty() {
                regex::Regex::new(pat)
                    .map_err(|e| AppError::Other(format!("bad path regex {pat:?}: {e}")))?;
            }
        }
    }

    let db = state.db().clone();
    let to_persist = rules.clone();
    tauri::async_runtime::spawn_blocking(move || db.save_scope_rules(&to_persist))
        .await
        .map_err(|e| AppError::Other(format!("join: {e}")))?
        .map_err(|e| AppError::Other(format!("save_scope_rules: {e}")))?;

    state.set_scope_rules(rules).await;
    Ok(())
}

// --- Phase 2: intercept + replay ---------------------------------------

#[tauri::command]
pub async fn intercept_set_mode(
    state: State<'_, Arc<ProxyState>>,
    mode: InterceptMode,
) -> AppResult<()> {
    state.set_intercept_mode(mode).await;
    Ok(())
}

#[tauri::command]
pub async fn intercept_get_mode(
    state: State<'_, Arc<ProxyState>>,
) -> AppResult<InterceptMode> {
    Ok(state.intercept_mode().await)
}

#[tauri::command]
pub async fn intercept_pending_list(
    state: State<'_, Arc<ProxyState>>,
) -> AppResult<Vec<PendingIntercept>> {
    Ok(state.intercept_queue().pending())
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InterceptVerdictInput {
    Forward,
    ForwardEdited { bytes_base64: String },
    Drop,
}

#[tauri::command]
pub async fn intercept_resolve(
    state: State<'_, Arc<ProxyState>>,
    id: ExchangeId,
    verdict: InterceptVerdictInput,
) -> AppResult<()> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let translated = match verdict {
        InterceptVerdictInput::Forward => InterceptVerdict::Forward,
        InterceptVerdictInput::Drop => InterceptVerdict::Drop,
        InterceptVerdictInput::ForwardEdited { bytes_base64 } => {
            let bytes = B64
                .decode(bytes_base64.as_bytes())
                .map_err(|e| AppError::Other(format!("base64: {e}")))?;
            InterceptVerdict::ForwardEdited { bytes }
        }
    };
    state
        .intercept_queue()
        .resolve(id, translated)
        .map_err(|e| AppError::Other(format!("intercept_resolve: {e}")))
}

#[tauri::command]
pub async fn intercept_drop_all(state: State<'_, Arc<ProxyState>>) -> AppResult<()> {
    state.intercept_queue().drop_all();
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayResult {
    pub id: String,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    pub response_headers: Vec<(String, String)>,
    pub response_body_base64: Option<String>,
}

#[tauri::command]
pub async fn replay_send(
    state: State<'_, Arc<ProxyState>>,
    base_id: ExchangeId,
    edited_bytes_base64: Option<String>,
) -> AppResult<ReplayResult> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let session_id = state
        .session_id()
        .ok_or_else(|| AppError::Other("no active proxy session".into()))?;

    // Hydrate the base request from the stored exchange so the user
    // doesn't have to ship it on every send.
    let db = state.db().clone();
    let stored = tauri::async_runtime::spawn_blocking(move || db.get_exchange_raw(&base_id))
        .await
        .map_err(|e| AppError::Other(format!("join: {e}")))?
        .map_err(|e| AppError::Other(format!("get_exchange: {e}")))?
        .ok_or_else(|| AppError::Other(format!("base exchange not found: {base_id}")))?;

    let headers: indexmap::IndexMap<String, String> =
        bincode::deserialize(&stored.req_headers)
            .map_err(|e| AppError::Other(format!("decode headers: {e}")))?;

    let mut base = corvex_core::http::request::Request::new(
        &stored.host,
        stored.port,
        &stored.method,
        &compose_uri(&stored.path, stored.query.as_deref()),
    );
    base.ssl = stored.scheme == "https";
    base.headers = headers;
    base.body = stored.req_body.unwrap_or_default();
    // Ensure Connection: close for corvex-core's close-delimited reads.
    base.headers.shift_remove("connection");
    base.headers.shift_remove("Connection");
    base.headers.insert("Connection".into(), "close".into());

    let edited_bytes = edited_bytes_base64
        .map(|s| B64.decode(s.as_bytes()))
        .transpose()
        .map_err(|e| AppError::Other(format!("base64: {e}")))?;

    let input = ReplayInput {
        session_id,
        base,
        base_id,
        edited_bytes,
    };

    let client = state.upstream_client();
    let exchange = run_replay(client, input)
        .await
        .map_err(|e| AppError::Other(format!("replay: {e}")))?;

    let result = ReplayResult {
        id: exchange.id.to_string(),
        status: exchange.response.as_ref().map(|r| r.status),
        duration_ms: exchange.duration_ms,
        response_headers: exchange
            .response
            .as_ref()
            .map(|r| r.headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default(),
        response_body_base64: exchange
            .response
            .as_ref()
            .map(|r| B64.encode(&r.body)),
    };

    // Persist + broadcast so the replayed request shows up in Traffic
    // under its own row with origin Replay{parent}.
    state.record_exchange(exchange);

    Ok(result)
}

fn compose_uri(path: &str, query: Option<&str>) -> String {
    match query {
        Some(q) if !q.is_empty() => format!("{path}?{q}"),
        _ => path.to_string(),
    }
}

// --- Phase 3: checks ----------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct CheckDescriptorPayload {
    pub id: String,
    pub name: String,
    pub category: String,
    pub category_label: String,
    /// Full prose description of the OWASP category, sourced from the
    /// active `top10.yaml` taxonomy. Powers tooltips on the Checks
    /// library group headers.
    pub category_description: Option<String>,
    pub kind: String,
    pub default_severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OwaspTaxonomyInfo {
    pub version: String,
    pub released: Option<String>,
    pub source: Option<String>,
    pub categories: Vec<OwaspCategoryInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OwaspCategoryInfo {
    pub code: String,
    pub label: String,
    pub description: Option<String>,
    pub reference: Option<String>,
}

/// Metadata describing the active OWASP Top 10 taxonomy — version,
/// release date, upstream link, and the full category list. Used by
/// the Checks tab to render the "OWASP Top 10 vYYYY" banner and
/// category tooltips.
#[tauri::command]
pub async fn owasp_taxonomy_info() -> AppResult<OwaspTaxonomyInfo> {
    let tax = corvex_intel::owasp::default_taxonomy();
    Ok(OwaspTaxonomyInfo {
        version: tax.version.clone(),
        released: tax.released.clone(),
        source: tax.source.clone(),
        categories: tax
            .categories
            .iter()
            .map(|c| OwaspCategoryInfo {
                code: c.code.clone(),
                label: c.label.clone(),
                description: c.description.clone(),
                reference: c.reference.clone(),
            })
            .collect(),
    })
}

#[tauri::command]
pub async fn checks_list(
    bridge: State<'_, Arc<CheckBridge>>,
) -> AppResult<Vec<CheckDescriptorPayload>> {
    // Resolve labels from the active OWASP taxonomy at render time so
    // swapping `top10.yaml` to a newer release picks up immediately
    // without touching any Rust source.
    let taxonomy = corvex_intel::owasp::default_taxonomy();
    Ok(bridge
        .registry
        .descriptors()
        .into_iter()
        .map(|d| {
            let code = d.category.code().to_string();
            let category = taxonomy.category(&code);
            let label = category
                .map(|c| c.label.clone())
                .unwrap_or_else(|| "Uncategorised".to_string());
            let description = category.and_then(|c| c.description.clone());
            CheckDescriptorPayload {
                id: d.id,
                name: d.name,
                category: code,
                category_label: label,
                category_description: description,
                kind: match d.kind {
                    corvex_checks::CheckKind::Passive => "passive".to_string(),
                    corvex_checks::CheckKind::Active => "active".to_string(),
                },
                default_severity: d.default_severity.as_str().to_string(),
                description: d.description,
            }
        })
        .collect())
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingRow {
    pub id: String,
    pub exchange_id: String,
    pub check_id: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub evidence: serde_json::Value,
    pub created_at_unix: i64,
}

#[tauri::command]
pub async fn findings_for_exchange(
    state: State<'_, Arc<ProxyState>>,
    id: ExchangeId,
) -> AppResult<Vec<FindingRow>> {
    let db = state.db().clone();
    let rows = tauri::async_runtime::spawn_blocking(move || db.findings_for_exchange(&id))
        .await
        .map_err(|e| AppError::Other(format!("join: {e}")))?
        .map_err(|e| AppError::Other(format!("findings_for_exchange: {e}")))?;
    Ok(rows.into_iter().map(stored_to_row).collect())
}

#[tauri::command]
pub async fn findings_for_session(
    state: State<'_, Arc<ProxyState>>,
    session: SessionId,
    limit: Option<usize>,
) -> AppResult<Vec<FindingRow>> {
    let limit = limit.unwrap_or(500).clamp(1, 5000);
    let db = state.db().clone();
    let rows =
        tauri::async_runtime::spawn_blocking(move || db.findings_for_session(&session, limit))
            .await
            .map_err(|e| AppError::Other(format!("join: {e}")))?
            .map_err(|e| AppError::Other(format!("findings_for_session: {e}")))?;
    Ok(rows.into_iter().map(stored_to_row).collect())
}

#[derive(Debug, Clone, Serialize)]
pub struct ChecksRunSummary {
    pub ran: Vec<String>,
    pub findings: usize,
}

#[tauri::command]
pub async fn checks_run(
    state: State<'_, Arc<ProxyState>>,
    bridge: State<'_, Arc<CheckBridge>>,
    app: tauri::AppHandle,
    target_ids: Vec<ExchangeId>,
    check_ids: Vec<String>,
) -> AppResult<ChecksRunSummary> {
    use tauri::Emitter;
    let client = state.upstream_client();
    let ctx = corvex_checks::CheckCtx { client };
    let registry = bridge.registry.clone();
    let db = state.db().clone();

    let mut total = 0usize;

    for target_id in &target_ids {
        // Hydrate the target exchange so active checks have a full
        // request to mutate.
        let Some(target_exchange) = hydrate_exchange(&state, *target_id).await? else {
            continue;
        };

        let findings = registry
            .run_active(&ctx, &target_exchange, &check_ids)
            .await;

        total += findings.len();
        for finding in &findings {
            let stored = StoredFinding {
                id: finding.id.to_string(),
                scan_run_id: None,
                exchange_id: finding.exchange_id.to_string(),
                check_id: finding.check_id.clone(),
                severity: finding.severity.as_str().to_string(),
                title: finding.title.clone(),
                description: finding.description.clone(),
                evidence: Some(
                    serde_json::to_vec(&finding.evidence)
                        .map_err(|e| AppError::Other(format!("evidence: {e}")))?,
                ),
                created_at: finding.created_at.unix_timestamp(),
            };
            let db_clone = db.clone();
            let stored_clone = stored.clone();
            tauri::async_runtime::spawn_blocking(move || db_clone.insert_finding(&stored_clone))
                .await
                .map_err(|e| AppError::Other(format!("join: {e}")))?
                .map_err(|e| AppError::Other(format!("insert finding: {e}")))?;

            let payload = crate::check_bridge::FindingPayload::from(&target_exchange, finding);
            let _ = app.emit("proxy://scan-finding", payload);
        }
    }

    Ok(ChecksRunSummary {
        ran: check_ids,
        findings: total,
    })
}

async fn hydrate_exchange(
    state: &State<'_, Arc<ProxyState>>,
    id: ExchangeId,
) -> AppResult<Option<Exchange>> {
    let db = state.db().clone();
    let stored = tauri::async_runtime::spawn_blocking(move || db.get_exchange_raw(&id))
        .await
        .map_err(|e| AppError::Other(format!("join: {e}")))?
        .map_err(|e| AppError::Other(format!("get_exchange: {e}")))?;
    let Some(stored) = stored else {
        return Ok(None);
    };

    let headers: indexmap::IndexMap<String, String> = bincode::deserialize(&stored.req_headers)
        .map_err(|e| AppError::Other(format!("decode headers: {e}")))?;
    let mut req = corvex_core::http::request::Request::new(
        &stored.host,
        stored.port,
        &stored.method,
        &compose_uri(&stored.path, stored.query.as_deref()),
    );
    req.ssl = stored.scheme == "https";
    req.headers = headers;
    req.body = stored.req_body.unwrap_or_default();
    req.headers.shift_remove("connection");
    req.headers.shift_remove("Connection");
    req.headers.insert("Connection".into(), "close".into());

    let session_id = state
        .session_id()
        .ok_or_else(|| AppError::Other("no active proxy session".into()))?;

    let origin = corvex_proxy::ExchangeOrigin::Check {
        check_id: "active".into(),
        parent: id,
    };
    let exchange = Exchange::new(
        session_id,
        origin,
        req,
        corvex_proxy::ScopeDecision::InScope,
    );
    // Preserve the parent id as the target — checks still attach their
    // findings to the user-selected row, not the synthetic parent.
    let mut exchange = exchange;
    exchange.id = id;
    Ok(Some(exchange))
}

fn stored_to_row(s: StoredFinding) -> FindingRow {
    let evidence: serde_json::Value = s
        .evidence
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(serde_json::Value::Null);
    FindingRow {
        id: s.id,
        exchange_id: s.exchange_id,
        check_id: s.check_id,
        severity: s.severity,
        title: s.title,
        description: s.description,
        evidence,
        created_at_unix: s.created_at,
    }
}
