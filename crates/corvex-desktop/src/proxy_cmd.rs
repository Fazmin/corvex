//! Tauri command surface for the proxy and Checks feature.
//!
//! Commands are thin adapters over the [`corvex_proxy::ProxyState`]
//! handle registered during Tauri setup. The command module focuses on
//! serialization and error mapping — the underlying logic lives in the
//! `corvex-proxy` crate so it can be reused from tests and, later, a
//! CLI entry point.

use std::sync::Arc;

use corvex_proxy::{
    Exchange, ExchangeId, ExchangeSummary, ProxyConfig, ProxyState, ProxyStatus, SessionId,
};
use serde::Serialize;
use tauri::State;

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
