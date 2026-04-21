//! Replay engine.
//!
//! The user picks a captured exchange, optionally edits the raw request
//! bytes, and hits Send. The replay runs directly through corvex-core's
//! HTTP client — it doesn't pass back through the MITM listener —
//! because the point of replay is to control the wire exactly. The
//! resulting request/response pair is captured as a child
//! [`Exchange`] with origin [`ExchangeOrigin::Replay`] so it joins the
//! traffic log alongside the original.

use std::sync::Arc;

use corvex_core::http::client::HttpClient;
use corvex_core::http::request::Request as CoreRequest;

use crate::exchange::{Exchange, ExchangeId, ExchangeOrigin, ScopeDecision, SessionId};
use crate::parser::parse_request;

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("base exchange not found: {0}")]
    BaseNotFound(ExchangeId),
    #[error("parse edited request: {0}")]
    ParseEdit(String),
    #[error("upstream: {0}")]
    Upstream(String),
}

/// Input supplied by the UI. When `edited_bytes` is `None` we replay
/// the base request unchanged.
pub struct ReplayInput {
    pub session_id: SessionId,
    pub base: CoreRequest,
    pub base_id: ExchangeId,
    pub edited_bytes: Option<Vec<u8>>,
}

/// Send the request and return a completed [`Exchange`]. The caller
/// (usually the Tauri command layer) is responsible for persisting and
/// broadcasting the result so the traffic log picks it up.
pub async fn run_replay(
    client: Arc<HttpClient>,
    input: ReplayInput,
) -> Result<Exchange, ReplayError> {
    let request = match input.edited_bytes {
        Some(bytes) => parse_request(&bytes, &input.base.host, input.base.port, input.base.ssl)
            .map_err(ReplayError::ParseEdit)?,
        None => input.base.clone(),
    };

    let started = std::time::Instant::now();
    let response = client
        .send(&request)
        .await
        .map_err(|e| ReplayError::Upstream(e.to_string()))?;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    let mut exchange = Exchange::new(
        input.session_id,
        ExchangeOrigin::Replay {
            parent: input.base_id,
        },
        request,
        // Replay always runs against whatever host the user targeted —
        // scope classification is done by the listener for proxied
        // traffic; for replay we treat it as in-scope so the Checks tab
        // can pick it up.
        ScopeDecision::InScope,
    );
    exchange.size_response = response.body.len() as u64;
    exchange.response = Some(response);
    exchange.duration_ms = Some(elapsed_ms);
    exchange.completed_at = Some(time::OffsetDateTime::now_utc());
    Ok(exchange)
}
