//! Captured HTTP exchange model.
//!
//! An [`Exchange`] wraps the wire-oriented `corvex_core::http::Request`
//! and `Response` types with the metadata we need to drive the UI:
//! where the exchange came from, when it happened, whether it was
//! intercepted, and how it relates to its scope decision. The wire
//! structs themselves are reused unchanged — adding fields there would
//! ripple through unrelated hot paths.

use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// ULID-like sortable identifier built on UUIDv7.
///
/// UUIDv7 encodes a Unix millisecond timestamp in the high bits so
/// lexical ordering matches chronological ordering — the property we
/// want for database keys and log rows.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExchangeId(pub Uuid);

impl ExchangeId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for ExchangeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ExchangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Session identifier (one per Start-Proxy click).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// How an exchange came to exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExchangeOrigin {
    /// The request entered through the MITM listener.
    Proxy { client_addr: SocketAddr },
    /// A user-triggered replay derived from a parent exchange.
    Replay { parent: ExchangeId },
    /// An active check sent this request while investigating a parent.
    Check {
        check_id: String,
        parent: ExchangeId,
    },
    /// A request originated from the Fuzzer view.
    Fuzzer { task: Uuid },
    /// Imported from a HAR / archive file.
    Imported { source: String },
}

impl ExchangeOrigin {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Proxy { .. } => "proxy",
            Self::Replay { .. } => "replay",
            Self::Check { .. } => "check",
            Self::Fuzzer { .. } => "fuzzer",
            Self::Imported { .. } => "imported",
        }
    }

    pub fn parent(&self) -> Option<ExchangeId> {
        match self {
            Self::Replay { parent } | Self::Check { parent, .. } => Some(*parent),
            _ => None,
        }
    }
}

/// Scope classification recorded at capture time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDecision {
    /// Host/path matched the active scope rules.
    InScope,
    /// Host/path did not match (still logged, but checks/intercept skip).
    OutOfScope,
    /// Host/path matched an explicit exclude rule.
    Excluded,
}

impl ScopeDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InScope => "in",
            Self::OutOfScope => "out",
            Self::Excluded => "excluded",
        }
    }
}

bitflags::bitflags! {
    /// Bitflags describing how an intercept affected an exchange.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct InterceptMarks: u8 {
        const REQUEST_PAUSED  = 0b0000_0001;
        const REQUEST_EDITED  = 0b0000_0010;
        const RESPONSE_PAUSED = 0b0000_0100;
        const RESPONSE_EDITED = 0b0000_1000;
    }
}

impl Serialize for InterceptMarks {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(self.bits())
    }
}

impl<'de> Deserialize<'de> for InterceptMarks {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bits = u8::deserialize(d)?;
        Ok(InterceptMarks::from_bits_truncate(bits))
    }
}

/// A captured request/response pair plus metadata.
///
/// `request` and `response` reuse the existing wire-aware structs from
/// `corvex-core` so every downstream tool (fuzzer, scanner, replay)
/// speaks the same shape. This struct is intentionally **not**
/// `Serialize` — the wire types aren't Serde-aware and we don't want
/// to ship full request/response bodies through every IPC call.
/// Callers that need an IPC-friendly projection use [`ExchangeSummary`]
/// for list rendering and the dedicated exchange-detail command for
/// single-row inspection.
#[derive(Debug, Clone)]
pub struct Exchange {
    pub id: ExchangeId,
    pub session_id: SessionId,
    pub origin: ExchangeOrigin,
    pub request: corvex_core::http::Request,
    pub response: Option<corvex_core::http::Response>,

    pub started_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,

    pub intercepted: InterceptMarks,
    pub scope: ScopeDecision,
    pub tags: Vec<String>,
    pub notes: Option<String>,

    pub size_request: u64,
    pub size_response: u64,
    pub duration_ms: Option<u64>,
}

impl Exchange {
    /// Build an in-flight exchange from a captured request.
    pub fn new(
        session_id: SessionId,
        origin: ExchangeOrigin,
        request: corvex_core::http::Request,
        scope: ScopeDecision,
    ) -> Self {
        let size_request = request.body.len() as u64;
        Self {
            id: ExchangeId::new(),
            session_id,
            origin,
            request,
            response: None,
            started_at: OffsetDateTime::now_utc(),
            completed_at: None,
            intercepted: InterceptMarks::empty(),
            scope,
            tags: Vec::new(),
            notes: None,
            size_request,
            size_response: 0,
            duration_ms: None,
        }
    }

    /// Build the IPC-friendly summary. Bodies are intentionally omitted
    /// — the UI fetches full detail on demand via a separate command.
    pub fn summary(&self) -> ExchangeSummary {
        let (path, query) = split_path_query(&self.request.uri);
        let mime = self
            .response
            .as_ref()
            .and_then(|r| header_lookup(&r.headers, "Content-Type"))
            .map(|s| s.split(';').next().unwrap_or(s).trim().to_string());
        ExchangeSummary {
            id: self.id,
            session_id: self.session_id,
            origin_kind: self.origin.kind().to_string(),
            method: self.request.method.clone(),
            scheme: if self.request.ssl { "https" } else { "http" }.to_string(),
            host: self.request.host.clone(),
            port: self.request.port,
            path,
            status: self.response.as_ref().map(|r| r.status),
            mime,
            size_request: self.size_request,
            size_response: self.size_response,
            started_at: self.started_at,
            duration_ms: self.duration_ms,
            scope: self.scope,
            intercepted: self.intercepted.bits(),
            tags: self.tags.clone(),
            query,
        }
    }
}

fn split_path_query(uri: &str) -> (String, Option<String>) {
    match uri.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (uri.to_string(), None),
    }
}

fn header_lookup<'a>(
    headers: &'a indexmap::IndexMap<String, String>,
    name: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Compact row used for the traffic list; avoids shipping full bodies
/// to the UI until a detail view is opened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeSummary {
    pub id: ExchangeId,
    pub session_id: SessionId,
    pub origin_kind: String,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub status: Option<u16>,
    pub mime: Option<String>,
    pub size_request: u64,
    pub size_response: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    pub duration_ms: Option<u64>,
    pub scope: ScopeDecision,
    pub intercepted: u8,
    pub tags: Vec<String>,
    pub query: Option<String>,
}
