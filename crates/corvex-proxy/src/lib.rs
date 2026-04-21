//! Corvex interactive proxy and Checks engine.
//!
//! This crate provides the plumbing for an HTTP(S) intercepting proxy
//! that sits between a browser and target servers, captures every
//! request/response pair as an [`Exchange`], and exposes the stream to
//! the desktop UI through the application's existing Tauri event bus.
//!
//! The MITM flow is built on [`hyper`] + [`tokio_openssl`] with a local
//! self-signed certificate authority (see [`ca`]). Captured exchanges
//! are written through a batched SQLite writer task to the same
//! on-disk database the rest of the desktop app uses.
//!
//! The public surface is intentionally thin: construct a [`ProxyState`]
//! once, call [`ProxyState::start`] / [`ProxyState::stop`] to control
//! the listener, and subscribe to the live exchange stream via
//! [`ProxyState::subscribe_exchanges`].

pub mod ca;
pub mod exchange;
pub mod scope;
pub mod store;

pub use ca::{Authority, CaConfig};
pub use exchange::{
    Exchange, ExchangeId, ExchangeOrigin, ExchangeSummary, InterceptMarks, ScopeDecision,
    SessionId,
};
pub use scope::{ScopeDecision as ScopeRuleDecision, ScopeRules};
pub use store::ProxyDb;

use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tokio_util::sync::CancellationToken;

/// Runtime configuration for a proxy session, supplied by the desktop
/// frontend when the user clicks Start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Bind address for the listener (default `127.0.0.1:8888`).
    pub listen: SocketAddr,
    /// Optional note shown in the History view alongside the session.
    pub note: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8888".parse().expect("literal addr"),
            note: None,
        }
    }
}

/// Status snapshot returned to the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub listen: Option<SocketAddr>,
    pub session_id: Option<SessionId>,
    pub ca_ready: bool,
    pub exchanges_captured: u64,
}

/// Long-lived proxy state owned by the Tauri app. Wrap in `Arc` and
/// register via `tauri::Manager::manage`.
pub struct ProxyState {
    /// Self-signed certificate authority used to mint per-host leaf
    /// certificates during TLS interception.
    authority: Arc<Authority>,
    /// SQLite-backed storage for captured exchanges and scan findings.
    db: Arc<ProxyDb>,
    /// Currently-running listener handle, if any.
    running: RwLock<Option<RunningSession>>,
    /// Read-only fan-out channel for live exchange events.
    tx: broadcast::Sender<exchange::Exchange>,
}

struct RunningSession {
    #[allow(dead_code)]
    cancel: CancellationToken,
    session_id: SessionId,
    listen: SocketAddr,
    captured: Arc<std::sync::atomic::AtomicU64>,
}

impl ProxyState {
    pub fn new(authority: Arc<Authority>, db: Arc<ProxyDb>) -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            authority,
            db,
            running: RwLock::new(None),
            tx,
        }
    }

    pub fn authority(&self) -> &Arc<Authority> {
        &self.authority
    }

    pub fn db(&self) -> &Arc<ProxyDb> {
        &self.db
    }

    /// Subscribe to the live exchange stream. Lagging receivers will
    /// drop older messages — callers that need every exchange should
    /// page through [`ProxyDb`] instead.
    pub fn subscribe_exchanges(&self) -> broadcast::Receiver<exchange::Exchange> {
        self.tx.subscribe()
    }

    pub async fn status(&self) -> ProxyStatus {
        let running = self.running.read().await;
        let ca_ready = self.authority.is_initialised();
        match running.as_ref() {
            Some(s) => ProxyStatus {
                running: true,
                listen: Some(s.listen),
                session_id: Some(s.session_id),
                ca_ready,
                exchanges_captured: s.captured.load(std::sync::atomic::Ordering::Relaxed),
            },
            None => ProxyStatus {
                running: false,
                listen: None,
                session_id: None,
                ca_ready,
                exchanges_captured: 0,
            },
        }
    }

    /// Start the listener. Phase 1 stub — installs a running session
    /// record and generates a session id, but does not yet bind a
    /// TCP listener. The listener implementation lands in a follow-up.
    pub async fn start(&self, config: ProxyConfig) -> anyhow::Result<SessionId> {
        let mut slot = self.running.write().await;
        if slot.is_some() {
            anyhow::bail!("proxy is already running");
        }
        self.authority.ensure_ready()?;
        let session_id = SessionId::new();
        self.db
            .insert_session(&session_id, &config.listen.to_string(), config.note.as_deref())?;
        *slot = Some(RunningSession {
            cancel: CancellationToken::new(),
            session_id,
            listen: config.listen,
            captured: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        tracing::info!(target: "proxy", %session_id, listen = %config.listen, "proxy session started");
        Ok(session_id)
    }

    /// Stop the listener if running. Idempotent.
    pub async fn stop(&self) -> anyhow::Result<()> {
        let mut slot = self.running.write().await;
        if let Some(session) = slot.take() {
            session.cancel.cancel();
            self.db.finish_session(&session.session_id)?;
            tracing::info!(target: "proxy", session = %session.session_id, "proxy session stopped");
        }
        Ok(())
    }
}
