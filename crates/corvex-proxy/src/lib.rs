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
pub mod intercept;
mod listener;
pub mod parser;
pub mod replay;
pub mod scope;
pub mod store;
mod writer;

pub use ca::{Authority, CaConfig};
pub use exchange::{
    Exchange, ExchangeId, ExchangeOrigin, ExchangeSummary, InterceptMarks, ScopeDecision,
    SessionId,
};
pub use intercept::{
    InterceptMode, InterceptPhase, InterceptQueue, InterceptVerdict, PendingIntercept,
};
pub use replay::{run_replay, ReplayError, ReplayInput};
pub use scope::{ScopeDecision as ScopeRuleDecision, ScopeRules};
pub use store::{ProxyDb, StoredFinding};

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tokio_util::sync::CancellationToken;

use crate::listener::ListenerCtx;
use crate::writer::ExchangeWriter;

use corvex_core::http::client::HttpClient;

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
    /// Active scope rules. Live-updatable from the Settings tab.
    scope: Arc<RwLock<ScopeRules>>,
    /// Intercept-mode toggle (off/request/response/both).
    intercept_mode: Arc<RwLock<InterceptMode>>,
    /// Pending intercept queue. Shared between the listener and the
    /// Tauri command layer.
    intercept_queue: InterceptQueue,
    /// Upstream client reused by the proxy listener and by replay.
    upstream: Arc<HttpClient>,
    /// Currently-running listener handle, if any.
    running: RwLock<Option<RunningSession>>,
    /// Read-only fan-out channel for live exchange events.
    tx: broadcast::Sender<exchange::Exchange>,
}

struct RunningSession {
    cancel: CancellationToken,
    session_id: SessionId,
    listen: SocketAddr,
    captured: Arc<AtomicU64>,
}

impl ProxyState {
    pub fn new(authority: Arc<Authority>, db: Arc<ProxyDb>) -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            authority,
            db,
            scope: Arc::new(RwLock::new(ScopeRules::default())),
            intercept_mode: Arc::new(RwLock::new(InterceptMode::Off)),
            intercept_queue: InterceptQueue::new(),
            upstream: Arc::new(listener::build_upstream()),
            running: RwLock::new(None),
            tx,
        }
    }

    pub fn scope(&self) -> Arc<RwLock<ScopeRules>> {
        self.scope.clone()
    }

    pub fn intercept_queue(&self) -> &InterceptQueue {
        &self.intercept_queue
    }

    pub async fn intercept_mode(&self) -> InterceptMode {
        *self.intercept_mode.read().await
    }

    pub async fn set_intercept_mode(&self, mode: InterceptMode) {
        *self.intercept_mode.write().await = mode;
        // When toggling off, release every pending request so the
        // client isn't left hanging.
        if mode == InterceptMode::Off {
            self.intercept_queue.drop_all();
        }
    }

    pub fn upstream_client(&self) -> Arc<HttpClient> {
        self.upstream.clone()
    }

    pub fn session_id(&self) -> Option<SessionId> {
        // RwLock is async; use try_read so this helper stays sync.
        let g = self.running.try_read().ok()?;
        g.as_ref().map(|s| s.session_id)
    }

    /// Persist an exchange and broadcast it so the UI updates live.
    /// Replay + Checks both go through this to stay consistent with
    /// the listener path.
    pub fn record_exchange(&self, exchange: Exchange) {
        let _ = self.tx.send(exchange.clone());
        if let Err(e) = self.db.insert_exchange(&exchange) {
            tracing::warn!(target: "proxy", "insert replay exchange failed: {e}");
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
                exchanges_captured: s.captured.load(Ordering::Relaxed),
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

    /// Start the listener and begin accepting browser connections.
    ///
    /// Spawns three cooperating tasks: the hyper-based listener, the
    /// batched SQLite writer, and a drain task that fans broadcast
    /// exchanges out to subscribers. Cancelling the returned session
    /// (via [`ProxyState::stop`]) unwinds all three cleanly.
    pub async fn start(&self, config: ProxyConfig) -> anyhow::Result<SessionId> {
        let mut slot = self.running.write().await;
        if slot.is_some() {
            anyhow::bail!("proxy is already running");
        }
        self.authority.ensure_ready()?;

        let session_id = SessionId::new();
        self.db.insert_session(
            &session_id,
            &config.listen.to_string(),
            config.note.as_deref(),
        )?;

        let cancel = CancellationToken::new();
        let captured = Arc::new(AtomicU64::new(0));

        let (writer, _writer_handle) = ExchangeWriter::spawn(self.db.clone());
        let ctx = Arc::new(ListenerCtx {
            authority: self.authority.clone(),
            session_id,
            scope: self.scope.clone(),
            intercept_mode: self.intercept_mode.clone(),
            intercept_queue: self.intercept_queue.clone(),
            writer,
            broadcast: self.tx.clone(),
            captured: captured.clone(),
            upstream: self.upstream.clone(),
        });

        let listen = config.listen;
        let task_cancel = cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = listener::serve(listen, ctx, task_cancel).await {
                tracing::error!(target: "proxy", "listener exited: {e}");
            }
        });

        *slot = Some(RunningSession {
            cancel,
            session_id,
            listen,
            captured,
        });
        tracing::info!(
            target: "proxy",
            session = %session_id,
            listen = %listen,
            "proxy session started"
        );
        Ok(session_id)
    }

    /// Stop the listener if running. Idempotent.
    pub async fn stop(&self) -> anyhow::Result<()> {
        // Drop any pending intercepts so the listener's oneshot
        // receivers don't hang on shutdown.
        self.intercept_queue.drop_all();
        let mut slot = self.running.write().await;
        if let Some(session) = slot.take() {
            session.cancel.cancel();
            self.db.finish_session(&session.session_id)?;
            tracing::info!(
                target: "proxy",
                session = %session.session_id,
                "proxy session stopped"
            );
        }
        Ok(())
    }
}
