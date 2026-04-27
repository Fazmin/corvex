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

pub mod body_store;
pub mod ca;
pub mod cluster;
pub mod csrf;
pub mod exchange;
pub mod har;
pub mod intercept;
pub mod intercept_rules;
mod listener;
pub mod parser;
pub mod replay;
pub mod scope;
pub mod spec_import;
pub mod store;
mod writer;
pub mod ws;

pub use ca::{Authority, CaConfig};
pub use cluster::{ClusterAnomaly, ClusterIndex, EndpointCluster};
pub use csrf::{CsrfObservation, CsrfRule, CsrfStore, TokenInject, TokenSource};
pub use intercept_rules::{
    InterceptRule, InterceptRules, MatchCtx as InterceptMatchCtx, Phase as InterceptRulePhase,
    PhaseFilter, RuleCondition, RuleKind,
};
pub use exchange::{
    Exchange, ExchangeId, ExchangeOrigin, ExchangeSummary, InterceptMarks, ScopeDecision,
    SessionId,
};
pub use intercept::{
    InterceptMode, InterceptPhase, InterceptQueue, InterceptVerdict, PendingIntercept,
};
pub use replay::{run_replay, ReplayError, ReplayInput};
pub use body_store::{BodyKind, BodyStore, HARD_CAP as BODY_HARD_CAP, INLINE_THRESHOLD as BODY_INLINE_THRESHOLD};
pub use scope::{ScopeDecision as ScopeRuleDecision, ScopeRule, ScopeRules};

/// Setting key for the per-session exchange retention cap.
pub const RETENTION_SETTING_KEY: &str = "retention.max_exchanges_per_session";

/// Default retention cap — ring-buffer size per session. `0` disables
/// eviction (unlimited). The listener caps at this number of captured
/// exchanges; older rows are dropped when the cap is exceeded.
pub const DEFAULT_RETENTION_MAX: usize = 5_000;

/// Runtime retention policy. Lives behind an `Arc<RwLock<...>>` on
/// [`ProxyState`] so the UI can update it without restarting the
/// listener; the writer consults the current value on every flush.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Maximum exchanges retained per session. `0` means no cap.
    pub max_exchanges_per_session: usize,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_exchanges_per_session: DEFAULT_RETENTION_MAX,
        }
    }
}
pub use store::{ProxyDb, StoredFinding};
pub use ws::{FrameSink as WsFrameSink, WsDirection, WsFrame};

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
    /// Live WebSocket-frame fan-out. Frames land here after the splice
    /// task parses them; both the SQLite writer and the UI event bridge
    /// drain the same channel.
    ws_tx: broadcast::Sender<ws::WsFrame>,
    /// Per-session retention cap. Read by the writer after every
    /// flush; edits from the Settings tab apply on the next flush.
    retention: Arc<RwLock<RetentionPolicy>>,
    /// Live endpoint-pattern aggregator. Subscribes to the broadcast
    /// channel; the snapshot is what the Traffic tab's "Group by
    /// endpoint" view renders. Cleared on every session start so the
    /// view always reflects the active session.
    cluster_index: Arc<RwLock<ClusterIndex>>,
    /// CSRF token store — observed values from responses, injected
    /// into matching outbound requests. Shared with the listener,
    /// replay, and the Checks engine so every outbound HTTP path
    /// gets the same auto-token treatment.
    csrf_store: Arc<csrf::CsrfStore>,
    /// Fan-out for newly-observed CSRF token values. Desktop layer
    /// subscribes and re-emits as `proxy://csrf-observed` so the
    /// Settings → CSRF status panel updates without polling.
    csrf_tx: broadcast::Sender<csrf::CsrfObservation>,
    /// Conditional intercept rules. Layered on top of
    /// [`InterceptMode`] — when the mode permits a pause, the
    /// listener consults this rule set to decide whether to
    /// actually queue the exchange. Edits from the Settings tab
    /// take effect on the next request without restarting.
    intercept_rules: Arc<RwLock<intercept_rules::InterceptRules>>,
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
        let (ws_tx, _) = broadcast::channel(1024);
        let (csrf_tx, _) = broadcast::channel(256);
        // Hydrate persisted rules; fall back to bundled defaults when
        // the table is empty (first run after upgrade) or unreadable.
        let initial_rules = match db.load_csrf_rules() {
            Ok(rules) if !rules.is_empty() => rules,
            Ok(_) => {
                let defaults = csrf::default_rules();
                if let Err(e) = db.save_csrf_rules(&defaults) {
                    tracing::warn!(
                        target: "proxy",
                        "could not seed default CSRF rules: {e}"
                    );
                }
                defaults
            }
            Err(e) => {
                tracing::warn!(
                    target: "proxy",
                    "load_csrf_rules failed ({e}); falling back to bundled defaults"
                );
                csrf::default_rules()
            }
        };
        // Hydrate persisted intercept rules. Empty / failing load
        // falls back to the empty set so the listener behaves like
        // mode-only intercept (the pre-Phase-3 baseline).
        let initial_intercept_rules = match db.load_intercept_rules() {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    target: "proxy",
                    "load_intercept_rules failed ({e}); starting empty"
                );
                intercept_rules::InterceptRules::empty()
            }
        };
        Self {
            authority,
            db,
            scope: Arc::new(RwLock::new(ScopeRules::default())),
            intercept_mode: Arc::new(RwLock::new(InterceptMode::Off)),
            intercept_queue: InterceptQueue::new(),
            upstream: Arc::new(listener::build_upstream()),
            running: RwLock::new(None),
            tx,
            ws_tx,
            retention: Arc::new(RwLock::new(RetentionPolicy::default())),
            cluster_index: Arc::new(RwLock::new(ClusterIndex::new())),
            csrf_store: Arc::new(csrf::CsrfStore::new(initial_rules)),
            csrf_tx,
            intercept_rules: Arc::new(RwLock::new(initial_intercept_rules)),
        }
    }

    /// Snapshot the active intercept-rule set. Cheap — clones the
    /// inner Vec; the listener takes a read lock on every pause
    /// decision but never holds it across an `await`.
    pub async fn intercept_rules_snapshot(&self) -> intercept_rules::InterceptRules {
        self.intercept_rules.read().await.clone()
    }

    /// Replace the active intercept-rule set, persisting to SQLite.
    /// Subsequent listener pause checks see the new rules
    /// immediately (no listener restart).
    pub async fn set_intercept_rules(
        &self,
        rules: intercept_rules::InterceptRules,
    ) -> anyhow::Result<()> {
        self.db.save_intercept_rules(&rules)?;
        *self.intercept_rules.write().await = rules;
        Ok(())
    }

    /// Shared handle to the live rule set. Passed to the listener
    /// context so the pause path can read without round-tripping
    /// through the state's async lock.
    pub fn intercept_rules_handle(
        &self,
    ) -> Arc<RwLock<intercept_rules::InterceptRules>> {
        self.intercept_rules.clone()
    }

    /// Live CSRF token store. Shared with the listener, replay, and
    /// active checks — anything that builds an outbound HTTP request
    /// can call `apply_to_request` to splice in fresh tokens.
    pub fn csrf_store(&self) -> Arc<csrf::CsrfStore> {
        self.csrf_store.clone()
    }

    pub fn csrf_rules_snapshot(&self) -> Vec<csrf::CsrfRule> {
        self.csrf_store.rules_snapshot()
    }

    pub fn csrf_observations_snapshot(&self) -> Vec<csrf::CsrfObservation> {
        self.csrf_store.observations_snapshot()
    }

    /// Replace the active CSRF rule set, persisting to SQLite. The
    /// store wipes observations belonging to deleted rules so the UI
    /// status panel doesn't show ghost entries.
    pub fn set_csrf_rules(&self, rules: Vec<csrf::CsrfRule>) -> anyhow::Result<()> {
        self.db.save_csrf_rules(&rules)?;
        self.csrf_store.replace_rules(rules);
        Ok(())
    }

    pub fn clear_csrf_observations(&self) {
        self.csrf_store.clear_observations();
    }

    pub fn subscribe_csrf_observations(
        &self,
    ) -> broadcast::Receiver<csrf::CsrfObservation> {
        self.csrf_tx.subscribe()
    }

    /// Snapshot of the live endpoint-pattern clusters for a given
    /// session. Returns an empty Vec when the requested session is not
    /// the active one — the index only retains data for the live
    /// session, by design.
    pub async fn cluster_snapshot(&self, session: &SessionId) -> Vec<EndpointCluster> {
        let active = self.session_id();
        if active.as_ref() != Some(session) {
            return Vec::new();
        }
        self.cluster_index.read().await.snapshot()
    }

    /// Current retention policy snapshot. Cheap — the policy is a
    /// pair of primitives.
    pub async fn retention_snapshot(&self) -> RetentionPolicy {
        *self.retention.read().await
    }

    /// Replace the active retention policy. The new value is honored
    /// on the next writer flush (≤ 250 ms later).
    pub async fn set_retention(&self, policy: RetentionPolicy) {
        *self.retention.write().await = policy;
    }

    /// Shared handle to the retention slot — passed into the writer so
    /// it can read the current cap on every flush without holding a
    /// lock for its whole run.
    pub fn retention_handle(&self) -> Arc<RwLock<RetentionPolicy>> {
        self.retention.clone()
    }

    /// Subscribe to the live WebSocket frame stream — parallel to
    /// [`ProxyState::subscribe_exchanges`] but scoped to captured
    /// frames only.
    pub fn subscribe_ws_frames(&self) -> broadcast::Receiver<ws::WsFrame> {
        self.ws_tx.subscribe()
    }

    /// Sink used by the listener's WebSocket splice to persist + fan
    /// out each captured frame.
    pub fn ws_frame_sink(&self) -> ws::FrameSink {
        ws::FrameSink {
            db: self.db.clone(),
            tx: self.ws_tx.clone(),
        }
    }

    pub fn scope(&self) -> Arc<RwLock<ScopeRules>> {
        self.scope.clone()
    }

    /// Snapshot of the live scope rules. Used by the UI to render the
    /// current include/exclude lists.
    pub async fn scope_snapshot(&self) -> ScopeRules {
        self.scope.read().await.clone()
    }

    /// Replace the live scope rules. The listener reads the rules fresh
    /// on every request, so updates take effect for new requests only —
    /// already-paused intercepts keep the decision that captured them.
    pub async fn set_scope_rules(&self, rules: ScopeRules) {
        *self.scope.write().await = rules;
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

        // Reset the cluster index so the new session's "Group by
        // endpoint" view starts clean — we never want patterns from a
        // previous session to bleed in.
        self.cluster_index.write().await.clear();

        let cancel = CancellationToken::new();
        let captured = Arc::new(AtomicU64::new(0));

        // Spawn the cluster-index drain. Subscribes to the broadcast
        // *before* the listener starts so we don't miss the first few
        // exchanges. Exits when the session is cancelled.
        {
            let index = self.cluster_index.clone();
            let mut rx = self.tx.subscribe();
            let task_cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = task_cancel.cancelled() => return,
                        recv = rx.recv() => match recv {
                            Ok(ex) => {
                                index.write().await.record(&ex);
                            }
                            // Lagging — skip ahead. Missing a handful of
                            // exchanges only loses fidelity in cluster
                            // counts; the next flush re-stabilises.
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                        }
                    }
                }
            });
        }

        let (writer, _writer_handle) = ExchangeWriter::spawn(
            self.db.clone(),
            session_id,
            self.retention.clone(),
        );
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
            ws_sink: self.ws_frame_sink(),
            csrf_store: self.csrf_store.clone(),
            csrf_tx: self.csrf_tx.clone(),
            intercept_rules: self.intercept_rules.clone(),
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
        // Empty the cluster snapshot so the UI doesn't show patterns
        // from a stopped session as if they were live.
        self.cluster_index.write().await.clear();
        Ok(())
    }
}
