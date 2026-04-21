//! Intercept queue and verdict plumbing.
//!
//! When intercept mode is on, the listener pauses an exchange at the
//! chosen phase (request, response, or both) by submitting a pending
//! record to [`InterceptQueue`]. Each pending record carries a
//! `oneshot::Sender` that the UI resolves to a verdict — forward the
//! bytes unchanged, forward an edited version, or drop. The listener
//! await-s its matching receiver and proceeds once the UI decides.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, oneshot};

use crate::exchange::ExchangeId;

/// How long to hold a request/response paused if the UI never responds.
/// After the timeout we auto-forward unchanged and emit a warning —
/// better than leaking a half-open upstream socket forever.
pub const INTERCEPT_TIMEOUT: Duration = Duration::from_secs(300);

/// Intercept-mode toggle, set from the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptMode {
    Off,
    Request,
    Response,
    Both,
}

impl Default for InterceptMode {
    fn default() -> Self {
        Self::Off
    }
}

impl InterceptMode {
    pub fn should_pause_request(self) -> bool {
        matches!(self, Self::Request | Self::Both)
    }

    pub fn should_pause_response(self) -> bool {
        matches!(self, Self::Response | Self::Both)
    }
}

/// Which side of the exchange the user is about to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptPhase {
    Request,
    Response,
}

/// Decision returned from the UI via `intercept_resolve`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InterceptVerdict {
    /// Forward the original bytes unchanged.
    Forward,
    /// Forward the supplied wire bytes (must re-parse cleanly).
    ForwardEdited { bytes: Vec<u8> },
    /// Drop the exchange — the client gets a 502.
    Drop,
}

/// Snapshot shipped to the UI so it can render the raw wire bytes in
/// an editor without having to fetch anything else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingIntercept {
    pub id: ExchangeId,
    pub phase: InterceptPhase,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub uri: String,
    /// Raw HTTP/1.x bytes as produced by `Request::to_wire` or
    /// equivalent. Base64-encoded so the Tauri JSON boundary doesn't
    /// mangle non-utf8 bodies.
    pub raw_bytes_base64: String,
}

/// Queue of paused exchanges. Cloneable handle over a shared mutex —
/// the listener holds one clone, the Tauri command layer holds another.
#[derive(Clone)]
pub struct InterceptQueue {
    inner: std::sync::Arc<Inner>,
}

struct Inner {
    waiters: Mutex<HashMap<ExchangeId, Waiter>>,
    tx: broadcast::Sender<PendingIntercept>,
}

struct Waiter {
    sender: oneshot::Sender<InterceptVerdict>,
    snapshot: PendingIntercept,
}

impl InterceptQueue {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            inner: std::sync::Arc::new(Inner {
                waiters: Mutex::new(HashMap::new()),
                tx,
            }),
        }
    }

    /// Subscribe to pending intercept announcements. The desktop layer
    /// drains this into a Tauri event so the UI can react immediately.
    pub fn subscribe(&self) -> broadcast::Receiver<PendingIntercept> {
        self.inner.tx.subscribe()
    }

    /// Register a pause and return the receiver the listener `.await`s.
    /// The snapshot is announced to subscribers so the UI can show it.
    pub fn pause(&self, snapshot: PendingIntercept) -> oneshot::Receiver<InterceptVerdict> {
        let (tx, rx) = oneshot::channel();
        let id = snapshot.id;
        {
            let mut waiters = self.inner.waiters.lock().expect("intercept mutex");
            waiters.insert(
                id,
                Waiter {
                    sender: tx,
                    snapshot: snapshot.clone(),
                },
            );
        }
        let _ = self.inner.tx.send(snapshot);
        rx
    }

    /// Return every pending intercept. Used by the UI on mount so it
    /// can recover state after a page reload.
    pub fn pending(&self) -> Vec<PendingIntercept> {
        self.inner
            .waiters
            .lock()
            .expect("intercept mutex")
            .values()
            .map(|w| w.snapshot.clone())
            .collect()
    }

    /// Resolve a pending intercept with the given verdict. Returns an
    /// error if the id is unknown (UI and queue drifted out of sync).
    pub fn resolve(&self, id: ExchangeId, verdict: InterceptVerdict) -> anyhow::Result<()> {
        let waiter = self
            .inner
            .waiters
            .lock()
            .expect("intercept mutex")
            .remove(&id);
        match waiter {
            Some(w) => {
                w.sender
                    .send(verdict)
                    .map_err(|_| anyhow::anyhow!("listener no longer waiting"))?;
                Ok(())
            }
            None => anyhow::bail!("no pending intercept {id}"),
        }
    }

    /// Release every pending intercept with a Forward verdict. Used by
    /// the "Stop proxy" path to avoid leaking upstream sockets.
    pub fn drop_all(&self) {
        let drained: Vec<Waiter> = {
            let mut waiters = self.inner.waiters.lock().expect("intercept mutex");
            waiters.drain().map(|(_, w)| w).collect()
        };
        for w in drained {
            let _ = w.sender.send(InterceptVerdict::Forward);
        }
    }
}

impl Default for InterceptQueue {
    fn default() -> Self {
        Self::new()
    }
}
