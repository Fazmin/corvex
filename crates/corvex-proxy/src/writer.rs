//! Background task that drains captured exchanges into SQLite in
//! batches.
//!
//! The proxy listener produces exchanges on the hot request path — one
//! SQLite insert per exchange would serialise the whole listener on the
//! DB mutex and invite contention with the existing scan-history
//! writer. Instead, exchanges go through a bounded mpsc channel to this
//! task, which flushes them to disk every 250ms or once 100 rows have
//! accumulated, whichever comes first.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{interval, MissedTickBehavior};

use crate::exchange::Exchange;
use crate::store::ProxyDb;

const FLUSH_EVERY: Duration = Duration::from_millis(250);
const BATCH_MAX: usize = 100;
const CHANNEL_CAPACITY: usize = 2048;

/// Handle to the batched writer task. Clone freely — all clones push
/// into the same underlying channel.
#[derive(Clone)]
pub struct ExchangeWriter {
    tx: mpsc::Sender<Exchange>,
}

impl ExchangeWriter {
    /// Spawn the writer task and return a handle. Call once per proxy
    /// session; drop the handle (and all clones) to let the task flush
    /// the remaining queue and exit.
    pub fn spawn(db: Arc<ProxyDb>) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel::<Exchange>(CHANNEL_CAPACITY);
        let handle = tokio::spawn(run(db, rx));
        (Self { tx }, handle)
    }

    /// Enqueue an exchange for persistence. Non-blocking: if the queue
    /// is full we drop the exchange and log — the traffic log stays
    /// responsive at the cost of losing a few rows under extreme load.
    /// Live UI streaming is independent of this path.
    pub fn submit(&self, exchange: Exchange) {
        if let Err(e) = self.tx.try_send(exchange) {
            tracing::warn!(
                target: "proxy",
                "dropping exchange — writer queue full: {e}"
            );
        }
    }
}

async fn run(db: Arc<ProxyDb>, mut rx: mpsc::Receiver<Exchange>) {
    let mut buf: Vec<Exchange> = Vec::with_capacity(BATCH_MAX);
    let mut tick = interval(FLUSH_EVERY);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(ex) => {
                        buf.push(ex);
                        if buf.len() >= BATCH_MAX {
                            flush(&db, &mut buf).await;
                        }
                    }
                    None => {
                        // Channel closed — flush and exit.
                        flush(&db, &mut buf).await;
                        return;
                    }
                }
            }
            _ = tick.tick() => {
                if !buf.is_empty() {
                    flush(&db, &mut buf).await;
                }
            }
        }
    }
}

async fn flush(db: &Arc<ProxyDb>, buf: &mut Vec<Exchange>) {
    if buf.is_empty() {
        return;
    }
    let batch = std::mem::take(buf);
    let db = db.clone();
    // Insert happens on a blocking-friendly thread so the listener
    // runtime never waits on SQLite fsyncs.
    let r = tokio::task::spawn_blocking(move || {
        let mut errors = 0usize;
        for exchange in &batch {
            if let Err(e) = db.insert_exchange(exchange) {
                errors += 1;
                tracing::warn!(target: "proxy", "exchange insert failed: {e}");
            }
        }
        (batch.len(), errors)
    })
    .await;
    match r {
        Ok((count, errors)) => {
            if errors > 0 {
                tracing::warn!(
                    target: "proxy",
                    "flushed {} exchanges with {} errors",
                    count,
                    errors
                );
            } else {
                tracing::debug!(target: "proxy", "flushed {} exchanges", count);
            }
        }
        Err(e) => {
            tracing::error!(target: "proxy", "writer flush task panicked: {e}");
        }
    }
}
