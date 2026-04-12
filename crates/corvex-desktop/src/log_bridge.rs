//! Tracing → Tauri event bridge.
//!
//! Installs a custom `tracing_subscriber::Layer` that forwards every
//! formatted event over an unbounded tokio channel. `main()` installs
//! this layer alongside the normal `fmt` layer (so stderr still gets
//! the usual output), and `setup()` takes the receiver and spawns a
//! task that re-emits every line on the `log://line` Tauri event.
//!
//! This way the frontend LogPanel shows real engine output (scan
//! lifecycle messages, plugin warnings, HTTP errors) — not just the
//! frontend-side lifecycle markers it used to show.

use std::sync::Mutex;

use once_cell::sync::OnceCell;
use serde::Serialize;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

/// The event payload the frontend sees on `log://line`.
#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub level: &'static str,
    pub target: String,
    pub message: String,
}

/// The sender side of the bridge — cloned into the tracing layer.
static LOG_TX: OnceCell<UnboundedSender<LogLine>> = OnceCell::new();

/// Where `main()` stashes the receiver until `setup()` can grab it.
static LOG_RX: OnceCell<Mutex<Option<UnboundedReceiver<LogLine>>>> = OnceCell::new();

/// Install the bridge. Must be called once, before any tracing events
/// are emitted. Returns a `Layer` that can be `.with`ed onto a
/// `tracing_subscriber::Registry`.
pub fn init() -> LogBridgeLayer {
    let (tx, rx) = unbounded_channel::<LogLine>();
    let _ = LOG_TX.set(tx);
    let _ = LOG_RX.set(Mutex::new(Some(rx)));
    LogBridgeLayer
}

/// Take the receiver out so the setup task can own it. Returns None if
/// called twice or before `init`.
pub fn take_receiver() -> Option<UnboundedReceiver<LogLine>> {
    LOG_RX.get().and_then(|m| m.lock().ok().and_then(|mut g| g.take()))
}

/// The tracing Layer implementation.
pub struct LogBridgeLayer;

impl<S> Layer<S> for LogBridgeLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let Some(tx) = LOG_TX.get() else { return };
        let meta = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        // Skip events that produced no message (e.g. spans).
        if visitor.message.is_empty() {
            return;
        }

        let level = match *meta.level() {
            Level::TRACE => "TRACE",
            Level::DEBUG => "DEBUG",
            Level::INFO => "INFO",
            Level::WARN => "WARN",
            Level::ERROR => "ERROR",
        };

        let _ = tx.send(LogLine {
            level,
            target: meta.target().to_string(),
            message: visitor.message,
        });
    }
}

/// Extract the `message` field from a tracing event; ignore other fields.
#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            use std::fmt::Write;
            let _ = write!(self.message, "{:?}", value);
            // `format!("{:?}", &"text")` yields `"text"` with surrounding
            // quotes; strip them for readability in the UI.
            if self.message.starts_with('"') && self.message.ends_with('"') && self.message.len() >= 2 {
                self.message = self.message[1..self.message.len() - 1].to_string();
            }
        }
    }
}
