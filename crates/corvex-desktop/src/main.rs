//! corvex-desktop — Tauri v2 GUI for the corvex-rust scanner.
//!
//! The Rust side is intentionally thin: it loads the same `corvex-core`
//! engine the CLI binary uses, exposes a handful of commands, and
//! streams findings + engine log lines back to the web frontend
//! through Tauri events.

mod commands;
mod error;
mod event_sink;
mod history;
mod log_bridge;
mod params;
mod scan_state;

use std::sync::Arc;

use history::HistoryDb;
use scan_state::ScanRegistry;
use tauri::{Emitter, Manager};
use tracing_subscriber::prelude::*;

fn main() {
    // Install the tracing subscriber with three layers:
    //   1. EnvFilter (respects RUST_LOG, defaults to info).
    //   2. fmt layer → stderr (unchanged from the CLI experience).
    //   3. LogBridge → a channel the Tauri setup task drains into
    //      `log://line` events for the frontend LogPanel.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,corvex_core=info"));

    let bridge_layer = log_bridge::init();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .with(bridge_layer)
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            app.manage(ScanRegistry::default());

            // Open the SQLite history DB at the platform's app data
            // directory. Failing to open isn't fatal — the rest of the
            // app keeps working, but the History view will be empty.
            match open_history(app) {
                Ok(db) => {
                    app.manage(Arc::new(db));
                    tracing::info!(target: "history", "history db ready");
                }
                Err(e) => {
                    tracing::error!(target: "history", "failed to open history db: {e}");
                }
            }

            // Forward every buffered + future tracing line to the frontend.
            // `setup` is called before Tauri starts its own runtime on this
            // thread, so `tokio::spawn` would panic ("no reactor running").
            // Tauri exposes its managed runtime via `async_runtime::spawn`,
            // which works from any context.
            if let Some(mut rx) = log_bridge::take_receiver() {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    while let Some(line) = rx.recv().await {
                        let _ = handle.emit("log://line", line);
                    }
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_plugins,
            commands::db_summary,
            commands::version_info,
            commands::scan_start,
            commands::scan_cancel,
            commands::scan_stats,
            commands::history_list,
            commands::history_clear,
            commands::history_delete,
            commands::vulndb_summary,
            commands::vulndb_update,
            commands::sonar_summary,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn open_history(app: &tauri::App) -> anyhow::Result<HistoryDb> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| anyhow::anyhow!("app_data_dir: {e}"))?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("history.sqlite");
    tracing::info!(target: "history", "opening history db at {}", path.display());
    HistoryDb::open(&path).map_err(|e| anyhow::anyhow!("sqlite: {e}"))
}
