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
mod probe_state;
mod proxy_cmd;
mod scan_state;

use std::sync::Arc;

use corvex_proxy::{Authority, CaConfig, ProxyDb, ProxyState};
use history::HistoryDb;
use probe_state::ProbeRegistry;
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
            app.manage(ProbeRegistry::default());

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

            // Register proxy state. The authority persists its CA under
            // `<app_data_dir>/proxy/ca/`; the proxy DB opens a second
            // connection to the shared `history.sqlite` file (WAL mode
            // lets multiple connections coexist). Any failure here is
            // non-fatal — the rest of the app keeps working, the Proxy
            // view shows an error and the "Export CA" button is
            // disabled.
            match open_proxy(app) {
                Ok(state) => {
                    let state = Arc::new(state);
                    // Drain the broadcast channel into Tauri events so
                    // the UI gets live `proxy://exchange-new` pushes for
                    // every captured exchange. A lagging receiver drops
                    // older messages — the UI can always catch up by
                    // calling `exchanges_list` against the persisted log.
                    let handle = app.handle().clone();
                    let mut rx = state.subscribe_exchanges();
                    tauri::async_runtime::spawn(async move {
                        loop {
                            match rx.recv().await {
                                Ok(exchange) => {
                                    let _ = handle
                                        .emit("proxy://exchange-new", exchange.summary());
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                    tracing::warn!(
                                        target: "proxy",
                                        "exchange broadcast lagged — {n} events dropped"
                                    );
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                    return;
                                }
                            }
                        }
                    });
                    app.manage(state);
                    tracing::info!(target: "proxy", "proxy state ready");
                }
                Err(e) => {
                    tracing::error!(target: "proxy", "failed to init proxy: {e}");
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
            commands::nuclei_summary,
            commands::nuclei_template_list,
            commands::nuclei_extras_download,
            commands::nuclei_extras_remove,
            commands::jarm_lookup,
            commands::probe_start,
            commands::probe_cancel,
            proxy_cmd::proxy_status,
            proxy_cmd::proxy_start,
            proxy_cmd::proxy_stop,
            proxy_cmd::proxy_export_ca_pem,
            proxy_cmd::exchanges_list,
            proxy_cmd::exchange_get,
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

fn open_proxy(app: &tauri::App) -> anyhow::Result<ProxyState> {
    let base = app
        .path()
        .app_data_dir()
        .map_err(|e| anyhow::anyhow!("app_data_dir: {e}"))?;
    let ca_dir = base.join("proxy").join("ca");
    let db_path = base.join("history.sqlite");

    tracing::info!(target: "proxy", "initialising CA at {}", ca_dir.display());
    let authority = Authority::load_or_generate(CaConfig::for_dir(&ca_dir))
        .map_err(|e| anyhow::anyhow!("ca init: {e}"))?;

    tracing::info!(target: "proxy", "opening proxy db at {}", db_path.display());
    let db = ProxyDb::open(&db_path).map_err(|e| anyhow::anyhow!("proxy db: {e}"))?;

    Ok(ProxyState::new(Arc::new(authority), Arc::new(db)))
}
