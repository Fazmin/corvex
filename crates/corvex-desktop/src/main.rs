//! corvex-desktop — Tauri v2 GUI for the corvex-rust scanner.
//!
//! The Rust side is intentionally thin: it loads the same `corvex-core`
//! engine the CLI binary uses, exposes a handful of commands, and
//! streams findings + engine log lines back to the web frontend
//! through Tauri events.

mod check_bridge;
mod commands;
mod error;
mod event_sink;
mod history;
mod log_bridge;
mod params;
mod probe_state;
mod proxy_cmd;
mod recon_cmd;
mod recon_state;
mod recon_store;
mod scan_state;

use std::sync::Arc;

use corvex_proxy::{Authority, CaConfig, ProxyDb, ProxyState};
use history::HistoryDb;
use probe_state::ProbeRegistry;
use recon_state::ReconRegistry;
use recon_store::ReconDb;
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
            app.manage(Arc::new(ReconRegistry::default()));

            // Open the Recon DB (sibling connection to history.sqlite).
            // WAL mode from history/proxy lets the third connection
            // coexist cleanly. Failure is non-fatal — the Recon view
            // will surface the error when the user tries to run.
            match open_recon(app) {
                Ok(db) => {
                    app.manage(Arc::new(db));
                    tracing::info!(target: "recon", "recon db ready");
                }
                Err(e) => {
                    tracing::error!(target: "recon", "recon db: {e}");
                }
            }

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
                    // Hydrate persisted scope rules before anything
                    // starts listening — a session that opens before the
                    // rules are restored would classify every request as
                    // in-scope until the user re-saved them.
                    {
                        let state = state.clone();
                        tauri::async_runtime::block_on(async move {
                            match state.db().load_scope_rules() {
                                Ok(rules) => {
                                    let loaded =
                                        rules.include.len() + rules.exclude.len();
                                    state.set_scope_rules(rules).await;
                                    tracing::info!(
                                        target: "proxy",
                                        rules = loaded,
                                        "scope rules hydrated"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        target: "proxy",
                                        "scope rules hydrate failed: {e}"
                                    );
                                }
                            }

                            // Retention policy: read the persisted cap
                            // if any, fall back to the default. Failing
                            // to load is non-fatal — retention just
                            // stays at its compile-time default.
                            let default_max =
                                corvex_proxy::DEFAULT_RETENTION_MAX;
                            let max = match state
                                .db()
                                .get_setting(corvex_proxy::RETENTION_SETTING_KEY)
                            {
                                Ok(Some(s)) => {
                                    s.parse::<usize>().unwrap_or(default_max)
                                }
                                Ok(None) => default_max,
                                Err(e) => {
                                    tracing::warn!(
                                        target: "proxy",
                                        "retention hydrate failed: {e}"
                                    );
                                    default_max
                                }
                            };
                            state
                                .set_retention(corvex_proxy::RetentionPolicy {
                                    max_exchanges_per_session: max,
                                })
                                .await;
                            tracing::info!(
                                target: "proxy",
                                max_exchanges_per_session = max,
                                "retention policy hydrated"
                            );
                        });
                    }
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
                    // Fan out captured WebSocket frames so the UI can
                    // render the traffic detail's frame list live.
                    let handle = app.handle().clone();
                    let mut wsrx = state.subscribe_ws_frames();
                    tauri::async_runtime::spawn(async move {
                        loop {
                            match wsrx.recv().await {
                                Ok(frame) => {
                                    let _ = handle
                                        .emit("proxy://ws-frame", ws_frame_payload(&frame));
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                    tracing::warn!(
                                        target: "proxy",
                                        "ws frame broadcast lagged — {n} events dropped"
                                    );
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                    return;
                                }
                            }
                        }
                    });
                    // Fan out pending intercepts to the UI so the
                    // Intercept tab can react without polling.
                    let handle = app.handle().clone();
                    let mut irx = state.intercept_queue().subscribe();
                    tauri::async_runtime::spawn(async move {
                        loop {
                            match irx.recv().await {
                                Ok(pending) => {
                                    let _ =
                                        handle.emit("proxy://intercept-pending", pending);
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                    return;
                                }
                            }
                        }
                    });
                    // Hook the Checks engine onto the proxy exchange
                    // stream. Passive findings stream in real time;
                    // active runs are triggered explicitly from the UI.
                    let bridge = Arc::new(check_bridge::CheckBridge::new());
                    bridge.attach(state.clone(), app.handle().clone());
                    app.manage(bridge);
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
            commands::wappalyzer_summary,
            commands::nuclei_extras_download,
            commands::nuclei_extras_remove,
            commands::jarm_lookup,
            commands::probe_start,
            commands::probe_cancel,
            proxy_cmd::proxy_status,
            proxy_cmd::proxy_start,
            proxy_cmd::proxy_stop,
            proxy_cmd::proxy_export_ca_pem,
            proxy_cmd::scope_get,
            proxy_cmd::scope_set,
            proxy_cmd::retention_get,
            proxy_cmd::retention_set,
            proxy_cmd::proxy_export_har,
            proxy_cmd::proxy_import_spec,
            proxy_cmd::proxy_seed_host,
            proxy_cmd::ws_frames_for_exchange,
            proxy_cmd::ws_frame_count,
            recon_cmd::recon_start,
            recon_cmd::recon_cancel,
            recon_cmd::recon_runs_list,
            recon_cmd::recon_run_get,
            recon_cmd::recon_findings_for_run,
            recon_cmd::recon_run_delete,
            proxy_cmd::exchanges_list,
            proxy_cmd::exchange_get,
            proxy_cmd::intercept_set_mode,
            proxy_cmd::intercept_get_mode,
            proxy_cmd::intercept_pending_list,
            proxy_cmd::intercept_resolve,
            proxy_cmd::intercept_drop_all,
            proxy_cmd::replay_send,
            proxy_cmd::checks_list,
            proxy_cmd::findings_for_exchange,
            proxy_cmd::findings_for_session,
            proxy_cmd::checks_run,
            proxy_cmd::owasp_taxonomy_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Serde-ready projection for `proxy://ws-frame` events. Mirrors the
/// `WsFrameRow` the traffic-detail command returns so the UI can reuse
/// one decoder.
#[derive(serde::Serialize, Clone)]
struct WsFrameEvent {
    exchange_id: String,
    sequence: u64,
    direction: &'static str,
    opcode: u8,
    opcode_label: &'static str,
    fin: bool,
    payload_base64: String,
    payload_size: usize,
    captured_at_unix: i64,
}

/// Re-exported as a function so the command layer doesn't have to
/// depend on corvex_proxy's internal constant path.
pub(crate) fn body_hard_cap() -> usize {
    corvex_proxy::BODY_HARD_CAP
}

fn ws_frame_payload(f: &corvex_proxy::WsFrame) -> WsFrameEvent {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    WsFrameEvent {
        exchange_id: f.exchange_id.to_string(),
        sequence: f.sequence,
        direction: f.direction.as_str(),
        opcode: f.opcode,
        opcode_label: f.opcode_label(),
        fin: f.fin,
        payload_base64: B64.encode(&f.payload),
        payload_size: f.payload.len(),
        captured_at_unix: f.captured_at.unix_timestamp(),
    }
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

fn open_recon(app: &tauri::App) -> anyhow::Result<ReconDb> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| anyhow::anyhow!("app_data_dir: {e}"))?;
    std::fs::create_dir_all(&dir)?;
    // Reuse history.sqlite — the two schemas are disjoint and WAL
    // mode lets multiple connections coexist.
    let path = dir.join("history.sqlite");
    tracing::info!(target: "recon", "opening recon db at {}", path.display());
    ReconDb::open(&path).map_err(|e| anyhow::anyhow!("sqlite: {e}"))
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
