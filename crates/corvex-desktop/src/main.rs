//! corvex-desktop — Tauri v2 GUI for the corvex-rust scanner.
//!
//! The Rust side is intentionally thin: it loads the same `corvex-core`
//! engine the CLI binary uses, exposes a handful of commands, and
//! streams findings + engine log lines back to the web frontend
//! through Tauri events.

mod asset_cmd;
mod asset_db;
mod asset_identity;
mod check_bridge;
mod commands;
mod device_embed;
mod error;
mod event_sink;
mod exploitdb;
mod history;
mod init_progress;
mod log_bridge;
mod params;
mod probe_state;
mod probe_store;
mod proxy_cmd;
mod recon_cmd;
mod recon_state;
mod recon_store;
mod rules_embed;
mod scan_state;

use std::path::PathBuf;
use std::sync::Arc;

use asset_db::AssetDb;
use corvex_devicedb::DeviceCatalog;
use corvex_proxy::{Authority, CaConfig, ProxyDb, ProxyState};
use exploitdb::ExploitDb;
use history::HistoryDb;
use probe_state::ProbeRegistry;
use probe_store::ProbeStore;
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
            // ---- Cheap, synchronous registrations -----------------
            //
            // These have to be in `manage()` before any frontend invoke
            // can run, but they're all in-memory `::default()` calls
            // that don't touch disk.
            app.manage(ScanRegistry::default());
            app.manage(ProbeRegistry::default());
            app.manage(Arc::new(ReconRegistry::default()));

            // Device-signature catalogue lives in a SQLite file that
            // ships embedded in the binary. `device_embed` writes it
            // out on first launch (or when the on-disk copy drifts
            // from the embedded bytes); we then open it read-only.
            // A failure here is non-fatal — probing still works without
            // device IDs, just without the Device panel populated.
            let resolved_devices_path = device_embed::resolve_devices_path();
            let device_cat = match &resolved_devices_path {
                Some(path) => match DeviceCatalog::open(path) {
                    Ok(cat) => {
                        tracing::info!(
                            target: "devicedb",
                            entries = cat.entries.len(),
                            path = %path.display(),
                            "device signature catalog ready"
                        );
                        cat
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "devicedb",
                            path = %path.display(),
                            "device catalog open failed: {e}; SNMP fingerprinting disabled"
                        );
                        DeviceCatalog::default()
                    }
                },
                None => {
                    tracing::info!(
                        target: "devicedb",
                        "no devices.sqlite available; SNMP fingerprinting disabled"
                    );
                    DeviceCatalog::default()
                }
            };
            app.manage(Arc::new(device_cat));
            // Stash the resolved SQLite path for commands that want to
            // query the bundled IANA / OUI reference tables (which
            // aren't loaded into the in-memory catalog above).
            app.manage(Arc::new(DevicesDbPath(resolved_devices_path)));

            // Init progress is also managed synchronously so the
            // splash's `init_status` poll has something to read even
            // before the heavy task has emitted its first event.
            let progress: init_progress::InitProgressHandle =
                Arc::new(std::sync::Mutex::new(init_progress::InitProgress::new()));
            app.manage(progress.clone());

            // ---- Heavy init runs on a background task ------------
            //
            // The webview is already visible by this point (Tauri
            // shows the window before `setup` returns control to the
            // builder), so by getting out of `setup` quickly we let
            // the frontend paint a "Configuring Corvex" splash while
            // DBs open and the proxy CA generates. Each stage flips
            // its step in `progress` and emits `app://init-step`;
            // when the last step finishes we emit `app://init-ready`
            // so the splash can swap itself out for the main UI.
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                run_heavy_init(app_handle, progress).await;
            });

            // ---- Vulndb warm-up (already async, leave as-is) ------
            //
            // The schema-v2
            // migration adds vendor/product columns + a composite
            // index to `cpe_matches`, which collapses SCA component
            // lookups from full-table scans (~700 ms each) into
            // index probes (<1 ms each). On a 1k-component scan
            // that's the difference between ~10 minutes and a few
            // seconds. We do it on app launch so the user's first
            // SCA scan is already fast — but only if the file
            // already exists, so users who never run SCA don't pay
            // the seed-from-snapshot cost.
            tauri::async_runtime::spawn(async move {
                let res = tauri::async_runtime::spawn_blocking(|| {
                    let path = match corvex_core::vulndb::default_db_path() {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::debug!(
                                target: "vulndb",
                                "no default vulndb path: {e}"
                            );
                            return;
                        }
                    };
                    if !path.exists() {
                        tracing::debug!(
                            target: "vulndb",
                            "no vulndb on disk yet — skipping warm-up"
                        );
                        return;
                    }
                    match corvex_core::vulndb::VulnDb::open(&path) {
                        Ok(_db) => {
                            tracing::info!(
                                target: "vulndb",
                                "warmed vulndb at startup (schema/index ready for SCA)"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "vulndb",
                                "vulndb warm-up failed: {e}"
                            );
                        }
                    }
                })
                .await;
                if let Err(e) = res {
                    tracing::warn!(target: "vulndb", "warm-up task: {e}");
                }
            });

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
            commands::init_status,
            commands::list_plugins,
            commands::db_summary,
            commands::version_info,
            commands::scan_start,
            commands::scan_cancel,
            commands::scan_stats,
            commands::history_list,
            commands::history_clear,
            commands::history_delete,
            commands::history_set_saved,
            commands::history_findings,
            commands::vulndb_summary,
            commands::vulndb_update,
            commands::sonar_summary,
            commands::device_db_summary,
            commands::nuclei_summary,
            commands::nuclei_template_list,
            commands::wappalyzer_summary,
            commands::nuclei_extras_download,
            commands::nuclei_extras_remove,
            commands::jarm_lookup,
            commands::probe_start,
            commands::probe_cancel,
            asset_cmd::asset_list,
            asset_cmd::asset_overview,
            asset_cmd::asset_services,
            asset_cmd::asset_stack,
            asset_cmd::asset_endpoints,
            asset_cmd::asset_endpoints_clustered,
            asset_cmd::asset_findings,
            asset_cmd::asset_related,
            asset_cmd::asset_timeline,
            proxy_cmd::proxy_status,
            proxy_cmd::proxy_start,
            proxy_cmd::proxy_stop,
            proxy_cmd::proxy_export_ca_pem,
            proxy_cmd::scope_get,
            proxy_cmd::scope_set,
            proxy_cmd::intercept_rules_get,
            proxy_cmd::intercept_rules_set,
            proxy_cmd::csrf_rules_get,
            proxy_cmd::csrf_rules_set,
            proxy_cmd::csrf_rules_reset_defaults,
            proxy_cmd::csrf_status,
            proxy_cmd::csrf_clear_session,
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
            proxy_cmd::exchanges_clustered_list,
            proxy_cmd::cluster_instances,
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
            commands::exploitdb_summary,
            commands::exploitdb_by_cve,
            commands::exploitdb_update,
            commands::exploitdb_fetch_source,
            commands::rules_summary,
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

/// Newtype wrapper so the resolved `devices.sqlite` path can be put
/// into Tauri-managed state (a bare `Option<PathBuf>` would clash with
/// any other state that uses the same shape).
pub struct DevicesDbPath(pub Option<PathBuf>);

fn open_history(app: &tauri::AppHandle) -> anyhow::Result<HistoryDb> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| anyhow::anyhow!("app_data_dir: {e}"))?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("history.sqlite");
    tracing::info!(target: "history", "opening history db at {}", path.display());
    HistoryDb::open(&path).map_err(|e| anyhow::anyhow!("sqlite: {e}"))
}

fn open_exploitdb(app: &tauri::AppHandle) -> anyhow::Result<ExploitDb> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| anyhow::anyhow!("app_data_dir: {e}"))?;
    std::fs::create_dir_all(&data_dir)?;
    let user_path = data_dir.join("exploitdb.sqlite");

    // Seed (missing) or upgrade (bundled commit is fresher) from the
    // resource-bundled snapshot. `resource_dir()` may fail in dev when
    // assets aren't staged there; `seed_or_upgrade` will still find the
    // source-tree path via its `cwd` candidate.
    let resource_dir = app.path().resource_dir().ok();
    exploitdb::seed_or_upgrade(&user_path, resource_dir.as_deref())
        .map_err(|e| anyhow::anyhow!("seed exploit-db: {e}"))?;

    tracing::info!(
        target: "exploitdb",
        "opening exploit-db at {}",
        user_path.display()
    );
    ExploitDb::open(&user_path).map_err(|e| anyhow::anyhow!("sqlite: {e}"))
}

fn open_probe_store(app: &tauri::AppHandle) -> anyhow::Result<ProbeStore> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| anyhow::anyhow!("app_data_dir: {e}"))?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("history.sqlite");
    tracing::info!(target: "probe", "opening probe store at {}", path.display());
    ProbeStore::open(&path).map_err(|e| anyhow::anyhow!("sqlite: {e}"))
}

fn open_asset_db(app: &tauri::AppHandle) -> anyhow::Result<AssetDb> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| anyhow::anyhow!("app_data_dir: {e}"))?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("history.sqlite");
    tracing::info!(target: "asset", "opening asset db at {}", path.display());
    AssetDb::open(&path).map_err(|e| anyhow::anyhow!("sqlite: {e}"))
}

fn open_recon(app: &tauri::AppHandle) -> anyhow::Result<ReconDb> {
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

fn open_proxy(app: &tauri::AppHandle) -> anyhow::Result<ProxyState> {
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

/// Run every disk-touching / CPU-bound init step on a background task,
/// emitting `app://init-step` progress events along the way and
/// `app://init-ready` at the end. The frontend renders a splash until
/// it sees the ready event.
///
/// All sub-steps are non-fatal individually: if one fails the others
/// still run, the splash flips that step to a "failed" badge, and the
/// app moves on with whatever subsystems did open. The user's first
/// scan / asset query will surface a more specific error if a critical
/// subsystem couldn't open.
async fn run_heavy_init(
    app: tauri::AppHandle,
    progress: init_progress::InitProgressHandle,
) {
    use init_progress as ip;

    // ---- Recon DB --------------------------------------------------
    ip::start(&app, &progress, ip::STEP_RECON);
    let recon_app = app.clone();
    let recon_res = tauri::async_runtime::spawn_blocking(move || open_recon(&recon_app))
        .await
        .unwrap_or_else(|e| Err(anyhow::anyhow!("join: {e}")));
    match recon_res {
        Ok(db) => {
            app.manage(Arc::new(db));
            tracing::info!(target: "recon", "recon db ready");
            ip::finish_ok(&app, &progress, ip::STEP_RECON);
        }
        Err(e) => {
            tracing::error!(target: "recon", "recon db: {e}");
            ip::finish_err(&app, &progress, ip::STEP_RECON, e.to_string());
        }
    }

    // ---- Exploit-DB ------------------------------------------------
    //
    // The slow first-launch step: copies the bundled SQLite snapshot
    // into the per-user app-data directory.
    ip::start(&app, &progress, ip::STEP_EXPLOITDB);
    let edb_app = app.clone();
    let edb_res = tauri::async_runtime::spawn_blocking(move || open_exploitdb(&edb_app))
        .await
        .unwrap_or_else(|e| Err(anyhow::anyhow!("join: {e}")));
    match edb_res {
        Ok(db) => {
            app.manage(Arc::new(db));
            tracing::info!(target: "exploitdb", "exploit-db ready");
            ip::finish_ok(&app, &progress, ip::STEP_EXPLOITDB);
        }
        Err(e) => {
            tracing::error!(target: "exploitdb", "failed to open exploit-db: {e}");
            ip::finish_err(&app, &progress, ip::STEP_EXPLOITDB, e.to_string());
        }
    }

    // ---- History DB ------------------------------------------------
    ip::start(&app, &progress, ip::STEP_HISTORY);
    let hist_app = app.clone();
    let hist_res = tauri::async_runtime::spawn_blocking(move || open_history(&hist_app))
        .await
        .unwrap_or_else(|e| Err(anyhow::anyhow!("join: {e}")));
    match hist_res {
        Ok(db) => {
            app.manage(Arc::new(db));
            tracing::info!(target: "history", "history db ready");
            ip::finish_ok(&app, &progress, ip::STEP_HISTORY);
        }
        Err(e) => {
            tracing::error!(target: "history", "failed to open history db: {e}");
            ip::finish_err(&app, &progress, ip::STEP_HISTORY, e.to_string());
        }
    }

    // ---- Probe store -----------------------------------------------
    ip::start(&app, &progress, ip::STEP_PROBE);
    let probe_app = app.clone();
    let probe_res = tauri::async_runtime::spawn_blocking(move || open_probe_store(&probe_app))
        .await
        .unwrap_or_else(|e| Err(anyhow::anyhow!("join: {e}")));
    match probe_res {
        Ok(db) => {
            app.manage(Arc::new(db));
            tracing::info!(target: "probe", "probe store ready");
            ip::finish_ok(&app, &progress, ip::STEP_PROBE);
        }
        Err(e) => {
            tracing::error!(target: "probe", "failed to open probe store: {e}");
            ip::finish_err(&app, &progress, ip::STEP_PROBE, e.to_string());
        }
    }

    // ---- Asset DB --------------------------------------------------
    ip::start(&app, &progress, ip::STEP_ASSET);
    let asset_app = app.clone();
    let asset_res = tauri::async_runtime::spawn_blocking(move || open_asset_db(&asset_app))
        .await
        .unwrap_or_else(|e| Err(anyhow::anyhow!("join: {e}")));
    match asset_res {
        Ok(db) => {
            app.manage(Arc::new(db));
            tracing::info!(target: "asset", "asset db ready");
            ip::finish_ok(&app, &progress, ip::STEP_ASSET);
        }
        Err(e) => {
            tracing::error!(target: "asset", "failed to open asset db: {e}");
            ip::finish_err(&app, &progress, ip::STEP_ASSET, e.to_string());
        }
    }

    // ---- Proxy state (CA generation, scope hydration, broadcasts) --
    //
    // The other big first-launch cost: `Authority::load_or_generate`
    // does an RSA keygen if no CA is on disk yet. After that we hydrate
    // scope rules + retention from the proxy DB and wire up four
    // broadcast → Tauri-event drains for live UI updates.
    ip::start(&app, &progress, ip::STEP_PROXY);
    let proxy_app = app.clone();
    let proxy_res = tauri::async_runtime::spawn_blocking(move || open_proxy(&proxy_app))
        .await
        .unwrap_or_else(|e| Err(anyhow::anyhow!("join: {e}")));
    match proxy_res {
        Ok(state) => {
            let state = Arc::new(state);
            // Hydrate persisted scope rules before anything starts
            // listening — a session that opens before the rules are
            // restored would classify every request as in-scope until
            // the user re-saved them. Now that we're already inside an
            // async task we can `await` directly.
            match state.db().load_scope_rules() {
                Ok(rules) => {
                    let loaded = rules.include.len() + rules.exclude.len();
                    state.set_scope_rules(rules).await;
                    tracing::info!(
                        target: "proxy",
                        rules = loaded,
                        "scope rules hydrated"
                    );
                }
                Err(e) => {
                    tracing::warn!(target: "proxy", "scope rules hydrate failed: {e}");
                }
            }

            // Retention policy: read the persisted cap if any, fall back
            // to the default. Failing to load is non-fatal — retention
            // just stays at its compile-time default.
            let default_max = corvex_proxy::DEFAULT_RETENTION_MAX;
            let max = match state.db().get_setting(corvex_proxy::RETENTION_SETTING_KEY) {
                Ok(Some(s)) => s.parse::<usize>().unwrap_or(default_max),
                Ok(None) => default_max,
                Err(e) => {
                    tracing::warn!(target: "proxy", "retention hydrate failed: {e}");
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

            // Drain the broadcast channel into Tauri events so the UI
            // gets live `proxy://exchange-new` pushes for every captured
            // exchange. A lagging receiver drops older messages — the
            // UI can always catch up by calling `exchanges_list` against
            // the persisted log.
            let handle = app.clone();
            let mut rx = state.subscribe_exchanges();
            tauri::async_runtime::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(exchange) => {
                            let _ = handle.emit("proxy://exchange-new", exchange.summary());
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

            // Fan out captured WebSocket frames so the UI can render
            // the traffic detail's frame list live.
            let handle = app.clone();
            let mut wsrx = state.subscribe_ws_frames();
            tauri::async_runtime::spawn(async move {
                loop {
                    match wsrx.recv().await {
                        Ok(frame) => {
                            let _ = handle.emit("proxy://ws-frame", ws_frame_payload(&frame));
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

            // Fan out pending intercepts to the UI so the Intercept tab
            // can react without polling.
            let handle = app.clone();
            let mut irx = state.intercept_queue().subscribe();
            tauri::async_runtime::spawn(async move {
                loop {
                    match irx.recv().await {
                        Ok(pending) => {
                            let _ = handle.emit("proxy://intercept-pending", pending);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            return;
                        }
                    }
                }
            });

            // Fan out newly-observed CSRF token values so the
            // Settings → CSRF status panel updates without polling.
            let handle = app.clone();
            let mut crx = state.subscribe_csrf_observations();
            tauri::async_runtime::spawn(async move {
                loop {
                    match crx.recv().await {
                        Ok(obs) => {
                            let _ = handle.emit("proxy://csrf-observed", obs);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            return;
                        }
                    }
                }
            });

            // Hook the Checks engine onto the proxy exchange stream.
            let bridge = Arc::new(check_bridge::CheckBridge::new());
            bridge.attach(state.clone(), app.clone());
            bridge.attach_cluster_anomalies(state.clone(), app.clone());
            app.manage(bridge);
            app.manage(state);
            tracing::info!(target: "proxy", "proxy state ready");
            ip::finish_ok(&app, &progress, ip::STEP_PROXY);
        }
        Err(e) => {
            tracing::error!(target: "proxy", "failed to init proxy: {e}");
            ip::finish_err(&app, &progress, ip::STEP_PROXY, e.to_string());
        }
    }

    // All steps reported their final state; tell the splash it can go
    // away. Steps that reported `Failed` keep their badge — the user
    // sees which subsystem couldn't load.
    ip::mark_ready(&app, &progress);
}
