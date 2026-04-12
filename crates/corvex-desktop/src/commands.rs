//! Tauri command surface.
//!
//! Every `#[tauri::command]` exported here can be called from the
//! frontend via `invoke('<name>', { ... })`.

use std::sync::Arc;

use corvex_core::config::Config;
use corvex_core::db;
use corvex_core::evasion::EvasionSet;
use corvex_core::http::HttpClient;
use corvex_core::plugin::{HookKind, PluginRegistry};
use corvex_core::report::ReportSink;
use corvex_core::scan::{self, ScanCtx};
use corvex_core::state::GlobalState;
use corvex_core::target::set_targets;
use corvex_core::tuning::TuningFilter;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{Mutex, Semaphore};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::event_sink::TauriEventSink;
use crate::history::{HistoryDb, HistoryEntry};
use crate::params::ScanParams;
use crate::scan_state::{RunningScan, ScanRegistry, ScanStats};

#[derive(Debug, Clone, Serialize)]
pub struct PluginSummary {
    pub name: &'static str,
    pub full_name: &'static str,
    pub description: &'static str,
    pub weight: i32,
    pub default: bool,
    pub extra: bool,
    pub hooks: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DbSummary {
    pub summary: String,
    pub tests: usize,
    pub outdated: usize,
    pub favicon: usize,
    pub server_msgs: usize,
    pub realms: usize,
    pub variables: usize,
    pub content_search: usize,
    pub headers_common: usize,
    pub headers_suggested: usize,
    pub multiple_index: usize,
    pub options: usize,
    pub useragents: usize,
    pub dictionary: usize,
    pub fourohfour: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub product: &'static str,
    pub version: &'static str,
}

#[tauri::command]
pub async fn list_plugins() -> Vec<PluginSummary> {
    let reg = corvex_plugins::register_all();
    reg.all()
        .iter()
        .map(|p| {
            let info = p.info();
            PluginSummary {
                name: info.name,
                full_name: info.full_name,
                description: info.description,
                weight: info.weight,
                default: info.default,
                extra: info.extra,
                hooks: info
                    .hooks
                    .iter()
                    .map(|h| match h {
                        HookKind::Start => "start",
                        HookKind::Recon => "recon",
                        HookKind::Scan => "scan",
                        HookKind::Prefetch => "prefetch",
                        HookKind::Postfetch => "postfetch",
                    })
                    .collect(),
            }
        })
        .collect()
}

#[tauri::command]
pub async fn db_summary() -> DbSummary {
    let dbs = db::load();
    DbSummary {
        summary: db::check_summary(),
        tests: dbs.tests.rows.len(),
        outdated: dbs.outdated.rows.len(),
        favicon: dbs.favicon.rows.len(),
        server_msgs: dbs.server_msgs.rows.len(),
        realms: dbs.realms.rows.len(),
        variables: dbs.variables.entries.len(),
        content_search: dbs.content_search.rows.len(),
        headers_common: dbs.headers_common.headers.len(),
        headers_suggested: dbs.headers_suggested.rows.len(),
        multiple_index: dbs.multiple_index.names.len(),
        options: dbs.options.rows.len(),
        useragents: dbs.useragents.agents.len(),
        dictionary: dbs.dictionary.entries.len(),
        fourohfour: dbs.fourohfour.signatures.len(),
    }
}

#[tauri::command]
pub fn version_info() -> VersionInfo {
    VersionInfo {
        product: corvex_core::PRODUCT_NAME,
        version: corvex_core::VERSION,
    }
}

#[tauri::command]
pub async fn scan_stats(
    registry: State<'_, ScanRegistry>,
    id: String,
) -> AppResult<Option<ScanStats>> {
    let uuid = Uuid::parse_str(&id).map_err(|e| AppError::Other(e.to_string()))?;
    Ok(registry.stats(uuid).await)
}

#[tauri::command]
pub async fn scan_cancel(
    registry: State<'_, ScanRegistry>,
    id: String,
) -> AppResult<bool> {
    let uuid = Uuid::parse_str(&id).map_err(|e| AppError::Other(e.to_string()))?;
    Ok(registry.cancel(uuid).await)
}

#[tauri::command]
pub async fn scan_start(
    app: AppHandle,
    params: ScanParams,
) -> AppResult<String> {
    // Capture a serialized form of the params before we move them into
    // the Cli struct so we can persist it in the history DB.
    let params_json = serde_json::to_string(&params).unwrap_or_else(|_| "{}".to_string());
    let host_for_history = params.host.clone();

    // Build a Cli shaped like the one the CLI binary constructs.
    let cli = params.into_cli();
    let host_arg = cli
        .effective_host()
        .ok_or_else(|| AppError::Other("host required".into()))?
        .to_string();

    // Config: same lookup order as the CLI binary.
    let (cfg, _cfg_path) =
        Config::locate_and_load(cli.config.as_deref()).map_err(AppError::Corvex)?;

    // Targets.
    let marks = set_targets(
        &host_arg,
        cli.port.as_deref(),
        cli.ssl,
        cli.root.as_deref(),
    )
    .map_err(AppError::Corvex)?;

    // Engine state.
    let state = Arc::new(GlobalState::new());
    let http = Arc::new(HttpClient::new(state.clone(), cli.timeout.unwrap_or(15)));
    let tuning = Arc::new(
        cli.tuning
            .as_deref()
            .map(TuningFilter::parse)
            .unwrap_or_default(),
    );
    let evasion = Arc::new(
        cli.evasion
            .as_deref()
            .map(EvasionSet::parse)
            .unwrap_or_default(),
    );

    // Databases + optional -Userdbs merge.
    let dbs = {
        let embedded = db::load();
        match cli.userdbs.as_ref() {
            Some(path) => {
                let mut cloned = (*embedded).clone();
                if let Ok(rows) = db::csv_loader::load_user_tests(path) {
                    db::csv_loader::merge_user_tests(&mut cloned, rows);
                }
                Arc::new(cloned)
            }
            None => embedded,
        }
    };

    // Plugins.
    let mut registry: PluginRegistry = corvex_plugins::register_all();
    if let Some(sel) = &cli.plugins {
        registry.apply_selector(
            sel,
            cfg.get_or("@@DEFAULT", "@@ALL"),
            cfg.get_or("@@EXTRAS", "dictionary;siebel"),
        );
    }

    // Report sinks: always include the Tauri event sink; optionally add
    // any file sinks the user asked for via -Format / --output.
    let scan_id = Uuid::new_v4();
    let mut sinks: Vec<Box<dyn ReportSink>> =
        vec![Box::new(TauriEventSink::new(app.clone(), scan_id))];
    if cli.output.is_some() {
        sinks.extend(corvex_plugins::build_sinks(
            cli.format.as_deref().unwrap_or("txt"),
            cli.output.as_deref(),
        ));
    }
    let reports = Arc::new(Mutex::new(sinks));

    let request_sem = Arc::new(Semaphore::new(cli.max_concurrent_requests.max(1)));
    let cancel = CancellationToken::new();

    let ctx = Arc::new(ScanCtx {
        cfg: Arc::new(cfg),
        cli: Arc::new(cli),
        http,
        plugins: Arc::new(registry),
        reports,
        state: state.clone(),
        dbs,
        tuning,
        evasion,
        request_sem,
        cancel: cancel.clone(),
    });

    // Register before spawning so cancel arrives in time.
    let registry = app.state::<ScanRegistry>();
    registry
        .insert(RunningScan {
            id: scan_id,
            cancel: cancel.clone(),
            state: state.clone(),
        })
        .await;

    // Persist a "running" row in the SQLite history DB so the scan
    // appears in the History view immediately. Failure to write isn't
    // fatal — the scan still runs.
    let history_id: Option<i64> = app
        .try_state::<Arc<HistoryDb>>()
        .and_then(|h| match h.insert_scan(&host_for_history, &params_json) {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::warn!(target: "history", "insert_scan failed: {e}");
                None
            }
        });

    // Spawn the scan. On completion we emit a done event, clean up the
    // running-scan registry, and update the history row with the final
    // counts. Use Tauri's managed runtime so this works from any context,
    // matching the `setup` closure — see main.rs for the same rationale.
    let app_for_task = app.clone();
    let scan_state = state.clone();
    tauri::async_runtime::spawn(async move {
        let result = scan::run(ctx, marks).await;
        let cancelled = cancel.is_cancelled();
        let final_status = if cancelled {
            "cancelled"
        } else if result.is_err() {
            "error"
        } else {
            "done"
        };

        // Snapshot final counts from the GlobalState.
        use std::sync::atomic::Ordering;
        let total_requests = scan_state.total_requests.load(Ordering::Relaxed);
        let total_findings = scan_state.total_findings.load(Ordering::Relaxed);
        let total_errors = scan_state.total_errors.load(Ordering::Relaxed);

        // Update the history row.
        if let (Some(id), Some(db)) = (history_id, app_for_task.try_state::<Arc<HistoryDb>>()) {
            if let Err(e) = db.finish_scan(
                id,
                final_status,
                total_requests,
                total_findings,
                total_errors,
            ) {
                tracing::warn!(target: "history", "finish_scan failed: {e}");
            }
        }

        let event = format!("scan://{}/done", scan_id);
        let _ = app_for_task.emit(
            &event,
            serde_json::json!({
                "cancelled": cancelled,
                "error": result.err().map(|e| e.to_string()),
                "status": final_status,
            }),
        );

        // Remove from in-memory registry.
        let registry: State<ScanRegistry> = app_for_task.state::<ScanRegistry>();
        registry.remove(scan_id).await;
    });

    Ok(scan_id.to_string())
}

// ----- History commands ----------------------------------------------------

#[tauri::command]
pub async fn history_list(
    db: State<'_, Arc<HistoryDb>>,
    limit: Option<usize>,
) -> AppResult<Vec<HistoryEntry>> {
    db.list(limit.unwrap_or(200))
        .map_err(|e| AppError::Other(format!("history.list: {e}")))
}

#[tauri::command]
pub async fn history_clear(db: State<'_, Arc<HistoryDb>>) -> AppResult<usize> {
    db.clear()
        .map_err(|e| AppError::Other(format!("history.clear: {e}")))
}

#[tauri::command]
pub async fn history_delete(
    db: State<'_, Arc<HistoryDb>>,
    id: i64,
) -> AppResult<usize> {
    db.delete(id)
        .map_err(|e| AppError::Other(format!("history.delete: {e}")))
}
