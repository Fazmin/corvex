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
use crate::probe_state::{ProbeRegistry, RunningProbe};
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

#[derive(Debug, Clone, Serialize)]
pub struct JarmLookupResult {
    /// The 62-character hash echoed back so the frontend can verify
    /// round-trip state even when there's no match.
    pub hash: String,
    /// Known metadata, `None` when the hash isn't in the DB.
    pub known: Option<JarmKnownPayload>,
    /// Cipher/version portion (first 30 chars). Identifies the per-probe
    /// TLS version + cipher suite chosen by the server.
    pub cipher_version: String,
    /// Extension-order SHA-256 digest portion (last 32 chars).
    pub extensions_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct JarmKnownPayload {
    pub name: String,
    pub notes: Option<String>,
    pub confidence: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NucleiTemplateEntry {
    pub id: String,
    pub name: String,
    pub path: String,
    pub severity: String,
    pub tags: Vec<String>,
    pub authors: Vec<String>,
    pub cve_ids: Vec<String>,
    pub supported: bool,
    pub skip_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NucleiSummary {
    pub enabled: bool,
    pub bundle_tag: Option<String>,
    pub bundle_commit: Option<String>,
    pub roots: Vec<String>,
    pub manifest_template_count: Option<usize>,
    pub supported: usize,
    pub skipped: usize,
    pub by_bucket: Vec<(String, usize)>,
    pub by_severity: Vec<(String, usize)>,
    pub by_tag_top: Vec<(String, usize)>,
    pub extras_cached: bool,
    pub extras_cache_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SonarSummary {
    pub scripted_probes: Vec<String>,
    pub static_probes: Vec<String>,
    pub fingerprint_sets: Vec<String>,
    pub fingerprint_count: usize,
    pub scripted_count: usize,
    pub static_count: usize,
    pub extra_files_loaded: usize,
    pub extra_probes_loaded: usize,
    pub extra_fps_loaded: usize,
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
                        HookKind::Active => "active",
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
pub async fn jarm_lookup(hash: String, extra_probe_files: Vec<String>) -> JarmLookupResult {
    let extras: Vec<std::path::PathBuf> = extra_probe_files
        .iter()
        .map(std::path::PathBuf::from)
        .collect();
    let db = if extras.is_empty() {
        corvex_sonar::db::sonar_db()
    } else {
        corvex_sonar::db::sonar_db_with_extras(&extras)
    };

    let trimmed = hash.trim().to_string();
    let known = db.lookup_jarm(&trimmed).map(|e| JarmKnownPayload {
        name: e.name.clone(),
        notes: e.notes.clone(),
        confidence: e.confidence.clone(),
    });

    // Decomposition: the jarm module produces `<30-char cipher/version><32-char ext digest>`.
    // Slice defensively so a truncated or malformed input doesn't panic.
    let lower = trimmed.to_ascii_lowercase();
    let cipher_version = lower.chars().take(30).collect::<String>();
    let extensions_digest = lower.chars().skip(30).take(32).collect::<String>();

    JarmLookupResult {
        hash: trimmed,
        known,
        cipher_version,
        extensions_digest,
    }
}

#[tauri::command]
pub async fn sonar_summary(extra_probe_files: Vec<String>) -> SonarSummary {
    let baseline = corvex_sonar::db::sonar_db();
    let baseline_scripted = baseline.scripted_probe_ids().len();
    let baseline_static = baseline.static_probe_ids().len();
    let baseline_fps = baseline.recog.len();

    let extras: Vec<std::path::PathBuf> = extra_probe_files
        .iter()
        .map(std::path::PathBuf::from)
        .collect();
    let db = if extras.is_empty() {
        baseline.clone()
    } else {
        corvex_sonar::db::sonar_db_with_extras(&extras)
    };

    let extra_probes_loaded = db.static_probe_ids().len().saturating_sub(baseline_static);
    let extra_fps_loaded = db.recog.len().saturating_sub(baseline_fps);

    SonarSummary {
        scripted_probes: db
            .scripted_probe_ids()
            .into_iter()
            .map(String::from)
            .collect(),
        static_probes: db.static_probe_ids(),
        fingerprint_sets: db.fp_set_names(),
        fingerprint_count: db.recog.len(),
        scripted_count: baseline_scripted,
        static_count: db.static_probe_ids().len(),
        extra_files_loaded: extras.len(),
        extra_probes_loaded,
        extra_fps_loaded,
    }
}

/// Vulnerability database summary (CVE count, last update, etc.).
#[derive(Debug, Clone, Serialize)]
pub struct VulnDbInfo {
    pub available: bool,
    pub cve_count: u64,
    pub cpe_match_count: u64,
    pub epss_count: u64,
    pub fix_count: u64,
    pub last_nvd_update: String,
    pub last_epss_update: String,
}

#[tauri::command]
pub async fn vulndb_summary() -> VulnDbInfo {
    match corvex_core::vulndb::VulnDb::open_default() {
        Ok(db) => match db.summary() {
            Ok(s) => VulnDbInfo {
                available: true,
                cve_count: s.cve_count,
                cpe_match_count: s.cpe_match_count,
                epss_count: s.epss_count,
                fix_count: s.fix_count,
                last_nvd_update: s.last_nvd_update,
                last_epss_update: s.last_epss_update,
            },
            Err(_) => VulnDbInfo {
                available: false,
                cve_count: 0,
                cpe_match_count: 0,
                epss_count: 0,
                fix_count: 0,
                last_nvd_update: String::new(),
                last_epss_update: String::new(),
            },
        },
        Err(_) => VulnDbInfo {
            available: false,
            cve_count: 0,
            cpe_match_count: 0,
            epss_count: 0,
            fix_count: 0,
            last_nvd_update: String::new(),
            last_epss_update: String::new(),
        },
    }
}

/// Update the vulnerability database (NVD + EPSS).
#[tauri::command]
pub async fn vulndb_update(mode: String) -> AppResult<String> {
    use corvex_core::vulndb::{self, update::UpdateMode, VulnDb};
    let db_path = vulndb::default_db_path()
        .map_err(|e| AppError::Other(e))?;
    let db = VulnDb::open(&db_path)
        .map_err(|e| AppError::Other(e))?;
    let update_mode = UpdateMode::parse(&mode).unwrap_or(UpdateMode::Daily);
    let api_key = std::env::var("NVD_API_KEY").ok();
    vulndb::update::run_update(&db, update_mode, api_key)
        .await
        .map_err(|e| AppError::Other(e))?;
    let summary = db.summary().map_err(|e| AppError::Other(e))?;
    Ok(format!("{} CVEs loaded", summary.cve_count))
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

    // Build the scope filter BEFORE moving cli into Arc.
    let scope = {
        let wants_active = cli.active || cli.crawl || cli.scope.is_some();
        if wants_active {
            let kind = cli
                .scope
                .as_deref()
                .and_then(corvex_core::scope::ScopeKind::parse)
                .unwrap_or(corvex_core::scope::ScopeKind::Domain);
            let excludes: Vec<regex::Regex> = cli
                .exclude_pattern
                .iter()
                .filter_map(|p| regex::Regex::new(p).ok())
                .collect();
            Some(Arc::new(corvex_core::scope::ScopeFilter::new(kind, &host_arg, excludes)))
        } else {
            None
        }
    };

    // Initialize vulnerability database if SCA features are requested.
    let vulndb = if cli.scan_dir.is_some()
        || cli.sbom_input.is_some()
        || cli.binary_scan.is_some()
    {
        match corvex_core::vulndb::VulnDb::open_default() {
            Ok(db) => Some(Arc::new(db)),
            Err(e) => {
                tracing::warn!(target: "vulndb", "failed to open vulndb: {e}");
                None
            }
        }
    } else {
        None
    };

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
        scope,
        vulndb,
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

// ===== Standalone service-probing =====================================

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProbeParams {
    /// One target per entry. Supports:
    ///   * Single IPv4 / IPv6 literal (`10.0.0.3`, `::1`)
    ///   * Hostname (resolved via DNS)
    ///   * IPv4 CIDR block (`192.168.1.0/24`)
    pub targets: Vec<String>,
    /// "rapid" | "deep"
    pub scan_mode: String,
    pub ports_range: String,
    #[serde(default)]
    pub jarm: bool,
    #[serde(default)]
    pub extra_probe_files: Vec<String>,
    #[serde(default)]
    pub host_concurrency: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct ProbeResolvedTarget {
    display: String,
    ip: String,
    hostname: String,
}

#[derive(Debug, Clone, Serialize)]
struct ProbeHostStart {
    probe_id: String,
    display: String,
    hostname: String,
    ip: String,
    index: usize,
    total: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ProbeHostEnd {
    probe_id: String,
    display: String,
    ip: String,
    open_count: usize,
    elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
struct ProbeOpenPort {
    probe_id: String,
    display: String,
    hostname: String,
    ip: String,
    port: u16,
    over_tls: bool,
    service: Option<String>,
    product: Option<String>,
    vendor: Option<String>,
    version: Option<String>,
    info: Option<String>,
    cpe: Vec<String>,
    jarm: Option<String>,
    banner: String,
}

#[derive(Debug, Clone, Serialize)]
struct ProbeSummary {
    probe_id: String,
    hosts_completed: usize,
    hosts_total: usize,
    open_ports_total: usize,
    elapsed_ms: u128,
    cancelled: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ProbeTargetError {
    probe_id: String,
    target: String,
    message: String,
}

#[tauri::command]
pub async fn probe_start(
    app: AppHandle,
    registry: State<'_, ProbeRegistry>,
    params: ProbeParams,
) -> AppResult<String> {
    let probe_id = Uuid::new_v4();
    let cancel = CancellationToken::new();
    registry
        .insert(RunningProbe {
            id: probe_id,
            cancel: cancel.clone(),
        })
        .await;

    let registry_handle: tauri::State<'_, ProbeRegistry> = registry;
    let _ = registry_handle;

    let app_cloned = app.clone();
    tauri::async_runtime::spawn(async move {
        let start = std::time::Instant::now();
        run_probe(app_cloned.clone(), probe_id, params, cancel, start).await;
        // Registry clean-up on completion.
        if let Some(registry) = app_cloned.try_state::<ProbeRegistry>() {
            registry.remove(probe_id).await;
        }
    });

    Ok(probe_id.to_string())
}

#[tauri::command]
pub async fn probe_cancel(
    registry: State<'_, ProbeRegistry>,
    id: String,
) -> AppResult<bool> {
    let uuid = Uuid::parse_str(&id).map_err(|e| AppError::Other(e.to_string()))?;
    Ok(registry.cancel(uuid).await)
}

async fn run_probe(
    app: AppHandle,
    probe_id: Uuid,
    params: ProbeParams,
    cancel: CancellationToken,
    start: std::time::Instant,
) {
    let id_str = probe_id.to_string();

    let scan_mode = match params.scan_mode.as_str() {
        "deep" => corvex_sonar::ScanMode::Deep,
        _ => corvex_sonar::ScanMode::Rapid,
    };
    let tuning = corvex_sonar::ScanTuning::defaults_for(scan_mode);
    let opts = corvex_sonar::SonarOpts {
        jarm: params.jarm,
        extra_probe_files: params.extra_probe_files.clone(),
    };
    let port_list = corvex_core::portscan::parse_port_range(&params.ports_range);
    if port_list.is_empty() {
        let _ = app.emit(
            &ev(&id_str, "error"),
            ProbeTargetError {
                probe_id: id_str.clone(),
                target: String::new(),
                message: format!("port range '{}' expanded to zero ports", params.ports_range),
            },
        );
        emit_final_summary(&app, &id_str, 0, 0, 0, start, true);
        return;
    }

    // Expand every target entry. Failures are reported per-target but do not
    // abort the whole run.
    let mut resolved: Vec<ProbeResolvedTarget> = Vec::new();
    for raw in &params.targets {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        match expand_target(entry).await {
            Ok(mut list) => resolved.append(&mut list),
            Err(e) => {
                let _ = app.emit(
                    &ev(&id_str, "error"),
                    ProbeTargetError {
                        probe_id: id_str.clone(),
                        target: entry.to_string(),
                        message: e,
                    },
                );
            }
        }
    }

    if resolved.is_empty() {
        emit_final_summary(&app, &id_str, 0, 0, 0, start, false);
        return;
    }

    let total = resolved.len();
    let host_cap = params.host_concurrency.unwrap_or(8).max(1);
    let sem = Arc::new(Semaphore::new(host_cap));
    let hosts_completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let open_ports_total = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut tasks = Vec::new();
    for (index, target) in resolved.into_iter().enumerate() {
        let app = app.clone();
        let id_str = id_str.clone();
        let sem = sem.clone();
        let cancel = cancel.clone();
        let hosts_completed = hosts_completed.clone();
        let open_ports_total = open_ports_total.clone();
        let port_list = port_list.clone();
        let opts = opts.clone();

        tasks.push(tauri::async_runtime::spawn(async move {
            if cancel.is_cancelled() {
                return;
            }
            let _permit = sem.acquire().await;
            if cancel.is_cancelled() {
                return;
            }

            let host_start_at = std::time::Instant::now();
            let _ = app.emit(
                &ev(&id_str, "host-start"),
                ProbeHostStart {
                    probe_id: id_str.clone(),
                    display: target.display.clone(),
                    hostname: target.hostname.clone(),
                    ip: target.ip.clone(),
                    index,
                    total,
                },
            );

            let ip: std::net::IpAddr = match target.ip.parse() {
                Ok(ip) => ip,
                Err(_) => return,
            };

            let scan_result = tokio::select! {
                _ = cancel.cancelled() => return,
                r = corvex_core::portscan::tcp_scan(
                    ip,
                    &target.hostname,
                    &port_list,
                    scan_mode,
                    tuning,
                    opts,
                ) => r,
            };

            let mut open_count = 0usize;
            for op in &scan_result.open_ports {
                open_count += 1;
                let svc = op.service.clone();
                let over_tls = svc.as_ref().map(|s| s.tls).unwrap_or(false);
                let payload = ProbeOpenPort {
                    probe_id: id_str.clone(),
                    display: target.display.clone(),
                    hostname: target.hostname.clone(),
                    ip: target.ip.clone(),
                    port: op.port,
                    over_tls,
                    service: svc.as_ref().map(|s| s.name.clone()),
                    product: svc.as_ref().and_then(|s| s.product.clone()),
                    vendor: svc.as_ref().and_then(|s| s.vendor.clone()),
                    version: svc.as_ref().and_then(|s| s.version.clone()),
                    info: svc.as_ref().and_then(|s| s.info.clone()),
                    cpe: svc.as_ref().map(|s| s.cpe.clone()).unwrap_or_default(),
                    jarm: svc.as_ref().and_then(|s| s.jarm.clone()),
                    banner: svc.as_ref().map(|s| s.banner.clone()).unwrap_or_default(),
                };
                let _ = app.emit(&ev(&id_str, "open-port"), payload);
            }

            open_ports_total.fetch_add(open_count, std::sync::atomic::Ordering::Relaxed);
            hosts_completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            let _ = app.emit(
                &ev(&id_str, "host-end"),
                ProbeHostEnd {
                    probe_id: id_str.clone(),
                    display: target.display.clone(),
                    ip: target.ip.clone(),
                    open_count,
                    elapsed_ms: host_start_at.elapsed().as_millis(),
                },
            );
        }));
    }

    for t in tasks {
        let _ = t.await;
    }

    let completed = hosts_completed.load(std::sync::atomic::Ordering::Relaxed);
    let opens = open_ports_total.load(std::sync::atomic::Ordering::Relaxed);
    emit_final_summary(&app, &id_str, completed, total, opens, start, cancel.is_cancelled());
}

fn emit_final_summary(
    app: &AppHandle,
    id_str: &str,
    hosts_completed: usize,
    hosts_total: usize,
    open_ports_total: usize,
    start: std::time::Instant,
    cancelled: bool,
) {
    let _ = app.emit(
        &ev(id_str, "summary"),
        ProbeSummary {
            probe_id: id_str.to_string(),
            hosts_completed,
            hosts_total,
            open_ports_total,
            elapsed_ms: start.elapsed().as_millis(),
            cancelled,
        },
    );
}

fn ev(id: &str, kind: &str) -> String {
    format!("probe://{}/{}", id, kind)
}

/// Supported target spellings on one line:
///   * `a.b.c.d`                       — single IPv4 or IPv6 literal
///   * `example.com`                   — hostname (resolved via DNS)
///   * `a.b.c.d/N`                     — IPv4 CIDR block
///   * `a.b.c.d-e.f.g.h`               — inclusive IPv4 range (full IPs)
///   * `a.b.c.d-M`                     — inclusive IPv4 range with a
///                                        short suffix on the last octet
///                                        (M must be 0-255 and ≥ d)
///   * `a,b,...`                       — comma-separated list where each
///                                        element is parsed independently
async fn expand_target(entry: &str) -> Result<Vec<ProbeResolvedTarget>, String> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    // Comma-separated lists on one line — parse each element recursively,
    // concatenate the results. Errors in any sub-element fail the whole
    // line so the user notices the typo.
    if trimmed.contains(',') {
        let mut out = Vec::new();
        for piece in trimmed.split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            let mut sub = Box::pin(expand_target(piece)).await?;
            out.append(&mut sub);
        }
        return Ok(out);
    }

    // CIDR form (IPv4 only in v1).
    if let Some((net, bits)) = trimmed.split_once('/') {
        let prefix: u8 = bits
            .parse()
            .map_err(|_| format!("invalid CIDR prefix '{bits}'"))?;
        let addr: std::net::Ipv4Addr = net
            .parse()
            .map_err(|_| format!("CIDR base '{net}' must be an IPv4 literal"))?;
        if prefix > 32 {
            return Err(format!("CIDR prefix /{prefix} out of range"));
        }
        return Ok(expand_ipv4_cidr(addr, prefix, trimmed));
    }

    // Dash-range forms. We only split on the *first* '-' so that an
    // upstream hostname containing a dash is still treated as a hostname
    // if both halves don't look like IPs.
    if let Some((left_raw, right_raw)) = trimmed.split_once('-') {
        let left = left_raw.trim();
        let right = right_raw.trim();
        if let Some(range) = parse_ipv4_dash_range(left, right, trimmed) {
            return range;
        }
    }

    // Bare IP literal.
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return Ok(vec![ProbeResolvedTarget {
            display: trimmed.to_string(),
            ip: ip.to_string(),
            hostname: trimmed.to_string(),
        }]);
    }

    // Hostname lookup. Bind to :0 so lookup_host doesn't complain about a
    // missing port; we use the first A/AAAA record returned.
    let lookup = format!("{trimmed}:0");
    let first = tokio::net::lookup_host(&lookup)
        .await
        .map_err(|e| format!("DNS lookup for '{trimmed}' failed: {e}"))?
        .next()
        .ok_or_else(|| format!("no A/AAAA records for '{trimmed}'"))?;
    Ok(vec![ProbeResolvedTarget {
        display: trimmed.to_string(),
        ip: first.ip().to_string(),
        hostname: trimmed.to_string(),
    }])
}

/// Parse an IPv4 dash-range (`a.b.c.d-e.f.g.h` or `a.b.c.d-M`) and return
/// the expanded host list. Returns `None` when `left`/`right` don't look
/// like an IPv4 range at all (so the caller falls through to hostname
/// resolution).
fn parse_ipv4_dash_range(
    left: &str,
    right: &str,
    display_original: &str,
) -> Option<Result<Vec<ProbeResolvedTarget>, String>> {
    // Left half must be a full IPv4 literal.
    let start: std::net::Ipv4Addr = left.parse().ok()?;

    // Right half: either a full IPv4 literal or a bare 0-255 last-octet.
    let end: std::net::Ipv4Addr = if let Ok(ip) = right.parse::<std::net::Ipv4Addr>() {
        ip
    } else if let Ok(last_octet) = right.parse::<u8>() {
        let o = start.octets();
        std::net::Ipv4Addr::new(o[0], o[1], o[2], last_octet)
    } else {
        return None;
    };

    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);
    if end_u32 < start_u32 {
        return Some(Err(format!(
            "IP range '{display_original}' is reversed: {start} > {end}"
        )));
    }

    let span = (end_u32 - start_u32) as u64 + 1;
    // Same safety cap as CIDR expansion: never emit more than 65,536
    // entries from a single range directive.
    let capped = span.min(1 << 16);

    let mut out = Vec::with_capacity(capped as usize);
    for i in 0..capped {
        let ip = std::net::Ipv4Addr::from(start_u32.wrapping_add(i as u32));
        out.push(ProbeResolvedTarget {
            display: format!("{display_original} [{ip}]"),
            ip: ip.to_string(),
            hostname: ip.to_string(),
        });
    }
    Some(Ok(out))
}

#[cfg(test)]
mod target_tests {
    use super::*;

    fn ips(v: &[ProbeResolvedTarget]) -> Vec<String> {
        v.iter().map(|t| t.ip.clone()).collect()
    }

    #[tokio::test]
    async fn full_ip_range_expands_inclusive() {
        let out = expand_target("10.0.0.5-10.0.0.7").await.unwrap();
        assert_eq!(ips(&out), vec!["10.0.0.5", "10.0.0.6", "10.0.0.7"]);
    }

    #[tokio::test]
    async fn short_last_octet_range_expands() {
        let out = expand_target("192.168.1.10-12").await.unwrap();
        assert_eq!(ips(&out), vec!["192.168.1.10", "192.168.1.11", "192.168.1.12"]);
    }

    #[tokio::test]
    async fn reversed_range_is_rejected() {
        let err = expand_target("10.0.0.5-10.0.0.4").await.unwrap_err();
        assert!(err.contains("reversed"), "err = {err}");
    }

    #[tokio::test]
    async fn comma_list_concatenates() {
        let out = expand_target("10.0.0.1,10.0.0.2-3").await.unwrap();
        assert_eq!(ips(&out), vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    }

    #[tokio::test]
    async fn single_ipv4_literal() {
        let out = expand_target("192.168.99.1").await.unwrap();
        assert_eq!(ips(&out), vec!["192.168.99.1"]);
    }

    #[tokio::test]
    async fn cidr_skips_network_and_broadcast() {
        let out = expand_target("10.0.0.0/30").await.unwrap();
        // /30 = 4 addresses, network + broadcast skipped => two usable.
        assert_eq!(ips(&out), vec!["10.0.0.1", "10.0.0.2"]);
    }

    #[tokio::test]
    async fn cidr_31_keeps_both_endpoints() {
        let out = expand_target("10.0.0.0/31").await.unwrap();
        assert_eq!(ips(&out), vec!["10.0.0.0", "10.0.0.1"]);
    }
}

fn expand_ipv4_cidr(
    base: std::net::Ipv4Addr,
    prefix: u8,
    display_original: &str,
) -> Vec<ProbeResolvedTarget> {
    if prefix == 32 {
        return vec![ProbeResolvedTarget {
            display: base.to_string(),
            ip: base.to_string(),
            hostname: base.to_string(),
        }];
    }
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let base_u32 = u32::from(base) & mask;
    let host_bits = 32 - prefix;
    // Cap expansion to prevent accidental /8-against-public scans inside a GUI.
    let max_hosts: u64 = 1u64 << host_bits;
    let capped = max_hosts.min(1 << 16); // never expand more than 65,536 at once
    let mut out = Vec::with_capacity(capped as usize);
    for i in 0..capped {
        let ip = std::net::Ipv4Addr::from(base_u32.wrapping_add(i as u32));
        // In a /31 or /32 we keep all entries. For wider prefixes we drop
        // the network + broadcast addresses so we don't poke identifiers.
        if prefix < 31 {
            if i == 0 || i == max_hosts - 1 {
                continue;
            }
        }
        out.push(ProbeResolvedTarget {
            display: format!("{} [{}]", display_original, ip),
            ip: ip.to_string(),
            hostname: ip.to_string(),
        });
    }
    out
}

/// Load the bundled + cached Nuclei templates and surface counts to the
/// Databases view. Fast enough to call synchronously from the UI tab.
#[tauri::command]
pub async fn nuclei_summary() -> NucleiSummary {
    use corvex_nuclei::{locate, schema::Severity as NS, TemplateStore};

    // Honor nuclei.enabled so the UI can tell users when the engine is
    // switched off. Counts are still populated — it's useful to see what
    // would run if they turned it on.
    let (cfg, _path) = match Config::locate_and_load(None) {
        Ok(v) => v,
        Err(_) => (Config::default(), std::path::PathBuf::new()),
    };
    let enabled = matches!(
        cfg.get("nuclei.enabled").unwrap_or("false"),
        "true" | "1" | "yes" | "on"
    );

    let mut store = TemplateStore::new();
    for root in locate::default_roots() {
        let _ = store.load_dir(&root);
    }
    for root in locate::extras_roots() {
        let _ = store.load_dir(&root);
    }

    let counts = store.counts();
    let by_severity = counts
        .by_severity
        .into_iter()
        .map(|(s, n)| {
            let label = match s {
                NS::Critical => "critical",
                NS::High => "high",
                NS::Medium => "medium",
                NS::Low => "low",
                NS::Info => "info",
                NS::Unknown => "unknown",
            };
            (label.to_string(), n)
        })
        .collect();

    let extras_roots = locate::extras_roots();
    let extras_cached = !extras_roots.is_empty();
    let extras_cache_path = extras_roots
        .first()
        .map(|p| p.display().to_string());

    NucleiSummary {
        enabled,
        bundle_tag: store.upstream_tag.clone(),
        bundle_commit: store.upstream_commit.clone(),
        roots: store
            .roots
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        manifest_template_count: store.manifest_template_count,
        supported: counts.supported,
        skipped: counts.skipped,
        by_bucket: counts.by_bucket,
        by_severity,
        by_tag_top: counts.by_tag_top,
        extras_cached,
        extras_cache_path,
    }
}

/// Enumerate every template on disk — supported AND skipped — with
/// enough metadata for the Help view's "All bundled Nuclei templates"
/// list to render a filterable table. Re-walks the bundle each call;
/// this isn't on a hot path (user-initiated via expand-to-view).
#[tauri::command]
pub async fn nuclei_template_list() -> Vec<NucleiTemplateEntry> {
    use corvex_nuclei::locate;
    use corvex_nuclei::parser::{load_file, LoadOutcome, SkipReason};
    use corvex_nuclei::schema::Severity as NS;

    fn sev_label(s: NS) -> &'static str {
        match s {
            NS::Critical => "critical",
            NS::High => "high",
            NS::Medium => "medium",
            NS::Low => "low",
            NS::Info => "info",
            NS::Unknown => "unknown",
        }
    }

    fn reason_string(r: &SkipReason) -> String {
        match r {
            SkipReason::Protocol(p) => format!("protocol:{p}"),
            SkipReason::DslFn(f) => format!("dsl_fn:{f}"),
            SkipReason::Interactsh => "interactsh".to_string(),
            SkipReason::ParseError(e) => format!(
                "parse_error:{}",
                e.lines().next().unwrap_or("").chars().take(200).collect::<String>()
            ),
            SkipReason::UnsupportedFeature(f) => format!("unsupported_feature:{f}"),
            SkipReason::NoHttp => "no_http".to_string(),
        }
    }

    let mut roots = locate::default_roots();
    roots.extend(locate::extras_roots());

    let mut out: Vec<NucleiTemplateEntry> = Vec::new();
    let mut seen_ids: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    for root in roots {
        for entry in walkdir::WalkDir::new(&root)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if !matches!(ext, "yaml" | "yml") {
                continue;
            }

            let outcome = match load_file(path) {
                Ok(o) => o,
                Err(_) => continue,
            };

            let rel = path
                .strip_prefix(&root)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| path.display().to_string())
                .replace('\\', "/");

            match outcome {
                LoadOutcome::Supported(tpl) => {
                    if !seen_ids.insert(tpl.id.clone()) {
                        continue;
                    }
                    let cves = tpl
                        .info
                        .classification
                        .as_ref()
                        .map(|c| c.cve_id.clone())
                        .unwrap_or_default();
                    out.push(NucleiTemplateEntry {
                        id: tpl.id.clone(),
                        name: tpl.info.name.clone(),
                        path: rel,
                        severity: sev_label(tpl.info.severity).to_string(),
                        tags: tpl.info.tags.clone(),
                        authors: tpl.info.author.clone(),
                        cve_ids: cves,
                        supported: true,
                        skip_reason: None,
                    });
                }
                LoadOutcome::Skipped { id, reason, .. } => {
                    let tid = id.unwrap_or_else(|| rel.clone());
                    if !seen_ids.insert(tid.clone()) {
                        continue;
                    }
                    out.push(NucleiTemplateEntry {
                        id: tid,
                        name: String::new(),
                        path: rel,
                        severity: String::new(),
                        tags: Vec::new(),
                        authors: Vec::new(),
                        cve_ids: Vec::new(),
                        supported: false,
                        skip_reason: Some(reason_string(&reason)),
                    });
                }
            }
        }
    }

    out.sort_by(|a, b| a.id.to_ascii_lowercase().cmp(&b.id.to_ascii_lowercase()));
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct NucleiExtrasStatus {
    pub cache_path: String,
    pub tag: String,
    pub http_template_count: usize,
}

/// Download the full nuclei-templates HTTP tree into the Tier-2 extras
/// cache under the user's data dir. Only `http/` is extracted — other
/// protocol trees (`network/`, `dns/`, `ssl/`, …) are not runnable in
/// v1 and would only inflate the cache. Idempotent: a second call
/// replaces the cached tree.
#[tauri::command]
pub async fn nuclei_extras_download(tag: Option<String>) -> AppResult<NucleiExtrasStatus> {
    use flate2::read::GzDecoder;
    use std::io::Cursor;

    let tag = tag.unwrap_or_else(|| "v10.4.2".to_string());
    let cache_root = extras_cache_root()
        .ok_or_else(|| AppError::Other("cannot resolve user data dir".into()))?;
    let dest = cache_root.join(&tag);

    // Wipe any previous download to keep pinning deterministic.
    if dest.exists() {
        std::fs::remove_dir_all(&dest)
            .map_err(|e| AppError::Other(format!("clear {}: {e}", dest.display())))?;
    }
    std::fs::create_dir_all(&dest)
        .map_err(|e| AppError::Other(format!("create {}: {e}", dest.display())))?;

    let url = format!(
        "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/{tag}.tar.gz"
    );
    let client = reqwest::Client::builder()
        .user_agent(format!("corvex-rust/{}", corvex_core::VERSION))
        .build()
        .map_err(|e| AppError::Other(format!("reqwest client: {e}")))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::Other(format!("GET {url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::Other(format!(
            "GET {url}: {}",
            resp.status()
        )));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| AppError::Other(format!("read body: {e}")))?;

    // Extract only the `http/` subtree of the archive. GitHub release
    // tarballs nest everything under `nuclei-templates-<tag>/` so we
    // strip the first path component.
    let gz = GzDecoder::new(Cursor::new(bytes.as_ref()));
    let mut archive = tar::Archive::new(gz);
    let mut count = 0usize;
    for entry in archive
        .entries()
        .map_err(|e| AppError::Other(format!("tar entries: {e}")))?
    {
        let mut entry = entry
            .map_err(|e| AppError::Other(format!("tar entry: {e}")))?;
        let path_in_archive = entry
            .path()
            .map_err(|e| AppError::Other(format!("entry path: {e}")))?
            .into_owned();

        // Strip the top-level `nuclei-templates-<tag>/` directory.
        let mut components = path_in_archive.components();
        let _root = components.next();
        let rel: std::path::PathBuf = components.collect();
        if rel.as_os_str().is_empty() {
            continue;
        }

        let first = rel
            .components()
            .next()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .unwrap_or_default();
        if first != "http" {
            continue;
        }

        let is_yaml = rel
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| matches!(s, "yaml" | "yml"))
            .unwrap_or(false);
        if !entry
            .header()
            .entry_type()
            .is_file()
            || !is_yaml
        {
            continue;
        }

        let target = dest.join(&rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AppError::Other(format!("mkdir {}: {e}", parent.display())))?;
        }
        entry
            .unpack(&target)
            .map_err(|e| AppError::Other(format!("unpack {}: {e}", target.display())))?;
        count += 1;
    }

    // Write a marker so future launches know which tag this cache was
    // populated from and can trigger a refresh if we bump the pinned
    // default later.
    let manifest = format!(
        "upstream_tag = \"{tag}\"\nextracted_count = {count}\nkind = \"tier2-http\"\n"
    );
    let _ = std::fs::write(dest.join("MANIFEST.toml"), manifest);

    Ok(NucleiExtrasStatus {
        cache_path: dest.display().to_string(),
        tag,
        http_template_count: count,
    })
}

/// Remove the Tier-2 extras cache (all versions). Tier-1 bundled
/// templates are untouched.
#[tauri::command]
pub async fn nuclei_extras_remove() -> AppResult<()> {
    let cache_root = extras_cache_root()
        .ok_or_else(|| AppError::Other("cannot resolve user data dir".into()))?;
    if cache_root.exists() {
        std::fs::remove_dir_all(&cache_root)
            .map_err(|e| AppError::Other(format!("remove {}: {e}", cache_root.display())))?;
    }
    Ok(())
}

fn extras_cache_root() -> Option<std::path::PathBuf> {
    let data = user_data_dir()?;
    Some(data.join("corvex").join("nuclei-templates"))
}

fn user_data_dir() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(std::path::PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("XDG_DATA_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| {
                    std::path::PathBuf::from(h).join(".local").join("share")
                })
            })
    }
}
