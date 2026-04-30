//! Tauri command surface.
//!
//! Every `#[tauri::command]` exported here can be called from the
//! frontend via `invoke('<name>', { ... })`.

use std::sync::{Arc, RwLock};

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
use crate::history::{HistoryDb, HistoryEntry, ScanFindingRow};
use crate::init_progress::{InitProgress, InitProgressHandle};
use crate::params::ScanParams;
use crate::probe_state::{ProbeRegistry, RunningProbe};
use crate::probe_store::{PendingDeviceMatch, PendingHostMac, PendingOpenPort, ProbeStore};
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
    /// Semver + `+build` metadata stamped at compile time — changes
    /// every rebuild when the git SHA or tree state shifts.
    pub full_version: &'static str,
    pub build_id: &'static str,
    pub build_date: &'static str,
    pub build_profile: &'static str,
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

/// Quick counts for the SNMP device-signature catalog. Drives the
/// "Datasets" tab on the Probing view so users can confirm the bundled
/// catalog has been wired in correctly. All numbers come from the
/// in-memory `DeviceCatalog` already managed as state — no extra
/// SQLite query at request time.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceDbSummary {
    /// Total entries (one per device YAML).
    pub entries: u32,
    /// Distinct vendor / group buckets across the entries.
    pub vendors: u32,
    /// Distinct device-type buckets ("network", "firewall", "pdu", …).
    pub device_types: u32,
    /// Total number of discovery clauses across all entries.
    pub clauses: u32,
    /// Clauses tagged disabled because they require an active SNMP GET
    /// the matcher cannot issue.
    pub disabled_clauses: u32,
    /// Total positive sysObjectID prefixes recorded (across all
    /// non-disabled clauses).
    pub sys_object_id_prefixes: u32,
    /// Total positive sysDescr substrings recorded.
    pub sys_descr_substrings: u32,
    /// Total positive sysDescr regexes recorded.
    pub sys_descr_regexes: u32,
    /// True when at least one entry loaded successfully — i.e. the
    /// SNMP device-fingerprint pass has data to match against.
    pub catalog_ready: bool,
    /// IANA Private Enterprise Number rows. Used as a fallback
    /// vendor lookup against the `1.3.6.1.4.1.<pen>` branch when the
    /// device-signature catalog has no specific match.
    pub iana_enterprise_count: u32,
    /// IEEE OUI rows (MA-L / MA-M / MA-S registrations). Resolves a
    /// MAC address into a vendor name when one is available.
    pub ieee_oui_count: u32,
}

#[tauri::command]
pub async fn device_db_summary(
    catalog: State<'_, std::sync::Arc<corvex_devicedb::DeviceCatalog>>,
    db_path: State<'_, std::sync::Arc<crate::DevicesDbPath>>,
) -> AppResult<DeviceDbSummary> {
    use std::collections::BTreeSet;

    let cat = catalog.inner().clone();
    let mut vendors: BTreeSet<&str> = BTreeSet::new();
    let mut device_types: BTreeSet<&str> = BTreeSet::new();
    let mut clauses = 0u32;
    let mut disabled_clauses = 0u32;
    let mut sys_object_id_prefixes = 0u32;
    let mut sys_descr_substrings = 0u32;
    let mut sys_descr_regexes = 0u32;
    for entry in &cat.entries {
        vendors.insert(entry.vendor.as_str());
        device_types.insert(entry.device_type.as_str());
        for c in &entry.clauses {
            clauses = clauses.saturating_add(1);
            if c.disabled {
                disabled_clauses = disabled_clauses.saturating_add(1);
                continue;
            }
            sys_object_id_prefixes =
                sys_object_id_prefixes.saturating_add(c.sys_object_id_prefixes.len() as u32);
            sys_descr_substrings =
                sys_descr_substrings.saturating_add(c.sys_descr_substrings.len() as u32);
            sys_descr_regexes =
                sys_descr_regexes.saturating_add(c.sys_descr_regexes.len() as u32);
        }
    }

    // Reference-table counts come from the SQLite file directly —
    // they're not loaded into the in-memory `DeviceCatalog`. Failing
    // to open is non-fatal: the panel just shows zeros and a hint.
    let (iana_count, oui_count) = match db_path.inner().as_ref().0.as_deref() {
        Some(path) => count_reference_tables(path).unwrap_or_else(|e| {
            tracing::warn!(
                target: "devicedb",
                path = %path.display(),
                "reference-table count failed: {e}"
            );
            (0, 0)
        }),
        None => (0, 0),
    };

    Ok(DeviceDbSummary {
        entries: cat.entries.len() as u32,
        vendors: vendors.len() as u32,
        device_types: device_types.len() as u32,
        clauses,
        disabled_clauses,
        sys_object_id_prefixes,
        sys_descr_substrings,
        sys_descr_regexes,
        catalog_ready: !cat.entries.is_empty(),
        iana_enterprise_count: iana_count,
        ieee_oui_count: oui_count,
    })
}

fn count_reference_tables(
    path: &std::path::Path,
) -> Result<(u32, u32), rusqlite::Error> {
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let iana: i64 = conn
        .query_row("SELECT COUNT(*) FROM iana_enterprise", [], |r| r.get(0))
        .unwrap_or(0);
    let oui: i64 = conn
        .query_row("SELECT COUNT(*) FROM ieee_oui", [], |r| r.get(0))
        .unwrap_or(0);
    Ok((iana as u32, oui as u32))
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
        full_version: corvex_core::FULL_VERSION,
        build_id: corvex_core::BUILD_ID,
        build_date: corvex_core::BUILD_DATE,
        build_profile: corvex_core::BUILD_PROFILE,
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

/// Returned by `scan_start`. The frontend uses `scan_id` to subscribe
/// to per-scan events and `history_id` to flip the persistence flag
/// when the user clicks "Save scan".
#[derive(Debug, Clone, Serialize)]
pub struct ScanStartHandle {
    pub scan_id: String,
    pub history_id: Option<i64>,
}

#[tauri::command]
pub async fn scan_start(
    app: AppHandle,
    params: ScanParams,
) -> AppResult<ScanStartHandle> {
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

    // Persist a "running" row first so the per-finding sink below can
    // attach the resulting scan id and write findings into
    // `scan_findings` as the engine produces them. Insert failure is
    // non-fatal — the scan still runs, just without DB-backed
    // per-finding history.
    let history_handle = app.try_state::<Arc<HistoryDb>>().map(|h| h.inner().clone());
    let history_id: Option<i64> = history_handle.as_ref().and_then(|h| {
        match h.insert_scan(&host_for_history, &params_json) {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::warn!(target: "history", "insert_scan failed: {e}");
                None
            }
        }
    });

    // Report sinks: always include the Tauri event sink; optionally add
    // any file sinks the user asked for via -Format / --output. The
    // event sink also writes findings to `scan_findings` when a history
    // handle is present so the asset view sees them after the scan
    // completes.
    let scan_id = Uuid::new_v4();
    let mut event_sink = TauriEventSink::new(app.clone(), scan_id);
    if let Some(history) = history_handle.clone() {
        event_sink = event_sink.with_history(history, history_id);
    }
    let mut sinks: Vec<Box<dyn ReportSink>> = vec![Box::new(event_sink)];
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

    // Unified rules catalog. Lookup order is: cwd → exe-dir → embedded
    // blob extracted to app_data_dir. Missing or unreadable files log a
    // warning and fall through to legacy behaviour.
    let rule_store: Option<Arc<dyn corvex_core::matcher::RuleProvider>> = {
        let path = crate::rules_embed::resolve_rules_path();
        match path {
            Some(p) => match corvex_rules::RuleStore::open(&p) {
                Ok(store) => {
                    let counts = store.count_by_source().unwrap_or_default();
                    let summary: Vec<String> = counts
                        .iter()
                        .map(|(s, n)| format!("{s}={n}"))
                        .collect();
                    tracing::info!(
                        target: "rules",
                        "rules.sqlite loaded ({}): {}",
                        p.display(),
                        summary.join(", ")
                    );
                    Some(Arc::new(store) as Arc<dyn corvex_core::matcher::RuleProvider>)
                }
                Err(e) => {
                    tracing::warn!(
                        target: "rules",
                        "failed to open {}: {e}",
                        p.display()
                    );
                    None
                }
            },
            None => None,
        }
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
        rule_store,
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

    // (`history_id` already obtained above so the per-finding sink
    // could attach to the scan row.)

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

    Ok(ScanStartHandle {
        scan_id: scan_id.to_string(),
        history_id,
    })
}

// ----- App init progress ---------------------------------------------------
//
// Returns a snapshot of the heavy first-launch init pipeline. The
// frontend's SplashScreen calls this once on mount as a backstop in
// case the `app://init-step` / `app://init-ready` events fired before
// it had a chance to subscribe.

#[tauri::command]
pub async fn init_status(progress: State<'_, InitProgressHandle>) -> AppResult<InitProgress> {
    let g = progress.lock().expect("init progress mutex");
    Ok(g.clone())
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

#[tauri::command]
pub async fn history_set_saved(
    db: State<'_, Arc<HistoryDb>>,
    id: i64,
    saved: bool,
) -> AppResult<usize> {
    db.set_saved(id, saved)
        .map_err(|e| AppError::Other(format!("history.set_saved: {e}")))
}

#[tauri::command]
pub async fn history_findings(
    db: State<'_, Arc<HistoryDb>>,
    id: i64,
) -> AppResult<Vec<ScanFindingRow>> {
    db.list_findings(id)
        .map_err(|e| AppError::Other(format!("history.findings: {e}")))
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
    /// Run an SNMP v2c GET against UDP/161 on each host and match the
    /// reply against the device-signature catalogue. Always on in Deep
    /// mode (the flag is ignored). In Rapid mode it's off by default
    /// and only fires when the user explicitly enables it.
    #[serde(default)]
    pub snmp_fingerprint: bool,
    /// After the TCP scan completes, read the OS ARP / neighbour cache
    /// for the target IP and resolve the MAC against the bundled
    /// `ieee_oui` table for a vendor name. Always on in Deep mode;
    /// opt-in in Rapid mode. Only L2-adjacent hosts return useful
    /// data — for routed targets the cache holds the upstream
    /// router's MAC (documented on the Datasets section).
    #[serde(default)]
    pub mac_lookup: bool,
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
struct ProbeMacResolved {
    probe_id: String,
    display: String,
    hostname: String,
    ip: String,
    mac: String,
    mac_vendor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ProbeDeviceMatch {
    probe_id: String,
    display: String,
    hostname: String,
    ip: String,
    os: String,
    vendor: String,
    device_type: String,
    source: &'static str,
    sys_descr: Option<String>,
    sys_object_id: Option<String>,
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

    // Persist a probe_runs row up-front so the asset view can correlate
    // open-port observations even when the probe is still running. We
    // pull the store from app state if present — the asset feature is
    // the only consumer, and persistence is non-fatal: if the store
    // isn't managed (DB open failure at startup) probes still run.
    let probe_store = app.try_state::<Arc<ProbeStore>>().map(|s| s.inner().clone());
    if let Some(store) = probe_store.as_ref() {
        if let Err(e) = store.insert_run(&probe_id, &params.targets) {
            tracing::warn!(target: "probe", "probe_runs insert failed: {e}");
        }
    }

    let app_cloned = app.clone();
    let probe_store_for_task = probe_store.clone();
    let device_catalog = app
        .try_state::<Arc<corvex_devicedb::DeviceCatalog>>()
        .map(|s| s.inner().clone());
    let devices_db_path = app
        .try_state::<Arc<crate::DevicesDbPath>>()
        .and_then(|s| s.inner().0.clone());
    tauri::async_runtime::spawn(async move {
        let start = std::time::Instant::now();
        run_probe(
            app_cloned.clone(),
            probe_id,
            params,
            cancel,
            start,
            probe_store_for_task.clone(),
            device_catalog,
            devices_db_path,
        )
        .await;
        if let Some(store) = probe_store_for_task.as_ref() {
            if let Err(e) = store.finish_run(&probe_id, "complete") {
                tracing::warn!(target: "probe", "probe_runs finish failed: {e}");
            }
        }
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
    probe_store: Option<Arc<ProbeStore>>,
    device_catalog: Option<Arc<corvex_devicedb::DeviceCatalog>>,
    devices_db_path: Option<std::path::PathBuf>,
) {
    let id_str = probe_id.to_string();

    let scan_mode = match params.scan_mode.as_str() {
        "deep" => corvex_sonar::ScanMode::Deep,
        _ => corvex_sonar::ScanMode::Rapid,
    };
    // SNMP fingerprinting + MAC capture are part of Deep by
    // definition; in Rapid they only fire when the user opts in.
    let do_snmp = matches!(scan_mode, corvex_sonar::ScanMode::Deep) || params.snmp_fingerprint;
    let do_mac = matches!(scan_mode, corvex_sonar::ScanMode::Deep) || params.mac_lookup;
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
        let probe_store = probe_store.clone();
        let device_catalog = device_catalog.clone();
        let devices_db_path = devices_db_path.clone();
        let probe_uuid = probe_id;

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

            // Launch the TCP service scan and (when enabled) the SNMP
            // device-fingerprint probe concurrently. SNMP needs its own
            // UDP round-trip and lives outside the TCP probe trait, so
            // running it in parallel keeps the host's wall-clock cost
            // bounded by `max(tcp_budget, snmp_timeout)`.
            let tcp_fut = corvex_core::portscan::tcp_scan(
                ip,
                &target.hostname,
                &port_list,
                scan_mode,
                tuning,
                opts,
            );
            let snmp_fut = async {
                if !do_snmp {
                    return None;
                }
                let snmp_target = std::net::SocketAddr::new(ip, 161);
                let snmp_opts = corvex_sonar::probes::snmp::SnmpProbeOpts::default();
                match corvex_sonar::probes::snmp::probe(snmp_target, &snmp_opts).await {
                    Ok(opt) => opt,
                    Err(e) => {
                        tracing::debug!(target: "snmp", "{snmp_target}: {e}");
                        None
                    }
                }
            };

            let (scan_result, snmp_result) = tokio::select! {
                _ = cancel.cancelled() => return,
                r = futures::future::join(tcp_fut, snmp_fut) => r,
            };

            // Collect every open port for this host and emit one event
            // with the full list. A per-port emit was one IPC round-trip
            // per open port — on a host with 20+ open ports that's 20+
            // serialize/emit calls for data the UI was already merging
            // into a single array.
            let mut host_ports: Vec<ProbeOpenPort> = Vec::with_capacity(scan_result.open_ports.len());
            for op in &scan_result.open_ports {
                let svc = op.service.clone();
                let over_tls = svc.as_ref().map(|s| s.tls).unwrap_or(false);
                host_ports.push(ProbeOpenPort {
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
                });
            }
            let open_count = host_ports.len();
            // Persist before emitting so the SQL row is committed by the
            // time the UI re-queries via `asset_services`. Failure logs
            // and is swallowed — the live event is still useful even if
            // persistence is unavailable.
            if let Some(store) = probe_store.as_ref() {
                let pending: Vec<PendingOpenPort> = host_ports
                    .iter()
                    .map(|p| PendingOpenPort {
                        host: crate::asset_identity::normalize_host(&p.hostname),
                        ip: Some(p.ip.clone()).filter(|s| !s.is_empty()),
                        port: p.port,
                        over_tls: p.over_tls,
                        service: p.service.clone(),
                        product: p.product.clone(),
                        vendor: p.vendor.clone(),
                        version: p.version.clone(),
                        info: p.info.clone(),
                        cpe: p.cpe.clone(),
                        jarm: p.jarm.clone(),
                        banner: p.banner.clone(),
                    })
                    .collect();
                if !pending.is_empty() {
                    if let Err(e) = store.insert_open_ports(&probe_uuid, &pending) {
                        tracing::warn!(target: "probe", "probe_open_ports insert failed: {e}");
                    }
                }
            }
            if !host_ports.is_empty() {
                let _ = app.emit(&ev(&id_str, "open-port"), host_ports);
            }

            // MAC-cache read. By this point the TCP scan has already
            // exchanged SYNs with the target so the OS ARP cache holds
            // a fresh entry for any L2-adjacent host. Routed targets
            // come back with their upstream router's MAC — we still
            // surface the value but document the limitation in the UI.
            if do_mac {
                if let Some(mac) = corvex_sonar::probes::arp::arp_lookup(ip).await {
                    let mac_vendor = devices_db_path.as_deref().and_then(|p| {
                        match rusqlite::Connection::open_with_flags(
                            p,
                            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                        ) {
                            Ok(conn) => corvex_devicedb::db::lookup_ieee_oui(&conn, &mac)
                                .unwrap_or(None),
                            Err(e) => {
                                tracing::debug!(
                                    target: "probe",
                                    "OUI lookup db open failed: {e}"
                                );
                                None
                            }
                        }
                    });
                    let host_norm =
                        crate::asset_identity::normalize_host(&target.hostname);
                    let pending = PendingHostMac {
                        host: host_norm.clone(),
                        ip: Some(target.ip.clone()).filter(|s| !s.is_empty()),
                        mac: mac.clone(),
                        mac_vendor: mac_vendor.clone(),
                    };
                    if let Some(store) = probe_store.as_ref() {
                        if let Err(e) = store.insert_host_mac(&probe_uuid, &pending) {
                            tracing::warn!(
                                target: "probe",
                                "host_mac insert failed: {e}"
                            );
                        }
                    }
                    let _ = app.emit(
                        &ev(&id_str, "mac-resolved"),
                        ProbeMacResolved {
                            probe_id: id_str.clone(),
                            display: target.display.clone(),
                            hostname: target.hostname.clone(),
                            ip: target.ip.clone(),
                            mac,
                            mac_vendor,
                        },
                    );
                }
            }

            // Resolve the device match (if any) once per host, persist
            // it, and push it to the UI. Errors are non-fatal — a host
            // with no SNMP / no matching signature simply leaves the
            // existing probe flow unchanged.
            if let Some(snmp) = snmp_result {
                if let Some(catalog) = device_catalog.as_ref() {
                    if let Some(m) = corvex_devicedb::identify(
                        snmp.sys_object_id.as_deref(),
                        snmp.sys_descr.as_deref(),
                        catalog,
                    ) {
                        let host_norm =
                            crate::asset_identity::normalize_host(&target.hostname);
                        let pending = PendingDeviceMatch {
                            host: host_norm.clone(),
                            ip: Some(target.ip.clone()).filter(|s| !s.is_empty()),
                            os: m.os.clone(),
                            vendor: m.vendor.clone(),
                            device_type: m.device_type.clone(),
                            source: m.source.as_str().to_string(),
                            sys_descr: snmp.sys_descr.clone(),
                            sys_object_id: snmp.sys_object_id.clone(),
                        };
                        if let Some(store) = probe_store.as_ref() {
                            if let Err(e) =
                                store.insert_device_match(&probe_uuid, &pending)
                            {
                                tracing::warn!(
                                    target: "probe",
                                    "device-match insert failed: {e}"
                                );
                            }
                        }
                        let _ = app.emit(
                            &ev(&id_str, "device-match"),
                            ProbeDeviceMatch {
                                probe_id: id_str.clone(),
                                display: target.display.clone(),
                                hostname: target.hostname.clone(),
                                ip: target.ip.clone(),
                                os: m.os,
                                vendor: m.vendor,
                                device_type: m.device_type,
                                source: m.source.as_str(),
                                sys_descr: snmp.sys_descr,
                                sys_object_id: snmp.sys_object_id,
                            },
                        );
                    }
                }
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

    // CIDR form (IPv4 only in v1). The expansion loop can touch up to
    // 65 536 entries — run it on a blocking worker so a /16 doesn't
    // stall the tokio runtime for the tens of ms it takes.
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
        let display = trimmed.to_string();
        return tokio::task::spawn_blocking(move || expand_ipv4_cidr(addr, prefix, &display))
            .await
            .map_err(|e| format!("CIDR expand task: {e}"));
    }

    // Dash-range forms. We only split on the *first* '-' so that an
    // upstream hostname containing a dash is still treated as a hostname
    // if both halves don't look like IPs. Same large-span concern as
    // CIDR — run the expansion on a blocking worker.
    if let Some((left_raw, right_raw)) = trimmed.split_once('-') {
        let left = left_raw.trim().to_string();
        let right = right_raw.trim().to_string();
        let display = trimmed.to_string();
        let parsed = tokio::task::spawn_blocking(move || {
            parse_ipv4_dash_range(&left, &right, &display)
        })
        .await
        .map_err(|e| format!("dash-range task: {e}"))?;
        if let Some(range) = parsed {
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

    // Cached roll-up — invalidated alongside the template list whenever
    // the Tier-2 extras cache is added or removed. `enabled` can flip
    // via config edits but the counts wouldn't, so the cache stores
    // everything *except* `enabled`.
    if let Ok(guard) = NUCLEI_SUMMARY_CACHE.read() {
        if let Some(cached) = guard.as_ref() {
            let mut fresh = (**cached).clone();
            fresh.enabled = enabled;
            return fresh;
        }
    }

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

    let summary = NucleiSummary {
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
    };

    if let Ok(mut guard) = NUCLEI_SUMMARY_CACHE.write() {
        *guard = Some(Arc::new(summary.clone()));
    }
    summary
}

#[derive(Debug, Clone, Serialize)]
pub struct WappalyzerSummary {
    /// True when the vendored upstream dataset was found on disk.
    pub loaded: bool,
    /// Absolute path the dataset was loaded from. `None` when only the
    /// seed is active.
    pub root: Option<String>,
    /// Number of runtime-loaded fingerprints (0 when the user hasn't
    /// run the refresh script).
    pub loaded_count: usize,
    /// Number of compile-time seed fingerprints — always present as a
    /// safety net so detection works even when `loaded_count == 0`.
    pub seed_count: usize,
    /// Top categories by fingerprint count, capped at 15. Each pair is
    /// `(category, count)`.
    pub top_categories: Vec<(String, usize)>,
    /// Upstream project as recorded in `UPSTREAM_LICENSE.md`.
    pub upstream: Option<String>,
    /// Pinned ref (tag or branch) the dataset was refreshed from.
    pub upstream_ref: Option<String>,
    /// Short commit SHA recorded at refresh time.
    pub upstream_commit: Option<String>,
    /// ISO date (YYYY-MM-DD) the refresh script was last run.
    pub refreshed_at: Option<String>,
    /// License name lifted from the first line of
    /// `UPSTREAM_LICENSE.md`, e.g. "MIT".
    pub license: Option<String>,
}

/// Summary of the bundled Wappalyzer-compatible fingerprint dataset.
/// Used by the Databases view. The source of truth for detection is
/// corvex-intel's runtime loader + the compile-time seed — this
/// command reports both.
#[tauri::command]
pub async fn wappalyzer_summary() -> WappalyzerSummary {
    use corvex_intel::fingerprint::{embedded_dataset, SEED_FINGERPRINTS};
    use std::collections::HashMap;

    // The dataset is compile-time embedded — always available at
    // runtime regardless of CWD, installation path, or whether the
    // source tree is shipped alongside the binary.
    let loaded = embedded_dataset();

    let mut by_cat: HashMap<String, usize> = HashMap::new();
    for fp in loaded {
        *by_cat.entry(fp.category.clone()).or_default() += 1;
    }
    let mut top_categories: Vec<(String, usize)> = by_cat.into_iter().collect();
    top_categories.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top_categories.truncate(15);

    WappalyzerSummary {
        loaded: !loaded.is_empty(),
        root: Some("embedded in binary".to_string()),
        loaded_count: loaded.len(),
        seed_count: SEED_FINGERPRINTS.len(),
        top_categories,
        // Upstream/ref/commit/refreshed/license are intentionally left
        // blank here — the Databases view no longer surfaces them; any
        // future datasets-admin view can re-parse UPSTREAM_LICENSE.md
        // from the crate source if needed.
        upstream: None,
        upstream_ref: None,
        upstream_commit: None,
        refreshed_at: None,
        license: None,
    }
}

// Cache of the full template enumeration. The bundle is static for the
// lifetime of the process except when the user downloads or removes
// the Tier-2 extras cache — both of those paths call
// `nuclei_template_list_invalidate()` below. Every subsequent UI open
// of the "All bundled Nuclei templates" panel then returns the cached
// Vec instead of re-walking thousands of files.
static NUCLEI_TEMPLATE_LIST_CACHE: RwLock<Option<Arc<Vec<NucleiTemplateEntry>>>> =
    RwLock::new(None);
static NUCLEI_SUMMARY_CACHE: RwLock<Option<Arc<NucleiSummary>>> = RwLock::new(None);

fn nuclei_template_list_invalidate() {
    if let Ok(mut guard) = NUCLEI_TEMPLATE_LIST_CACHE.write() {
        *guard = None;
    }
    if let Ok(mut guard) = NUCLEI_SUMMARY_CACHE.write() {
        *guard = None;
    }
}

/// Enumerate every template on disk — supported AND skipped — with
/// enough metadata for the Help view's "All bundled Nuclei templates"
/// list to render a filterable table. Result is cached until the
/// Tier-2 extras cache is modified.
#[tauri::command]
pub async fn nuclei_template_list() -> Vec<NucleiTemplateEntry> {
    if let Ok(guard) = NUCLEI_TEMPLATE_LIST_CACHE.read() {
        if let Some(cached) = guard.as_ref() {
            return (**cached).clone();
        }
    }
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

    if let Ok(mut guard) = NUCLEI_TEMPLATE_LIST_CACHE.write() {
        *guard = Some(Arc::new(out.clone()));
    }
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
    // strip the first path component. The gzip + tar pass is CPU- and
    // IO-heavy (~100MB, thousands of files), so it runs on a blocking
    // worker instead of stalling a tokio async runtime thread.
    let bytes_owned = bytes.to_vec();
    let dest_for_task = dest.clone();
    let count = tauri::async_runtime::spawn_blocking(move || -> AppResult<usize> {
        let gz = GzDecoder::new(Cursor::new(bytes_owned));
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

            let target = dest_for_task.join(&rel);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| AppError::Other(format!("mkdir {}: {e}", parent.display())))?;
            }
            entry
                .unpack(&target)
                .map_err(|e| AppError::Other(format!("unpack {}: {e}", target.display())))?;
            count += 1;
        }
        Ok(count)
    })
    .await
    .map_err(|e| AppError::Other(format!("extract task: {e}")))??;

    // Write a marker so future launches know which tag this cache was
    // populated from and can trigger a refresh if we bump the pinned
    // default later.
    let manifest = format!(
        "upstream_tag = \"{tag}\"\nextracted_count = {count}\nkind = \"tier2-http\"\n"
    );
    let _ = std::fs::write(dest.join("MANIFEST.toml"), manifest);

    // New files on disk — any cached enumeration is now stale.
    nuclei_template_list_invalidate();

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
    nuclei_template_list_invalidate();
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

/* ================================================================== */
/* Exploit-DB — CVE → public-exploit enrichment                        */
/* ================================================================== */

use crate::exploitdb::{self, ExploitDb, ExploitDbSummary, ExploitHit};

/// Body of an exploit fetched lazily on "View source". Cached on disk
/// under `<app_data_dir>/exploitdb/cache/<edb_id>.<ext>` after first
/// fetch so repeat views are instant and offline.
#[derive(Debug, Clone, Serialize)]
pub struct ExploitSource {
    pub edb_id: i64,
    pub body: String,
    /// Best-guess language hint for syntax highlighting — mapped from
    /// the file extension.
    pub lang_hint: Option<String>,
    /// Absolute path where the body was cached.
    pub cached_path: String,
    /// Origin URL the body was fetched from (shown in the UI for
    /// transparency / attribution).
    pub source_url: String,
}

#[tauri::command]
pub async fn exploitdb_summary(
    db: State<'_, Arc<ExploitDb>>,
) -> AppResult<ExploitDbSummary> {
    db.summary()
        .map_err(|e| AppError::Other(format!("exploitdb summary: {e}")))
}

#[tauri::command]
pub async fn exploitdb_by_cve(
    cve: String,
    db: State<'_, Arc<ExploitDb>>,
) -> AppResult<Vec<ExploitHit>> {
    db.by_cve(&cve)
        .map_err(|e| AppError::Other(format!("exploitdb by_cve: {e}")))
}

/// Re-sync the per-user Exploit-DB index from upstream. Downloads
/// `files_exploits.csv` from gitlab, parses it, and replaces the rows
/// in the per-user SQLite in one transaction. Flips the `origin` meta
/// to `user-synced` so future app upgrades won't clobber it without
/// reason.
#[tauri::command]
pub async fn exploitdb_update(
    app: AppHandle,
    db: State<'_, Arc<ExploitDb>>,
) -> AppResult<ExploitDbSummary> {
    const CSV_URL: &str =
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv";
    const COMMITS_API: &str =
        "https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb/repository/commits?ref_name=main&per_page=1";

    let db_for_task = Arc::clone(&*db);
    let handle = app.clone();
    let _ = handle.emit("exploitdb://progress", progress("start", 0));

    let client = reqwest::Client::builder()
        .user_agent(format!("corvex-rust/{}", corvex_core::VERSION))
        .build()
        .map_err(|e| AppError::Other(format!("reqwest client: {e}")))?;

    // Short-circuit if the upstream CSV hasn't changed since we last
    // synced. The `source_etag` meta is set at the end of a successful
    // sync (below).
    let current_etag = db_for_task.get_meta(exploitdb::META_SOURCE_ETAG).ok().flatten();

    let mut head_req = client.get(CSV_URL);
    if let Some(ref etag) = current_etag {
        head_req = head_req.header("If-None-Match", etag.clone());
    }
    let _ = handle.emit("exploitdb://progress", progress("download", 10));
    let resp = head_req
        .send()
        .await
        .map_err(|e| AppError::Other(format!("GET csv: {e}")))?;

    if resp.status().as_u16() == 304 {
        let _ = handle.emit("exploitdb://progress", progress("up_to_date", 100));
        return db_for_task
            .summary()
            .map_err(|e| AppError::Other(format!("summary: {e}")));
    }
    if !resp.status().is_success() {
        return Err(AppError::Other(format!(
            "GET csv: {}",
            resp.status()
        )));
    }
    let new_etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| AppError::Other(format!("read csv body: {e}")))?;

    // Capture upstream HEAD commit for provenance. Best-effort — we
    // still complete the sync even if the API is rate-limited.
    let _ = handle.emit("exploitdb://progress", progress("commit_lookup", 40));
    let commit = match client.get(COMMITS_API).send().await {
        Ok(r) if r.status().is_success() => r
            .text()
            .await
            .ok()
            .and_then(|t| parse_first_commit_id(&t)),
        _ => None,
    };

    // Parse + replace on a blocking worker — CSV parsing + 50k upserts
    // would stall the async runtime thread otherwise.
    let _ = handle.emit("exploitdb://progress", progress("parse", 60));
    let bytes_owned = bytes.to_vec();
    let db_task = Arc::clone(&db_for_task);
    let commit_for_task = commit.clone();
    let etag_for_task = new_etag.clone();

    let stats = tauri::async_runtime::spawn_blocking(move || -> AppResult<u64> {
        use std::io::Write as _;
        // Write to a temp file so the CSV parser (which wants a path)
        // can mmap it; simpler than refactoring `parse_csv` to take an
        // arbitrary `Read`.
        let tmp = std::env::temp_dir().join(format!(
            "corvex-exploitdb-sync-{}.csv",
            std::process::id()
        ));
        {
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| AppError::Other(format!("tmp create: {e}")))?;
            f.write_all(&bytes_owned)
                .map_err(|e| AppError::Other(format!("tmp write: {e}")))?;
            f.sync_all().ok();
        }
        let rows = exploitdb::parse_csv(&tmp)
            .map_err(|e| AppError::Other(format!("csv parse: {e}")))?;
        let _ = std::fs::remove_file(&tmp);

        let row_count = rows.len() as u64;
        db_task
            .replace_all(&rows)
            .map_err(|e| AppError::Other(format!("replace_all: {e}")))?;
        db_task
            .set_meta(exploitdb::META_ORIGIN, exploitdb::ORIGIN_USER_SYNCED)
            .ok();
        db_task
            .set_meta(exploitdb::META_REFRESHED_AT, &utc_now_iso())
            .ok();
        db_task
            .set_meta(exploitdb::META_ROW_COUNT, &row_count.to_string())
            .ok();
        if let Some(c) = commit_for_task {
            db_task.set_meta(exploitdb::META_SOURCE_COMMIT, &c).ok();
        }
        if let Some(e) = etag_for_task {
            db_task.set_meta(exploitdb::META_SOURCE_ETAG, &e).ok();
        }
        Ok(row_count)
    })
    .await
    .map_err(|e| AppError::Other(format!("parse task: {e}")))??;

    let _ = handle.emit(
        "exploitdb://progress",
        ProgressPayload {
            stage: "done".into(),
            pct: 100,
            detail: Some(format!("{stats} rows")),
        },
    );

    db.summary()
        .map_err(|e| AppError::Other(format!("summary: {e}")))
}

/// Fetch the source of an exploit by EDB-ID. Checks the local cache
/// first; if missing, downloads from the gitlab raw URL and writes to
/// `<app_data_dir>/exploitdb/cache/<edb_id>.<ext>`. Subsequent calls
/// are offline.
#[tauri::command]
pub async fn exploitdb_fetch_source(
    edb_id: i64,
    app: AppHandle,
    db: State<'_, Arc<ExploitDb>>,
) -> AppResult<ExploitSource> {
    let (file_rel, _title) = db
        .get_file(edb_id)
        .map_err(|e| AppError::Other(format!("get_file: {e}")))?
        .ok_or_else(|| AppError::Other(format!("no such EDB-ID: {edb_id}")))?;

    let base = app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::Other(format!("app_data_dir: {e}")))?;
    let cache_dir = base.join("exploitdb").join("cache");
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| AppError::Other(format!("mkdir {}: {e}", cache_dir.display())))?;

    // Use the upstream file's extension so syntax highlighting works
    // naturally (e.g. `50406.py` → lang_hint = "python").
    let ext = std::path::Path::new(&file_rel)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("txt")
        .to_string();
    let cached = cache_dir.join(format!("{edb_id}.{ext}"));
    let source_url = format!(
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/{}",
        file_rel
    );

    let body = if cached.exists() {
        std::fs::read_to_string(&cached)
            .map_err(|e| AppError::Other(format!("read cache: {e}")))?
    } else {
        let client = reqwest::Client::builder()
            .user_agent(format!("corvex-rust/{}", corvex_core::VERSION))
            .build()
            .map_err(|e| AppError::Other(format!("reqwest client: {e}")))?;
        let resp = client
            .get(&source_url)
            .send()
            .await
            .map_err(|e| AppError::Other(format!("GET {source_url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(AppError::Other(format!(
                "GET {source_url}: {}",
                resp.status()
            )));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| AppError::Other(format!("body: {e}")))?;
        std::fs::write(&cached, &text)
            .map_err(|e| AppError::Other(format!("cache write: {e}")))?;
        text
    };

    Ok(ExploitSource {
        edb_id,
        body,
        lang_hint: lang_from_ext(&ext),
        cached_path: cached.display().to_string(),
        source_url,
    })
}

fn lang_from_ext(ext: &str) -> Option<String> {
    Some(
        match ext.to_ascii_lowercase().as_str() {
            "py" => "python",
            "rb" => "ruby",
            "pl" => "perl",
            "php" => "php",
            "c" | "h" => "c",
            "cpp" | "cc" | "hpp" => "cpp",
            "java" => "java",
            "js" => "javascript",
            "ts" => "typescript",
            "sh" | "bash" => "bash",
            "ps1" => "powershell",
            "html" | "htm" => "html",
            "asm" | "nasm" => "asm",
            "go" => "go",
            "rs" => "rust",
            "txt" => return None,
            _ => return None,
        }
        .to_string(),
    )
}

#[derive(Debug, Clone, Serialize)]
struct ProgressPayload {
    stage: String,
    pct: u32,
    detail: Option<String>,
}

fn progress(stage: &str, pct: u32) -> ProgressPayload {
    ProgressPayload {
        stage: stage.to_string(),
        pct,
        detail: None,
    }
}

/// Pull the first `"id":"<sha>"` out of GitLab's commits JSON without a
/// JSON dep — the API response is a tiny array, regex-free scan is
/// more than sufficient.
fn parse_first_commit_id(json: &str) -> Option<String> {
    let key = "\"id\":\"";
    let start = json.find(key)? + key.len();
    let tail = &json[start..];
    let end = tail.find('"')?;
    Some(tail[..end].to_string())
}

fn utc_now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Reuse the helper in exploitdb.rs so formats match exactly.
    let (y, mo, d, h, mi, s) = civil(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn civil(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400) as u32;
    let h = rem / 3600;
    let mi = (rem % 3600) / 60;
    let s = rem % 60;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i32 + (era as i32) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, mi, s)
}

/* ====================================================================== */
/* Unified rules catalog (rules.sqlite — Phase 1 + 2 work)                 */
/* ====================================================================== */

#[derive(Debug, Clone, Serialize)]
pub struct RulesSourceCounts {
    pub source_tool: String,
    pub ingested: u64,
    pub lowered: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RulesSeverityCount {
    pub source_tool: String,
    pub severity: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct RulesSummary {
    /// Absolute path the catalog was loaded from. Empty when no rules.sqlite
    /// was found (the desktop falls back to legacy-only behaviour silently).
    pub path: String,
    /// Whether a `rules.sqlite` was found and opened successfully.
    pub loaded: bool,
    /// Schema version stamped by `corvex-rules-builder`.
    pub schema_version: Option<String>,
    /// Builder run timestamp (ISO-8601 UTC).
    pub build_ts: Option<String>,
    /// Pinned upstream commit SHAs.
    pub nikto_commit: Option<String>,
    pub zap_commit: Option<String>,
    pub burp_commit: Option<String>,
    /// Per-source ingest + executable counts.
    pub by_source: Vec<RulesSourceCounts>,
    /// Per-(source, severity) count.
    pub by_severity: Vec<RulesSeverityCount>,
    /// Number of rules whose JSON columns failed `json_valid()` (must be 0
    /// in healthy catalogs).
    pub invalid_json_rows: u64,
    /// Total executable rules across all sources (those with non-NULL
    /// `match_spec_json`).
    pub total_executable: u64,
    /// Total ingested rules across all sources.
    pub total_ingested: u64,
}

#[tauri::command]
pub async fn rules_summary() -> AppResult<RulesSummary> {
    use rusqlite::{Connection, OpenFlags};

    let mut summary = RulesSummary::default();
    let path = match crate::rules_embed::resolve_rules_path() {
        Some(p) => p,
        None => return Ok(summary),
    };
    summary.path = path.display().to_string();

    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(&path, flags)
        .map_err(|e| AppError::Other(format!("open {}: {e}", path.display())))?;

    // Smoke-check the schema is what we expect.
    if let Err(e) = conn.prepare("SELECT 1 FROM rules LIMIT 1") {
        return Err(AppError::Other(format!(
            "rules.sqlite at {} missing `rules` table: {e}",
            path.display()
        )));
    }
    summary.loaded = true;

    // Per-source ingested + lowered counts.
    let mut stmt = conn
        .prepare(
            "SELECT source_tool,
                    COUNT(*) AS ingested,
                    SUM(CASE WHEN match_spec_json IS NOT NULL THEN 1 ELSE 0 END) AS lowered
               FROM rules
              WHERE enabled = 1
           GROUP BY source_tool
           ORDER BY source_tool",
        )
        .map_err(|e| AppError::Other(format!("prepare counts: {e}")))?;
    let rows = stmt
        .query_map([], |r| {
            Ok(RulesSourceCounts {
                source_tool: r.get(0)?,
                ingested: r.get::<_, i64>(1)? as u64,
                lowered: r.get::<_, i64>(2)? as u64,
            })
        })
        .map_err(|e| AppError::Other(format!("query counts: {e}")))?;
    for row in rows {
        let row = row.map_err(|e| AppError::Other(format!("row: {e}")))?;
        summary.total_ingested += row.ingested;
        summary.total_executable += row.lowered;
        summary.by_source.push(row);
    }

    // Per-(source, severity) breakdown.
    let mut stmt = conn
        .prepare(
            "SELECT source_tool, severity, COUNT(*)
               FROM rules
              WHERE enabled = 1
           GROUP BY source_tool, severity
           ORDER BY source_tool,
                    CASE severity
                      WHEN 'critical' THEN 0
                      WHEN 'high'     THEN 1
                      WHEN 'medium'   THEN 2
                      WHEN 'low'      THEN 3
                      WHEN 'info'     THEN 4
                      ELSE 5 END",
        )
        .map_err(|e| AppError::Other(format!("prepare severity: {e}")))?;
    let rows = stmt
        .query_map([], |r| {
            Ok(RulesSeverityCount {
                source_tool: r.get(0)?,
                severity: r.get(1)?,
                count: r.get::<_, i64>(2)? as u64,
            })
        })
        .map_err(|e| AppError::Other(format!("query severity: {e}")))?;
    for row in rows {
        summary
            .by_severity
            .push(row.map_err(|e| AppError::Other(format!("row: {e}")))?);
    }

    // JSON-validity sanity check.
    summary.invalid_json_rows = conn
        .query_row(
            "SELECT COUNT(*) FROM rules
              WHERE json_valid(refs_json) = 0
                 OR json_valid(payloads_json) = 0
                 OR json_valid(detection_json) = 0
                 OR json_valid(source_meta_json) = 0",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n as u64)
        .unwrap_or(0);

    // Build metadata.
    if let Ok(mut stmt) = conn.prepare("SELECT key, value FROM rules_meta") {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        }) {
            for row in rows.flatten() {
                match row.0.as_str() {
                    "schema_version" => summary.schema_version = Some(row.1),
                    "build_ts" => summary.build_ts = Some(row.1),
                    "nikto_commit" => summary.nikto_commit = Some(row.1),
                    "zap_commit" => summary.zap_commit = Some(row.1),
                    "burp_commit" => summary.burp_commit = Some(row.1),
                    _ => {}
                }
            }
        }
    }

    Ok(summary)
}
