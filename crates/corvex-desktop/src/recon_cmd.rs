//! Tauri command surface for the Recon view.
//!
//! Mirrors the probe-job pattern: `recon_start` spawns a background
//! task that drives [`corvex_proxy`]-adjacent — actually
//! [`corvex_core::recon::run_recon`] — and bridges events onto the
//! UI's `recon://event` stream. Persistence goes through [`ReconDb`].

use std::sync::Arc;

use corvex_core::recon::{run_recon, ReconEvent, ReconParams};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::recon_state::{ReconRegistry, RunningRecon};
use crate::recon_store::{
    PendingFinding, ReconDb, ReconFindingKind, ReconFindingRow, ReconRunSummary,
};

/// Shape the UI supplies at `recon_start`. Matches
/// [`ReconParams`] but substitutes a file path the desktop layer
/// resolves before handing bytes to core.
#[derive(Debug, Clone, Deserialize)]
pub struct ReconStartInput {
    pub domain: String,
    pub passive_sources: Vec<String>,
    pub active: bool,
    pub wordlist_path: Option<String>,
    #[serde(default = "default_concurrency")]
    pub max_concurrent: usize,
}

fn default_concurrency() -> usize {
    500
}

/// Event payload bridged to the UI. Adds the `run_id` so a single
/// listener can demux concurrent runs (we only ever run one today,
/// but the UI listener is simpler this way).
#[derive(Debug, Clone, Serialize)]
struct ReconEventPayload {
    run_id: String,
    #[serde(flatten)]
    event: ReconEvent,
}

#[tauri::command]
pub async fn recon_start(
    app: AppHandle,
    registry: State<'_, Arc<ReconRegistry>>,
    db: State<'_, Arc<ReconDb>>,
    input: ReconStartInput,
) -> AppResult<String> {
    if input.domain.trim().is_empty() {
        return Err(AppError::Other("domain is required".into()));
    }

    // If the user pointed at a wordlist file, read it on the blocking
    // pool. Missing or unreadable files fall back to the embedded
    // default rather than aborting the run.
    let wordlist = match input.wordlist_path.as_deref() {
        Some(path) => {
            let path = path.to_string();
            match tauri::async_runtime::spawn_blocking(move || std::fs::read_to_string(path))
                .await
            {
                Ok(Ok(body)) => Some(body),
                Ok(Err(e)) => {
                    tracing::warn!(
                        target: "recon",
                        "wordlist read failed, using default: {e}"
                    );
                    None
                }
                Err(e) => {
                    tracing::warn!(target: "recon", "wordlist join: {e}");
                    None
                }
            }
        }
        None => None,
    };

    let params = ReconParams {
        domain: input.domain.trim().to_string(),
        passive_sources: input.passive_sources.clone(),
        active: input.active,
        wordlist,
        max_concurrent: input.max_concurrent.max(1),
    };

    let run_id = Uuid::new_v4();
    let cancel = CancellationToken::new();
    registry
        .insert(RunningRecon {
            id: run_id,
            cancel: cancel.clone(),
        })
        .await;

    {
        let db = db.inner().clone();
        let passive_sources = input.passive_sources.clone();
        let domain = params.domain.clone();
        let active = input.active;
        tauri::async_runtime::spawn_blocking(move || {
            db.insert_run(&run_id, &domain, &passive_sources, active)
        })
        .await
        .map_err(|e| AppError::Other(format!("join: {e}")))?
        .map_err(|e| AppError::Other(format!("insert run: {e}")))?;
    }

    // Spawn the driver — events come out on a tokio mpsc; we drain
    // into the Tauri event bus + SQLite here.
    let app_for_task = app.clone();
    let registry_for_task = registry.inner().clone();
    let db_for_task = db.inner().clone();
    let cancel_for_task = cancel.clone();
    let params_for_task = params.clone();

    tauri::async_runtime::spawn(async move {
        let (tx, mut rx) = mpsc::channel::<ReconEvent>(256);
        // Run the core engine on its own task so the event loop below
        // can keep draining even if the engine is busy.
        let engine_cancel = cancel_for_task.clone();
        let engine_handle = tokio::spawn(async move {
            run_recon(params_for_task, tx, engine_cancel).await;
        });

        // Spawn a dedicated writer task that receives pending findings
        // and flushes them to SQLite in batches. This decouples the
        // per-event UI emit path from DB commits — the event loop no
        // longer awaits a spawn_blocking per finding. Flush triggers:
        // 32 accumulated rows or 150 ms elapsed, whichever first. The
        // per-event UI emit still fires immediately so live counters
        // update without waiting for a batch.
        const FLUSH_SIZE: usize = 32;
        const FLUSH_INTERVAL: std::time::Duration =
            std::time::Duration::from_millis(150);
        let (writer_tx, mut writer_rx) = mpsc::unbounded_channel::<PendingFinding>();
        let writer_db = db_for_task.clone();
        let writer_handle = tokio::spawn(async move {
            let mut buf: Vec<PendingFinding> = Vec::with_capacity(FLUSH_SIZE);
            let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
            ticker.set_missed_tick_behavior(
                tokio::time::MissedTickBehavior::Delay,
            );
            // The first tick fires immediately; skip it so we don't
            // flush an empty batch before anything arrives.
            ticker.tick().await;
            let flush = |buf: &mut Vec<PendingFinding>, db: &Arc<ReconDb>| {
                if buf.is_empty() {
                    return;
                }
                let rows = std::mem::take(buf);
                let db = db.clone();
                // Fire-and-forget — we don't block the writer task on
                // disk I/O any longer than necessary, and errors are
                // logged (not propagated) so one bad batch doesn't
                // abort the run.
                tauri::async_runtime::spawn_blocking(move || {
                    if let Err(e) = db.insert_findings_batch(&run_id, &rows) {
                        tracing::warn!(target: "recon", "batch insert: {e}");
                    }
                });
            };
            loop {
                tokio::select! {
                    maybe = writer_rx.recv() => {
                        match maybe {
                            Some(row) => {
                                buf.push(row);
                                if buf.len() >= FLUSH_SIZE {
                                    flush(&mut buf, &writer_db);
                                }
                            }
                            None => {
                                // Channel closed — flush remainder and exit.
                                flush(&mut buf, &writer_db);
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        flush(&mut buf, &writer_db);
                    }
                }
            }
        });

        let mut found_subdomains: u64 = 0;
        let mut found_records: u64 = 0;
        let mut final_status = "complete".to_string();
        let mut final_error: Option<String> = None;

        while let Some(event) = rx.recv().await {
            // Persist salient events so History can rehydrate a run.
            match &event {
                ReconEvent::SubdomainDiscovered { host, sources, ips } => {
                    found_subdomains += 1;
                    let value = if ips.is_empty() {
                        None
                    } else {
                        Some(ips.join(","))
                    };
                    let _ = writer_tx.send(PendingFinding {
                        kind: ReconFindingKind::Subdomain,
                        name: host.clone(),
                        value,
                        record_type: None,
                        sources: sources.clone(),
                    });
                }
                ReconEvent::RecordDiscovered {
                    name,
                    record_type,
                    value,
                } => {
                    found_records += 1;
                    let _ = writer_tx.send(PendingFinding {
                        kind: ReconFindingKind::Record,
                        name: name.clone(),
                        value: Some(value.clone()),
                        record_type: Some(record_type.clone()),
                        sources: Vec::new(),
                    });
                }
                ReconEvent::WildcardDetected { ips } => {
                    // One-shot per run — stays on the awaited path so
                    // the wildcard row is durable before the run finishes.
                    let db = db_for_task.clone();
                    let ips = ips.clone();
                    let _ = tauri::async_runtime::spawn_blocking(move || {
                        db.record_wildcard(&run_id, &ips)
                    })
                    .await;
                }
                ReconEvent::ZoneTransfer { .. } => {
                    let _ = writer_tx.send(PendingFinding {
                        kind: ReconFindingKind::ZoneTransfer,
                        name: "AXFR".to_string(),
                        value: None,
                        record_type: None,
                        sources: Vec::new(),
                    });
                }
                ReconEvent::Cancelled => {
                    final_status = "cancelled".to_string();
                }
                ReconEvent::Failed { error } => {
                    final_status = "failed".to_string();
                    final_error = Some(error.clone());
                }
                _ => {}
            }

            // Bridge to the UI. Fires immediately per event so live
            // counters don't wait for a batch flush.
            let payload = ReconEventPayload {
                run_id: run_id.to_string(),
                event,
            };
            let _ = app_for_task.emit("recon://event", payload);
        }

        let _ = engine_handle.await;

        // Close the writer channel so the writer task flushes its
        // remaining buffer and exits, then wait for it so the
        // finish_run() update reads fully-committed counts.
        drop(writer_tx);
        let _ = writer_handle.await;

        let db = db_for_task.clone();
        let err_str = final_error.clone();
        let status = final_status.clone();
        let _ = tauri::async_runtime::spawn_blocking(move || {
            db.finish_run(
                &run_id,
                &status,
                found_subdomains,
                found_records,
                err_str.as_deref(),
            )
        })
        .await;

        registry_for_task.remove(run_id).await;
    });

    Ok(run_id.to_string())
}

#[tauri::command]
pub async fn recon_cancel(
    registry: State<'_, Arc<ReconRegistry>>,
    id: String,
) -> AppResult<bool> {
    let uuid = Uuid::parse_str(&id)
        .map_err(|e| AppError::Other(format!("bad id: {e}")))?;
    Ok(registry.cancel(uuid).await)
}

#[tauri::command]
pub async fn recon_runs_list(
    db: State<'_, Arc<ReconDb>>,
    limit: Option<usize>,
) -> AppResult<Vec<ReconRunSummary>> {
    let limit = limit.unwrap_or(50).clamp(1, 500);
    let db = db.inner().clone();
    tauri::async_runtime::spawn_blocking(move || db.list_runs(limit))
        .await
        .map_err(|e| AppError::Other(format!("join: {e}")))?
        .map_err(|e| AppError::Other(format!("list runs: {e}")))
}

#[tauri::command]
pub async fn recon_run_get(
    db: State<'_, Arc<ReconDb>>,
    id: String,
) -> AppResult<Option<ReconRunSummary>> {
    let uuid = Uuid::parse_str(&id)
        .map_err(|e| AppError::Other(format!("bad id: {e}")))?;
    let db = db.inner().clone();
    tauri::async_runtime::spawn_blocking(move || db.get_run(&uuid))
        .await
        .map_err(|e| AppError::Other(format!("join: {e}")))?
        .map_err(|e| AppError::Other(format!("get run: {e}")))
}

#[tauri::command]
pub async fn recon_findings_for_run(
    db: State<'_, Arc<ReconDb>>,
    id: String,
) -> AppResult<Vec<ReconFindingRow>> {
    let uuid = Uuid::parse_str(&id)
        .map_err(|e| AppError::Other(format!("bad id: {e}")))?;
    let db = db.inner().clone();
    tauri::async_runtime::spawn_blocking(move || db.findings_for_run(&uuid))
        .await
        .map_err(|e| AppError::Other(format!("join: {e}")))?
        .map_err(|e| AppError::Other(format!("findings: {e}")))
}

#[tauri::command]
pub async fn recon_run_delete(
    db: State<'_, Arc<ReconDb>>,
    id: String,
) -> AppResult<usize> {
    let uuid = Uuid::parse_str(&id)
        .map_err(|e| AppError::Other(format!("bad id: {e}")))?;
    let db = db.inner().clone();
    tauri::async_runtime::spawn_blocking(move || db.delete_run(&uuid))
        .await
        .map_err(|e| AppError::Other(format!("join: {e}")))?
        .map_err(|e| AppError::Other(format!("delete run: {e}")))
}
