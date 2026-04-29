//! Tracks the state of the heavy first-launch initialization so the
//! frontend can show a "Configuring Corvex" splash instead of a frozen
//! window.
//!
//! `setup()` returns almost immediately after registering this state +
//! a few cheap registries. The actual DB opens / file extractions /
//! CA generation run on a spawned task that flips steps from
//! `Pending` → `Running` → `Ok` (or `Failed`) one at a time and emits
//! `app://init-step` events. When the last step finishes the task
//! emits `app://init-ready`.
//!
//! Each step is identified by a stable string id (`history`,
//! `exploitdb`, …) so the splash can render meaningful labels without
//! the backend hard-coding UI strings.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

pub const STEP_RECON: &str = "recon";
pub const STEP_EXPLOITDB: &str = "exploitdb";
pub const STEP_HISTORY: &str = "history";
pub const STEP_PROBE: &str = "probe";
pub const STEP_ASSET: &str = "asset";
pub const STEP_PROXY: &str = "proxy";

pub const EVENT_STEP: &str = "app://init-step";
pub const EVENT_READY: &str = "app://init-ready";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum StepStatus {
    Pending,
    Running,
    Ok,
    Failed { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitStep {
    pub id: String,
    pub label: String,
    pub status: StepStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitProgress {
    pub steps: Vec<InitStep>,
    pub ready: bool,
}

impl InitProgress {
    pub fn new() -> Self {
        let steps = vec![
            step(STEP_RECON, "Recon database"),
            step(STEP_EXPLOITDB, "Exploit-DB index"),
            step(STEP_HISTORY, "Scan history"),
            step(STEP_PROBE, "Service probe store"),
            step(STEP_ASSET, "Asset database"),
            step(STEP_PROXY, "Proxy state & CA"),
        ];
        Self {
            steps,
            ready: false,
        }
    }

    fn set(&mut self, id: &str, status: StepStatus) {
        if let Some(s) = self.steps.iter_mut().find(|s| s.id == id) {
            s.status = status;
        }
    }
}

fn step(id: &str, label: &str) -> InitStep {
    InitStep {
        id: id.to_string(),
        label: label.to_string(),
        status: StepStatus::Pending,
    }
}

pub type InitProgressHandle = Arc<Mutex<InitProgress>>;

/// Flip a step to `Running` and broadcast the change.
pub fn start(app: &AppHandle, handle: &InitProgressHandle, id: &str) {
    let updated = {
        let mut g = handle.lock().expect("init progress mutex");
        g.set(id, StepStatus::Running);
        g.steps.iter().find(|s| s.id == id).cloned()
    };
    if let Some(step) = updated {
        let _ = app.emit(EVENT_STEP, &step);
    }
}

/// Flip a step to `Ok` and broadcast the change.
pub fn finish_ok(app: &AppHandle, handle: &InitProgressHandle, id: &str) {
    let updated = {
        let mut g = handle.lock().expect("init progress mutex");
        g.set(id, StepStatus::Ok);
        g.steps.iter().find(|s| s.id == id).cloned()
    };
    if let Some(step) = updated {
        let _ = app.emit(EVENT_STEP, &step);
    }
}

/// Flip a step to `Failed { message }` and broadcast the change. Init
/// continues — most subsystems are non-fatal — but the splash can show
/// a warning marker on the failed step.
pub fn finish_err(
    app: &AppHandle,
    handle: &InitProgressHandle,
    id: &str,
    message: impl Into<String>,
) {
    let updated = {
        let mut g = handle.lock().expect("init progress mutex");
        g.set(
            id,
            StepStatus::Failed {
                message: message.into(),
            },
        );
        g.steps.iter().find(|s| s.id == id).cloned()
    };
    if let Some(step) = updated {
        let _ = app.emit(EVENT_STEP, &step);
    }
}

/// Mark the whole pipeline as ready and broadcast `app://init-ready`.
/// The frontend uses this as the signal to hide the splash and render
/// the main UI.
pub fn mark_ready(app: &AppHandle, handle: &InitProgressHandle) {
    let snapshot = {
        let mut g = handle.lock().expect("init progress mutex");
        g.ready = true;
        g.clone()
    };
    let _ = app.emit(EVENT_READY, &snapshot);
}
