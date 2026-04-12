//! Registry of in-flight scans. Each entry carries a CancellationToken
//! that the Tauri command surface flips to halt an active scan, plus a
//! reference to the `GlobalState` so the UI can poll live counters.

use std::collections::HashMap;
use std::sync::Arc;

use corvex_core::state::GlobalState;
use serde::Serialize;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct RunningScan {
    pub id: Uuid,
    pub cancel: CancellationToken,
    pub state: Arc<GlobalState>,
}

#[derive(Default)]
pub struct ScanRegistry {
    inner: Mutex<HashMap<Uuid, RunningScan>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanStats {
    pub id: String,
    pub total_requests: u64,
    pub total_findings: u64,
    pub total_errors: u64,
    pub hosts_completed: u64,
    pub elapsed_secs: u64,
    pub cancelled: bool,
}

impl ScanRegistry {
    pub async fn insert(&self, scan: RunningScan) {
        self.inner.lock().await.insert(scan.id, scan);
    }

    pub async fn cancel(&self, id: Uuid) -> bool {
        if let Some(scan) = self.inner.lock().await.get(&id) {
            scan.cancel.cancel();
            true
        } else {
            false
        }
    }

    pub async fn remove(&self, id: Uuid) {
        self.inner.lock().await.remove(&id);
    }

    pub async fn stats(&self, id: Uuid) -> Option<ScanStats> {
        let guard = self.inner.lock().await;
        let scan = guard.get(&id)?;
        use std::sync::atomic::Ordering;
        Some(ScanStats {
            id: id.to_string(),
            total_requests: scan.state.total_requests.load(Ordering::Relaxed),
            total_findings: scan.state.total_findings.load(Ordering::Relaxed),
            total_errors: scan.state.total_errors.load(Ordering::Relaxed),
            hosts_completed: scan.state.hosts_completed.load(Ordering::Relaxed),
            elapsed_secs: scan.state.elapsed_secs(),
            cancelled: scan.cancel.is_cancelled(),
        })
    }
}
