//! Registry of in-flight standalone probing runs.
//!
//! A probing run is a lightweight port-scan + service-identification
//! cycle that does NOT spin up the full web-scan pipeline. Each entry
//! carries its own cancellation token so the UI can halt a run that's
//! still iterating targets.

use std::collections::HashMap;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct RunningProbe {
    pub id: Uuid,
    pub cancel: CancellationToken,
}

#[derive(Default)]
pub struct ProbeRegistry {
    inner: Mutex<HashMap<Uuid, RunningProbe>>,
}

impl ProbeRegistry {
    pub async fn insert(&self, probe: RunningProbe) {
        self.inner.lock().await.insert(probe.id, probe);
    }

    pub async fn cancel(&self, id: Uuid) -> bool {
        if let Some(p) = self.inner.lock().await.get(&id) {
            p.cancel.cancel();
            true
        } else {
            false
        }
    }

    pub async fn remove(&self, id: Uuid) {
        self.inner.lock().await.remove(&id);
    }
}
