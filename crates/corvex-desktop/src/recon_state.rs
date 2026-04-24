//! In-flight recon-run registry. Mirrors [`crate::probe_state`] — one
//! cancellation token per running job so the UI can halt a long
//! brute-force without restarting the app.

use std::collections::HashMap;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct RunningRecon {
    pub id: Uuid,
    pub cancel: CancellationToken,
}

#[derive(Default)]
pub struct ReconRegistry {
    inner: Mutex<HashMap<Uuid, RunningRecon>>,
}

impl ReconRegistry {
    pub async fn insert(&self, recon: RunningRecon) {
        self.inner.lock().await.insert(recon.id, recon);
    }

    pub async fn cancel(&self, id: Uuid) -> bool {
        if let Some(r) = self.inner.lock().await.get(&id) {
            r.cancel.cancel();
            true
        } else {
            false
        }
    }

    pub async fn remove(&self, id: Uuid) {
        self.inner.lock().await.remove(&id);
    }
}
