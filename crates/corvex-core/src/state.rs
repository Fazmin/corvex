//! Global runtime counters & state (= Perl %COUNTERS + %VARIABLES).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Default)]
pub struct GlobalState {
    pub scan_start: AtomicU64,
    pub scan_end: AtomicU64,
    pub total_targets: AtomicU64,
    pub hosts_completed: AtomicU64,
    pub total_requests: AtomicU64,
    pub total_errors: AtomicU64,
    pub total_findings: AtomicU64,
    pub urls_crawled: AtomicU64,
    pub ports_scanned: AtomicU64,
    pub open_ports_found: AtomicU64,
    /// Human-readable one-line status set by long-running plugins
    /// (currently SCA) so the UI can show what's happening during
    /// the inevitable "scanning node_modules / looking up CVEs"
    /// wait. Read by `scan_stats` which is polled every ~750ms.
    pub stage: Mutex<Option<String>>,
}

impl GlobalState {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let s = Self::default();
        s.scan_start.store(now, Ordering::Relaxed);
        s
    }

    pub fn incr_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn incr_error(&self) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn incr_finding(&self) {
        self.total_findings.fetch_add(1, Ordering::Relaxed);
    }

    pub fn incr_urls_crawled(&self) {
        self.urls_crawled.fetch_add(1, Ordering::Relaxed);
    }

    pub fn finalize(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.scan_end.store(now, Ordering::Relaxed);
    }

    pub fn elapsed_secs(&self) -> u64 {
        self.scan_end
            .load(Ordering::Relaxed)
            .saturating_sub(self.scan_start.load(Ordering::Relaxed))
    }

    /// Publish a human-readable status line. Overwrites any previous
    /// stage. Safe to call from plugin code on any thread.
    pub fn set_stage(&self, s: impl Into<String>) {
        if let Ok(mut guard) = self.stage.lock() {
            *guard = Some(s.into());
        }
    }

    pub fn clear_stage(&self) {
        if let Ok(mut guard) = self.stage.lock() {
            *guard = None;
        }
    }

    pub fn get_stage(&self) -> Option<String> {
        self.stage.lock().ok().and_then(|g| g.clone())
    }
}
