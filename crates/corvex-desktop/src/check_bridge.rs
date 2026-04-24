//! Glue between the proxy's exchange stream and the Checks engine.
//!
//! `corvex-proxy` stays free of any checks dependency — it just
//! broadcasts exchanges. This module owns the [`CheckRegistry`],
//! subscribes to the broadcast on session start, runs every passive
//! check per exchange, persists findings to SQLite, and fans them out
//! to the UI through a `proxy://scan-finding` Tauri event.

use std::sync::Arc;

use corvex_checks::{registry_with_bundles, CheckRegistry, Finding};
use corvex_core::vulndb::VulnDb;
use corvex_intel::fingerprint::{embedded_dataset, LoadedFingerprint};
use corvex_nuclei::{locate, store::TemplateStore};
use corvex_proxy::{Exchange, ProxyDb, ProxyState, StoredFinding};
use serde::Serialize;
use tauri::{AppHandle, Emitter};

pub struct CheckBridge {
    pub registry: Arc<CheckRegistry>,
}

impl CheckBridge {
    pub fn new() -> Self {
        // Nuclei templates (tier-1 bundled + tier-2 extras from the
        // Databases view) feed the per-template Checks library rows.
        let mut store = TemplateStore::new();
        for root in locate::default_roots() {
            let _ = store.load_dir(&root);
        }
        for root in locate::extras_roots() {
            let _ = store.load_dir(&root);
        }
        let store = Arc::new(store);
        tracing::info!(
            target: "checks",
            "loaded {} nuclei templates for passive matching",
            store.len()
        );

        // Vendored Wappalyzer dataset — populated by
        // `scripts/refresh-wappalyzer.sh`. Empty when the user hasn't
        // run it yet; the stack-fingerprint check falls back to the
        // compile-time seed in that case.
        let upstream = Arc::new(load_upstream_fingerprints());
        tracing::info!(
            target: "checks",
            "loaded {} upstream Wappalyzer fingerprints (seed covers the rest)",
            upstream.len()
        );

        // Shared vulndb handle — same file the CLI uses. When the DB
        // is missing we keep the rest of the pipeline running; the
        // Banner CVE cross-reference degrades to a no-op and logs
        // once at startup so the user knows why no CVE findings are
        // appearing.
        let vulndb = match VulnDb::open_default() {
            Ok(db) => {
                let count = db.cve_count().unwrap_or(0);
                tracing::info!(
                    target: "checks",
                    "vulndb ready for banner-cve cross-reference ({count} CVEs)"
                );
                Some(Arc::new(db))
            }
            Err(e) => {
                tracing::warn!(
                    target: "checks",
                    "vulndb unavailable ({e}) — banner-cve check disabled; \
                     run `vulndb update` from the Databases view to enable it"
                );
                None
            }
        };

        Self {
            registry: Arc::new(registry_with_bundles(store, upstream, vulndb)),
        }
    }

    /// Spawn the subscription task. Call once at app setup.
    pub fn attach(&self, state: Arc<ProxyState>, app: AppHandle) {
        let registry = self.registry.clone();
        let db = state.db().clone();
        let mut rx = state.subscribe_exchanges();
        tauri::async_runtime::spawn(async move {
            loop {
                let exchange = match rx.recv().await {
                    Ok(ex) => ex,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                };
                // Out-of-scope traffic is logged but checks skip it —
                // saves a round of regex work per noisy background
                // request.
                use corvex_proxy::ScopeDecision;
                if exchange.scope != ScopeDecision::InScope {
                    continue;
                }
                let findings = registry.run_passive(&exchange);
                if findings.is_empty() {
                    continue;
                }
                for finding in findings {
                    if let Err(e) = persist_finding(&db, &exchange, &finding) {
                        tracing::warn!(target: "checks", "persist finding: {e}");
                        continue;
                    }
                    let payload = FindingPayload::from(&exchange, &finding);
                    let _ = app.emit("proxy://scan-finding", payload);
                }
            }
        });
    }
}

impl Default for CheckBridge {
    fn default() -> Self {
        Self::new()
    }
}

/// Payload shipped to the frontend. Separate from the internal
/// `Finding` so we can trim / adapt without breaking the engine.
#[derive(Debug, Clone, Serialize)]
pub struct FindingPayload {
    pub id: String,
    pub exchange_id: String,
    pub check_id: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub evidence: serde_json::Value,
    pub host: String,
    pub path: String,
}

impl FindingPayload {
    pub fn from(exchange: &Exchange, finding: &Finding) -> Self {
        Self {
            id: finding.id.to_string(),
            exchange_id: finding.exchange_id.to_string(),
            check_id: finding.check_id.clone(),
            severity: finding.severity.as_str().to_string(),
            title: finding.title.clone(),
            description: finding.description.clone(),
            evidence: finding.evidence.clone(),
            host: exchange.request.host.clone(),
            path: exchange
                .request
                .uri
                .split_once('?')
                .map(|(p, _)| p.to_string())
                .unwrap_or_else(|| exchange.request.uri.clone()),
        }
    }
}

fn load_upstream_fingerprints() -> Vec<LoadedFingerprint> {
    // The vendored dataset is compile-time embedded via `build.rs` +
    // `include_str!`, so the binary ships with the data regardless of
    // working directory. An empty slice comes back only if the refresh
    // script hasn't been run at build time.
    embedded_dataset().to_vec()
}

fn persist_finding(
    db: &Arc<ProxyDb>,
    _exchange: &Exchange,
    finding: &Finding,
) -> anyhow::Result<()> {
    let stored = StoredFinding {
        id: finding.id.to_string(),
        scan_run_id: None,
        exchange_id: finding.exchange_id.to_string(),
        check_id: finding.check_id.clone(),
        severity: finding.severity.as_str().to_string(),
        title: finding.title.clone(),
        description: finding.description.clone(),
        evidence: Some(serde_json::to_vec(&finding.evidence)?),
        created_at: finding.created_at.unix_timestamp(),
    };
    db.insert_finding(&stored)?;
    Ok(())
}
