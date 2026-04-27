//! Glue between the proxy's exchange stream and the Checks engine.
//!
//! `corvex-proxy` stays free of any checks dependency — it just
//! broadcasts exchanges. This module owns the [`CheckRegistry`],
//! subscribes to the broadcast on session start, runs every passive
//! check per exchange, persists findings to SQLite, and fans them out
//! to the UI through a `proxy://scan-finding` Tauri event.

use std::collections::HashSet;
use std::sync::Arc;

use corvex_checks::{
    finding::Severity, registry_with_bundles, CheckRegistry, Finding,
};
use corvex_core::vulndb::VulnDb;
use corvex_intel::fingerprint::{embedded_dataset, LoadedFingerprint};
use corvex_nuclei::{locate, store::TemplateStore};
use corvex_proxy::{
    ClusterAnomaly, EndpointCluster, Exchange, ProxyDb, ProxyState, StoredFinding,
};
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

    /// Spawn the cluster-anomaly subscription. Tapped off the same
    /// broadcast channel as the per-exchange passive checks, but it
    /// uses each exchange as a *tick* — the actual analysis reads the
    /// `ProxyState` cluster snapshot and diffs against an in-memory
    /// "already emitted" set. The first time a cluster's anomaly flag
    /// flips on (e.g. `AuthMismatch` because anonymous + authed
    /// requests now coexist on the same `/api/users/:id` shape) a
    /// finding is persisted against a representative member exchange
    /// so it surfaces alongside its peers in the Findings panel.
    pub fn attach_cluster_anomalies(&self, state: Arc<ProxyState>, app: AppHandle) {
        let db = state.db().clone();
        let mut rx = state.subscribe_exchanges();
        tauri::async_runtime::spawn(async move {
            // Key: (method, host, port, pattern, anomaly_kind).
            // Sticky for the lifetime of the session — a cluster may
            // accumulate more anomalies later, but we won't re-emit
            // ones the user has already been told about.
            let mut emitted: HashSet<(String, String, u16, String, &'static str)> =
                HashSet::new();
            loop {
                // Drain the broadcast: every received exchange is just
                // a wakeup. The actual cluster snapshot is read from
                // ProxyState, which is already populated by the
                // session's drain task.
                match rx.recv().await {
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
                let session = match state.session_id() {
                    Some(s) => s,
                    None => {
                        // Session bounced — let stale entries from a
                        // previous run drop so the next session starts
                        // clean. The cluster index is also cleared on
                        // start/stop, so a stale find would never
                        // resolve to a real cluster anyway.
                        emitted.clear();
                        continue;
                    }
                };
                let clusters = state.cluster_snapshot(&session).await;
                for cluster in clusters {
                    for flag in &cluster.anomaly_flags {
                        let kind = anomaly_kind_str(*flag);
                        let key = (
                            cluster.method.clone(),
                            cluster.host.clone(),
                            cluster.port,
                            cluster.pattern.clone(),
                            kind,
                        );
                        if !emitted.insert(key) {
                            continue;
                        }
                        let parent = match cluster.sample_exchange_ids.first() {
                            Some(id) => *id,
                            None => continue,
                        };
                        let (severity, title, description) =
                            describe_cluster_anomaly(*flag, &cluster);
                        let mut finding = Finding::new(
                            format!("auth-consistency:{kind}"),
                            parent,
                            severity,
                            title,
                        );
                        finding.description = Some(description);
                        finding.evidence = serde_json::json!({
                            "method": cluster.method,
                            "host": cluster.host,
                            "port": cluster.port,
                            "pattern": cluster.pattern,
                            "instance_count": cluster.instance_count,
                            "status_breakdown": cluster.status_breakdown,
                            "anomaly": kind,
                            "sample_exchange_ids": cluster
                                .sample_exchange_ids
                                .iter()
                                .map(|id| id.to_string())
                                .collect::<Vec<_>>(),
                        });
                        if let Err(e) = persist_cluster_finding(&db, &finding) {
                            tracing::warn!(
                                target: "checks",
                                "persist cluster finding: {e}"
                            );
                            continue;
                        }
                        let payload = FindingPayload::from_cluster(&cluster, &finding);
                        let _ = app.emit("proxy://scan-finding", payload);
                    }
                }
            }
        });
    }
}

fn anomaly_kind_str(flag: ClusterAnomaly) -> &'static str {
    match flag {
        ClusterAnomaly::AuthMismatch => "auth-mismatch",
        ClusterAnomaly::StatusOutlier => "status-outlier",
        ClusterAnomaly::SizeOutlier => "size-outlier",
        ClusterAnomaly::RateLimited => "rate-limited",
    }
}

fn describe_cluster_anomaly(
    flag: ClusterAnomaly,
    cluster: &EndpointCluster,
) -> (Severity, String, String) {
    match flag {
        ClusterAnomaly::AuthMismatch => (
            Severity::Medium,
            format!(
                "Auth mismatch across {} instances of {}",
                cluster.instance_count, cluster.pattern,
            ),
            format!(
                "Some requests to this endpoint shape carry an Authorization \
                 header while others do not. Mixing logged-in and anonymous \
                 traffic on the same REST pattern is the canonical IDOR / \
                 broken-access-control signal — confirm that anonymous \
                 instances should actually be permitted, and that authed \
                 ones are not leaking into a public path. Status mix: {}.",
                format_status_breakdown(&cluster.status_breakdown),
            ),
        ),
        ClusterAnomaly::StatusOutlier => (
            Severity::Low,
            format!("Status outlier on {}", cluster.pattern),
            format!(
                "≥80% of {} instances of this endpoint share one status \
                 class but at least one sits outside it. The outlier may \
                 reveal an authorization bypass or a hidden error path. \
                 Status mix: {}.",
                cluster.instance_count,
                format_status_breakdown(&cluster.status_breakdown),
            ),
        ),
        ClusterAnomaly::SizeOutlier => (
            Severity::Info,
            format!("Response-size outlier on {}", cluster.pattern),
            format!(
                "At least one 2xx response on this endpoint shape sits \
                 more than 3σ from the cluster mean ({} ± {} bytes). The \
                 body shape of one instance differs meaningfully from \
                 the rest — worth a closer read.",
                cluster.size_mean, cluster.size_stddev,
            ),
        ),
        ClusterAnomaly::RateLimited => (
            Severity::Info,
            format!("Rate limit observed on {}", cluster.pattern),
            "At least one member returned 429. Consider throttling scans \
             or fuzz runs against this pattern, and check whether the \
             rate-limit threshold is intentional."
                .to_string(),
        ),
    }
}

fn format_status_breakdown(breakdown: &[(u16, u32)]) -> String {
    let mut parts: Vec<String> =
        breakdown.iter().map(|(s, c)| format!("{s}×{c}")).collect();
    if parts.is_empty() {
        parts.push("(none)".to_string());
    }
    parts.join(", ")
}

fn persist_cluster_finding(
    db: &Arc<ProxyDb>,
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

    /// Build a payload from a clustered anomaly finding. The cluster
    /// already knows the host + pattern, so we don't need to fetch a
    /// representative exchange just to fill these fields. The
    /// `exchange_id` on the finding still points at a real cluster
    /// member so deep-linking from the Findings panel works.
    pub fn from_cluster(cluster: &EndpointCluster, finding: &Finding) -> Self {
        Self {
            id: finding.id.to_string(),
            exchange_id: finding.exchange_id.to_string(),
            check_id: finding.check_id.clone(),
            severity: finding.severity.as_str().to_string(),
            title: finding.title.clone(),
            description: finding.description.clone(),
            evidence: finding.evidence.clone(),
            host: cluster.host.clone(),
            path: cluster.pattern.clone(),
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
