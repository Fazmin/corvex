//! Tauri command surface for the asset (target-centered) ecosystem
//! view.
//!
//! Every command takes a host name and stitches data from the four
//! per-feature stores (probe, proxy, recon, history) into one of the
//! panels rendered by [`AssetDetailView`]. Reads only — the asset view
//! never mutates state, so each command is a thin orchestration layer
//! over `AssetDb` + `ProbeStore` + `ReconDb` + `HistoryDb`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::asset_db::{
    AssetDb, AssetEndpointRow, AssetFindingRow, AssetSummaryRow,
};
use crate::asset_identity::{
    cidr_24, extract_host_from_scan_target, normalize_host, registrable_suffix,
};
use crate::error::AppResult;
use crate::history::HistoryDb;
use crate::probe_store::{DeviceMatchRow, HostMacRow, ProbeServiceRow, ProbeStore};
use crate::recon_store::ReconDb;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetOverview {
    pub host: String,
    pub ips: Vec<String>,
    pub dns_records: Vec<DnsRecord>,
    pub probe_port_count: u32,
    pub exchange_count: u32,
    pub finding_count: u32,
    pub recon_hit_count: u32,
    pub first_seen_unix: Option<i64>,
    pub last_seen_unix: Option<i64>,
    pub asn_placeholder: Option<String>,
    pub cidr_24s: Vec<String>,
    pub scanned_count: u32,
    /// Latest SNMP device-fingerprint match for this host, if any.
    /// `None` when SNMP has not produced a hit on this host.
    pub device: Option<AssetDeviceMatch>,
    /// Latest MAC-resolution observation for this host. Populated only
    /// when MAC capture was enabled at probe time and the host was L2
    /// adjacent (or otherwise present in the OS ARP cache).
    pub mac: Option<AssetHostMac>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetHostMac {
    pub mac: String,
    pub mac_vendor: Option<String>,
    pub observed_at_unix: i64,
}

impl From<HostMacRow> for AssetHostMac {
    fn from(r: HostMacRow) -> Self {
        Self {
            mac: r.mac,
            mac_vendor: r.mac_vendor,
            observed_at_unix: r.observed_at_unix,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetDeviceMatch {
    pub os: String,
    pub vendor: String,
    pub device_type: String,
    pub source: String,
    pub sys_descr: Option<String>,
    pub sys_object_id: Option<String>,
    pub observed_at_unix: i64,
}

impl From<DeviceMatchRow> for AssetDeviceMatch {
    fn from(r: DeviceMatchRow) -> Self {
        Self {
            os: r.os,
            vendor: r.vendor,
            device_type: r.device_type,
            source: r.source,
            sys_descr: r.sys_descr,
            sys_object_id: r.sys_object_id,
            observed_at_unix: r.observed_at_unix,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub kind: String,
    pub value: String,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetTechRow {
    pub name: String,
    pub version: Option<String>,
    pub categories: Vec<String>,
    pub observed_on_paths: Vec<String>,
    pub last_seen_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRelated {
    pub same_jarm: Vec<RelatedHost>,
    pub same_root_domain: Vec<String>,
    pub same_cidr_24: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedHost {
    pub host: String,
    pub jarm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetFindingDeduped {
    pub check_id: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub host: String,
    pub port: u16,
    pub example_path: String,
    pub example_exchange_id: String,
    pub occurrence_count: u32,
    pub last_seen_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetTimelineEvent {
    pub kind: String, // "probe" | "exchange" | "finding" | "recon" | "scan"
    pub ts_unix: i64,
    pub summary: String,
    pub deep_link: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSummary {
    pub host: String,
    pub finding_count: u32,
    pub exchange_count: u32,
    pub probe_port_count: u32,
    pub recon_hit_count: u32,
    pub scan_count: u32,
    pub last_seen_unix: i64,
}

impl From<AssetSummaryRow> for AssetSummary {
    fn from(r: AssetSummaryRow) -> Self {
        Self {
            host: r.host,
            finding_count: r.finding_count,
            exchange_count: r.exchange_count,
            probe_port_count: r.probe_port_count,
            recon_hit_count: r.recon_hit_count,
            scan_count: r.scan_count,
            last_seen_unix: r.last_seen_unix,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEndpoint {
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub method: String,
    pub path: String,
    pub last_status: Option<u16>,
    pub exchange_count: u32,
    pub finding_count: u32,
    pub last_seen_unix: i64,
    pub last_exchange_id: String,
}

impl From<AssetEndpointRow> for AssetEndpoint {
    fn from(r: AssetEndpointRow) -> Self {
        Self {
            host: r.host,
            port: r.port,
            scheme: r.scheme,
            method: r.method,
            path: r.path,
            last_status: r.last_status,
            exchange_count: r.exchange_count,
            finding_count: r.finding_count,
            last_seen_unix: r.last_seen_unix,
            last_exchange_id: r.last_exchange_id,
        }
    }
}

#[tauri::command]
pub async fn asset_list(
    asset_db: State<'_, Arc<AssetDb>>,
    query: Option<String>,
    limit: Option<usize>,
) -> AppResult<Vec<AssetSummary>> {
    let q = query.unwrap_or_default();
    let lim = limit.unwrap_or(200).clamp(1, 2000);
    let db = asset_db.inner().clone();
    let q_owned = q;
    let rows = tauri::async_runtime::spawn_blocking(move || db.list_assets(&q_owned, lim))
        .await
        .map_err(|e| crate::error::AppError::Other(format!("join: {e}")))?
        .map_err(|e| crate::error::AppError::Other(format!("list_assets: {e}")))?;
    Ok(rows.into_iter().map(Into::into).collect())
}

#[tauri::command]
pub async fn asset_overview(
    asset_db: State<'_, Arc<AssetDb>>,
    probe: State<'_, Arc<ProbeStore>>,
    history: State<'_, Arc<HistoryDb>>,
    host: String,
) -> AppResult<AssetOverview> {
    let host_norm = normalize_host(&host);
    if host_norm.is_empty() {
        return Err(crate::error::AppError::Other("empty host".into()));
    }
    let asset_db = asset_db.inner().clone();
    let probe = probe.inner().clone();
    let history = history.inner().clone();
    let h = host_norm.clone();
    tauri::async_runtime::spawn_blocking(move || -> AppResult<AssetOverview> {
        let ips = asset_db
            .ips_for_host(&h)
            .map_err(|e| crate::error::AppError::Other(format!("ips_for_host: {e}")))?;
        let dns = asset_db
            .dns_records_for_host(&h)
            .map_err(|e| crate::error::AppError::Other(format!("dns_records: {e}")))?
            .into_iter()
            .map(|(k, v, sources)| DnsRecord {
                kind: k,
                value: v,
                sources: split_csv(&sources),
            })
            .collect();

        let cidrs: Vec<String> = ips.iter().filter_map(|ip| cidr_24(ip)).collect::<BTreeSet<_>>().into_iter().collect();

        let counts = asset_db
            .summary_for_host(&h)
            .map_err(|e| crate::error::AppError::Other(format!("summary_for_host: {e}")))?;

        let probe_last = probe
            .last_seen_for_host(&h)
            .map_err(|e| crate::error::AppError::Other(format!("probe last_seen: {e}")))?;

        let device = probe
            .latest_device_match_for_host(&h)
            .map_err(|e| crate::error::AppError::Other(format!("device_match: {e}")))?
            .map(AssetDeviceMatch::from);

        let mac = probe
            .latest_host_mac(&h)
            .map_err(|e| crate::error::AppError::Other(format!("host_mac: {e}")))?
            .map(AssetHostMac::from);

        // We rely on `summary_for_host` for scan_count + the latest
        // scan timestamp folded into last_seen_unix. We still walk the
        // history rows here once to compute the *earliest* scan
        // timestamp (first_seen) — there's no SQL helper that returns
        // a min-by-extracted-host without a similar Rust pass.
        let scans = history
            .list(2000)
            .map_err(|e| crate::error::AppError::Other(format!("history.list: {e}")))?;
        let earliest_scan = scans
            .iter()
            .filter(|s| extract_host_from_scan_target(&s.host) == h)
            .map(|s| s.started_at)
            .min();

        let last_seen_unix = [Some(counts.last_seen_unix).filter(|v| *v > 0), probe_last]
            .into_iter()
            .flatten()
            .max();
        let first_seen_unix = [earliest_scan, probe_last]
            .into_iter()
            .flatten()
            .min();

        Ok(AssetOverview {
            host: h.clone(),
            ips,
            dns_records: dns,
            probe_port_count: counts.probe_port_count,
            exchange_count: counts.exchange_count,
            finding_count: counts.finding_count,
            recon_hit_count: counts.recon_hit_count,
            first_seen_unix,
            last_seen_unix,
            asn_placeholder: None,
            cidr_24s: cidrs,
            scanned_count: counts.scan_count,
            device,
            mac,
        })
    })
    .await
    .map_err(|e| crate::error::AppError::Other(format!("join: {e}")))?
}

#[tauri::command]
pub async fn asset_services(
    probe: State<'_, Arc<ProbeStore>>,
    host: String,
) -> AppResult<Vec<ProbeServiceRow>> {
    let host = normalize_host(&host);
    let probe = probe.inner().clone();
    tauri::async_runtime::spawn_blocking(move || probe.services_for_host(&host))
        .await
        .map_err(|e| crate::error::AppError::Other(format!("join: {e}")))?
        .map_err(|e| crate::error::AppError::Other(format!("services_for_host: {e}")))
}

#[tauri::command]
pub async fn asset_stack(
    asset_db: State<'_, Arc<AssetDb>>,
    host: String,
    port: Option<u16>,
) -> AppResult<Vec<AssetTechRow>> {
    let host = normalize_host(&host);
    let asset_db = asset_db.inner().clone();
    tauri::async_runtime::spawn_blocking(move || -> AppResult<Vec<AssetTechRow>> {
        // Pull the most recent stack-fingerprint findings for the host
        // and project the Wappalyzer detections into rows. Dedup by
        // (name, version) so repeated detections collapse into one chip
        // with an "observed on N paths" count.
        let rows = asset_db
            .findings_for_host(&host, port, 1000)
            .map_err(|e| crate::error::AppError::Other(format!("findings_for_host: {e}")))?;
        let mut out: BTreeMap<(String, Option<String>), AssetTechRow> = BTreeMap::new();
        for row in rows {
            if row.check_id != "stack-fingerprint" {
                continue;
            }
            let Some(json) = row.evidence_json.as_deref() else {
                continue;
            };
            let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json) else {
                continue;
            };
            let detections = parsed.get("detections").and_then(|d| d.as_array());
            let Some(detections) = detections else {
                continue;
            };
            for det in detections {
                let name = det
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if name.is_empty() {
                    continue;
                }
                let version = det
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let categories: Vec<String> = det
                    .get("categories")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|c| c.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let key = (name.clone(), version.clone());
                let entry = out.entry(key).or_insert_with(|| AssetTechRow {
                    name: name.clone(),
                    version: version.clone(),
                    categories: categories.clone(),
                    observed_on_paths: Vec::new(),
                    last_seen_unix: row.created_at_unix,
                });
                if !entry.observed_on_paths.contains(&row.path) {
                    entry.observed_on_paths.push(row.path.clone());
                }
                if row.created_at_unix > entry.last_seen_unix {
                    entry.last_seen_unix = row.created_at_unix;
                }
                // Categories may differ between detections — union them.
                for c in &categories {
                    if !entry.categories.contains(c) {
                        entry.categories.push(c.clone());
                    }
                }
            }
        }
        let mut list: Vec<AssetTechRow> = out.into_values().collect();
        list.sort_by(|a, b| b.last_seen_unix.cmp(&a.last_seen_unix));
        Ok(list)
    })
    .await
    .map_err(|e| crate::error::AppError::Other(format!("join: {e}")))?
}

#[tauri::command]
pub async fn asset_endpoints(
    asset_db: State<'_, Arc<AssetDb>>,
    host: String,
    port: Option<u16>,
    limit: Option<usize>,
) -> AppResult<Vec<AssetEndpoint>> {
    let host = normalize_host(&host);
    let lim = limit.unwrap_or(200).clamp(1, 2000);
    let asset_db = asset_db.inner().clone();
    let rows = tauri::async_runtime::spawn_blocking(move || {
        asset_db.endpoints_for_host(&host, port, lim)
    })
    .await
    .map_err(|e| crate::error::AppError::Other(format!("join: {e}")))?
    .map_err(|e| crate::error::AppError::Other(format!("endpoints_for_host: {e}")))?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Clustered view of `asset_endpoints` — paths sharing a pattern
/// (`/api/users/1`, `/api/users/2`, …) collapse into one row keyed by
/// `/api/users/:id`. Counts are summed across underlying instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEndpointCluster {
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub method: String,
    /// Pattern with `:id`, `:uuid`, `:oid`, `:slug` placeholders.
    pub pattern: String,
    /// Number of distinct concrete paths that fold into this pattern.
    pub instance_count: u32,
    /// Sum of exchange_count across instances.
    pub exchange_count: u32,
    /// Sum of finding_count across instances.
    pub finding_count: u32,
    /// Latest status seen across the instances.
    pub last_status: Option<u16>,
    pub last_seen_unix: i64,
    /// Up to 5 sample concrete paths the cluster stands in for, so the
    /// UI can show "/api/users/1, /api/users/2, +3 more" on hover.
    pub sample_paths: Vec<String>,
}

#[tauri::command]
pub async fn asset_endpoints_clustered(
    asset_db: State<'_, Arc<AssetDb>>,
    host: String,
    port: Option<u16>,
    limit: Option<usize>,
) -> AppResult<Vec<AssetEndpointCluster>> {
    use corvex_proxy::cluster::derive_pattern;

    let host = normalize_host(&host);
    let lim = limit.unwrap_or(2000).clamp(1, 5000);
    let asset_db = asset_db.inner().clone();
    let rows = tauri::async_runtime::spawn_blocking(move || {
        asset_db.endpoints_for_host(&host, port, lim)
    })
    .await
    .map_err(|e| crate::error::AppError::Other(format!("join: {e}")))?
    .map_err(|e| crate::error::AppError::Other(format!("endpoints_for_host: {e}")))?;

    // Aggregate by (method, scheme, host, port, pattern). The
    // BTreeMap key keeps the iteration order deterministic so the UI's
    // sort behaviour is stable across calls.
    type Key = (String, String, String, u16, String);
    let mut acc: BTreeMap<Key, AssetEndpointCluster> = BTreeMap::new();
    for r in rows {
        let pattern = derive_pattern(&r.path);
        let key = (
            r.method.clone(),
            r.scheme.clone(),
            r.host.clone(),
            r.port,
            pattern.clone(),
        );
        let entry =
            acc.entry(key).or_insert_with(|| AssetEndpointCluster {
                host: r.host.clone(),
                port: r.port,
                scheme: r.scheme.clone(),
                method: r.method.clone(),
                pattern: pattern.clone(),
                instance_count: 0,
                exchange_count: 0,
                finding_count: 0,
                last_status: None,
                last_seen_unix: 0,
                sample_paths: Vec::new(),
            });
        entry.instance_count = entry.instance_count.saturating_add(1);
        entry.exchange_count = entry.exchange_count.saturating_add(r.exchange_count);
        entry.finding_count = entry.finding_count.saturating_add(r.finding_count);
        if r.last_seen_unix > entry.last_seen_unix {
            entry.last_seen_unix = r.last_seen_unix;
            entry.last_status = r.last_status;
        }
        if entry.sample_paths.len() < 5 && !entry.sample_paths.contains(&r.path) {
            entry.sample_paths.push(r.path);
        }
    }

    // Newest, then highest exchange volume — same precedence the
    // proxy's cluster snapshot uses.
    let mut out: Vec<AssetEndpointCluster> = acc.into_values().collect();
    out.sort_by(|a, b| {
        b.last_seen_unix
            .cmp(&a.last_seen_unix)
            .then_with(|| b.exchange_count.cmp(&a.exchange_count))
    });
    Ok(out)
}

#[tauri::command]
pub async fn asset_findings(
    asset_db: State<'_, Arc<AssetDb>>,
    host: String,
    port: Option<u16>,
    limit: Option<usize>,
) -> AppResult<Vec<AssetFindingDeduped>> {
    let host = normalize_host(&host);
    let lim = limit.unwrap_or(500).clamp(1, 5000);
    let asset_db = asset_db.inner().clone();
    let rows: Vec<AssetFindingRow> = tauri::async_runtime::spawn_blocking(move || {
        asset_db.findings_for_host(&host, port, lim)
    })
    .await
    .map_err(|e| crate::error::AppError::Other(format!("join: {e}")))?
    .map_err(|e| crate::error::AppError::Other(format!("findings_for_host: {e}")))?;

    // Dedup by (check_id, port, path, title). Title is included so
    // distinct issues that happen to share a plugin + path don't
    // collapse — e.g. the dashboard "headers" plugin emits one finding
    // per missing header (CSP, HSTS, X-CTO, …) all on `/`, and we
    // want each as its own row instead of one consolidated entry.
    // Keep the latest matching row as the example, tally the rest into
    // `occurrence_count`. Sorted by severity weight then recency.
    let mut out: BTreeMap<(String, u16, String, String), AssetFindingDeduped> =
        BTreeMap::new();
    for row in rows {
        let key = (
            row.check_id.clone(),
            row.port,
            row.path.clone(),
            row.title.clone(),
        );
        let entry = out.entry(key).or_insert_with(|| AssetFindingDeduped {
            check_id: row.check_id.clone(),
            severity: row.severity.clone(),
            title: row.title.clone(),
            description: row.description.clone(),
            host: row.host.clone(),
            port: row.port,
            example_path: row.path.clone(),
            example_exchange_id: row.exchange_id.clone(),
            occurrence_count: 0,
            last_seen_unix: row.created_at_unix,
        });
        entry.occurrence_count += 1;
        if row.created_at_unix > entry.last_seen_unix {
            entry.last_seen_unix = row.created_at_unix;
            entry.example_exchange_id = row.exchange_id.clone();
        }
    }
    let mut list: Vec<AssetFindingDeduped> = out.into_values().collect();
    list.sort_by(|a, b| {
        severity_weight(&b.severity)
            .cmp(&severity_weight(&a.severity))
            .then_with(|| b.last_seen_unix.cmp(&a.last_seen_unix))
    });
    Ok(list)
}

#[tauri::command]
pub async fn asset_related(
    asset_db: State<'_, Arc<AssetDb>>,
    probe: State<'_, Arc<ProbeStore>>,
    host: String,
) -> AppResult<AssetRelated> {
    let host = normalize_host(&host);
    let asset_db = asset_db.inner().clone();
    let probe = probe.inner().clone();
    tauri::async_runtime::spawn_blocking(move || -> AppResult<AssetRelated> {
        let suffix = registrable_suffix(&host);
        let mut siblings = asset_db
            .siblings_under_suffix(&suffix, 200)
            .map_err(|e| crate::error::AppError::Other(format!("siblings: {e}")))?;
        siblings.retain(|h| h != &host);

        let ips = asset_db
            .ips_for_host(&host)
            .map_err(|e| crate::error::AppError::Other(format!("ips: {e}")))?;
        let cidrs: Vec<String> = ips
            .iter()
            .filter_map(|ip| cidr_24(ip))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut neighbors = asset_db
            .hosts_in_cidrs(&cidrs)
            .map_err(|e| crate::error::AppError::Other(format!("cidr neighbors: {e}")))?;
        neighbors.retain(|h| h != &host);

        let jarm_pairs = probe
            .hosts_sharing_jarm(&host)
            .map_err(|e| crate::error::AppError::Other(format!("jarm siblings: {e}")))?;
        let same_jarm: Vec<RelatedHost> = jarm_pairs
            .into_iter()
            .map(|(host, jarm)| RelatedHost {
                host,
                jarm: Some(jarm),
            })
            .collect();

        Ok(AssetRelated {
            same_jarm,
            same_root_domain: siblings,
            same_cidr_24: neighbors,
        })
    })
    .await
    .map_err(|e| crate::error::AppError::Other(format!("join: {e}")))?
}

#[tauri::command]
pub async fn asset_timeline(
    asset_db: State<'_, Arc<AssetDb>>,
    probe: State<'_, Arc<ProbeStore>>,
    history: State<'_, Arc<HistoryDb>>,
    recon: State<'_, Arc<ReconDb>>,
    host: String,
    limit: Option<usize>,
) -> AppResult<Vec<AssetTimelineEvent>> {
    let host = normalize_host(&host);
    let lim = limit.unwrap_or(200).clamp(1, 2000);
    let asset_db = asset_db.inner().clone();
    let probe = probe.inner().clone();
    let history = history.inner().clone();
    let recon = recon.inner().clone();
    tauri::async_runtime::spawn_blocking(move || -> AppResult<Vec<AssetTimelineEvent>> {
        let mut events: Vec<AssetTimelineEvent> = Vec::new();

        let exchanges = asset_db
            .recent_exchanges_for_host(&host, lim.min(100))
            .map_err(|e| crate::error::AppError::Other(format!("recent exchanges: {e}")))?;
        for ex in exchanges {
            events.push(AssetTimelineEvent {
                kind: "exchange".into(),
                ts_unix: ex.started_at_unix,
                summary: format!(
                    "{} {} {}://{}:{}{}{}",
                    ex.method,
                    ex.status.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                    ex.scheme,
                    host,
                    ex.port,
                    if ex.path.starts_with('/') { "" } else { "/" },
                    ex.path
                ),
                deep_link: Some(format!("exchange:{}", ex.id)),
            });
        }

        let findings = asset_db
            .findings_for_host(&host, None, lim.min(200))
            .map_err(|e| crate::error::AppError::Other(format!("findings: {e}")))?;
        for f in findings {
            events.push(AssetTimelineEvent {
                kind: "finding".into(),
                ts_unix: f.created_at_unix,
                summary: format!("[{}] {} — {}", f.severity, f.title, f.path),
                deep_link: Some(format!("exchange:{}", f.exchange_id)),
            });
        }

        let services = probe
            .services_for_host(&host)
            .map_err(|e| crate::error::AppError::Other(format!("services: {e}")))?;
        for s in services {
            events.push(AssetTimelineEvent {
                kind: "probe".into(),
                ts_unix: s.last_seen_unix,
                summary: format!(
                    "probe — {} {}{}",
                    s.port,
                    s.product.as_deref().unwrap_or(s.service.as_deref().unwrap_or("?")),
                    s.version.as_deref().map(|v| format!(" {v}")).unwrap_or_default()
                ),
                deep_link: None,
            });
        }

        // Recon — the recon store only exposes per-run queries; pull
        // the latest 100 runs and project hits matching this host.
        let runs = recon
            .list_runs(100)
            .map_err(|e| crate::error::AppError::Other(format!("recon runs: {e}")))?;
        for run in runs {
            let run_id = match uuid::Uuid::parse_str(&run.id) {
                Ok(u) => u,
                Err(_) => continue,
            };
            let findings = recon
                .findings_for_run(&run_id)
                .map_err(|e| crate::error::AppError::Other(format!("recon findings: {e}")))?;
            for f in findings {
                if normalize_host(&f.name) != host {
                    continue;
                }
                events.push(AssetTimelineEvent {
                    kind: "recon".into(),
                    ts_unix: f.discovered_at_unix,
                    summary: format!(
                        "recon {} {}",
                        f.kind.as_str(),
                        f.value.unwrap_or_default()
                    ),
                    deep_link: Some(format!("recon:{}", run.id)),
                });
            }
        }

        let scans = history
            .list(500)
            .map_err(|e| crate::error::AppError::Other(format!("history: {e}")))?;
        for s in scans {
            if extract_host_from_scan_target(&s.host) != host {
                continue;
            }
            events.push(AssetTimelineEvent {
                kind: "scan".into(),
                ts_unix: s.started_at,
                summary: format!(
                    "scan #{} — {} requests, {} findings",
                    s.id, s.total_requests, s.total_findings
                ),
                deep_link: Some(format!("history:{}", s.id)),
            });
        }

        events.sort_by(|a, b| b.ts_unix.cmp(&a.ts_unix));
        events.truncate(lim);
        Ok(events)
    })
    .await
    .map_err(|e| crate::error::AppError::Other(format!("join: {e}")))?
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

fn severity_weight(sev: &str) -> u8 {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => 5,
        "HIGH" => 4,
        "MEDIUM" => 3,
        "LOW" => 2,
        "INFO" => 1,
        _ => 0,
    }
}
