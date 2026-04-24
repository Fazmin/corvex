//! Recon runner — orchestrates passive subdomain enumeration and
//! optional active DNS work against a single target domain.
//!
//! The runner is deliberately event-driven: every interesting moment
//! (a source finishing, a subdomain landing, a wildcard being
//! detected, a brute-force progress tick) is emitted on a tokio
//! mpsc channel so the desktop layer can bridge events to the UI
//! without the runner knowing anything about Tauri.
//!
//! Partial failures are first-class: one source timing out doesn't
//! abort the whole run — the event stream reports the error, the
//! runner keeps going with the sources that did answer.

pub mod passive;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::dns::{
    brute_subdomains_filtered, detect_wildcard, lookup_host_addrs, lookup_records,
    try_zone_transfer, DnsRecord,
};
use crate::recon::passive::{
    AlienVaultSource, CertSpotterSource, CrtShSource, PassiveSource,
};

/// Default subdomain wordlist embedded at compile time. Used when the
/// caller hasn't pointed at a custom wordlist file on disk.
pub const DEFAULT_WORDLIST: &str = include_str!("../../data/subdomains.txt");

/// Parameters for a single recon run. Designed to round-trip cleanly
/// through the Tauri IPC boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconParams {
    pub domain: String,
    /// Subset of passive source names (e.g. "crt.sh"). Empty disables
    /// passive discovery.
    pub passive_sources: Vec<String>,
    /// When true, also run active DNS enumeration + wordlist
    /// brute-force against the target.
    pub active: bool,
    /// Custom wordlist contents (one prefix per line). When `None`,
    /// the embedded default ships. Desktop side reads the user-picked
    /// file and hands us the bytes so the core crate has no IO.
    pub wordlist: Option<String>,
    /// Concurrency cap for the brute-force pool. 500 is a reasonable
    /// default for residential connections.
    pub max_concurrent: usize,
}

impl Default for ReconParams {
    fn default() -> Self {
        Self {
            domain: String::new(),
            passive_sources: vec![
                "crt.sh".into(),
                "AlienVault OTX".into(),
                "CertSpotter".into(),
            ],
            active: false,
            wordlist: None,
            max_concurrent: 500,
        }
    }
}

/// Events emitted by the runner. The desktop layer bridges these to a
/// `recon://event` Tauri event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReconEvent {
    SourceStarted {
        source: String,
    },
    SourceFinished {
        source: String,
        found: usize,
        error: Option<String>,
    },
    WildcardDetected {
        ips: Vec<String>,
    },
    /// Emitted once per unique subdomain — after passive union and
    /// after brute-force. Includes IP annotations when the runner
    /// could resolve them.
    SubdomainDiscovered {
        host: String,
        sources: Vec<String>,
        ips: Vec<String>,
    },
    RecordDiscovered {
        name: String,
        record_type: String,
        value: String,
    },
    ZoneTransfer {
        records: usize,
    },
    BruteProgress {
        tested: usize,
        total: usize,
        found: usize,
    },
    Complete {
        found_subdomains: usize,
        found_records: usize,
        duration_ms: u64,
    },
    Failed {
        error: String,
    },
    Cancelled,
}

/// Build a PassiveSource by name, preserving user toggles from the UI.
fn passive_source_by_name(name: &str) -> Option<Box<dyn PassiveSource>> {
    match name {
        "crt.sh" => Some(Box::new(CrtShSource)),
        "AlienVault OTX" => Some(Box::new(AlienVaultSource)),
        "CertSpotter" => Some(Box::new(CertSpotterSource)),
        _ => None,
    }
}

/// Run one recon job to completion. Every observation goes out on
/// `events`; the caller drains the channel and persists / broadcasts
/// as it sees fit. `cancel` trips every in-flight stage cleanly.
pub async fn run_recon(
    params: ReconParams,
    events: mpsc::Sender<ReconEvent>,
    cancel: CancellationToken,
) {
    let started = Instant::now();
    let mut subdomain_sources: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut subdomain_ips: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut records: Vec<DnsRecord> = Vec::new();
    let mut wildcard_ips: Vec<String> = Vec::new();

    // --- Passive phase ------------------------------------------------
    let client = match reqwest::Client::builder()
        .user_agent(format!(
            "corvex-recon/{}",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = events
                .send(ReconEvent::Failed {
                    error: format!("http client: {e}"),
                })
                .await;
            return;
        }
    };

    let mut passive_futs = Vec::new();
    for name in &params.passive_sources {
        let Some(source) = passive_source_by_name(name) else {
            continue;
        };
        let tx = events.clone();
        let client = client.clone();
        let domain = params.domain.clone();
        let cancel = cancel.clone();
        let name_owned = name.clone();
        passive_futs.push(tokio::spawn(async move {
            let _ = tx
                .send(ReconEvent::SourceStarted {
                    source: name_owned.clone(),
                })
                .await;
            let fut = source.enumerate(&domain, &client);
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    (name_owned, Err("cancelled".to_string()), Vec::new())
                }
                r = fut => match r {
                    Ok(hosts) => (name_owned, Ok(hosts.len()), hosts),
                    Err(e) => (name_owned, Err(e), Vec::new()),
                },
            }
        }));
    }
    for fut in passive_futs {
        if cancel.is_cancelled() {
            break;
        }
        let Ok((source, outcome, hosts)) = fut.await else {
            continue;
        };
        let found = hosts.len();
        match outcome {
            Ok(_) => {
                for host in hosts {
                    subdomain_sources
                        .entry(host)
                        .or_default()
                        .insert(source.clone());
                }
                let _ = events
                    .send(ReconEvent::SourceFinished {
                        source,
                        found,
                        error: None,
                    })
                    .await;
            }
            Err(e) => {
                let _ = events
                    .send(ReconEvent::SourceFinished {
                        source,
                        found: 0,
                        error: Some(e),
                    })
                    .await;
            }
        }
    }

    if cancel.is_cancelled() {
        let _ = events.send(ReconEvent::Cancelled).await;
        return;
    }

    // --- Active phase -------------------------------------------------
    if params.active && !cancel.is_cancelled() {
        // DNS records
        if let Ok(recs) = lookup_records(&params.domain).await {
            for r in &recs {
                let _ = events
                    .send(ReconEvent::RecordDiscovered {
                        name: r.name.clone(),
                        record_type: r.record_type.clone(),
                        value: r.value.clone(),
                    })
                    .await;
            }
            records.extend(recs);
        }

        // Zone transfer (typically refused; success is noteworthy)
        if let Ok(axfr) = try_zone_transfer(&params.domain).await {
            if !axfr.is_empty() {
                let _ = events
                    .send(ReconEvent::ZoneTransfer {
                        records: axfr.len(),
                    })
                    .await;
                for r in &axfr {
                    // Each AXFR row is also a DNS record for the log.
                    let _ = events
                        .send(ReconEvent::RecordDiscovered {
                            name: r.name.clone(),
                            record_type: r.record_type.clone(),
                            value: r.value.clone(),
                        })
                        .await;
                    // Bonus: if the AXFR row is itself a subdomain,
                    // add it to the discovered set.
                    if r.name != params.domain
                        && r.name.ends_with(&format!(".{}", params.domain))
                    {
                        subdomain_sources
                            .entry(r.name.clone())
                            .or_default()
                            .insert("zone-transfer".into());
                    }
                }
                records.extend(axfr);
            }
        }

        // Wildcard probe before brute-force
        if let Ok(wips) = detect_wildcard(&params.domain).await {
            if !wips.is_empty() {
                let _ = events
                    .send(ReconEvent::WildcardDetected { ips: wips.clone() })
                    .await;
                wildcard_ips = wips;
            }
        }

        // Wordlist brute-force
        let wordlist_src = params
            .wordlist
            .as_deref()
            .unwrap_or(DEFAULT_WORDLIST);
        let wordlist: Vec<String> = wordlist_src
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        if !wordlist.is_empty() && !cancel.is_cancelled() {
            let _ = events
                .send(ReconEvent::BruteProgress {
                    tested: 0,
                    total: wordlist.len(),
                    found: subdomain_sources.len(),
                })
                .await;
            let brute = tokio::select! {
                biased;
                _ = cancel.cancelled() => Vec::new(),
                r = brute_subdomains_filtered(
                    &params.domain,
                    &wordlist,
                    params.max_concurrent.max(1),
                    &wildcard_ips,
                ) => r.unwrap_or_default(),
            };
            for host in brute {
                subdomain_sources
                    .entry(host)
                    .or_default()
                    .insert("brute".into());
            }
            let _ = events
                .send(ReconEvent::BruteProgress {
                    tested: wordlist.len(),
                    total: wordlist.len(),
                    found: subdomain_sources.len(),
                })
                .await;
        }
    }

    if cancel.is_cancelled() {
        let _ = events.send(ReconEvent::Cancelled).await;
        return;
    }

    // --- Annotate subdomains with A/AAAA/CNAME ------------------------
    // Keep this cheap: one resolver call per host, sequential to avoid
    // stampeding a single recursive resolver. For very large sets the
    // user typically only cares about the live ones — a later pass can
    // parallelise with a Semaphore.
    let hosts: Vec<String> = subdomain_sources.keys().cloned().collect();
    for host in &hosts {
        if cancel.is_cancelled() {
            break;
        }
        let Ok(addrs) = lookup_host_addrs(host).await else {
            continue;
        };
        let ips: Vec<String> = addrs
            .iter()
            .filter(|r| r.record_type == "A" || r.record_type == "AAAA")
            .map(|r| r.value.clone())
            .collect();
        subdomain_ips.insert(host.clone(), ips.clone());
        let sources: Vec<String> = subdomain_sources
            .get(host)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        let _ = events
            .send(ReconEvent::SubdomainDiscovered {
                host: host.clone(),
                sources,
                ips,
            })
            .await;
    }

    // Surface any subdomains we never managed to resolve as well —
    // they still came from a trusted passive source.
    for host in &hosts {
        if subdomain_ips.contains_key(host) {
            continue;
        }
        let sources: Vec<String> = subdomain_sources
            .get(host)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        let _ = events
            .send(ReconEvent::SubdomainDiscovered {
                host: host.clone(),
                sources,
                ips: Vec::new(),
            })
            .await;
    }

    let _ = events
        .send(ReconEvent::Complete {
            found_subdomains: subdomain_sources.len(),
            found_records: records.len(),
            duration_ms: started.elapsed().as_millis() as u64,
        })
        .await;
}
