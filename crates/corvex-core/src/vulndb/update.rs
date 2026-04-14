//! Vulnerability database update orchestrator.
//!
//! Supports multiple update modes: now (full refresh), daily (check staleness),
//! never (skip), latest (incremental since last update).

use crate::vulndb::epss::EpssClient;
use crate::vulndb::nvd::NvdClient;
use crate::vulndb::VulnDb;
use tracing;

/// Update mode for the vulnerability database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateMode {
    /// Full refresh — delete cached data and re-download everything.
    Now,
    /// Check staleness — update only if last update was >24 hours ago.
    Daily,
    /// Skip all update checks.
    Never,
    /// Incremental — fetch only CVEs modified since last update.
    Latest,
}

impl UpdateMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "now" => Some(Self::Now),
            "daily" => Some(Self::Daily),
            "never" => Some(Self::Never),
            "latest" => Some(Self::Latest),
            _ => None,
        }
    }
}

impl std::fmt::Display for UpdateMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Now => write!(f, "now"),
            Self::Daily => write!(f, "daily"),
            Self::Never => write!(f, "never"),
            Self::Latest => write!(f, "latest"),
        }
    }
}

/// Run the database update process based on the selected mode.
pub async fn run_update(
    db: &VulnDb,
    mode: UpdateMode,
    api_key: Option<String>,
) -> Result<(), String> {
    match mode {
        UpdateMode::Never => {
            tracing::info!(target: "vulndb", "update mode=never, skipping");
            return Ok(());
        }
        UpdateMode::Daily => {
            if !db.is_stale(24 * 3600)? {
                tracing::info!(target: "vulndb", "database is fresh (< 24h), skipping update");
                return Ok(());
            }
            tracing::info!(target: "vulndb", "database is stale, running update");
        }
        UpdateMode::Now => {
            tracing::info!(target: "vulndb", "full refresh requested");
            db.clear_all()?;
        }
        UpdateMode::Latest => {
            tracing::info!(target: "vulndb", "incremental update requested");
        }
    }

    // Fetch NVD data
    let nvd = NvdClient::new(api_key);

    if mode == UpdateMode::Latest {
        if let Some(last_update) = db.get_meta("last_nvd_update")? {
            tracing::info!(target: "vulndb", "fetching NVD CVEs modified since {}", last_update);
            let count = nvd
                .fetch_modified(&last_update, |batch| {
                    db.upsert_nvd_batch(&batch)
                })
                .await?;
            tracing::info!(target: "vulndb", "updated {} CVEs from NVD (incremental)", count);
        } else {
            tracing::info!(target: "vulndb", "no previous update timestamp, doing full fetch");
            let count = nvd
                .fetch_all(|batch| db.upsert_nvd_batch(&batch))
                .await?;
            tracing::info!(target: "vulndb", "loaded {} CVEs from NVD (full)", count);
        }
    } else {
        let count = nvd
            .fetch_all(|batch| db.upsert_nvd_batch(&batch))
            .await?;
        tracing::info!(target: "vulndb", "loaded {} CVEs from NVD", count);
    }

    // Update the last NVD update timestamp
    let now = time::OffsetDateTime::now_utc();
    let now_str = now
        .format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap_or_default();
    db.set_meta("last_nvd_update", &now_str)?;

    // Fetch EPSS data
    tracing::info!(target: "vulndb", "updating EPSS scores");
    let epss = EpssClient::new();
    match epss.fetch_scores().await {
        Ok(scores) => {
            let count = scores.len();
            db.upsert_epss_batch(&scores)?;
            db.set_meta("last_epss_update", &now_str)?;
            tracing::info!(target: "vulndb", "loaded {} EPSS scores", count);
        }
        Err(e) => {
            tracing::warn!(target: "vulndb", "EPSS update failed (non-fatal): {}", e);
        }
    }

    tracing::info!(target: "vulndb", "database update complete");
    Ok(())
}
