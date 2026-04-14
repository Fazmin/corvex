//! NVD (National Vulnerability Database) API v2.0 client.
//!
//! Fetches CVE data from the NVD REST API with proper pagination,
//! rate limiting, and incremental update support.

use crate::vulndb::models::{CpeMatch, CveRecord, CveReference};
use serde::Deserialize;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing;

/// NVD API v2.0 base URL.
const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// Results per page (NVD max is 2000).
const RESULTS_PER_PAGE: u32 = 2000;

/// Rate limiter for NVD API requests.
pub struct RateLimiter {
    last_request: Mutex<Instant>,
    min_interval: Duration,
}

impl RateLimiter {
    /// Create a rate limiter. `requests_per_minute` controls throughput.
    pub fn new(requests_per_minute: u32) -> Self {
        let interval_ms = 60_000 / requests_per_minute.max(1);
        Self {
            last_request: Mutex::new(Instant::now() - Duration::from_secs(60)),
            min_interval: Duration::from_millis(interval_ms as u64),
        }
    }

    /// Wait until we can make the next request.
    pub async fn wait(&self) {
        let mut last = self.last_request.lock().await;
        let elapsed = last.elapsed();
        if elapsed < self.min_interval {
            tokio::time::sleep(self.min_interval - elapsed).await;
        }
        *last = Instant::now();
    }
}

/// NVD API client.
pub struct NvdClient {
    client: reqwest::Client,
    api_key: Option<String>,
    rate_limiter: RateLimiter,
}

impl NvdClient {
    /// Create a new NVD client. If `api_key` is provided, rate limit is 100 req/60s,
    /// otherwise 10 req/60s.
    pub fn new(api_key: Option<String>) -> Self {
        let rpm = if api_key.is_some() { 100 } else { 10 };
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .unwrap_or_default(),
            api_key,
            rate_limiter: RateLimiter::new(rpm),
        }
    }

    /// Fetch all CVEs, calling `on_batch` for each page of results.
    /// Returns total number of CVEs fetched.
    pub async fn fetch_all<F>(&self, mut on_batch: F) -> Result<u64, String>
    where
        F: FnMut(Vec<NvdCveItem>) -> Result<(), String>,
    {
        let mut start_index: u32 = 0;
        let mut fetched: u64 = 0;

        loop {
            self.rate_limiter.wait().await;

            let mut url = format!(
                "{}?resultsPerPage={}&startIndex={}",
                NVD_API_BASE, RESULTS_PER_PAGE, start_index
            );

            // Add API key if available.
            if let Some(ref key) = self.api_key {
                url.push_str(&format!("&apiKey={}", key));
            }

            tracing::info!(
                target: "vulndb",
                "NVD fetch: startIndex={}, fetched={}",
                start_index, fetched
            );

            let resp = self
                .client
                .get(&url)
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|e| format!("NVD request failed: {e}"))?;

            if !resp.status().is_success() {
                return Err(format!("NVD API returned status {}", resp.status()));
            }

            let body: NvdResponse = resp
                .json()
                .await
                .map_err(|e| format!("NVD JSON parse failed: {e}"))?;

            let total_results = body.total_results;
            let batch_len = body.vulnerabilities.len() as u64;

            if batch_len == 0 {
                break;
            }

            on_batch(body.vulnerabilities)?;
            fetched += batch_len;
            start_index += RESULTS_PER_PAGE;

            if start_index >= total_results {
                break;
            }
        }

        Ok(fetched)
    }

    /// Fetch CVEs modified since `last_modified` (ISO 8601 datetime).
    pub async fn fetch_modified<F>(
        &self,
        last_modified: &str,
        mut on_batch: F,
    ) -> Result<u64, String>
    where
        F: FnMut(Vec<NvdCveItem>) -> Result<(), String>,
    {
        let mut start_index: u32 = 0;
        let mut fetched: u64 = 0;
        let now = time::OffsetDateTime::now_utc();
        let end_date = now
            .format(&time::format_description::well_known::Iso8601::DEFAULT)
            .unwrap_or_default();

        loop {
            self.rate_limiter.wait().await;

            let mut url = format!(
                "{}?resultsPerPage={}&startIndex={}&lastModStartDate={}&lastModEndDate={}",
                NVD_API_BASE, RESULTS_PER_PAGE, start_index, last_modified, end_date
            );

            if let Some(ref key) = self.api_key {
                url.push_str(&format!("&apiKey={}", key));
            }

            tracing::info!(
                target: "vulndb",
                "NVD incremental fetch: startIndex={}, since={}",
                start_index, last_modified
            );

            let resp = self
                .client
                .get(&url)
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|e| format!("NVD request failed: {e}"))?;

            if !resp.status().is_success() {
                return Err(format!("NVD API returned status {}", resp.status()));
            }

            let body: NvdResponse = resp
                .json()
                .await
                .map_err(|e| format!("NVD JSON parse failed: {e}"))?;

            let total_results = body.total_results;
            let batch_len = body.vulnerabilities.len() as u64;

            if batch_len == 0 {
                break;
            }

            on_batch(body.vulnerabilities)?;
            fetched += batch_len;
            start_index += RESULTS_PER_PAGE;

            if start_index >= total_results {
                break;
            }
        }

        Ok(fetched)
    }
}

// ---- NVD API v2.0 JSON response models ----

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdResponse {
    #[serde(default)]
    pub results_per_page: u32,
    #[serde(default)]
    pub start_index: u32,
    pub total_results: u32,
    #[serde(default)]
    pub vulnerabilities: Vec<NvdCveItem>,
}

#[derive(Debug, Deserialize)]
pub struct NvdCveItem {
    pub cve: NvdCve,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCve {
    pub id: String,
    #[serde(default)]
    pub descriptions: Vec<NvdDescription>,
    pub published: Option<String>,
    pub last_modified: Option<String>,
    #[serde(default)]
    pub metrics: NvdMetrics,
    #[serde(default)]
    pub configurations: Vec<NvdConfiguration>,
    #[serde(default)]
    pub references: Vec<NvdReference>,
}

#[derive(Debug, Deserialize)]
pub struct NvdDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdMetrics {
    #[serde(default)]
    pub cvss_metric_v31: Vec<NvdCvssV31>,
    #[serde(default)]
    pub cvss_metric_v30: Vec<NvdCvssV30>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssV31 {
    pub cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssV30 {
    pub cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssData {
    pub base_score: f32,
    pub vector_string: Option<String>,
    pub base_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NvdConfiguration {
    #[serde(default)]
    pub nodes: Vec<NvdNode>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdNode {
    #[serde(default)]
    pub cpe_match: Vec<NvdCpeMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCpeMatch {
    pub criteria: String,
    pub vulnerable: bool,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NvdReference {
    pub url: String,
    pub source: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

// ---- Conversion from NVD API types to our models ----

impl NvdCveItem {
    /// Extract the English description.
    pub fn description(&self) -> String {
        self.cve
            .descriptions
            .iter()
            .find(|d| d.lang == "en")
            .map(|d| d.value.clone())
            .unwrap_or_default()
    }

    /// Extract CVSS v3.1 score (falling back to v3.0).
    pub fn cvss_v31(&self) -> Option<(f32, String, String)> {
        if let Some(m) = self.cve.metrics.cvss_metric_v31.first() {
            return Some((
                m.cvss_data.base_score,
                m.cvss_data.vector_string.clone().unwrap_or_default(),
                m.cvss_data.base_severity.clone().unwrap_or_default(),
            ));
        }
        if let Some(m) = self.cve.metrics.cvss_metric_v30.first() {
            return Some((
                m.cvss_data.base_score,
                m.cvss_data.vector_string.clone().unwrap_or_default(),
                m.cvss_data.base_severity.clone().unwrap_or_default(),
            ));
        }
        None
    }

    /// Convert to our CveRecord model.
    pub fn to_cve_record(&self) -> CveRecord {
        let (score, vector, severity) = self
            .cvss_v31()
            .map(|(s, v, sev)| (Some(s), Some(v), Some(sev)))
            .unwrap_or((None, None, None));

        CveRecord {
            cve_id: self.cve.id.clone(),
            description: self.description(),
            published: self.cve.published.clone(),
            modified: self.cve.last_modified.clone(),
            cvss_v31_score: score,
            cvss_v31_vector: vector,
            severity,
            source: "nvd".to_string(),
        }
    }

    /// Extract CPE match entries.
    pub fn to_cpe_matches(&self) -> Vec<CpeMatch> {
        let mut matches = Vec::new();
        for config in &self.cve.configurations {
            for node in &config.nodes {
                for m in &node.cpe_match {
                    matches.push(CpeMatch {
                        cve_id: self.cve.id.clone(),
                        cpe23_uri: m.criteria.clone(),
                        vulnerable: m.vulnerable,
                        version_start_including: m.version_start_including.clone(),
                        version_start_excluding: m.version_start_excluding.clone(),
                        version_end_including: m.version_end_including.clone(),
                        version_end_excluding: m.version_end_excluding.clone(),
                    });
                }
            }
        }
        matches
    }

    /// Extract reference URLs.
    pub fn to_references(&self) -> Vec<CveReference> {
        self.cve
            .references
            .iter()
            .map(|r| CveReference {
                cve_id: self.cve.id.clone(),
                url: r.url.clone(),
                source: r.source.clone(),
                tags: r.tags.clone(),
            })
            .collect()
    }
}
