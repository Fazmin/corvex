//! OSV (Open Source Vulnerabilities) API client.
//!
//! Queries the OSV.dev REST API to supplement NVD data with
//! ecosystem-specific vulnerability information.

use crate::vulndb::models::{CveRecord, FixInfo};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing;

const OSV_API_BASE: &str = "https://api.osv.dev/v1";

/// OSV API client.
pub struct OsvClient {
    client: reqwest::Client,
}

impl OsvClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Query OSV for vulnerabilities affecting a specific package.
    pub async fn query_package(
        &self,
        ecosystem: &str,
        name: &str,
        version: &str,
    ) -> Result<Vec<OsvVulnerability>, String> {
        let body = OsvQueryRequest {
            version: Some(version.to_string()),
            package: OsvPackage {
                name: name.to_string(),
                ecosystem: ecosystem.to_string(),
            },
        };

        let resp = self
            .client
            .post(&format!("{}/query", OSV_API_BASE))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("OSV query failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("OSV API returned status {}", resp.status()));
        }

        let result: OsvQueryResponse = resp
            .json()
            .await
            .map_err(|e| format!("OSV JSON parse failed: {e}"))?;

        Ok(result.vulns.unwrap_or_default())
    }

    /// Fetch a specific vulnerability by its OSV ID.
    pub async fn get_vulnerability(&self, id: &str) -> Result<OsvVulnerability, String> {
        let resp = self
            .client
            .get(&format!("{}/vulns/{}", OSV_API_BASE, id))
            .send()
            .await
            .map_err(|e| format!("OSV fetch failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("OSV API returned status {}", resp.status()));
        }

        resp.json()
            .await
            .map_err(|e| format!("OSV JSON parse failed: {e}"))
    }
}

// ---- OSV API JSON models ----

#[derive(Debug, Serialize)]
struct OsvQueryRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    package: OsvPackage,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsvPackage {
    pub name: String,
    pub ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    vulns: Option<Vec<OsvVulnerability>>,
}

#[derive(Debug, Deserialize)]
pub struct OsvVulnerability {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub published: Option<String>,
    pub modified: Option<String>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub references: Vec<OsvReference>,
}

#[derive(Debug, Deserialize)]
pub struct OsvAffected {
    pub package: Option<OsvPackage>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
pub struct OsvEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
    pub limit: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

#[derive(Debug, Deserialize)]
pub struct OsvReference {
    #[serde(rename = "type")]
    pub ref_type: Option<String>,
    pub url: String,
}

// ---- Conversion helpers ----

impl OsvVulnerability {
    /// Get the CVE alias if one exists.
    pub fn cve_id(&self) -> Option<&str> {
        self.aliases
            .iter()
            .find(|a| a.starts_with("CVE-"))
            .map(|s| s.as_str())
    }

    /// Extract CVSS score from severity entries.
    pub fn cvss_score(&self) -> Option<f32> {
        for s in &self.severity {
            if s.severity_type == "CVSS_V3" {
                // Parse score from CVSS vector string if possible
                if let Some(score_str) = s.score.split('/').last() {
                    if let Ok(score) = score_str.parse::<f32>() {
                        return Some(score);
                    }
                }
                // Try parsing the full string as a number
                if let Ok(score) = s.score.parse::<f32>() {
                    return Some(score);
                }
            }
        }
        None
    }

    /// Convert to a CveRecord (uses CVE alias as ID, or OSV ID if no CVE).
    pub fn to_cve_record(&self) -> CveRecord {
        let id = self.cve_id().unwrap_or(&self.id).to_string();
        let description = self
            .summary
            .clone()
            .or_else(|| self.details.clone())
            .unwrap_or_default();

        CveRecord {
            cve_id: id,
            description,
            published: self.published.clone(),
            modified: self.modified.clone(),
            cvss_v31_score: self.cvss_score(),
            cvss_v31_vector: self
                .severity
                .first()
                .map(|s| s.score.clone()),
            severity: None,
            source: "osv".to_string(),
        }
    }

    /// Extract fix information from affected ranges.
    pub fn to_fix_infos(&self) -> Vec<FixInfo> {
        let mut fixes = Vec::new();
        let cve_id = self.cve_id().unwrap_or(&self.id).to_string();

        for affected in &self.affected {
            let (ecosystem, package) = affected
                .package
                .as_ref()
                .map(|p| (Some(p.ecosystem.clone()), Some(p.name.clone())))
                .unwrap_or((None, None));

            for range in &affected.ranges {
                for event in &range.events {
                    if let Some(ref fixed) = event.fixed {
                        fixes.push(FixInfo {
                            cve_id: cve_id.clone(),
                            ecosystem: ecosystem.clone(),
                            package: package.clone(),
                            fixed_version: fixed.clone(),
                        });
                    }
                }
            }
        }
        fixes
    }
}
