//! Data models for the vulnerability database.

use serde::{Deserialize, Serialize};

/// A CVE record stored in the local vulnerability database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveRecord {
    pub cve_id: String,
    pub description: String,
    pub published: Option<String>,
    pub modified: Option<String>,
    pub cvss_v31_score: Option<f32>,
    pub cvss_v31_vector: Option<String>,
    pub severity: Option<String>,
    pub source: String,
}

/// A CPE match entry linking a CVE to affected software versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeMatch {
    pub cve_id: String,
    pub cpe23_uri: String,
    pub vulnerable: bool,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}

/// A CVE reference URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveReference {
    pub cve_id: String,
    pub url: String,
    pub source: Option<String>,
    pub tags: Vec<String>,
}

/// EPSS (Exploit Prediction Scoring System) score for a CVE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssScore {
    pub cve_id: String,
    pub score: f32,
    pub percentile: f32,
    pub date: String,
}

/// Information about an available fix for a CVE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixInfo {
    pub cve_id: String,
    pub ecosystem: Option<String>,
    pub package: Option<String>,
    pub fixed_version: String,
}

/// Metadata about the database state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbMeta {
    pub key: String,
    pub value: String,
}

/// A full CVE with all associated data, used for export/import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveFullRecord {
    pub cve: CveRecord,
    pub cpe_matches: Vec<CpeMatch>,
    pub references: Vec<CveReference>,
    pub epss: Option<EpssScore>,
}
