//! CycloneDX VEX document parser and generator.

use crate::vex::triage::{TriageEntry, TriageStatus};
use serde::{Deserialize, Serialize};

/// Parse a CycloneDX VEX JSON document into triage entries.
pub fn parse_vex_json(content: &str) -> Result<Vec<TriageEntry>, String> {
    let doc: CdxVexDocument =
        serde_json::from_str(content).map_err(|e| format!("CycloneDX VEX parse: {e}"))?;

    let mut entries = Vec::new();

    for vuln in doc.vulnerabilities.unwrap_or_default() {
        let cve_id = vuln.id.clone();
        let status = match vuln
            .analysis
            .as_ref()
            .and_then(|a| a.state.as_deref())
        {
            Some("not_affected") => TriageStatus::NotAffected,
            Some("false_positive") => TriageStatus::FalsePositive,
            Some("exploitable") | Some("confirmed") => TriageStatus::Confirmed,
            Some("in_triage") => TriageStatus::Unexplored,
            Some("resolved") => TriageStatus::Mitigated,
            _ => TriageStatus::NewFound,
        };

        let justification = vuln
            .analysis
            .as_ref()
            .and_then(|a| a.justification.clone());

        let component = vuln
            .affects
            .as_ref()
            .and_then(|a| a.first())
            .and_then(|a| a.ref_field.clone());

        entries.push(TriageEntry {
            cve_id,
            component,
            status,
            justification,
            updated_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        });
    }

    Ok(entries)
}

/// Generate a CycloneDX VEX JSON document from triage entries.
pub fn generate_vex_json(entries: &[TriageEntry]) -> Result<String, String> {
    let vulnerabilities: Vec<CdxVulnerability> = entries
        .iter()
        .map(|e| {
            let state = match e.status {
                TriageStatus::NotAffected => "not_affected",
                TriageStatus::FalsePositive => "false_positive",
                TriageStatus::Confirmed => "exploitable",
                TriageStatus::Mitigated => "resolved",
                TriageStatus::Unexplored => "in_triage",
                TriageStatus::NewFound => "in_triage",
            };

            CdxVulnerability {
                id: e.cve_id.clone(),
                analysis: Some(CdxAnalysis {
                    state: Some(state.to_string()),
                    justification: e.justification.clone(),
                }),
                affects: e.component.as_ref().map(|c| {
                    vec![CdxAffect {
                        ref_field: Some(c.clone()),
                    }]
                }),
            }
        })
        .collect();

    let doc = CdxVexDocument {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.5".to_string(),
        version: 1,
        vulnerabilities: Some(vulnerabilities),
    };

    serde_json::to_string_pretty(&doc).map_err(|e| format!("generate VEX: {e}"))
}

// ---- CycloneDX VEX JSON schema types ----

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxVexDocument {
    bom_format: String,
    spec_version: String,
    version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    vulnerabilities: Option<Vec<CdxVulnerability>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CdxVulnerability {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    analysis: Option<CdxAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    affects: Option<Vec<CdxAffect>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CdxAnalysis {
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    justification: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CdxAffect {
    #[serde(rename = "ref")]
    #[serde(skip_serializing_if = "Option::is_none")]
    ref_field: Option<String>,
}
