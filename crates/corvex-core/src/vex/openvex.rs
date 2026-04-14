//! OpenVEX document parser and generator.

use crate::vex::triage::{TriageEntry, TriageStatus};
use serde::{Deserialize, Serialize};

/// Parse an OpenVEX JSON document into triage entries.
pub fn parse_openvex_json(content: &str) -> Result<Vec<TriageEntry>, String> {
    let doc: OpenVexDocument =
        serde_json::from_str(content).map_err(|e| format!("OpenVEX parse: {e}"))?;

    let mut entries = Vec::new();

    for stmt in doc.statements.unwrap_or_default() {
        let cve_id = stmt
            .vulnerability
            .as_ref()
            .map(|v| v.name.clone().unwrap_or_default())
            .unwrap_or_default();

        if cve_id.is_empty() {
            continue;
        }

        let status = match stmt.status.as_deref() {
            Some("not_affected") => TriageStatus::NotAffected,
            Some("affected") => TriageStatus::Confirmed,
            Some("fixed") => TriageStatus::Mitigated,
            Some("under_investigation") => TriageStatus::Unexplored,
            _ => TriageStatus::NewFound,
        };

        let component = stmt
            .products
            .as_ref()
            .and_then(|p| p.first())
            .and_then(|p| p.id.clone());

        entries.push(TriageEntry {
            cve_id,
            component,
            status,
            justification: stmt.justification,
            updated_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        });
    }

    Ok(entries)
}

/// Generate an OpenVEX JSON document from triage entries.
pub fn generate_openvex_json(entries: &[TriageEntry]) -> Result<String, String> {
    let statements: Vec<OpenVexStatement> = entries
        .iter()
        .map(|e| {
            let status = match e.status {
                TriageStatus::NotAffected | TriageStatus::FalsePositive => "not_affected",
                TriageStatus::Confirmed | TriageStatus::NewFound => "affected",
                TriageStatus::Mitigated => "fixed",
                TriageStatus::Unexplored => "under_investigation",
            };

            OpenVexStatement {
                vulnerability: Some(OpenVexVulnerability {
                    name: Some(e.cve_id.clone()),
                }),
                status: Some(status.to_string()),
                justification: e.justification.clone(),
                products: e.component.as_ref().map(|c| {
                    vec![OpenVexProduct {
                        id: Some(c.clone()),
                    }]
                }),
            }
        })
        .collect();

    let doc = OpenVexDocument {
        context: "https://openvex.dev/ns/v0.2.0".to_string(),
        id: format!("corvex-vex-{}", uuid::Uuid::new_v4()),
        author: "Corvex Scanner".to_string(),
        timestamp: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        statements: Some(statements),
    };

    serde_json::to_string_pretty(&doc).map_err(|e| format!("generate OpenVEX: {e}"))
}

// ---- OpenVEX JSON schema types ----

#[derive(Debug, Serialize, Deserialize)]
struct OpenVexDocument {
    #[serde(rename = "@context")]
    context: String,
    #[serde(rename = "@id")]
    id: String,
    author: String,
    timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    statements: Option<Vec<OpenVexStatement>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenVexStatement {
    #[serde(skip_serializing_if = "Option::is_none")]
    vulnerability: Option<OpenVexVulnerability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    justification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    products: Option<Vec<OpenVexProduct>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenVexVulnerability {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenVexProduct {
    #[serde(rename = "@id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}
