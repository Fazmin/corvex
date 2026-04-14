//! VEX (Vulnerability Exploitability eXchange) support.
//!
//! Provides parsing and generation of VEX documents in CycloneDX and OpenVEX
//! formats, along with a vulnerability triage system.

pub mod cyclonedx_vex;
pub mod openvex;
pub mod triage;

use crate::vex::triage::TriageEntry;
use std::path::Path;

/// VEX document format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VexFormat {
    CycloneDx,
    OpenVex,
}

impl VexFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "cyclonedx" | "cdx" => Some(Self::CycloneDx),
            "openvex" | "vex" => Some(Self::OpenVex),
            _ => None,
        }
    }
}

/// Parse a VEX document file (auto-detects format).
pub fn parse_vex_file(path: &Path) -> Result<Vec<TriageEntry>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

    let content_trimmed = content.trim();
    if !content_trimmed.starts_with('{') {
        return Err("VEX file must be JSON".to_string());
    }

    // Try CycloneDX first (has bomFormat field)
    if content_trimmed.contains("\"bomFormat\"") {
        return cyclonedx_vex::parse_vex_json(&content);
    }

    // Try OpenVEX (has @context field)
    if content_trimmed.contains("\"@context\"") {
        return openvex::parse_openvex_json(&content);
    }

    // Default to CycloneDX
    cyclonedx_vex::parse_vex_json(&content)
}

/// Generate a VEX document from triage entries.
pub fn generate_vex(
    entries: &[TriageEntry],
    format: VexFormat,
    path: &Path,
) -> Result<(), String> {
    let content = match format {
        VexFormat::CycloneDx => cyclonedx_vex::generate_vex_json(entries)?,
        VexFormat::OpenVex => openvex::generate_openvex_json(entries)?,
    };

    std::fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))?;
    tracing::info!(target: "vex", "generated VEX document at {}", path.display());
    Ok(())
}
