//! SBOM (Software Bill of Materials) parsing and generation.

pub mod cyclonedx;
pub mod spdx;

use crate::sca::component::Component;
use std::path::Path;

/// Supported SBOM formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    CycloneDxJson,
    CycloneDxXml,
    SpdxJson,
    SpdxTagValue,
}

impl SbomFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "cyclonedx-json" | "cdx-json" => Some(Self::CycloneDxJson),
            "cyclonedx-xml" | "cdx-xml" => Some(Self::CycloneDxXml),
            "spdx-json" => Some(Self::SpdxJson),
            "spdx-tv" | "spdx-tag-value" => Some(Self::SpdxTagValue),
            _ => None,
        }
    }
}

/// Auto-detect SBOM format from file extension/content and parse components.
pub fn parse_sbom(path: &Path) -> Result<Vec<Component>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

    let content_trimmed = content.trim();

    // Detect format
    if content_trimmed.starts_with('{') {
        // JSON — try CycloneDX first, then SPDX
        if content_trimmed.contains("\"bomFormat\"") || content_trimmed.contains("\"components\"") {
            return cyclonedx::parse_json(&content);
        }
        if content_trimmed.contains("\"spdxVersion\"") || content_trimmed.contains("\"SPDX-") {
            return spdx::parse_json(&content);
        }
        // Default to CycloneDX JSON
        cyclonedx::parse_json(&content)
    } else if content_trimmed.starts_with('<') {
        // XML — CycloneDX
        cyclonedx::parse_xml(&content)
    } else if content_trimmed.starts_with("SPDXVersion:") {
        // SPDX Tag-Value
        spdx::parse_tag_value(&content)
    } else {
        Err(format!(
            "unrecognized SBOM format in {}",
            path.display()
        ))
    }
}

/// Generate an SBOM file from components.
pub fn generate_sbom(
    components: &[Component],
    format: SbomFormat,
    path: &Path,
) -> Result<(), String> {
    let content = match format {
        SbomFormat::CycloneDxJson => cyclonedx::generate_json(components)?,
        SbomFormat::CycloneDxXml => cyclonedx::generate_xml(components)?,
        SbomFormat::SpdxJson => spdx::generate_json(components)?,
        SbomFormat::SpdxTagValue => spdx::generate_tag_value(components)?,
    };

    std::fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))?;
    tracing::info!(target: "sca", "generated SBOM at {}", path.display());
    Ok(())
}
