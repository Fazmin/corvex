//! CycloneDX SBOM parser and generator.
//!
//! Supports CycloneDX 1.4/1.5 JSON and XML formats.

use crate::sca::component::{Component, Ecosystem};
use serde::{Deserialize, Serialize};

/// Parse a CycloneDX JSON SBOM.
pub fn parse_json(content: &str) -> Result<Vec<Component>, String> {
    let doc: CdxDocument =
        serde_json::from_str(content).map_err(|e| format!("CycloneDX JSON parse: {e}"))?;

    let mut components = Vec::new();
    for comp in doc.components.unwrap_or_default() {
        let ecosystem = purl_ecosystem(comp.purl.as_deref());
        let version = comp.version.unwrap_or_default();
        if !comp.name.is_empty() && !version.is_empty() {
            let mut c = Component::new(&comp.name, &version, ecosystem);
            c.purl = comp.purl;
            c.license = comp
                .licenses
                .and_then(|ls| ls.first().cloned())
                .and_then(|l| l.license)
                .map(|l| l.id.unwrap_or(l.name.unwrap_or_default()));
            c.description = comp.description;
            c.vendor = comp.publisher.or(comp.group);
            components.push(c);
        }
    }

    Ok(components)
}

/// Parse a CycloneDX XML SBOM (simplified — extracts components).
pub fn parse_xml(content: &str) -> Result<Vec<Component>, String> {
    let mut components = Vec::new();
    let mut in_component = false;
    let mut name = String::new();
    let mut version = String::new();
    let mut purl = String::new();
    let mut current_tag = String::new();

    for event in xml::EventReader::from_str(content) {
        match event {
            Ok(xml::reader::XmlEvent::StartElement {
                name: tag_name, ..
            }) => {
                current_tag = tag_name.local_name.clone();
                if current_tag == "component" {
                    in_component = true;
                    name.clear();
                    version.clear();
                    purl.clear();
                }
            }
            Ok(xml::reader::XmlEvent::EndElement {
                name: tag_name, ..
            }) => {
                if tag_name.local_name == "component" && in_component {
                    if !name.is_empty() && !version.is_empty() {
                        let ecosystem = purl_ecosystem(if purl.is_empty() {
                            None
                        } else {
                            Some(purl.as_str())
                        });
                        let mut c = Component::new(&name, &version, ecosystem);
                        if !purl.is_empty() {
                            c.purl = Some(purl.clone());
                        }
                        components.push(c);
                    }
                    in_component = false;
                }
            }
            Ok(xml::reader::XmlEvent::Characters(text)) => {
                if in_component {
                    match current_tag.as_str() {
                        "name" => name = text,
                        "version" => version = text,
                        "purl" => purl = text,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    Ok(components)
}

/// Generate a CycloneDX 1.5 JSON SBOM from components.
pub fn generate_json(components: &[Component]) -> Result<String, String> {
    let doc = CdxDocument {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.5".to_string(),
        version: 1,
        components: Some(
            components
                .iter()
                .map(|c| CdxComponent {
                    component_type: "library".to_string(),
                    name: c.name.clone(),
                    version: Some(c.version.clone()),
                    purl: c.purl.clone(),
                    group: c.vendor.clone(),
                    publisher: None,
                    description: c.description.clone(),
                    licenses: c.license.as_ref().map(|l| {
                        vec![CdxLicenseWrapper {
                            license: Some(CdxLicense {
                                id: Some(l.clone()),
                                name: None,
                            }),
                        }]
                    }),
                })
                .collect(),
        ),
    };

    serde_json::to_string_pretty(&doc).map_err(|e| format!("CycloneDX JSON generate: {e}"))
}

/// Generate a CycloneDX XML SBOM from components (simplified).
pub fn generate_xml(components: &[Component]) -> Result<String, String> {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<bom xmlns=\"http://cyclonedx.org/schema/bom/1.5\" version=\"1\">\n");
    xml.push_str("  <components>\n");

    for c in components {
        xml.push_str("    <component type=\"library\">\n");
        xml.push_str(&format!("      <name>{}</name>\n", escape_xml(&c.name)));
        xml.push_str(&format!(
            "      <version>{}</version>\n",
            escape_xml(&c.version)
        ));
        if let Some(ref purl) = c.purl {
            xml.push_str(&format!("      <purl>{}</purl>\n", escape_xml(purl)));
        }
        xml.push_str("    </component>\n");
    }

    xml.push_str("  </components>\n");
    xml.push_str("</bom>\n");
    Ok(xml)
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Determine ecosystem from a Package URL.
fn purl_ecosystem(purl: Option<&str>) -> Ecosystem {
    let Some(purl) = purl else {
        return Ecosystem::Unknown;
    };
    if let Some(rest) = purl.strip_prefix("pkg:") {
        let pkg_type = rest.split('/').next().unwrap_or("");
        match pkg_type {
            "cargo" => Ecosystem::Cargo,
            "npm" => Ecosystem::Npm,
            "pypi" => Ecosystem::PyPI,
            "maven" => Ecosystem::Maven,
            "golang" => Ecosystem::Go,
            "gem" => Ecosystem::RubyGems,
            "composer" => Ecosystem::Packagist,
            "nuget" => Ecosystem::NuGet,
            _ => Ecosystem::Unknown,
        }
    } else {
        Ecosystem::Unknown
    }
}

// ---- CycloneDX JSON schema types ----

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxDocument {
    bom_format: String,
    spec_version: String,
    version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    components: Option<Vec<CdxComponent>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxComponent {
    #[serde(rename = "type")]
    component_type: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    publisher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    licenses: Option<Vec<CdxLicenseWrapper>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CdxLicenseWrapper {
    #[serde(skip_serializing_if = "Option::is_none")]
    license: Option<CdxLicense>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CdxLicense {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}
