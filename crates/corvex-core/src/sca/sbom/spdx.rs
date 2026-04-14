//! SPDX SBOM parser and generator.
//!
//! Supports SPDX 2.3 JSON and Tag-Value formats.

use crate::sca::component::{Component, Ecosystem};
use serde::{Deserialize, Serialize};

/// Parse an SPDX JSON SBOM.
pub fn parse_json(content: &str) -> Result<Vec<Component>, String> {
    let doc: SpdxDocument =
        serde_json::from_str(content).map_err(|e| format!("SPDX JSON parse: {e}"))?;

    let mut components = Vec::new();
    for pkg in doc.packages.unwrap_or_default() {
        // Skip the document-describes package (the root)
        if pkg.spdxid == "SPDXRef-DOCUMENT" {
            continue;
        }

        let version = pkg.version_info.unwrap_or_default();
        if pkg.name.is_empty() || version.is_empty() || version == "NOASSERTION" {
            continue;
        }

        let ecosystem = pkg
            .external_refs
            .as_ref()
            .and_then(|refs| {
                refs.iter().find_map(|r| {
                    if r.reference_type == "purl" {
                        purl_ecosystem(Some(&r.reference_locator))
                    } else {
                        None
                    }
                })
            })
            .unwrap_or(Ecosystem::Unknown);

        let purl = pkg.external_refs.as_ref().and_then(|refs| {
            refs.iter()
                .find(|r| r.reference_type == "purl")
                .map(|r| r.reference_locator.clone())
        });

        let mut c = Component::new(&pkg.name, &version, ecosystem);
        c.purl = purl;
        c.vendor = pkg.supplier.and_then(|s| {
            s.strip_prefix("Organization: ")
                .map(|o| o.to_string())
        });
        c.license = pkg.license_concluded.and_then(|l| {
            if l == "NOASSERTION" {
                None
            } else {
                Some(l)
            }
        });
        c.description = pkg.description;
        components.push(c);
    }

    Ok(components)
}

/// Parse an SPDX Tag-Value format SBOM.
pub fn parse_tag_value(content: &str) -> Result<Vec<Component>, String> {
    let mut components = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut purl: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();

            match key {
                "PackageName" => {
                    // Emit previous package
                    if let (Some(n), Some(v)) = (name.take(), version.take()) {
                        let mut c = Component::new(&n, &v, Ecosystem::Unknown);
                        c.purl = purl.take();
                        components.push(c);
                    }
                    name = Some(value.to_string());
                    version = None;
                    purl = None;
                }
                "PackageVersion" => {
                    if value != "NOASSERTION" {
                        version = Some(value.to_string());
                    }
                }
                "ExternalRef" => {
                    // Format: PACKAGE-MANAGER purl pkg:type/name@version
                    if value.contains("purl") {
                        if let Some(p) = value.split_whitespace().last() {
                            if p.starts_with("pkg:") {
                                purl = Some(p.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Emit last package
    if let (Some(n), Some(v)) = (name, version) {
        let mut c = Component::new(&n, &v, Ecosystem::Unknown);
        c.purl = purl;
        components.push(c);
    }

    Ok(components)
}

/// Generate an SPDX 2.3 JSON SBOM from components.
pub fn generate_json(components: &[Component]) -> Result<String, String> {
    let packages: Vec<SpdxPackage> = components
        .iter()
        .enumerate()
        .map(|(i, c)| SpdxPackage {
            spdxid: format!("SPDXRef-Package-{}", i),
            name: c.name.clone(),
            version_info: Some(c.version.clone()),
            download_location: "NOASSERTION".to_string(),
            files_analyzed: false,
            supplier: c.vendor.as_ref().map(|v| format!("Organization: {v}")),
            license_concluded: c.license.clone(),
            description: c.description.clone(),
            external_refs: c.purl.as_ref().map(|p| {
                vec![SpdxExternalRef {
                    reference_category: "PACKAGE-MANAGER".to_string(),
                    reference_type: "purl".to_string(),
                    reference_locator: p.clone(),
                }]
            }),
        })
        .collect();

    let doc = SpdxDocument {
        spdx_version: "SPDX-2.3".to_string(),
        data_license: "CC0-1.0".to_string(),
        spdxid: "SPDXRef-DOCUMENT".to_string(),
        name: "corvex-scan-result".to_string(),
        document_namespace: format!(
            "https://corvex.io/spdx/{}",
            uuid::Uuid::new_v4()
        ),
        packages: Some(packages),
    };

    serde_json::to_string_pretty(&doc).map_err(|e| format!("SPDX JSON generate: {e}"))
}

/// Generate an SPDX 2.3 Tag-Value format SBOM from components.
pub fn generate_tag_value(components: &[Component]) -> Result<String, String> {
    let mut output = String::new();
    output.push_str("SPDXVersion: SPDX-2.3\n");
    output.push_str("DataLicense: CC0-1.0\n");
    output.push_str("SPDXID: SPDXRef-DOCUMENT\n");
    output.push_str("DocumentName: corvex-scan-result\n");
    output.push_str(&format!(
        "DocumentNamespace: https://corvex.io/spdx/{}\n",
        uuid::Uuid::new_v4()
    ));
    output.push('\n');

    for (i, c) in components.iter().enumerate() {
        output.push_str(&format!("PackageName: {}\n", c.name));
        output.push_str(&format!("SPDXID: SPDXRef-Package-{}\n", i));
        output.push_str(&format!("PackageVersion: {}\n", c.version));
        output.push_str("PackageDownloadLocation: NOASSERTION\n");
        output.push_str("FilesAnalyzed: false\n");
        if let Some(ref purl) = c.purl {
            output.push_str(&format!(
                "ExternalRef: PACKAGE-MANAGER purl {}\n",
                purl
            ));
        }
        if let Some(ref license) = c.license {
            output.push_str(&format!("PackageLicenseConcluded: {}\n", license));
        } else {
            output.push_str("PackageLicenseConcluded: NOASSERTION\n");
        }
        output.push_str("PackageLicenseDeclared: NOASSERTION\n");
        output.push_str("PackageCopyrightText: NOASSERTION\n");
        output.push('\n');
    }

    Ok(output)
}

fn purl_ecosystem(purl: Option<&str>) -> Option<Ecosystem> {
    let purl = purl?;
    let rest = purl.strip_prefix("pkg:")?;
    let pkg_type = rest.split('/').next()?;
    Some(match pkg_type {
        "cargo" => Ecosystem::Cargo,
        "npm" => Ecosystem::Npm,
        "pypi" => Ecosystem::PyPI,
        "maven" => Ecosystem::Maven,
        "golang" => Ecosystem::Go,
        "gem" => Ecosystem::RubyGems,
        "composer" => Ecosystem::Packagist,
        "nuget" => Ecosystem::NuGet,
        _ => Ecosystem::Unknown,
    })
}

// ---- SPDX JSON schema types ----

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxDocument {
    spdx_version: String,
    data_license: String,
    #[serde(rename = "SPDXID")]
    spdxid: String,
    name: String,
    document_namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    packages: Option<Vec<SpdxPackage>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdxid: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_info: Option<String>,
    download_location: String,
    files_analyzed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    supplier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    license_concluded: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_refs: Option<Vec<SpdxExternalRef>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxExternalRef {
    reference_category: String,
    reference_type: String,
    reference_locator: String,
}
