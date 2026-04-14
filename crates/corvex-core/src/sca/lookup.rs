//! SCA vulnerability lookup — cross-references detected components against the CVE database.

use crate::sca::component::Component;
use crate::sca::cpe_map;
use crate::vulndb::models::{EpssScore, FixInfo};
use crate::vulndb::VulnDb;

/// A vulnerability finding for a specific component.
#[derive(Debug, Clone)]
pub struct ScaFinding {
    pub component: Component,
    pub cve_id: String,
    pub description: String,
    pub cvss_score: Option<f32>,
    pub severity: Option<String>,
    pub epss: Option<EpssScore>,
    pub fixes: Vec<FixInfo>,
}

/// Look up all known vulnerabilities for a set of components.
pub fn lookup_components(
    db: &VulnDb,
    components: &[Component],
    epss_threshold: Option<f32>,
    epss_percentile_min: Option<f32>,
) -> Vec<ScaFinding> {
    let mut findings = Vec::new();

    for component in components {
        // Determine CPE vendor:product
        let (vendor, product) = if let Some(mapping) =
            cpe_map::lookup_cpe(component.ecosystem, &component.name)
        {
            (mapping.0.to_string(), mapping.1.to_string())
        } else {
            let (v, p) = cpe_map::guess_cpe(&component.name);
            (v, p)
        };

        // Query the vulnerability database
        match db.lookup_component(&vendor, &product, &component.version) {
            Ok(cves) => {
                for (cve, epss) in cves {
                    // Apply EPSS filters
                    if let Some(threshold) = epss_threshold {
                        if let Some(ref e) = epss {
                            if e.score < threshold {
                                continue;
                            }
                        } else {
                            continue; // No EPSS data, skip if threshold is set
                        }
                    }
                    if let Some(percentile_min) = epss_percentile_min {
                        if let Some(ref e) = epss {
                            if e.percentile * 100.0 < percentile_min {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }

                    let fixes = db.get_fixes(&cve.cve_id).unwrap_or_default();

                    findings.push(ScaFinding {
                        component: component.clone(),
                        cve_id: cve.cve_id.clone(),
                        description: cve.description.clone(),
                        cvss_score: cve.cvss_v31_score,
                        severity: cve.severity.clone(),
                        epss,
                        fixes,
                    });
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "sca",
                    "CVE lookup failed for {} {}: {}",
                    component.name,
                    component.version,
                    e
                );
            }
        }
    }

    // Sort by CVSS score (highest first)
    findings.sort_by(|a, b| {
        b.cvss_score
            .unwrap_or(0.0)
            .partial_cmp(&a.cvss_score.unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    findings
}
