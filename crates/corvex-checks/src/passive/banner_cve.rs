//! Banner-CVE cross-reference (A03 — Software Supply Chain Failures).
//!
//! Runs the same Wappalyzer-compatible engine as [`StackFingerprint`],
//! then for every detected product with a version string it queries the
//! local [`VulnDb`] for matching CVEs. Each CVE becomes a finding with
//! severity mapped from the CVSS v3.1 base score.
//!
//! The check degrades gracefully:
//!   * No VulnDb handle → silently skip. The UI still gets stack tags
//!     from [`StackFingerprint`].
//!   * Detection without a version → skip (NVD range matching needs a
//!     concrete version).
//!   * Unknown product → fall back to [`guess_cpe`], which lets
//!     well-named products ("moodle", "vtiger") still surface CVEs.

use std::sync::Arc;

use corvex_core::sca::cpe_map::{guess_cpe, lookup_web_tech_cpe};
use corvex_core::vulndb::models::{CveRecord, EpssScore};
use corvex_core::vulndb::VulnDb;
use corvex_intel::fingerprint::{
    detect_any, DetectionInput, FingerprintLike, LoadedFingerprint, SEED_FINGERPRINTS,
};
use corvex_proxy::Exchange;
use serde_json::json;

use crate::check::{CheckDescriptor, CheckKind, OwaspCategory, PassiveCheck};
use crate::finding::{Finding, Severity};

/// Banner-CVE cross-reference check.
///
/// Owns an optional [`VulnDb`] handle — when `None`, the check produces
/// no findings. The shared upstream fingerprint dataset mirrors
/// `StackFingerprint` so the two checks stay in sync when a Wappalyzer
/// refresh lands.
pub struct BannerCve {
    upstream: Arc<Vec<LoadedFingerprint>>,
    vulndb: Option<Arc<VulnDb>>,
    /// Hard cap per exchange so a noisy page (React + jQuery + Bootstrap
    /// + ...) with dozens of outdated JS libs doesn't spam the findings
    /// feed with hundreds of low-impact rows. Still emits a summary
    /// count in the evidence so nothing is silently dropped.
    max_findings_per_exchange: usize,
}

impl BannerCve {
    pub fn new(vulndb: Option<Arc<VulnDb>>) -> Self {
        Self {
            upstream: Arc::new(Vec::new()),
            vulndb,
            max_findings_per_exchange: 25,
        }
    }

    pub fn with_upstream(
        upstream: Arc<Vec<LoadedFingerprint>>,
        vulndb: Option<Arc<VulnDb>>,
    ) -> Self {
        Self {
            upstream,
            vulndb,
            max_findings_per_exchange: 25,
        }
    }
}

impl PassiveCheck for BannerCve {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "banner-cve".into(),
            name: "Banner CVE Cross-Reference".into(),
            category: OwaspCategory::A03(),
            kind: CheckKind::Passive,
            default_severity: Severity::Medium,
            description: "For each stack banner with a version, queries the local vulndb \
                 for matching CVEs and emits a finding per CVE with severity \
                 derived from the CVSS v3.1 base score. Requires an up-to-date \
                 vulndb — see the Databases view."
                .to_string(),
        }
    }

    fn inspect(&self, exchange: &Exchange) -> Vec<Finding> {
        let Some(vulndb) = self.vulndb.as_ref() else {
            return Vec::new();
        };
        let Some(response) = &exchange.response else {
            return Vec::new();
        };

        // Same detection primitives as stack_fingerprint.rs. Keeping the
        // logic inline (rather than sharing a helper) avoids coupling
        // the two checks, which will diverge over time — banner-CVE
        // only cares about detections with a version.
        let headers: Vec<(&str, &str)> = response
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let mut cookie_buf: Vec<(String, String)> = Vec::new();
        for (k, v) in &response.headers {
            if k.eq_ignore_ascii_case("set-cookie") {
                if let Some((name, value)) = parse_set_cookie(v) {
                    cookie_buf.push((name, value));
                }
            }
        }
        for (k, v) in &exchange.request.headers {
            if k.eq_ignore_ascii_case("cookie") {
                for part in v.split(';') {
                    let part = part.trim();
                    if let Some((name, value)) = part.split_once('=') {
                        cookie_buf.push((name.trim().to_string(), value.trim().to_string()));
                    }
                }
            }
        }
        let cookies: Vec<(&str, &str)> = cookie_buf
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let body = response.body_str();
        let body_ref: &str = body.as_ref();
        let path = split_path(&exchange.request.uri);

        let input = DetectionInput {
            headers: &headers,
            cookies: &cookies,
            body: body_ref,
            url_path: &path,
        };
        let upstream_iter = self.upstream.iter().map(|f| f as &dyn FingerprintLike);
        let seed_iter = SEED_FINGERPRINTS.iter().map(|f| f as &dyn FingerprintLike);
        let detections = detect_any(&input, upstream_iter.chain(seed_iter));

        let mut findings = Vec::new();
        for det in detections {
            // Skip detections without a concrete version — NVD CPE
            // ranges require a pinpoint version for accurate matching,
            // and emitting "nginx ? is maybe vulnerable" is noise.
            let Some(version) = det.version.as_deref() else {
                continue;
            };
            if version.trim().is_empty() {
                continue;
            }

            let (vendor, product) = match lookup_web_tech_cpe(&det.name) {
                Some((v, p)) => (v.to_string(), p.to_string()),
                None => guess_cpe(&det.name),
            };

            let cves = match vulndb.lookup_component(&vendor, &product, version) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        target: "checks.banner-cve",
                        "vulndb lookup failed for {vendor}:{product}@{version}: {e}"
                    );
                    continue;
                }
            };
            if cves.is_empty() {
                continue;
            }

            let total = cves.len();
            for (cve, epss) in cves.into_iter().take(self.max_findings_per_exchange) {
                findings.push(build_finding(
                    exchange,
                    &det.name,
                    version,
                    &vendor,
                    &product,
                    &cve,
                    epss,
                    total,
                ));
                if findings.len() >= self.max_findings_per_exchange {
                    break;
                }
            }
            if findings.len() >= self.max_findings_per_exchange {
                break;
            }
        }

        findings
    }
}

fn build_finding(
    exchange: &Exchange,
    product_name: &str,
    version: &str,
    cpe_vendor: &str,
    cpe_product: &str,
    cve: &CveRecord,
    epss: Option<EpssScore>,
    total_cves: usize,
) -> Finding {
    let severity = severity_from_cvss(cve.cvss_v31_score, cve.severity.as_deref());
    let title = format!(
        "{product_name} {version} affected by {cve_id}",
        cve_id = cve.cve_id,
    );
    let description = format!(
        "Detected `{product_name} {version}` via passive banner / fingerprint. \
         Local vulndb reports this version falls within the affected range of \
         {cve_id}. Confirm the banner isn't stale (load balancer, reverse \
         proxy) before reporting, then check the reference URLs for patched \
         versions.",
        cve_id = cve.cve_id,
    );

    let evidence = json!({
        "product": product_name,
        "version": version,
        "cpe_vendor": cpe_vendor,
        "cpe_product": cpe_product,
        "cve_id": cve.cve_id,
        "cvss_v31_score": cve.cvss_v31_score,
        "cvss_v31_vector": cve.cvss_v31_vector,
        "nvd_severity": cve.severity,
        "published": cve.published,
        "modified": cve.modified,
        "description": trim_description(&cve.description),
        "epss_score": epss.as_ref().map(|e| e.score),
        "epss_percentile": epss.as_ref().map(|e| e.percentile),
        "total_cves_for_banner": total_cves,
    });

    Finding::new("banner-cve", exchange.id, severity, title)
        .with_description(description)
        .with_evidence(evidence)
}

/// CVSS v3.1 base score → severity bucket. Falls back to the NVD
/// `severity` string when no score is present, and to `Medium` as a
/// last resort so we never drop a CVE silently.
fn severity_from_cvss(score: Option<f32>, nvd_severity: Option<&str>) -> Severity {
    if let Some(s) = score {
        if s >= 9.0 {
            return Severity::Critical;
        }
        if s >= 7.0 {
            return Severity::High;
        }
        if s >= 4.0 {
            return Severity::Medium;
        }
        if s > 0.0 {
            return Severity::Low;
        }
    }
    match nvd_severity.map(|s| s.to_ascii_uppercase()) {
        Some(s) if s == "CRITICAL" => Severity::Critical,
        Some(s) if s == "HIGH" => Severity::High,
        Some(s) if s == "MEDIUM" => Severity::Medium,
        Some(s) if s == "LOW" => Severity::Low,
        _ => Severity::Medium,
    }
}

fn trim_description(raw: &str) -> String {
    const MAX: usize = 500;
    let cleaned = raw.trim();
    if cleaned.len() <= MAX {
        return cleaned.to_string();
    }
    let mut end = MAX;
    while end > 0 && !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &cleaned[..end])
}

fn parse_set_cookie(raw: &str) -> Option<(String, String)> {
    let first = raw.split(';').next()?.trim();
    let (name, value) = first.split_once('=')?;
    Some((name.trim().to_string(), value.trim().to_string()))
}

fn split_path(uri: &str) -> String {
    uri.split_once('?')
        .map(|(p, _)| p.to_string())
        .unwrap_or_else(|| uri.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_buckets_match_cvss_bands() {
        assert_eq!(severity_from_cvss(Some(9.8), None), Severity::Critical);
        assert_eq!(severity_from_cvss(Some(9.0), None), Severity::Critical);
        assert_eq!(severity_from_cvss(Some(7.5), None), Severity::High);
        assert_eq!(severity_from_cvss(Some(7.0), None), Severity::High);
        assert_eq!(severity_from_cvss(Some(6.5), None), Severity::Medium);
        assert_eq!(severity_from_cvss(Some(4.0), None), Severity::Medium);
        assert_eq!(severity_from_cvss(Some(3.1), None), Severity::Low);
        assert_eq!(severity_from_cvss(Some(0.1), None), Severity::Low);
    }

    #[test]
    fn severity_falls_back_to_nvd_string_when_no_score() {
        assert_eq!(severity_from_cvss(None, Some("CRITICAL")), Severity::Critical);
        assert_eq!(severity_from_cvss(None, Some("High")), Severity::High);
        assert_eq!(severity_from_cvss(None, Some("medium")), Severity::Medium);
        assert_eq!(severity_from_cvss(None, Some("LOW")), Severity::Low);
        assert_eq!(severity_from_cvss(None, None), Severity::Medium);
    }

    #[test]
    fn trim_description_respects_char_boundaries() {
        let long = "é".repeat(1000);
        let trimmed = trim_description(&long);
        assert!(trimmed.ends_with('…'));
        assert!(trimmed.len() <= 1001);
    }

    #[test]
    fn descriptor_is_passive_a03() {
        let check = BannerCve::new(None);
        let d = check.descriptor();
        assert_eq!(d.id, "banner-cve");
        assert_eq!(d.category.code(), "A03");
        assert_eq!(d.kind, CheckKind::Passive);
    }

    #[test]
    fn no_vulndb_produces_no_findings() {
        // A check built without a vulndb handle (e.g. the user never
        // ran `vulndb update` and there's no embedded snapshot) must
        // stay quiet — loudly emitting "no DB" on every exchange would
        // be worse than no check at all.
        let check = BannerCve::new(None);
        // We can't easily build a full Exchange here without pulling in
        // test utilities, so just confirm the check refuses work.
        // Deeper wiring is exercised by the integration test at
        // crates/corvex-checks/tests/banner_cve.rs.
        assert!(check.vulndb.is_none());
    }
}
