//! Integration tests for the Banner-CVE cross-reference check.
//!
//! Builds a throwaway [`VulnDb`] in a temp directory, seeds it with a
//! couple of synthesized NVD records (one matching nginx 1.18.x, one
//! for a different product), and verifies that the Banner-CVE check
//! produces a finding for the matching banner and stays quiet for
//! versions outside the affected range.

use std::path::PathBuf;
use std::sync::Arc;

use corvex_checks::passive::BannerCve;
use corvex_checks::{CheckKind, PassiveCheck, Severity};
use corvex_core::vulndb::nvd::NvdCveItem;
use corvex_core::vulndb::VulnDb;
use indexmap::IndexMap;
use serde_json::json;
use uuid::Uuid;

use corvex_core::http::request::Request as CoreReq;
use corvex_core::http::response::Response as CoreResp;
use corvex_proxy::{Exchange, ExchangeOrigin, ScopeDecision, SessionId};

/// RAII guard so test DBs get cleaned up even if a test panics.
struct TempDbPath(PathBuf);

impl TempDbPath {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("corvex-banner-cve-{}.sqlite", Uuid::new_v4()));
        Self(p)
    }
}

impl Drop for TempDbPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        // SQLite WAL + SHM files live next to the main DB.
        let mut wal = self.0.clone();
        wal.set_extension("sqlite-wal");
        let _ = std::fs::remove_file(&wal);
        let mut shm = self.0.clone();
        shm.set_extension("sqlite-shm");
        let _ = std::fs::remove_file(&shm);
    }
}

fn headers_from(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
    let mut m = IndexMap::new();
    for (k, v) in pairs {
        m.insert((*k).to_string(), (*v).to_string());
    }
    m
}

fn synth_exchange(response_headers: &[(&str, &str)]) -> Exchange {
    let mut req = CoreReq::new("example.com", 443, "GET", "/");
    req.ssl = true;
    let resp = CoreResp {
        status: 200,
        status_text: "OK".into(),
        version: "1.1".into(),
        headers: headers_from(response_headers),
        body: b"<html></html>".to_vec(),
        error: None,
        tls: None,
        elapsed: std::time::Duration::ZERO,
    };
    let mut ex = Exchange::new(
        SessionId::new(),
        ExchangeOrigin::Imported { source: "test".into() },
        req,
        ScopeDecision::InScope,
    );
    ex.response = Some(resp);
    ex
}

/// Build an NVD-shaped JSON record for a CVE covering `vendor:product`
/// in the inclusive range `[start, end]`. Parsing it through serde
/// keeps the test resilient to private field changes in NvdCveItem.
fn nvd_item(
    cve_id: &str,
    vendor: &str,
    product: &str,
    version_start_including: &str,
    version_end_including: &str,
    cvss: f32,
    severity: &str,
) -> NvdCveItem {
    let value = json!({
        "cve": {
            "id": cve_id,
            "descriptions": [
                { "lang": "en", "value": format!("Synthesized test CVE for {product}") }
            ],
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-02T00:00:00.000",
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": cvss,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseSeverity": severity,
                    }
                }]
            },
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "criteria": format!("cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"),
                        "vulnerable": true,
                        "versionStartIncluding": version_start_including,
                        "versionEndIncluding": version_end_including,
                    }]
                }]
            }],
            "references": []
        }
    });
    serde_json::from_value(value).expect("synthesised NVD item must parse")
}

fn open_seeded_db(items: &[NvdCveItem]) -> (TempDbPath, Arc<VulnDb>) {
    let tmp = TempDbPath::new();
    let db = VulnDb::open(&tmp.0).expect("open temp vulndb");
    db.upsert_nvd_batch(items).expect("seed vulndb");
    (tmp, Arc::new(db))
}

#[test]
fn banner_cve_flags_vulnerable_nginx_version() {
    let items = [
        nvd_item(
            "CVE-2021-23017",
            "nginx",
            "nginx",
            "0.6.18",
            "1.20.0",
            7.7,
            "HIGH",
        ),
    ];
    let (_tmp, db) = open_seeded_db(&items);

    let check = BannerCve::new(Some(db));
    let ex = synth_exchange(&[
        ("Server", "nginx/1.18.0"),
        ("Content-Type", "text/html"),
    ]);
    let findings = check.inspect(&ex);
    assert!(
        !findings.is_empty(),
        "expected at least one banner-cve finding, got none"
    );
    let hit = findings
        .iter()
        .find(|f| f.title.contains("CVE-2021-23017"))
        .expect("CVE-2021-23017 finding missing");
    assert_eq!(hit.check_id, "banner-cve");
    assert!(
        matches!(hit.severity, Severity::High | Severity::Critical),
        "expected High/Critical severity for CVSS 7.7, got {:?}",
        hit.severity
    );
    let evidence = &hit.evidence;
    assert_eq!(evidence["product"].as_str(), Some("nginx"));
    assert_eq!(evidence["version"].as_str(), Some("1.18.0"));
    assert_eq!(evidence["cpe_vendor"].as_str(), Some("nginx"));
    assert_eq!(evidence["cpe_product"].as_str(), Some("nginx"));
}

#[test]
fn banner_cve_stays_quiet_for_patched_version() {
    // Same CVE as above (end_including 1.20.0) — the banner claims
    // nginx 1.25.0 which is outside the affected range.
    let items = [
        nvd_item(
            "CVE-2021-23017",
            "nginx",
            "nginx",
            "0.6.18",
            "1.20.0",
            7.7,
            "HIGH",
        ),
    ];
    let (_tmp, db) = open_seeded_db(&items);

    let check = BannerCve::new(Some(db));
    let ex = synth_exchange(&[("Server", "nginx/1.25.0")]);
    let findings = check.inspect(&ex);
    assert!(
        findings.is_empty(),
        "patched nginx 1.25.0 should not raise banner-cve findings, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[test]
fn banner_cve_skips_when_no_version_in_banner() {
    let items = [nvd_item(
        "CVE-2021-23017",
        "nginx",
        "nginx",
        "0.6.18",
        "1.20.0",
        7.7,
        "HIGH",
    )];
    let (_tmp, db) = open_seeded_db(&items);

    let check = BannerCve::new(Some(db));
    // Bare `nginx` banner with no version — the check must not guess.
    let ex = synth_exchange(&[("Server", "nginx")]);
    let findings = check.inspect(&ex);
    assert!(
        findings.is_empty(),
        "versionless banner should be skipped, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[test]
fn banner_cve_noop_when_vulndb_is_missing() {
    // The check is constructed without a vulndb — must not produce any
    // findings regardless of the banner.
    let check = BannerCve::new(None);
    let ex = synth_exchange(&[("Server", "nginx/1.18.0")]);
    assert!(check.inspect(&ex).is_empty());
}

#[test]
fn descriptor_advertises_passive_a03_medium_default() {
    let check = BannerCve::new(None);
    let d = check.descriptor();
    assert_eq!(d.id, "banner-cve");
    assert_eq!(d.kind, CheckKind::Passive);
    assert_eq!(d.category.code(), "A03");
    assert_eq!(d.default_severity, Severity::Medium);
}
