//! Compliance and configuration auditing plugin.
//!
//! Analyses response headers, cookies, CORS configuration, and CSP policies
//! to produce a per-host compliance grade (A–F) plus individual findings.
//! Runs as a Postfetch hook (inspects each response) and emits a summary
//! finding with the overall grade once per host via the Recon hook.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use corvex_core::compliance::ComplianceScore;
use corvex_core::error::Result;
use corvex_core::http::request::Request;
use corvex_core::http::response::Response;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;

static INFO: PluginInfo = PluginInfo {
    name: "compliance",
    full_name: "Compliance Audit",
    description:
        "Security header, cookie, CORS, and CSP compliance analysis with A–F grading.",
    weight: 25,
    default: true,
    extra: false,
    hooks: &[HookKind::Postfetch],
};

pub struct CompliancePlugin {
    /// Guard so the summary grade is only emitted once per scan.
    emitted: AtomicBool,
}

impl Default for CompliancePlugin {
    fn default() -> Self {
        Self {
            emitted: AtomicBool::new(false),
        }
    }
}

// ---- Header analysis -------------------------------------------------------

fn check_hsts(value: &str, score: &mut ComplianceScore) {
    let lower = value.to_ascii_lowercase();

    // max-age present and >= 1 year (31536000)?
    let max_age: u64 = lower
        .split(';')
        .find_map(|p| {
            let p = p.trim();
            p.strip_prefix("max-age=")
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0);

    score.check(
        max_age >= 31_536_000,
        3,
        "headers",
        Severity::Medium,
        format!(
            "HSTS max-age is {max_age}s (recommended >= 31536000 / 1 year)."
        ),
        "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    );

    score.check(
        lower.contains("includesubdomains"),
        1,
        "headers",
        Severity::Low,
        "HSTS does not include includeSubDomains directive.",
        "Add includeSubDomains to the Strict-Transport-Security header.",
    );
}

fn check_csp(value: &str, score: &mut ComplianceScore) -> Vec<ReportItem> {
    let mut items = Vec::new();
    let lower = value.to_ascii_lowercase();

    let has_default = lower.contains("default-src");
    score.check(
        has_default,
        3,
        "csp",
        Severity::Medium,
        "CSP is missing a default-src directive.",
        "Add default-src 'self' as a fallback policy.",
    );

    let has_unsafe_inline = lower.contains("'unsafe-inline'");
    score.check(
        !has_unsafe_inline,
        3,
        "csp",
        Severity::Medium,
        "CSP allows 'unsafe-inline' — XSS mitigation is weakened.",
        "Remove 'unsafe-inline' and use nonce- or hash-based CSP.",
    );
    if has_unsafe_inline {
        items.push(ReportItem {
            corvex_id: "COMPLIANCE-CSP-UNSAFE-INLINE".into(),
            method: String::new(),
            uri: "/".into(),
            message: "CSP allows 'unsafe-inline' which weakens XSS protection.".into(),
            refs: String::new(),
            data: String::new(),
            plugin: INFO.name.to_string(),
            severity: Severity::Medium,
            ..Default::default()
        });
    }

    let has_unsafe_eval = lower.contains("'unsafe-eval'");
    score.check(
        !has_unsafe_eval,
        2,
        "csp",
        Severity::Medium,
        "CSP allows 'unsafe-eval' — code injection risk.",
        "Remove 'unsafe-eval' from CSP directives.",
    );
    if has_unsafe_eval {
        items.push(ReportItem {
            corvex_id: "COMPLIANCE-CSP-UNSAFE-EVAL".into(),
            method: String::new(),
            uri: "/".into(),
            message: "CSP allows 'unsafe-eval' which permits dynamic code execution.".into(),
            refs: String::new(),
            data: String::new(),
            plugin: INFO.name.to_string(),
            severity: Severity::Medium,
            ..Default::default()
        });
    }

    let has_wildcard = lower
        .split(';')
        .any(|d| d.split_whitespace().any(|t| t == "*"));
    score.check(
        !has_wildcard,
        2,
        "csp",
        Severity::Medium,
        "CSP contains a wildcard (*) source — effectively no restriction.",
        "Replace wildcard sources with explicit trusted origins.",
    );

    let has_frame_ancestors = lower.contains("frame-ancestors");
    score.check(
        has_frame_ancestors,
        1,
        "csp",
        Severity::Low,
        "CSP is missing frame-ancestors directive (clickjacking protection).",
        "Add frame-ancestors 'self' to your CSP.",
    );

    items
}

fn check_xframe(value: &str, score: &mut ComplianceScore) {
    let upper = value.to_ascii_uppercase();
    let ok = upper == "DENY" || upper == "SAMEORIGIN" || upper.starts_with("ALLOW-FROM");
    score.check(
        ok,
        2,
        "headers",
        Severity::Low,
        format!("X-Frame-Options has unexpected value: {value}"),
        "Set X-Frame-Options to DENY or SAMEORIGIN.",
    );
}

// ---- Cookie analysis -------------------------------------------------------

struct CookieFlags {
    secure: bool,
    httponly: bool,
    samesite: Option<String>,
    #[allow(dead_code)]
    path_slash: bool,
}

fn parse_cookie_flags(header_val: &str) -> (String, CookieFlags) {
    let parts: Vec<&str> = header_val.split(';').collect();
    let name = parts
        .first()
        .and_then(|p| p.split('=').next())
        .unwrap_or("")
        .trim()
        .to_string();

    let lower = header_val.to_ascii_lowercase();
    let secure = lower.contains("secure");
    let httponly = lower.contains("httponly");
    let samesite = lower
        .split(';')
        .find_map(|p| {
            let p = p.trim();
            p.strip_prefix("samesite=")
                .map(|v| v.trim().to_string())
        });
    let path_slash = lower
        .split(';')
        .any(|p| {
            let p = p.trim();
            p.starts_with("path=/") && p.len() <= 7 // path=/ or path=/;
        });

    (
        name,
        CookieFlags {
            secure,
            httponly,
            samesite,
            path_slash,
        },
    )
}

fn check_cookie(
    name: &str,
    flags: &CookieFlags,
    is_ssl: bool,
    score: &mut ComplianceScore,
) -> Vec<ReportItem> {
    let mut items = Vec::new();

    if is_ssl {
        score.check(
            flags.secure,
            2,
            "cookies",
            Severity::Medium,
            format!("Cookie '{name}' is missing the Secure flag on an HTTPS site."),
            "Add the Secure flag to all cookies on HTTPS sites.",
        );
        if !flags.secure {
            items.push(ReportItem {
                corvex_id: format!("COMPLIANCE-COOKIE-SECURE-{name}"),
                method: String::new(),
                uri: "/".into(),
                message: format!("Cookie '{name}' is missing the Secure flag."),
                refs: String::new(),
                data: String::new(),
                plugin: INFO.name.to_string(),
                severity: Severity::Medium,
                ..Default::default()
            });
        }
    }

    score.check(
        flags.httponly,
        2,
        "cookies",
        Severity::Low,
        format!("Cookie '{name}' is missing the HttpOnly flag."),
        "Add HttpOnly to prevent JavaScript access to session cookies.",
    );
    if !flags.httponly {
        items.push(ReportItem {
            corvex_id: format!("COMPLIANCE-COOKIE-HTTPONLY-{name}"),
            method: String::new(),
            uri: "/".into(),
            message: format!("Cookie '{name}' is missing the HttpOnly flag."),
            refs: String::new(),
            data: String::new(),
            plugin: INFO.name.to_string(),
            severity: Severity::Low,
            ..Default::default()
        });
    }

    // SameSite checks
    match &flags.samesite {
        Some(val) if val == "none" => {
            score.check(
                flags.secure,
                2,
                "cookies",
                Severity::Medium,
                format!("Cookie '{name}' has SameSite=None without the Secure flag."),
                "SameSite=None requires the Secure flag.",
            );
        }
        None => {
            score.check(
                false,
                1,
                "cookies",
                Severity::Low,
                format!("Cookie '{name}' is missing the SameSite attribute."),
                "Add SameSite=Lax or SameSite=Strict.",
            );
        }
        _ => {
            // Lax or Strict — good
            score.check(true, 1, "cookies", Severity::Low, "", "");
        }
    }

    items
}

// ---- CORS analysis ---------------------------------------------------------

fn check_cors(resp: &Response, score: &mut ComplianceScore) -> Vec<ReportItem> {
    let mut items = Vec::new();
    let acao = match resp.header("access-control-allow-origin") {
        Some(v) => v.to_string(),
        None => return items,
    };

    let creds = resp
        .header("access-control-allow-credentials")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    // Wildcard + credentials is a misconfiguration
    if acao.trim() == "*" && creds {
        score.check(
            false,
            4,
            "cors",
            Severity::High,
            "CORS allows wildcard origin (*) with Access-Control-Allow-Credentials: true.",
            "Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true.",
        );
        items.push(ReportItem {
            corvex_id: "COMPLIANCE-CORS-WILDCARD-CREDS".into(),
            method: String::new(),
            uri: "/".into(),
            message: "CORS misconfiguration: wildcard origin with credentials enabled."
                .into(),
            refs: String::new(),
            data: String::new(),
            plugin: INFO.name.to_string(),
            severity: Severity::High,
            ..Default::default()
        });
    } else if acao.trim() == "*" {
        score.check(
            false,
            2,
            "cors",
            Severity::Low,
            "CORS allows any origin (Access-Control-Allow-Origin: *).",
            "Restrict CORS to specific trusted origins.",
        );
        items.push(ReportItem {
            corvex_id: "COMPLIANCE-CORS-WILDCARD".into(),
            method: String::new(),
            uri: "/".into(),
            message: "CORS allows any origin (*).".into(),
            refs: String::new(),
            data: String::new(),
            plugin: INFO.name.to_string(),
            severity: Severity::Low,
            ..Default::default()
        });
    } else {
        // Non-wildcard origin is fine
        score.check(true, 2, "cors", Severity::Low, "", "");
    }

    items
}

// ---- Plugin implementation -------------------------------------------------

#[async_trait]
impl Plugin for CompliancePlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_postfetch(
        &self,
        _ctx: &ScanCtx,
        mark: Arc<Mutex<Mark>>,
        req: &Request,
        resp: &Response,
    ) -> Result<Vec<ReportItem>> {
        // Only run the full audit on the root page.
        if req.uri != "/" {
            return Ok(Vec::new());
        }
        // Only run once per host.
        if self.emitted.swap(true, Ordering::SeqCst) {
            return Ok(Vec::new());
        }

        let is_ssl = {
            let m = mark.lock().await;
            m.ssl
        };

        let mut score = ComplianceScore::new();
        let mut items: Vec<ReportItem> = Vec::new();

        // ---- Security headers ----

        // Strict-Transport-Security
        if let Some(hsts) = resp.header("strict-transport-security") {
            check_hsts(hsts, &mut score);
        } else if is_ssl {
            score.check(
                false,
                3,
                "headers",
                Severity::Medium,
                "Strict-Transport-Security header is missing on an HTTPS site.",
                "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
            );
        }

        // Content-Security-Policy
        if let Some(csp) = resp.header("content-security-policy") {
            let csp_items = check_csp(csp, &mut score);
            items.extend(csp_items);
        } else {
            score.check(
                false,
                3,
                "csp",
                Severity::Medium,
                "Content-Security-Policy header is missing.",
                "Add a Content-Security-Policy header to prevent XSS and data injection.",
            );
        }

        // X-Content-Type-Options
        let xcto = resp.header("x-content-type-options");
        score.check(
            xcto.map(|v| v.trim().eq_ignore_ascii_case("nosniff")).unwrap_or(false),
            2,
            "headers",
            Severity::Low,
            "X-Content-Type-Options: nosniff is not set.",
            "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
        );

        // X-Frame-Options
        if let Some(xfo) = resp.header("x-frame-options") {
            check_xframe(xfo, &mut score);
        } else {
            score.check(
                false,
                2,
                "headers",
                Severity::Low,
                "X-Frame-Options header is missing (clickjacking risk).",
                "Add X-Frame-Options: DENY or SAMEORIGIN.",
            );
        }

        // Referrer-Policy
        let rp = resp.header("referrer-policy");
        score.check(
            rp.is_some(),
            1,
            "headers",
            Severity::Low,
            "Referrer-Policy header is not set.",
            "Add Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
        );

        // Permissions-Policy
        let pp = resp.header("permissions-policy");
        score.check(
            pp.is_some(),
            1,
            "headers",
            Severity::Low,
            "Permissions-Policy header is not set.",
            "Add a Permissions-Policy header to restrict browser feature access.",
        );

        // ---- Cookies ----
        let mut seen_cookies: HashSet<String> = HashSet::new();
        for (k, v) in &resp.headers {
            if k.eq_ignore_ascii_case("set-cookie") {
                let (name, flags) = parse_cookie_flags(v);
                if !name.is_empty() && seen_cookies.insert(name.clone()) {
                    let cookie_items = check_cookie(&name, &flags, is_ssl, &mut score);
                    items.extend(cookie_items);
                }
            }
        }

        // ---- CORS ----
        let cors_items = check_cors(resp, &mut score);
        items.extend(cors_items);

        // ---- Finalize grade ----
        score.finalize();

        // Emit the summary grade finding. This is a derived posture summary,
        // not a confirmed vulnerability — the substantive per-header issues
        // already carry their own severities below. A typical real site lacks
        // HSTS/CSP and lands at D/F, so grading the summary as High made it a
        // near-universal noisy finding; cap it well below the real issues.
        let grade_severity = match score.grade {
            'A' | 'B' => Severity::Info,
            'C' | 'D' => Severity::Low,
            'F' => Severity::Medium,
            _ => Severity::Info,
        };

        let issue_summary: String = if score.findings.is_empty() {
            "No issues found.".into()
        } else {
            let cats: HashSet<&str> = score.findings.iter().map(|f| f.category.as_str()).collect();
            format!(
                "{} issues across {} ({}/{} points).",
                score.findings.len(),
                cats.into_iter().collect::<Vec<_>>().join(", "),
                score.points,
                score.max_points,
            )
        };

        let details_json = serde_json::to_string(&score).unwrap_or_default();

        items.push(ReportItem {
            corvex_id: format!("COMPLIANCE-GRADE-{}", score.grade),
            method: "GET".into(),
            uri: "/".into(),
            message: format!(
                "Compliance grade: {} — {}",
                score.grade, issue_summary,
            ),
            refs: String::new(),
            data: details_json,
            plugin: INFO.name.to_string(),
            severity: grade_severity,
            ..Default::default()
        });

        // Emit individual findings from the score as report items
        for finding in &score.findings {
            if !finding.message.is_empty() {
                items.push(ReportItem {
                    corvex_id: format!(
                        "COMPLIANCE-{}",
                        finding.category.to_ascii_uppercase()
                    ),
                    method: String::new(),
                    uri: "/".into(),
                    message: format!(
                        "{} Recommendation: {}",
                        finding.message, finding.recommendation
                    ),
                    refs: String::new(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                    severity: finding.severity,
                    ..Default::default()
                });
            }
        }

        Ok(items)
    }
}
