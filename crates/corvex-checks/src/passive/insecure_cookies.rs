//! Insecure Cookie Flags (A02). Parses every Set-Cookie and reports
//! missing Secure / HttpOnly / SameSite attributes.

use corvex_proxy::Exchange;
use serde_json::json;

use crate::check::{CheckDescriptor, CheckKind, OwaspCategory, PassiveCheck};
use crate::finding::{Finding, Severity};

pub struct InsecureCookies;

impl PassiveCheck for InsecureCookies {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "insecure-cookies".into(),
            name: "Insecure Cookie Flags".into(),
            // 2025: Cryptographic Failures moved to A04 (from A02 in
            // 2021). Cookie integrity + transport protection lives
            // here.
            category: OwaspCategory::A04(),
            kind: CheckKind::Passive,
            default_severity: Severity::Low,
            description:
                "Checks every Set-Cookie for Secure (on HTTPS), HttpOnly and SameSite \
                 attributes. Missing flags make session cookies easier to steal or \
                 forge."
                    .to_string(),        }
    }

    fn inspect(&self, exchange: &Exchange) -> Vec<Finding> {
        let Some(response) = &exchange.response else {
            return Vec::new();
        };
        let is_https = exchange.request.ssl;
        let mut findings = Vec::new();

        for (k, v) in &response.headers {
            if !k.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            let name = cookie_name(v).unwrap_or("<unnamed>".into());
            let attrs: Vec<&str> = v
                .split(';')
                .skip(1)
                .map(|p| p.trim())
                .collect();
            let lower: Vec<String> = attrs.iter().map(|a| a.to_ascii_lowercase()).collect();

            let has_secure = lower.iter().any(|a| a == "secure");
            let has_httponly = lower.iter().any(|a| a == "httponly");
            let has_samesite = lower.iter().any(|a| a.starts_with("samesite"));

            let mut missing = Vec::new();
            if is_https && !has_secure {
                missing.push("Secure");
            }
            if !has_httponly {
                missing.push("HttpOnly");
            }
            if !has_samesite {
                missing.push("SameSite");
            }

            if missing.is_empty() {
                continue;
            }

            findings.push(
                Finding::new(
                    "insecure-cookies",
                    exchange.id,
                    Severity::Low,
                    format!("Cookie `{name}` missing {}", missing.join(", ")),
                )
                .with_description(
                    "Session cookies should be marked Secure on HTTPS, HttpOnly to \
                     block JavaScript reads, and SameSite to limit cross-site \
                     submission."
                        .to_string(),                )
                .with_evidence(json!({
                    "cookie": name,
                    "missing": missing,
                    "raw": v,
                })),
            );
        }

        findings
    }
}

fn cookie_name(set_cookie: &str) -> Option<String> {
    let first = set_cookie.split(';').next()?.trim();
    let (name, _) = first.split_once('=')?;
    Some(name.to_string())
}
