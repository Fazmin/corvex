//! OWASP Secure Headers Project baseline.
//!
//! Each entry describes an HTTP response header the Secure Headers
//! Project recommends. The `https_only` flag controls whether absence
//! on a plain-HTTP response is worth reporting.

pub struct HeaderBaseline {
    /// Canonical header name for display.
    pub name: &'static str,
    /// Short human-readable description, shown in findings.
    pub description: &'static str,
    /// Severity when the header is missing.
    pub severity: Severity,
    /// Reference URL for remediation docs.
    pub reference: &'static str,
    /// If true, only report when the exchange used HTTPS (HSTS is the
    /// canonical example — meaningless on plain HTTP).
    pub https_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

pub static OWASP_HEADER_BASELINE: &[HeaderBaseline] = &[
    HeaderBaseline {
        name: "Content-Security-Policy",
        description:
            "Blocks XSS and data-injection vectors by restricting allowed script/style/\
             resource origins. Absence leaves the page reliant on browser-side escaping.",
        severity: Severity::Medium,
        reference: "https://owasp.org/www-project-secure-headers/#content-security-policy",
        https_only: false,
    },
    HeaderBaseline {
        name: "Strict-Transport-Security",
        description:
            "Forces the browser to use HTTPS for future visits. Absence lets a MITM \
             downgrade a first-time visit over HTTP.",
        severity: Severity::Medium,
        reference: "https://owasp.org/www-project-secure-headers/#http-strict-transport-security",
        https_only: true,
    },
    HeaderBaseline {
        name: "X-Content-Type-Options",
        description:
            "Set to `nosniff` so browsers honour the declared Content-Type. Without it, \
             response bodies can be rendered under a different MIME (XSS vector).",
        severity: Severity::Low,
        reference: "https://owasp.org/www-project-secure-headers/#x-content-type-options",
        https_only: false,
    },
    HeaderBaseline {
        name: "X-Frame-Options",
        description:
            "Prevents clickjacking by restricting framing. Modern code should use \
             `Content-Security-Policy: frame-ancestors` instead, but either satisfies \
             the check.",
        severity: Severity::Low,
        reference: "https://owasp.org/www-project-secure-headers/#x-frame-options",
        https_only: false,
    },
    HeaderBaseline {
        name: "Referrer-Policy",
        description:
            "Controls how much referrer information is shared with outgoing links. \
             Absence defaults to policy-free, which leaks URL paths and query strings \
             to third parties.",
        severity: Severity::Info,
        reference: "https://owasp.org/www-project-secure-headers/#referrer-policy",
        https_only: false,
    },
    HeaderBaseline {
        name: "Permissions-Policy",
        description:
            "Opt-out of browser features (camera, microphone, geolocation, …) the app \
             doesn't use. Tightens blast radius when an XSS does land.",
        severity: Severity::Info,
        reference: "https://owasp.org/www-project-secure-headers/#permissions-policy",
        https_only: false,
    },
];

/// Special-case — Content-Security-Policy with `frame-ancestors` obviates
/// X-Frame-Options. Checks use this to avoid double-flagging.
pub fn csp_has_frame_ancestors(csp_value: &str) -> bool {
    csp_value
        .split(';')
        .any(|d| d.trim().to_ascii_lowercase().starts_with("frame-ancestors"))
}
