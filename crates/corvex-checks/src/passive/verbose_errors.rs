//! Verbose Errors / Stack Traces (A05).
//!
//! Scans the response body for stack-trace / debug-page patterns
//! associated with common web frameworks. The list is deliberately
//! conservative — false positives on forums and technical docs would
//! poison the dashboard. Add patterns only when the signal is
//! unambiguous (framework-specific debug UI, filesystem paths combined
//! with class names).

use corvex_proxy::Exchange;
use once_cell::sync::Lazy;
use regex::RegexSet;
use serde_json::json;

use crate::check::{CheckDescriptor, CheckKind, OwaspCategory, PassiveCheck};
use crate::finding::{Finding, Severity};

struct Pattern {
    stack: &'static str,
    pattern: &'static str,
}

static PATTERNS: &[Pattern] = &[
    Pattern {
        stack: "Java",
        // `at package.Class.method(File.java:123)` frames — two in a row
        // is load-bearing on avoiding false positives.
        pattern: r"(?m)^\s*at [A-Za-z0-9_.]+\([^)]+\.java:\d+\)\s*$",
    },
    Pattern {
        stack: "PHP",
        pattern: r"(?i)Fatal error:[^<\n]{0,120}? in [^<\n]{1,200}? on line \d+",
    },
    Pattern {
        stack: ".NET",
        pattern: r"(?i)Server Error in .+ Application\.|System\.(?:Data|Web|IO)\.[A-Z][A-Za-z0-9_]+Exception:",
    },
    Pattern {
        stack: "Node.js",
        pattern: r"(?m)^\s*at [A-Za-z0-9_.<>]+ \(/[^\s)]+\.js:\d+:\d+\)\s*$",
    },
    Pattern {
        stack: "Python",
        pattern: r#"(?m)Traceback \(most recent call last\):[\s\S]{0,400}?File "[^"]+", line \d+"#,
    },
    Pattern {
        stack: "Laravel Whoops",
        pattern: r#"Whoops, looks like something went wrong\.|</span>\s*</div>\s*<div class="message">"#,
    },
    Pattern {
        stack: "Django DEBUG",
        pattern: r"(?i)You're seeing this error because you have <code>DEBUG ?= ?True</code>|DoesNotExist at /",
    },
    Pattern {
        stack: "Flask Werkzeug",
        pattern: r"werkzeug\.debug|The debugger caught an exception in your WSGI application",
    },
    Pattern {
        stack: "Ruby",
        pattern: r"(?m)^\s*from .+\.rb:\d+:in `[^']+'\s*$",
    },
];

static COMBINED: Lazy<(RegexSet, Vec<&'static Pattern>)> = Lazy::new(|| {
    let patterns: Vec<_> = PATTERNS.iter().map(|p| p.pattern).collect();
    let set = RegexSet::new(&patterns).expect("stack-trace regex set");
    (set, PATTERNS.iter().collect())
});

pub struct VerboseErrors;

impl PassiveCheck for VerboseErrors {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "verbose-errors".into(),
            name: "Verbose Errors / Stack Traces".into(),
            // 2025: Verbose / debug-leaking responses fall under
            // Security Misconfiguration (A02). A case could be made
            // for A10 Mishandling of Exceptional Conditions too;
            // keeping misconfig here to match how the rest of the
            // 2021 misconfig-bucket checks were re-routed.
            category: OwaspCategory::A02(),
            kind: CheckKind::Passive,
            default_severity: Severity::Medium,
            description:
                "Flags responses containing framework stack traces or debug pages that \
                 leak code paths and internal configuration."
                    .to_string(),        }
    }

    fn inspect(&self, exchange: &Exchange) -> Vec<Finding> {
        let Some(response) = &exchange.response else {
            return Vec::new();
        };
        // Only bother with textual MIMEs — binary bodies drown the
        // regex engine without giving us useful signal.
        if !likely_text(&response.headers) {
            return Vec::new();
        }
        let body = response.body_str();
        let matches = COMBINED.0.matches(body.as_ref());
        if !matches.matched_any() {
            return Vec::new();
        }
        let stacks: Vec<&'static str> = matches
            .into_iter()
            .map(|i| COMBINED.1[i].stack)
            .collect();
        vec![Finding::new(
            "verbose-errors",
            exchange.id,
            Severity::Medium,
            format!("Stack trace leaked ({} match)", stacks.join(", ")),
        )
        .with_description(
            "Production responses should not expose framework error pages. Disable \
             DEBUG/verbose error handlers and return a generic error page instead."
                .to_string(),        )
        .with_evidence(json!({ "stacks": stacks }))]
    }
}

fn likely_text(headers: &indexmap::IndexMap<String, String>) -> bool {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| {
            let lower = v.to_ascii_lowercase();
            lower.starts_with("text/")
                || lower.contains("json")
                || lower.contains("xml")
                || lower.contains("javascript")
                || lower.contains("html")
        })
        .unwrap_or(true)
}
