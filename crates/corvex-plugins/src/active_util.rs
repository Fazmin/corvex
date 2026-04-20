//! Small helpers shared by active-scan plugins.
//!
//! Kept deliberately tiny — only the patterns every active module uses.
//! Detection logic (regexes, timing thresholds, payload lists) stays in
//! each plugin so the rules are co-located with the classification they
//! produce.

use rand::Rng;

use corvex_core::fuzzer::param::InjectionPoint;

/// Human-readable "where was the payload injected" string used in finding
/// messages. Same format across every active plugin so UI filters + export
/// parsers can rely on it.
pub fn format_point(p: &InjectionPoint) -> String {
    match p {
        InjectionPoint::Query(n) => format!("query:{n}"),
        InjectionPoint::Body(n) => format!("body:{n}"),
        InjectionPoint::Header(n) => format!("header:{n}"),
        InjectionPoint::Cookie(n) => format!("cookie:{n}"),
        InjectionPoint::PathSegment(i) => format!("path:{i}"),
    }
}

/// Truncate a string at `max` characters, appending `…` when cut.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// Build a short, high-entropy canary token.
///
/// `prefix` lets plugins namespace their markers (`CORVXSS…` /
/// `CORVLFI…` / …) so if multiple active plugins fire against the same
/// target the body-scan patterns don't cross-contaminate.
pub fn canary(prefix: &str) -> String {
    let mut r = rand::thread_rng();
    let mut s = String::with_capacity(prefix.len() + 10);
    s.push_str(prefix);
    for _ in 0..10 {
        let n: u8 = r.gen_range(0..10);
        s.push(char::from(b'0' + n));
    }
    s
}

/// Convert a response body to UTF-8 lossy, but bounded — some probes dump
/// hundreds of KB of binary garbage which makes contains-checks expensive
/// and the ellipsized message unhelpful. 64 KiB is enough for headers,
/// stack traces, and typical error pages.
pub fn body_snippet(body: &[u8], max_bytes: usize) -> String {
    let slice = &body[..body.len().min(max_bytes)];
    String::from_utf8_lossy(slice).into_owned()
}
