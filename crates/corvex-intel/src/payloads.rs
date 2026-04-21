//! Minimal payload bank used by the active checks.
//!
//! Phase 3A ships a hand-picked shortlist of the highest-signal
//! context-breakers. Phase 3B vendors the full SecLists / FuzzDB /
//! PayloadsAllTheThings subsets with sidecar metadata.

/// XSS context-breakers paired with the canary token `__CVX_CANARY__`.
/// Each entry is a `(description, payload-template)` pair. Callers
/// substitute `__CVX_CANARY__` with the per-run unique marker so
/// reflections can be identified unambiguously.
pub fn xss_canary_context_breakers() -> &'static [(&'static str, &'static str)] {
    &[
        ("plain", "__CVX_CANARY__"),
        ("html-tag", "<__CVX_CANARY__>"),
        ("attribute-break", "\"><svg/onload=__CVX_CANARY__>"),
        ("script-break", "</script><__CVX_CANARY__>"),
        ("single-quote-attr", "' autofocus onfocus=__CVX_CANARY__ '"),
    ]
}

/// Sentinel host used by the open-redirect check. The hostname is
/// deliberately invalid per RFC 2606 so there's zero risk of an actual
/// redirect reaching an attacker-controlled origin during a check run.
pub fn open_redirect_sentinel() -> &'static str {
    "corvex-redirect-canary.invalid"
}

/// SQLi error-probe payloads. The detection side lives in
/// `corvex-core::sqli::detection::error_matches`, so we only need to
/// supply the canonical boundary-breakers.
pub fn sqli_error_probes() -> &'static [&'static str] {
    &["'", "\"", "')", "\")", "' OR '1'='1", "\" OR \"1\"=\"1"]
}
