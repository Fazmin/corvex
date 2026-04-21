//! Thin compatibility shim — classification now lives in
//! [`crate::owasp`]. This module preserves the existing `classify`
//! entry point so call sites keep compiling.

/// Classify a Nuclei template by its tags + identifier. Returns an
/// OWASP category code string (e.g. `"A03"`). Drives the Checks
/// library grouping.
pub fn classify(tags: &[String], id_or_name: &str) -> String {
    crate::owasp::classify(tags, id_or_name)
}
