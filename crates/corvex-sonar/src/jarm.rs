//! JARM TLS-stack fingerprinting.
//!
//! TODO(v2): build 10 raw TLS Client Hellos with the standard JARM
//! permutation table, parse ServerHellos, and hash to the canonical
//! 30 + 32-char format. Engine currently returns a placeholder when
//! `SonarOpts::jarm` is set.

pub fn placeholder_hash() -> &'static str {
    "jarm_not_implemented_v1"
}
