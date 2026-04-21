//! Embedded datasets consumed by `corvex-checks`.
//!
//! Phase 3A shipped the OWASP header baseline and the XSS / redirect
//! canary payload banks. Phase 3B adds a Nuclei-template OWASP
//! classifier and a Wappalyzer-schema-compatible stack fingerprint
//! engine with a small seed dataset. Larger upstream data drops (full
//! Wappalyzer JSON, SecLists / FuzzDB) plug into the existing types via
//! a refresh script documented at `data/LICENSE_NOTES.md`.

pub mod fingerprint;
pub mod headers;
pub mod nuclei_mapping;
pub mod owasp;
pub mod payloads;

pub use fingerprint::{
    detect_any, detect_stack, embedded_dataset, load_dataset, Fingerprint, FingerprintLike,
    FingerprintMatch, LoadedFingerprint, SEED_FINGERPRINTS,
};
pub use headers::{HeaderBaseline, OWASP_HEADER_BASELINE};
pub use nuclei_mapping::classify as classify_template;
pub use owasp::{default_taxonomy, label_for, CategoryDef, OwaspTaxonomy};
pub use payloads::{open_redirect_sentinel, xss_canary_context_breakers};
