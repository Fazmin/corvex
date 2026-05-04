//! Per-source rule parsers. Each module reads a vendored upstream format and
//! emits `Vec<NormalizedRule>` plus a `ParseStats` describing what was
//! ingested vs. skipped.

pub mod burp;
pub mod nikto;
pub mod openvas_port;
pub mod zap;
