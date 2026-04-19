//! Corvex Sonar — active service-identification engine.
//!
//! Fingerprint data: Recog XML files under `data/recog/` (BSD-2-Clause;
//! see `THIRD_PARTY_LICENSES.md` at the repo root for the required notice).
//! Probe payloads: authored in this crate from public protocol specs.

pub mod connector;
pub mod db;
pub mod directive;
pub mod engine;
pub mod jarm;
pub mod probe;
pub mod probes;
pub mod recog;
pub mod schema;
pub mod types;

pub use engine::identify;
pub use types::{ProbeMatch, ScanMode, ScanTuning, SonarOpts, TlsMeta, TlsRequirement};
