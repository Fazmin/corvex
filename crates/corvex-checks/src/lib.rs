//! Modular OWASP Top 10 checks for corvex.
//!
//! The crate exposes two trait families — [`PassiveCheck`] for fast,
//! synchronous inspection of already-captured exchanges, and
//! [`ActiveCheck`] for on-demand probes that send additional requests
//! upstream. A single [`CheckRegistry`] owns the bundled
//! implementations and is the only surface the desktop layer depends
//! on.

pub mod active;
pub mod check;
pub mod finding;
pub mod passive;
pub mod registry;

pub use check::{ActiveCheck, CheckCtx, CheckDescriptor, CheckKind, OwaspCategory, PassiveCheck};
pub use finding::{Finding, Severity};
pub use registry::{
    default_registry, registry_with_bundles, registry_with_templates, CheckRegistry,
};
