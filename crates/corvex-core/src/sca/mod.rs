//! Software Composition Analysis (SCA) module.
//!
//! Provides dependency manifest parsing, SBOM support, and CPE mapping
//! for cross-referencing detected components against the CVE database.

pub mod component;
pub mod cpe_map;
pub mod lookup;
pub mod parsers;
pub mod sbom;
