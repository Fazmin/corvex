//! corvex-core — engine library for the Rust port of Corvex.

pub mod cli;
pub mod compliance;
pub mod config;
pub mod dns;
pub mod crawler;
pub mod db;
pub mod dsl;
pub mod error;
pub mod evasion;
pub mod forms;
pub mod fourohfour;
pub mod fuzzer;
pub mod http;
pub mod matcher;
pub mod mutate;
pub mod netservice;
pub mod os_fingerprint;
pub mod plugin;
pub mod portscan;
pub mod profile;
pub mod recon;
pub mod report;
pub mod scan;
pub mod sqli;
pub mod scope;
pub mod tls_audit;
pub mod state;
pub mod target;
pub mod tuning;
pub mod binary;
pub mod merge;
pub mod sca;
pub mod vars;
pub mod vex;
pub mod vulndb;

pub use error::{CorvexError, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Short build identifier stamped by `build.rs`. Format: the short
/// git SHA when the build happens inside a git tree (with a
/// `-dirty` suffix if the working tree has uncommitted changes), or
/// `sde.<epoch>` / `d<YYYYMMDD>` as fallbacks for off-tree builds.
pub const BUILD_ID: &str = env!("CORVEX_BUILD_ID");

/// UTC date the current binary was built, as `YYYYMMDD`.
pub const BUILD_DATE: &str = env!("CORVEX_BUILD_DATE");

/// Cargo profile the binary was compiled under (`debug` / `release`).
pub const BUILD_PROFILE: &str = env!("CORVEX_BUILD_PROFILE");

/// Full display-friendly version: the crate's semver plus a SemVer
/// `+build` metadata tag that changes on every rebuild. This is what
/// the UI surfaces in the title bar and exports in findings so every
/// report is pinned to an identifiable build.
pub const FULL_VERSION: &str = env!("CORVEX_FULL_VERSION");
pub const PRODUCT_NAME: &str = "Corvex";
