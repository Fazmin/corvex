//! SNMP-based device-signature catalog and matcher.
//!
//! Given the result of an SNMP `GET` for `sysDescr.0` and
//! `sysObjectID.0`, the matcher returns a coarse `(os, vendor,
//! device_type)` triple sourced from the on-disk YAML signature
//! catalog. The catalog is loaded once at startup and held immutable
//! for the lifetime of the process.

pub mod db;
pub mod loader;
pub mod matcher;
pub mod types;

pub use db::DbError;
pub use loader::{DeviceCatalog, DeviceEntry, LoadError, RawDef, RawDiscovery};
pub use matcher::identify;
pub use types::{DeviceMatch, MatchSource};

/// Default on-disk path for the YAML signature source directory,
/// relative to the repository root. Used by the builder to find the
/// inputs it should ingest into `devices.sqlite`.
pub const DEFAULT_DATA_SUBDIR: &str = "data/devices";

/// Default on-disk filename for the produced SQLite catalog.
pub const DEFAULT_DB_FILENAME: &str = "devices.sqlite";

/// Canonical repo-relative path to the built SQLite catalog. Mirrors
/// the `program/vulndb/snapshot.db.gz` layout so committed binary
/// artifacts live together under `program/`, away from the source
/// crates.
pub const DEFAULT_DB_RELPATH: &str = "program/devicedb/devices.sqlite";
