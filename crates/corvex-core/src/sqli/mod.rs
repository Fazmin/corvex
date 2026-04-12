//! Advanced SQL injection detection and exploitation engine.
//!
//! This module provides the core infrastructure for active SQL injection
//! testing against web applications. It supports five detection techniques
//! (error-based, boolean-blind, time-blind, UNION query, stacked queries),
//! 8+ DBMS backends, ~50 tamper/WAF-bypass modules, and post-exploitation
//! capabilities (enumeration, data dumping, file I/O, OS command execution).
//!
//! The engine integrates into the Corvex plugin architecture via the
//! `Active` hook and reuses the `FuzzRunner`/`FuzzTarget`/`InjectionPoint`
//! infrastructure from `crate::fuzzer`.

pub mod config;
pub mod dbms;
pub mod detection;
pub mod enumerate;
pub mod exploit;
pub mod payloads;
pub mod tamper;
pub mod technique;

pub use config::SqliConfig;
pub use dbms::Dbms;
pub use detection::{contains_error_signature, page_ratio};
pub use tamper::TamperChain;
pub use technique::{Confidence, SqliFinding, Technique};
