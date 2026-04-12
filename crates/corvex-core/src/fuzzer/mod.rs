//! Active fuzzer framework.
//!
//! This module provides the injection-point abstraction, the
//! `FuzzTarget` type, and the `FuzzRunner` that drives the one-
//! parameter-at-a-time substitution loop used by every active plugin.

pub mod param;
pub mod runner;

pub use param::{FuzzTarget, InjectionPoint};
pub use runner::FuzzRunner;
