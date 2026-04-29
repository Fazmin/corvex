//! Trait-only abstraction over the unified rule store.
//!
//! The actual `MatchSpec` AST + multi-step engine live in `corvex-rules`
//! to keep `corvex-core`'s compile time low — the recursive serde-derived
//! `Cond` enum forces a 32× recursion-limit bump and substantial
//! monomorphisation, and exposing it from this foundational crate makes
//! every downstream crate pay that cost. By keeping only the trait here,
//! `corvex-core` stays cheap and the heavy code is opt-in.

pub mod provider;

pub use provider::{ExecutableRule, RuleProvider};
