//! Multi-step match engine + spec types.
//!
//! Lives in this crate (rather than `corvex-core`) so the heavy generics
//! introduced by serde + tokio + regex don't slow down the compile of every
//! other crate that depends on corvex-core.
//!
//! Phase 2a uses a flat non-recursive `Vec<LeafCond>` shape that compiles
//! quickly on Windows. Phase 2b/2c will introduce a recursive `Cond` tree
//! (with hand-written serde impls) when ZAP / Burp rules need OR / NOT /
//! cross-step deltas.

pub mod engine;
pub mod spec;

pub use engine::{
    eval_cond, eval_when, parse_json, run_match, to_json, EvalError, MatchHit, StepResult,
};
pub use spec::{
    Alphabet, CondGraph, CondNode, DiffMode, LeafCond, MatchSpec, Matcher, NumOp, Payload, StepId,
    StepSpec, VarRef,
};
