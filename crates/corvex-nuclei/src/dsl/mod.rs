//! Minimal Nuclei-DSL compatible expression language.
//!
//! Covers literals, identifiers, binary (`+ - * / && || == != < <= > >=`)
//! and unary (`! -`) operators, function calls, string concat via `+`.
//! The helper-function allowlist in [`fns`] is the single source of
//! truth for what counts as `supported`; unknown functions are rejected
//! at template-load time.

pub mod eval;
pub mod fns;
pub mod parser;

pub use eval::{Environment, EvalError, Value};
pub use parser::{parse, Expr};
