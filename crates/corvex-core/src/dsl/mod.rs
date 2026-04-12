//! The Corvex test DSL.
//!
//! A DSL string is a conjunction (`&&`) of matchers. Each matcher is of
//! one of the forms:
//!     CODE:regex
//!     BODY:regex
//!     HEADER:name:regex
//!     COOKIE:name:regex
//! with optional `!` negation prefix.
//!
//! Regex alternation (`|`) is supported within the regex portion, following
//! Perl's use of Perl regex. We compile with the `regex` crate's Unicode
//! engine which handles `(?i)`, alternation, character classes, etc.
//!
//! Examples observed in db_tests:
//!     BODY:Calypso Server
//!     CODE:200&&BODY:phpinfo\(\)
//!     CODE:200|301
//!     HEADER:server:nginx

pub mod eval;
pub mod parser;

pub use eval::{DslEvaluator, DslMatch};
pub use parser::{parse, Dsl, Matcher};
