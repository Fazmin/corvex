//! Nuclei-format HTTP template parser and executor.
//!
//! Parses YAML templates modeled on the
//! [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
//! schema and runs the HTTP-protocol subset against targets using the
//! shared `corvex-core` `HttpClient`. Templates that require features
//! outside the v1 subset (non-HTTP protocols, unknown DSL helpers, real
//! OOB interactsh, workflows) are classified as `Skipped` at load time
//! with a structured reason.

pub mod attribution;
pub mod dsl;
pub mod executor;
pub mod extractor;
pub mod matcher;
pub mod overlap;
pub mod parser;
pub mod payloads;
pub mod schema;
pub mod store;
pub mod vars;

pub use executor::{Executor, Hit};
pub use parser::{LoadError, LoadOutcome, SkipReason};
pub use schema::{Info, Severity, Template};
pub use store::TemplateStore;
