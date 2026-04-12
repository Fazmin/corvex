//! corvex-core — engine library for the Rust port of Corvex.

pub mod cli;
pub mod config;
pub mod db;
pub mod dsl;
pub mod error;
pub mod evasion;
pub mod fourohfour;
pub mod http;
pub mod mutate;
pub mod plugin;
pub mod profile;
pub mod report;
pub mod scan;
pub mod state;
pub mod target;
pub mod tuning;
pub mod vars;

pub use error::{CorvexError, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PRODUCT_NAME: &str = "Corvex";
