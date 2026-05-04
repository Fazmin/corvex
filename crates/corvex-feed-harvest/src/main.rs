//! corvex-feed-harvest — dev-only OpenVAS Community Feed metadata harvester.
//!
//! **Scope:** scaffold stubs for hand-authored rules under
//! `rules-sources/openvas-port/_scaffolds/`. NEVER ships with the product.
//! See `LICENSE_NOTES.md` next to this file for the policy.
//!
//! Hard rules (enforced by `nasl::extract` + `lint::run`):
//!   1. Reads `.nasl` files for **factual metadata only** — OID, CVE list,
//!      family, category, default ports, CPE matches, BID, xref. No body
//!      strings, no regex literals, no `description {}` text.
//!   2. Scaffolds land under `rules-sources/openvas-port/_scaffolds/` and
//!      are NEVER ingested by the rules-builder.
//!   3. The `lint` subcommand fails any hand-authored rule whose
//!      `match_spec` strings co-occur (≥6-byte token) with the cached NASL.

mod lint;
mod nasl;
mod scaffold;
mod sync;
mod transpile;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "corvex-feed-harvest",
    about = "Dev-only: scaffold openvas-port rule stubs from OpenVAS feed metadata. NOT a runtime component."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Sync the Greenbone Community Feed into the local cache via rsync.
    /// The cache directory is `.gitignore`d.
    Sync {
        /// Override the rsync source URL.
        #[arg(
            long,
            default_value = "rsync://feed.community.greenbone.net/community/vulnerability-feed/22.04/vt-data/nasl/"
        )]
        source: String,
        /// Local cache directory.
        #[arg(long, default_value = "program/feed-cache/openvas")]
        cache: PathBuf,
        /// Print the rsync command and exit without running it.
        #[arg(long)]
        dry_run: bool,
    },

    /// Scaffold one or more rule stubs into
    /// `rules-sources/openvas-port/_scaffolds/`. Reads only metadata from
    /// the cached `.nasl` files — no body strings, no regex literals.
    Scaffold {
        /// OpenVAS OID to scaffold. Repeat for multiple rules.
        #[arg(long, value_name = "OID")]
        oid: Vec<String>,
        /// Filter by `script_family` (case-insensitive substring match).
        /// Combine with `--limit` to bulk-scaffold a slice.
        #[arg(long)]
        family: Vec<String>,
        /// Maximum number of stubs to emit when family filtering. Ignored
        /// when `--oid` is given.
        #[arg(long, default_value_t = 25)]
        limit: usize,
        /// Cache directory to read from.
        #[arg(long, default_value = "program/feed-cache/openvas")]
        cache: PathBuf,
        /// Where to write scaffold JSON files.
        #[arg(long, default_value = "rules-sources/openvas-port/_scaffolds")]
        out: PathBuf,
        /// Overwrite existing scaffolds with the same OID.
        #[arg(long)]
        force: bool,
    },

    /// Lint hand-authored rules in `rules-sources/openvas-port/` against
    /// the cached feed: fail any rule whose `match_spec` strings overlap
    /// (≥6-byte tokens) with the corresponding `.nasl` body. Enforces the
    /// clean-room discipline at PR time.
    Lint {
        #[arg(long, default_value = "rules-sources/openvas-port")]
        rules: PathBuf,
        #[arg(long, default_value = "program/feed-cache/openvas")]
        cache: PathBuf,
        /// Minimum token length (bytes) to flag as overlap.
        #[arg(long, default_value_t = 6)]
        min_token: usize,
    },

    /// Bulk auto-emit `MatchSpec` for VTs whose detection is fully
    /// expressed by factual identifiers (regex literal, port, CPE).
    /// Output lands at `rules-sources/openvas-port/_transpiled/<family>/<oid>.json`,
    /// disjoint from hand-authored rules. Regenerable; safe to wipe.
    Transpile {
        /// Cache directory to read from.
        #[arg(long, default_value = "program/feed-cache/openvas")]
        cache: PathBuf,
        /// Where to write transpiled JSON files.
        #[arg(long, default_value = "rules-sources/openvas-port/_transpiled")]
        out: PathBuf,
        /// Overwrite existing transpiled files with the same OID.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Sync {
            source,
            cache,
            dry_run,
        } => sync::run(&source, &cache, dry_run),
        Cmd::Scaffold {
            oid,
            family,
            limit,
            cache,
            out,
            force,
        } => scaffold::run(&oid, &family, limit, &cache, &out, force),
        Cmd::Lint {
            rules,
            cache,
            min_token,
        } => lint::run(&rules, &cache, min_token),
        Cmd::Transpile { cache, out, force } => transpile::run(&cache, &out, force),
    }
}
