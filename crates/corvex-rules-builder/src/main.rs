//! corvex-rules-builder
//!
//! Ingests rule data from three vendored upstream projects (Nikto, OWASP ZAP,
//! Burp Suite BChecks) and writes a unified `rules.sqlite` catalog that the
//! scanner will (in a follow-on phase) read.
//!
//! Usage:
//!     corvex-rules-builder --sources rules-sources/ --output rules.sqlite
//!     corvex-rules-builder --sources rules-sources/ --output rules.sqlite \
//!         --filter-source nikto
//!     corvex-rules-builder --report rules.sqlite

mod normalized;
mod parsers;
mod report;
mod schema;
mod severity;
mod writer;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use rusqlite::Connection;

use crate::normalized::{NormalizedRule, ParseStats, SourceTool};
use crate::report::BuildReport;

#[derive(Debug, Parser)]
#[command(
    name = "corvex-rules-builder",
    about = "Ingest Nikto / ZAP / Burp rule sources into a unified rules.sqlite catalog"
)]
struct Cli {
    /// Root of the vendored source tree (default: rules-sources/).
    #[arg(long, default_value = "rules-sources")]
    sources: PathBuf,

    /// Output path for the SQLite catalog.
    #[arg(long, default_value = "rules.sqlite")]
    output: PathBuf,

    /// Limit ingestion to a single source. Repeatable.
    #[arg(long, value_name = "SOURCE")]
    filter_source: Vec<String>,

    /// Print a report on the given existing rules.sqlite and exit.
    #[arg(long, value_name = "PATH")]
    report: Option<PathBuf>,
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

    if let Some(path) = &cli.report {
        let conn = Connection::open(path)
            .with_context(|| format!("open {}", path.display()))?;
        let txt = report::render_db_report(&conn)?;
        print!("{txt}");
        return Ok(());
    }

    run_build(&cli)
}

fn run_build(cli: &Cli) -> Result<()> {
    let filter: Vec<SourceTool> = cli
        .filter_source
        .iter()
        .filter_map(|s| {
            let parsed = SourceTool::parse(s);
            if parsed.is_none() {
                eprintln!("warning: ignoring unknown --filter-source value '{s}'");
            }
            parsed
        })
        .collect();

    let want = |s: SourceTool| filter.is_empty() || filter.contains(&s);

    println!("==========================================");
    println!("  corvex-rules-builder");
    println!("==========================================");
    println!();
    println!("  sources: {}", cli.sources.display());
    println!("  output:  {}", cli.output.display());
    if !filter.is_empty() {
        let names: Vec<&str> = filter.iter().map(|s| s.as_str()).collect();
        println!("  filter:  {}", names.join(", "));
    }
    println!();

    if !cli.sources.exists() {
        anyhow::bail!(
            "sources directory not found: {} (create rules-sources/ first or pass --sources)",
            cli.sources.display()
        );
    }

    if let Some(parent) = cli.output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create directory {}", parent.display()))?;
        }
    }

    // Open SQLite. We re-create from scratch each run rather than upserting
    // into the previous DB, so the build is reproducible.
    let _ = std::fs::remove_file(&cli.output);
    let mut conn = Connection::open(&cli.output)
        .with_context(|| format!("open {}", cli.output.display()))?;
    schema::init_schema(&conn).context("init schema")?;
    schema::truncate_for_rebuild(&conn).context("truncate for rebuild")?;

    let mut all_rules: Vec<NormalizedRule> = Vec::new();
    let mut build_report = BuildReport::default();

    if want(SourceTool::Nikto) {
        let nikto_path = cli.sources.join("nikto").join("db_tests");
        if nikto_path.exists() {
            println!("[Nikto] reading {}", nikto_path.display());
            let (rules, stats) = parsers::nikto::parse(&nikto_path)
                .with_context(|| format!("parse nikto {}", nikto_path.display()))?;
            println!(
                "         ingested = {}  skipped = {}",
                stats.ingested,
                stats.skipped_total()
            );
            all_rules.extend(rules);
            build_report.record(SourceTool::Nikto, stats);
        } else {
            println!("[Nikto] (no rules-sources/nikto/db_tests — skipping)");
            build_report.record(SourceTool::Nikto, ParseStats::default());
        }
    }

    if want(SourceTool::Zap) {
        let zap_dir = cli.sources.join("zap");
        if zap_dir.exists() {
            println!("[ZAP]   reading {}", zap_dir.display());
            let (rules, stats) = parsers::zap::parse_dir(&zap_dir)
                .with_context(|| format!("parse zap dir {}", zap_dir.display()))?;
            println!(
                "         ingested = {}  skipped = {}",
                stats.ingested,
                stats.skipped_total()
            );
            all_rules.extend(rules);
            build_report.record(SourceTool::Zap, stats);
        } else {
            println!("[ZAP]   (no rules-sources/zap/ — skipping)");
            build_report.record(SourceTool::Zap, ParseStats::default());
        }
    }

    if want(SourceTool::Burp) {
        let burp_dir = cli.sources.join("burp");
        if burp_dir.exists() {
            println!("[Burp]  reading {}", burp_dir.display());
            let (rules, stats) = parsers::burp::parse_dir(&burp_dir)
                .with_context(|| format!("parse burp dir {}", burp_dir.display()))?;
            println!(
                "         ingested = {}  skipped = {}",
                stats.ingested,
                stats.skipped_total()
            );
            all_rules.extend(rules);
            build_report.record(SourceTool::Burp, stats);
        } else {
            println!("[Burp]  (no rules-sources/burp/ — skipping)");
            build_report.record(SourceTool::Burp, ParseStats::default());
        }
    }

    println!();
    println!("[insert] writing {} rules into {}", all_rules.len(), cli.output.display());
    let written = writer::insert_rules(&mut conn, &all_rules).context("insert rules")?;
    println!("         {} rows written", written);

    // Build metadata.
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap_or_default();
    writer::set_meta(&conn, "build_ts", &now)?;
    writer::set_meta(&conn, "schema_version", &schema::SCHEMA_VERSION.to_string())?;
    for (source_name, stats) in &build_report.by_source {
        writer::set_meta(
            &conn,
            &format!("ingested_count_{source_name}"),
            &stats.ingested.to_string(),
        )?;
        writer::set_meta(
            &conn,
            &format!("skipped_count_{source_name}"),
            &stats.skipped_total().to_string(),
        )?;
        writer::set_meta(
            &conn,
            &format!("skip_reasons_{source_name}_json"),
            &serde_json::to_string(&stats.skipped_by_reason).unwrap_or_else(|_| "{}".into()),
        )?;
    }
    if let Some(commit) = read_commit_marker(&cli.sources.join("zap").join("COMMIT")) {
        writer::set_meta(&conn, "zap_commit", &commit)?;
    }
    if let Some(commit) = read_commit_marker(&cli.sources.join("burp").join("COMMIT")) {
        writer::set_meta(&conn, "burp_commit", &commit)?;
    }

    print!("{}", build_report.render_text());

    let report_text = report::render_db_report(&conn)?;
    print!("{report_text}");

    Ok(())
}

fn read_commit_marker(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let first = text
        .lines()
        .map(|l| l.trim())
        .find(|l| !l.is_empty() && !l.starts_with('#'))?
        .to_string();
    Some(first)
}
