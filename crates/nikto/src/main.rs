//! Nikto CLI binary.

use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use clap::Parser;
use nikto_core::{
    cli::Cli,
    config::Config,
    db,
    error::NiktoError,
    evasion::EvasionSet,
    http::HttpClient,
    scan::{self, ScanCtx},
    state::GlobalState,
    target::set_targets,
    tuning::TuningFilter,
};
use tokio::sync::{Mutex, Semaphore};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if cli.version_flag {
        println!("Nikto {} (Rust port)", nikto_core::VERSION);
        return Ok(());
    }

    // Load config from --config or the usual locations.
    let (cfg, cfg_path) =
        Config::locate_and_load(cli.config.as_deref()).map_err(anyhow::Error::from)?;
    println!("- Nikto v{} (Rust)", nikto_core::VERSION);
    println!("- config: {}", cfg_path.display());

    // Build plugin registry (filter by -Plugins)
    let mut registry = nikto_plugins::register_all();
    if let Some(sel) = &cli.plugins {
        registry.apply_selector(
            sel,
            cfg.get_or("@@DEFAULT", "@@ALL"),
            cfg.get_or("@@EXTRAS", "dictionary;siebel"),
        );
    }

    if cli.list_plugins {
        println!("Available plugins:");
        for p in registry.all() {
            let i = p.info();
            println!("  {:<20}  {} (weight {})", i.name, i.full_name, i.weight);
        }
        return Ok(());
    }

    if cli.dbcheck {
        println!("+ Database check:");
        println!("  {}", db::check_summary());
        return Ok(());
    }

    // From here on we need a target.
    let host = match cli.effective_host() {
        Some(h) => h.to_string(),
        None => {
            println!("+ ERROR: No host (-host) specified. Use --Help for usage.");
            std::process::exit(1);
        }
    };

    // Target parsing
    let ssl_forced = cli.ssl;
    let marks = set_targets(
        &host,
        cli.port.as_deref(),
        ssl_forced,
        cli.root.as_deref(),
    )
    .map_err(anyhow::Error::from)?;
    println!("+ {} target(s) resolved from {}", marks.len(), host);

    // Engine state
    let state = Arc::new(GlobalState::new());
    let timeout = cli.timeout.unwrap_or(15);
    let http = Arc::new(HttpClient::new(state.clone(), timeout));
    let tuning = Arc::new(
        cli.tuning
            .as_deref()
            .map(TuningFilter::parse)
            .unwrap_or_default(),
    );
    let evasion = Arc::new(
        cli.evasion
            .as_deref()
            .map(EvasionSet::parse)
            .unwrap_or_default(),
    );
    // Load embedded databases; optionally merge a user-supplied -Userdbs CSV.
    let dbs = {
        let embedded = db::load();
        match cli.userdbs.as_ref() {
            Some(path) => {
                let mut cloned = (*embedded).clone();
                match db::csv_loader::load_user_tests(path) {
                    Ok(rows) => {
                        let n = rows.len();
                        db::csv_loader::merge_user_tests(&mut cloned, rows);
                        println!("+ -Userdbs: merged {n} rows from {}", path.display());
                    }
                    Err(e) => {
                        eprintln!("- WARNING: failed to load {}: {e}", path.display());
                    }
                }
                Arc::new(cloned)
            }
            None => embedded,
        }
    };
    let reports = Arc::new(Mutex::new(nikto_plugins::build_sinks(
        cli.format.as_deref().unwrap_or("txt"),
        cli.output.as_deref(),
    )));
    let request_sem = Arc::new(Semaphore::new(cli.max_concurrent_requests.max(1)));

    let ctx = Arc::new(ScanCtx {
        cfg: Arc::new(cfg),
        cli: Arc::new(cli),
        http,
        plugins: Arc::new(registry),
        reports,
        state,
        dbs,
        tuning,
        evasion,
        request_sem,
    });

    let start = SystemTime::now();
    println!(
        "+ scan start: {}",
        humantime::format_rfc3339_seconds(start)
            .to_string()
            .replace('T', " ")
    );

    if let Err(e) = scan::run(ctx.clone(), marks).await {
        eprintln!("- ERROR: {e}");
        std::process::exit(2);
    }

    let elapsed = start.elapsed().unwrap_or_default().as_secs();
    println!("+ scan complete in {elapsed}s");
    Ok(())
}

// Silence unused-import warnings — some code paths are referenced below.
#[allow(dead_code)]
fn _nikto_error_is_used(e: NiktoError) -> NiktoError {
    e
}

mod humantime {
    use std::time::SystemTime;
    pub fn format_rfc3339_seconds(t: SystemTime) -> String {
        let d = t
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = d.as_secs();
        // Minimal formatter — good enough for the banner line.
        let (y, mo, da, h, mi, s) = to_ymdhms(secs);
        format!("{y:04}-{mo:02}-{da:02}T{h:02}:{mi:02}:{s:02}Z")
    }

    fn to_ymdhms(mut s: u64) -> (u32, u32, u32, u32, u32, u32) {
        let sec = (s % 60) as u32;
        s /= 60;
        let min = (s % 60) as u32;
        s /= 60;
        let hour = (s % 24) as u32;
        s /= 24;
        let mut days = s as i64;
        let mut year: i64 = 1970;
        loop {
            let dy = if is_leap(year) { 366 } else { 365 };
            if days < dy {
                break;
            }
            days -= dy;
            year += 1;
        }
        let mut month = 0u32;
        let mdays = [31u32, if is_leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let mut d_left = days as u32;
        for (i, dm) in mdays.iter().enumerate() {
            if d_left < *dm {
                month = (i + 1) as u32;
                break;
            }
            d_left -= dm;
        }
        (year as u32, month, d_left + 1, hour, min, sec)
    }

    fn is_leap(y: i64) -> bool {
        (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
    }
}
