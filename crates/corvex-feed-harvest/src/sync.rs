//! `corvex-feed-harvest sync` — rsync wrapper for the Greenbone Community
//! Feed. Pulls into the local cache directory; never shipped, never
//! committed (the cache path is `.gitignore`d).
//!
//! Tries the host's `rsync` binary first. If it's not on PATH (typical
//! Windows clean install) the wrapper transparently falls back to running
//! rsync inside a small Alpine container via Docker, with the cache
//! directory bind-mounted. The user gets the same final state either way.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

/// Public entry-point. Tries native rsync, falls back to Docker, errors
/// with a clear remediation message if neither is available.
pub fn run(source: &str, cache: &Path, dry_run: bool) -> Result<()> {
    if !source.starts_with("rsync://") {
        bail!(
            "refusing source `{source}` — must start with rsync:// (typo guard)"
        );
    }

    std::fs::create_dir_all(cache)
        .with_context(|| format!("create cache dir {}", cache.display()))?;

    if dry_run {
        let cache_str = cache
            .to_str()
            .ok_or_else(|| anyhow!("cache path is not valid UTF-8"))?;
        println!("rsync -rtv --delete --include='*/' --include='*.nasl' \\");
        println!("      --include='*.notus' --exclude='*' \\");
        println!("      {source} {cache_str}");
        println!();
        println!("(dry-run — no rsync invoked)");
        return Ok(());
    }

    let outcome = if rsync_on_path() {
        run_native_rsync(source, cache)
    } else if docker_available() {
        println!(
            "[sync] rsync not on PATH — falling back to Docker (\
             alpine + rsync, ~12 MB image)"
        );
        run_docker_rsync(source, cache)
    } else {
        bail!(
            "neither `rsync` nor `docker` is on PATH. \
             Install one of:\n  \
             • Docker Desktop (already on this system: launch it)\n  \
             • winget install --id Greg.Sebastian.cwRsync\n  \
             • Scoop: `scoop install rsync`\n  \
             • WSL Ubuntu: `wsl --install` then `sudo apt install rsync`"
        );
    };
    outcome?;

    let nasl_count = walkdir::WalkDir::new(cache)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file()
                && e.path().extension().and_then(|x| x.to_str()) == Some("nasl")
        })
        .count();
    println!("[sync] cache now contains {nasl_count} .nasl files");

    Ok(())
}

fn rsync_on_path() -> bool {
    // `rsync --version` is the cheapest portable existence check.
    Command::new("rsync")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn docker_available() -> bool {
    // `docker --version` is a pure CLI check that doesn't require the
    // daemon. If the daemon isn't running the actual `docker run` call
    // below will fail with a clear, native Docker error message —
    // better than us trying to predict daemon state with `docker info`,
    // which is slow and sometimes hangs from a non-interactive subprocess.
    Command::new("docker")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_native_rsync(source: &str, cache: &Path) -> Result<()> {
    let cache_str = cache
        .to_str()
        .ok_or_else(|| anyhow!("cache path is not valid UTF-8"))?;
    let args = [
        "-rtv",
        // `--partial` keeps half-transferred files on the disk if the
        // run is interrupted (Docker Desktop cycle, daemon restart,
        // network glitch); `--append-verify` lets the next run resume
        // from where the last one left off and re-verifies the joined
        // file's checksum so a corrupted partial never becomes a clean
        // file. `--timeout` prevents stalled connections from hanging
        // the whole sync indefinitely.
        "--partial",
        "--append-verify",
        "--timeout=60",
        "--delete",
        "--include=*/",
        "--include=*.nasl",
        "--include=*.notus",
        "--exclude=*",
        source,
        cache_str,
    ];
    println!("[sync] rsync {} → {}", source, cache.display());
    let status = Command::new("rsync")
        .args(args)
        .status()
        .context("failed to launch rsync")?;
    if !status.success() {
        bail!("rsync exited with status {status}");
    }
    Ok(())
}

/// Run rsync inside a one-shot Alpine container with the cache directory
/// bind-mounted at `/cache`. Using `instrumentisto/rsync-ssh` because it's
/// a maintained, minimal image that pins to upstream rsync versions; the
/// fallback `eeacms/rsync` is similar but slightly larger.
fn run_docker_rsync(source: &str, cache: &Path) -> Result<()> {
    let abs_cache = absolute_cache_path(cache)?;
    let mount_src = normalise_for_docker_mount(&abs_cache)?;

    println!(
        "[sync] docker run --rm -v \"{}:/cache\" instrumentisto/rsync-ssh rsync …",
        mount_src
    );
    let bind = format!("{mount_src}:/cache");
    let status = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &bind,
            "instrumentisto/rsync-ssh",
            "rsync",
            "-rtv",
            // Same resume-friendly flags as the native path; see
            // `run_native_rsync` for the rationale.
            "--partial",
            "--append-verify",
            "--timeout=60",
            "--delete",
            "--include=*/",
            "--include=*.nasl",
            "--include=*.notus",
            "--exclude=*",
            source,
            "/cache",
        ])
        .status()
        .context("failed to launch docker rsync container")?;
    if !status.success() {
        bail!(
            "docker rsync exited with status {status}. \
             If the daemon error mentioned `dockerDesktopLinuxEngine`, \
             open Docker Desktop and wait for the whale icon to be \
             solid (not animated) before re-running."
        );
    }
    Ok(())
}

/// Convert a Windows-style absolute path (e.g. `D:\foo\bar`) into the
/// shape Docker Desktop's bind-mount parser accepts (`D:/foo/bar`).
/// Linux/macOS paths pass through unchanged.
fn normalise_for_docker_mount(p: &Path) -> Result<String> {
    let s = p
        .to_str()
        .ok_or_else(|| anyhow!("path is not valid UTF-8: {}", p.display()))?;
    Ok(s.replace('\\', "/"))
}

fn absolute_cache_path(cache: &Path) -> Result<PathBuf> {
    if cache.is_absolute() {
        return Ok(cache.to_path_buf());
    }
    let cwd = std::env::current_dir().context("read current dir")?;
    Ok(cwd.join(cache))
}
