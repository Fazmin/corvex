//! `corvex.conf` key=value parser.
//!
//! Mirrors `load_config` in [../../../program/corvex.pl](../../../program/corvex.pl):
//! strip `#` comments, trim, split on first `=`. Later files override earlier
//! ones (first-wins semantics differ from Perl, which also stops at first
//! successful load — we match that here).

use indexmap::IndexMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{CorvexError, Result};

/// The shipped default config, embedded at compile time so the binary
/// is self-contained. This is the final fallback when no `corvex.conf`
/// or `corvex.conf.default` is found on disk — used by the desktop app
/// when its CWD is somewhere that can't see the source tree.
const EMBEDDED_DEFAULT_CONF: &str =
    include_str!("../../../program/corvex.conf.default");

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub items: IndexMap<String, String>,
}

impl Config {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.items.get(key).map(String::as_str)
    }

    pub fn get_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get(key).unwrap_or(default)
    }

    pub fn set_default(&mut self, key: &str, default: &str) {
        self.items.entry(key.to_string()).or_insert_with(|| default.to_string());
    }

    pub fn parse_str(text: &str) -> Self {
        let mut items: IndexMap<String, String> = IndexMap::new();
        for raw in text.lines() {
            let mut line = raw.to_string();
            if let Some(idx) = line.find('#') {
                line.truncate(idx);
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim().to_string();
                let v = v.trim().to_string();
                if !k.is_empty() {
                    items.insert(k, v);
                }
            }
        }
        Self { items }
    }

    pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let text = fs::read_to_string(path.as_ref())
            .map_err(|e| CorvexError::Config(format!("{}: {e}", path.as_ref().display())))?;
        Ok(Self::parse_str(&text))
    }

    /// Replicates `config_init` lookup order in corvex.pl:
    ///   --config arg > ./corvex.conf > ./corvex.conf.default > ~/corvex.conf > /etc/corvex.conf
    pub fn locate_and_load(explicit: Option<&Path>) -> Result<(Self, PathBuf)> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(p) = explicit {
            candidates.push(p.to_path_buf());
        }
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        candidates.push(cwd.join("corvex.conf"));
        candidates.push(cwd.join("corvex.conf.default"));

        // Bundled default alongside the binary.
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                candidates.push(parent.join("corvex.conf"));
                candidates.push(parent.join("corvex.conf.default"));
            }
        }

        // Shipped in the source tree (dev runs).
        candidates.push(PathBuf::from("program").join("corvex.conf.default"));

        if let Some(home) = dirs_home() {
            candidates.push(home.join("corvex.conf"));
            candidates.push(home.join(".corvex").join("corvex.conf"));
        }

        #[cfg(not(windows))]
        candidates.push(PathBuf::from("/etc/corvex.conf"));

        for path in &candidates {
            if path.exists() {
                let mut cfg = Config::parse_file(path)?;
                apply_config_defaults(&mut cfg);
                return Ok((cfg, path.clone()));
            }
        }

        // Nothing on disk — fall back to the embedded default. This is
        // what lets the desktop binary run without a source-tree CWD.
        let mut cfg = Config::parse_str(EMBEDDED_DEFAULT_CONF);
        apply_config_defaults(&mut cfg);
        Ok((cfg, PathBuf::from("<embedded>")))
    }
}

fn apply_config_defaults(cfg: &mut Config) {
    cfg.set_default("CHECKMETHODS", "GET");
    cfg.set_default("@@DEFAULT", "@@ALL");
    cfg.set_default("DEFAULTHTTPVER", "1.1");
    cfg.set_default("FAILURES", "20");
    cfg.set_default("LW_SSL_ENGINE", "auto");
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_value_and_strips_comments() {
        let cfg = Config::parse_str(
            "# comment\nRFIURL=https://example.com  # trailing\nFAILURES=20\n\n",
        );
        assert_eq!(cfg.get("RFIURL"), Some("https://example.com"));
        assert_eq!(cfg.get("FAILURES"), Some("20"));
    }
}
