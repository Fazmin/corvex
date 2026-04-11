//! `nikto.conf` key=value parser.
//!
//! Mirrors `load_config` in [../../../program/nikto.pl](../../../program/nikto.pl):
//! strip `#` comments, trim, split on first `=`. Later files override earlier
//! ones (first-wins semantics differ from Perl, which also stops at first
//! successful load — we match that here).

use indexmap::IndexMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{NiktoError, Result};

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
            .map_err(|e| NiktoError::Config(format!("{}: {e}", path.as_ref().display())))?;
        Ok(Self::parse_str(&text))
    }

    /// Replicates `config_init` lookup order in nikto.pl:
    ///   --config arg > ./nikto.conf > ./nikto.conf.default > ~/nikto.conf > /etc/nikto.conf
    pub fn locate_and_load(explicit: Option<&Path>) -> Result<(Self, PathBuf)> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(p) = explicit {
            candidates.push(p.to_path_buf());
        }
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        candidates.push(cwd.join("nikto.conf"));
        candidates.push(cwd.join("nikto.conf.default"));

        // Bundled default alongside the binary.
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                candidates.push(parent.join("nikto.conf"));
                candidates.push(parent.join("nikto.conf.default"));
            }
        }

        // Shipped in the source tree (dev runs).
        candidates.push(PathBuf::from("program").join("nikto.conf.default"));

        if let Some(home) = dirs_home() {
            candidates.push(home.join("nikto.conf"));
            candidates.push(home.join(".nikto").join("nikto.conf"));
        }

        #[cfg(not(windows))]
        candidates.push(PathBuf::from("/etc/nikto.conf"));

        for path in &candidates {
            if path.exists() {
                let mut cfg = Config::parse_file(path)?;
                cfg.set_default("CHECKMETHODS", "GET");
                cfg.set_default("@@DEFAULT", "@@ALL");
                cfg.set_default("DEFAULTHTTPVER", "1.1");
                cfg.set_default("FAILURES", "20");
                cfg.set_default("LW_SSL_ENGINE", "auto");
                return Ok((cfg, path.clone()));
            }
        }

        Err(NiktoError::Config(format!(
            "no nikto.conf found (tried: {})",
            candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }
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
