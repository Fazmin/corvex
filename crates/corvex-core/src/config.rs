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

    /// Parse a TOML config file into a Config.
    pub fn parse_toml(text: &str) -> Result<Self> {
        let table: toml_crate::Table = text
            .parse()
            .map_err(|e| CorvexError::Config(format!("TOML parse: {e}")))?;
        let mut items = IndexMap::new();
        flatten_toml(&table, "", &mut items);
        Ok(Self { items })
    }

    /// Parse a YAML config file into a Config.
    pub fn parse_yaml(text: &str) -> Result<Self> {
        let value: serde_yaml::Value = serde_yaml::from_str(text)
            .map_err(|e| CorvexError::Config(format!("YAML parse: {e}")))?;
        let mut items = IndexMap::new();
        flatten_yaml(&value, "", &mut items);
        Ok(Self { items })
    }

    /// Parse any supported config format based on extension.
    pub fn parse_auto(path: &Path) -> Result<Self> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        let text = fs::read_to_string(path)
            .map_err(|e| CorvexError::Config(format!("{}: {e}", path.display())))?;

        match ext.as_str() {
            "toml" => Self::parse_toml(&text),
            "yaml" | "yml" => Self::parse_yaml(&text),
            _ => Ok(Self::parse_str(&text)),
        }
    }

    /// Generate a template TOML config file with all options documented.
    pub fn generate_template_toml() -> String {
        let mut out = String::new();
        out.push_str("# Corvex Scanner Configuration\n");
        out.push_str("# Generated template — uncomment and modify as needed.\n\n");
        out.push_str("[scan]\n");
        out.push_str("# host = \"example.com\"\n");
        out.push_str("# port = \"80,443\"\n");
        out.push_str("# ssl = false\n");
        out.push_str("# tuning = \"0123456789abcx\"\n");
        out.push_str("# plugins = \"@@DEFAULT\"\n");
        out.push_str("# max_concurrent_requests = 8\n");
        out.push_str("# max_concurrent_hosts = 4\n");
        out.push_str("# timeout = 10\n");
        out.push_str("# pause = 0.0\n\n");
        out.push_str("[output]\n");
        out.push_str("# format = \"txt\"\n");
        out.push_str("# output = \"report.txt\"\n\n");
        out.push_str("[auth]\n");
        out.push_str("# id = \"user:pass\"\n");
        out.push_str("# form_login = \"https://example.com/login\"\n");
        out.push_str("# form_login_data = [\"user=admin\", \"pass=secret\"]\n\n");
        out.push_str("[active]\n");
        out.push_str("# enabled = false\n");
        out.push_str("# crawl_depth = 3\n");
        out.push_str("# max_urls = 500\n");
        out.push_str("# scope = \"domain\"\n\n");
        out.push_str("[sqli]\n");
        out.push_str("# level = 1\n");
        out.push_str("# risk = 1\n");
        out.push_str("# techniques = \"BEUST\"\n");
        out.push_str("# tamper = \"space2comment,randomcase\"\n\n");
        out.push_str("[vulndb]\n");
        out.push_str("# update = \"daily\"\n");
        out.push_str("# nvd_api_key = \"\"\n");
        out.push_str("# path = \"\"\n\n");
        out.push_str("[sca]\n");
        out.push_str("# scan_dir = \"\"\n");
        out.push_str("# sbom_input = \"\"\n");
        out.push_str("# sbom_output = \"\"\n");
        out.push_str("# sbom_format = \"cyclonedx-json\"\n");
        out.push_str("# epss_threshold = 0.0\n\n");
        out.push_str("[binary]\n");
        out.push_str("# scan = \"\"\n");
        out.push_str("# recursive = false\n");
        out.push_str("# extract = false\n\n");
        out.push_str("[vex]\n");
        out.push_str("# input = \"\"\n");
        out.push_str("# output = \"\"\n");
        out.push_str("# format = \"cyclonedx\"\n");
        out
    }

    /// Generate a template YAML config file.
    pub fn generate_template_yaml() -> String {
        let mut out = String::new();
        out.push_str("# Corvex Scanner Configuration\n");
        out.push_str("# Generated template — uncomment and modify as needed.\n\n");
        out.push_str("scan:\n");
        out.push_str("  # host: example.com\n");
        out.push_str("  # port: \"80,443\"\n");
        out.push_str("  # ssl: false\n");
        out.push_str("  # tuning: \"0123456789abcx\"\n");
        out.push_str("  # plugins: \"@@DEFAULT\"\n");
        out.push_str("  # max_concurrent_requests: 8\n");
        out.push_str("  # max_concurrent_hosts: 4\n\n");
        out.push_str("output:\n");
        out.push_str("  # format: txt\n");
        out.push_str("  # file: report.txt\n\n");
        out.push_str("vulndb:\n");
        out.push_str("  # update: daily\n");
        out.push_str("  # nvd_api_key: \"\"\n\n");
        out.push_str("sca:\n");
        out.push_str("  # scan_dir: \"\"\n");
        out.push_str("  # sbom_input: \"\"\n\n");
        out
    }

    /// Replicates `config_init` lookup order:
    ///   --config arg > ./corvex.toml > ./corvex.yaml > ./corvex.conf > etc.
    pub fn locate_and_load(explicit: Option<&Path>) -> Result<(Self, PathBuf)> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(p) = explicit {
            candidates.push(p.to_path_buf());
        }
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        // New formats first
        candidates.push(cwd.join("corvex.toml"));
        candidates.push(cwd.join("corvex.yaml"));
        candidates.push(cwd.join("corvex.yml"));
        // Legacy format
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
                let mut cfg = Config::parse_auto(path)?;
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

/// Flatten a TOML table into key=value pairs with dotted keys.
fn flatten_toml(table: &toml_crate::Table, prefix: &str, items: &mut IndexMap<String, String>) {
    for (key, value) in table {
        let full_key = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{}.{}", prefix, key)
        };
        match value {
            toml_crate::Value::Table(t) => flatten_toml(t, &full_key, items),
            toml_crate::Value::String(s) => {
                items.insert(full_key, s.clone());
            }
            toml_crate::Value::Integer(i) => {
                items.insert(full_key, i.to_string());
            }
            toml_crate::Value::Float(f) => {
                items.insert(full_key, f.to_string());
            }
            toml_crate::Value::Boolean(b) => {
                items.insert(full_key, b.to_string());
            }
            toml_crate::Value::Array(arr) => {
                let vals: Vec<String> = arr.iter().filter_map(|v| match v {
                    toml_crate::Value::String(s) => Some(s.clone()),
                    other => Some(other.to_string()),
                }).collect();
                items.insert(full_key, vals.join(","));
            }
            _ => {}
        }
    }
}

/// Flatten a YAML value into key=value pairs with dotted keys.
fn flatten_yaml(value: &serde_yaml::Value, prefix: &str, items: &mut IndexMap<String, String>) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                let key_str = match k {
                    serde_yaml::Value::String(s) => s.clone(),
                    other => format!("{:?}", other),
                };
                let full_key = if prefix.is_empty() {
                    key_str
                } else {
                    format!("{}.{}", prefix, key_str)
                };
                flatten_yaml(v, &full_key, items);
            }
        }
        serde_yaml::Value::String(s) => {
            items.insert(prefix.to_string(), s.clone());
        }
        serde_yaml::Value::Number(n) => {
            items.insert(prefix.to_string(), n.to_string());
        }
        serde_yaml::Value::Bool(b) => {
            items.insert(prefix.to_string(), b.to_string());
        }
        serde_yaml::Value::Sequence(arr) => {
            let vals: Vec<String> = arr.iter().filter_map(|v| match v {
                serde_yaml::Value::String(s) => Some(s.clone()),
                other => Some(format!("{:?}", other)),
            }).collect();
            items.insert(prefix.to_string(), vals.join(","));
        }
        _ => {}
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
