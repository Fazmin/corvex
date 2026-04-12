//! SQLi engine configuration.

use super::dbms::Dbms;

/// Configuration for the SQL injection detection and exploitation engine.
#[derive(Debug, Clone)]
pub struct SqliConfig {
    /// Testing level (1-5). Higher levels test more injection points:
    /// 1 = GET/POST parameters only
    /// 2 = adds Cookie parameters
    /// 3 = adds User-Agent, Referer headers
    /// 4 = adds other headers
    /// 5 = adds path segments, all headers
    pub level: u8,

    /// Risk level (1-3). Controls payload danger:
    /// 1 = read-only/safe queries only
    /// 2 = adds OR-based payloads (may modify data)
    /// 3 = adds UPDATE/INSERT/write operations
    pub risk: u8,

    /// Technique bitmask string. Each char enables a technique:
    /// B = Boolean-based blind
    /// E = Error-based
    /// U = UNION query-based
    /// S = Stacked queries
    /// T = Time-based blind
    pub techniques: String,

    /// Force a specific DBMS (skips fingerprinting).
    pub dbms: Option<Dbms>,

    /// Seconds to inject for time-based blind detection (default 5).
    pub time_delay: u32,

    /// Tamper module names (comma-separated in CLI).
    pub tamper: Vec<String>,

    /// Second-order: check injection results on this URL.
    pub second_url: Option<String>,

    /// Force injection prefix (e.g., `')` or `1 AND`).
    pub prefix: Option<String>,

    /// Force injection suffix (e.g., `-- -` or `#`).
    pub suffix: Option<String>,

    /// Post-detection enumeration targets (comma-separated):
    /// dbs, tables, columns, users, dump, passwords, file-read, file-write, os-cmd
    pub enumerate: Option<String>,
}

impl Default for SqliConfig {
    fn default() -> Self {
        Self {
            level: 1,
            risk: 1,
            techniques: "BEUST".to_string(),
            dbms: None,
            time_delay: 5,
            tamper: Vec::new(),
            second_url: None,
            prefix: None,
            suffix: None,
            enumerate: None,
        }
    }
}

impl SqliConfig {
    /// Check if a specific technique is enabled.
    pub fn has_technique(&self, ch: char) -> bool {
        self.techniques.contains(ch)
    }

    /// Parse the enumerate string into individual targets.
    pub fn enumerate_targets(&self) -> Vec<&str> {
        self.enumerate
            .as_deref()
            .map(|s| s.split(',').map(str::trim).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default()
    }
}
