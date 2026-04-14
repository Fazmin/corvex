//! Report merging and diffing.
//!
//! Supports saving intermediate scan reports with tags, merging multiple
//! reports, and diffing to track vulnerability changes over time.

use crate::report::ReportItem;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A saved report with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedReport {
    pub tag: String,
    pub timestamp: String,
    pub items: Vec<ReportItem>,
}

/// Diff result between two reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportDiff {
    pub added: Vec<ReportItem>,
    pub removed: Vec<ReportItem>,
    pub unchanged: usize,
}

/// Get the reports storage directory.
pub fn reports_dir() -> Result<PathBuf, String> {
    let home = if cfg!(windows) {
        std::env::var("APPDATA").unwrap_or_else(|_| {
            std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string())
        })
    } else {
        std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
    };
    let base = PathBuf::from(home);
    let dir = if cfg!(windows) {
        base.join("corvex").join("reports")
    } else {
        base.join(".corvex").join("reports")
    };
    std::fs::create_dir_all(&dir).map_err(|e| format!("create reports dir: {e}"))?;
    Ok(dir)
}

/// Save a report with a tag.
pub fn save_report(tag: &str, items: &[ReportItem]) -> Result<PathBuf, String> {
    let dir = reports_dir()?;
    let now = time::OffsetDateTime::now_utc();
    let timestamp = now
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let filename = format!(
        "{}-{}.json",
        tag,
        now.unix_timestamp()
    );
    let path = dir.join(&filename);

    let report = SavedReport {
        tag: tag.to_string(),
        timestamp,
        items: items.to_vec(),
    };

    let json =
        serde_json::to_string_pretty(&report).map_err(|e| format!("serialize report: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("write report: {e}"))?;

    tracing::info!(target: "merge", "saved report '{}' to {}", tag, path.display());
    Ok(path)
}

/// Load reports by tag. Returns all reports matching the tag.
pub fn load_reports_by_tag(tag: &str) -> Result<Vec<SavedReport>, String> {
    let dir = reports_dir()?;
    let mut reports = Vec::new();

    let prefix = format!("{}-", tag);
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("read dir: {e}"))? {
        let entry = entry.map_err(|e| format!("entry: {e}"))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(&prefix) && name.ends_with(".json") {
            let content = std::fs::read_to_string(entry.path())
                .map_err(|e| format!("read {}: {e}", entry.path().display()))?;
            let report: SavedReport =
                serde_json::from_str(&content).map_err(|e| format!("parse: {e}"))?;
            reports.push(report);
        }
    }

    // Sort by timestamp
    reports.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    Ok(reports)
}

/// Merge multiple reports, deduplicating by (corvex_id, uri).
pub fn merge_reports(tags: &[&str]) -> Result<Vec<ReportItem>, String> {
    let mut all_items = Vec::new();
    for tag in tags {
        let reports = load_reports_by_tag(tag)?;
        for report in reports {
            all_items.extend(report.items);
        }
    }

    // Deduplicate by (corvex_id, uri)
    let mut seen = HashMap::new();
    let mut merged = Vec::new();
    for item in all_items {
        let key = format!("{}|{}", item.corvex_id, item.uri);
        if !seen.contains_key(&key) {
            seen.insert(key, true);
            merged.push(item);
        }
    }

    Ok(merged)
}

/// Diff two reports by tags.
pub fn diff_reports(tag_a: &str, tag_b: &str) -> Result<ReportDiff, String> {
    let reports_a = load_reports_by_tag(tag_a)?;
    let reports_b = load_reports_by_tag(tag_b)?;

    let items_a: HashMap<String, &ReportItem> = reports_a
        .iter()
        .flat_map(|r| &r.items)
        .map(|i| (format!("{}|{}", i.corvex_id, i.uri), i))
        .collect();

    let items_b: HashMap<String, &ReportItem> = reports_b
        .iter()
        .flat_map(|r| &r.items)
        .map(|i| (format!("{}|{}", i.corvex_id, i.uri), i))
        .collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut unchanged = 0usize;

    // Items in B but not in A → added
    for (key, item) in &items_b {
        if items_a.contains_key(key) {
            unchanged += 1;
        } else {
            added.push((*item).clone());
        }
    }

    // Items in A but not in B → removed
    for (key, item) in &items_a {
        if !items_b.contains_key(key) {
            removed.push((*item).clone());
        }
    }

    Ok(ReportDiff {
        added,
        removed,
        unchanged,
    })
}
