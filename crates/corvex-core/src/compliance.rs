//! Shared types for the compliance and configuration auditing system.

use std::collections::BTreeMap;

use crate::report::Severity;
use serde::{Deserialize, Serialize};

/// A single compliance finding produced during header / cookie / CORS / CSP
/// analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    pub category: String,
    pub severity: Severity,
    pub message: String,
    pub recommendation: String,
}

/// Per-category point totals so the UI can render a breakdown without
/// reverse-engineering weights from the failing-finding list.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CategoryScore {
    pub earned: u32,
    pub max: u32,
}

/// Aggregate compliance score for a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceScore {
    pub grade: char,
    pub points: u32,
    pub max_points: u32,
    pub findings: Vec<ComplianceFinding>,
    #[serde(default)]
    pub categories: BTreeMap<String, CategoryScore>,
}

impl ComplianceScore {
    pub fn new() -> Self {
        Self {
            grade: 'A',
            points: 0,
            max_points: 0,
            findings: Vec::new(),
            categories: BTreeMap::new(),
        }
    }

    /// Add a check (max_points += weight). If `pass` is false, record the
    /// finding and leave points unchanged; otherwise award the points.
    pub fn check(
        &mut self,
        pass: bool,
        weight: u32,
        category: &str,
        severity: Severity,
        message: impl Into<String>,
        recommendation: impl Into<String>,
    ) {
        self.max_points += weight;
        let cat = self.categories.entry(category.to_string()).or_default();
        cat.max += weight;
        if pass {
            self.points += weight;
            cat.earned += weight;
        } else {
            self.findings.push(ComplianceFinding {
                category: category.to_string(),
                severity,
                message: message.into(),
                recommendation: recommendation.into(),
            });
        }
    }

    /// Compute the letter grade from accumulated points.
    pub fn finalize(&mut self) {
        if self.max_points == 0 {
            self.grade = 'A';
            return;
        }
        let pct = (self.points as f64 / self.max_points as f64) * 100.0;
        self.grade = if pct >= 90.0 {
            'A'
        } else if pct >= 80.0 {
            'B'
        } else if pct >= 65.0 {
            'C'
        } else if pct >= 50.0 {
            'D'
        } else {
            'F'
        };
    }
}

impl Default for ComplianceScore {
    fn default() -> Self {
        Self::new()
    }
}
