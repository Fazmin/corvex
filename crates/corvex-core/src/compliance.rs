//! Shared types for the compliance and configuration auditing system.

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

/// Aggregate compliance score for a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceScore {
    pub grade: char,
    pub points: u32,
    pub max_points: u32,
    pub findings: Vec<ComplianceFinding>,
}

impl ComplianceScore {
    pub fn new() -> Self {
        Self {
            grade: 'A',
            points: 0,
            max_points: 0,
            findings: Vec::new(),
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
        if pass {
            self.points += weight;
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
