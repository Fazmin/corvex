//! SQL injection detection techniques.
//!
//! Each technique module implements a specific detection method for
//! identifying injectable parameters. Techniques are run in priority
//! order: Error -> Boolean -> Time -> UNION -> Stacked.

pub mod boolean;
pub mod error;
pub mod stacked;
pub mod time;
pub mod union_query;

use crate::fuzzer::InjectionPoint;
use super::dbms::Dbms;

/// Detection technique identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Technique {
    ErrorBased,
    BooleanBlind,
    TimeBlind,
    UnionQuery,
    StackedQueries,
}

impl std::fmt::Display for Technique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ErrorBased => write!(f, "error-based"),
            Self::BooleanBlind => write!(f, "boolean-based blind"),
            Self::TimeBlind => write!(f, "time-based blind"),
            Self::UnionQuery => write!(f, "UNION query-based"),
            Self::StackedQueries => write!(f, "stacked queries"),
        }
    }
}

/// Confidence level for a detection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

/// A confirmed or suspected SQL injection finding.
#[derive(Debug, Clone)]
pub struct SqliFinding {
    /// Which detection technique identified this.
    pub technique: Technique,
    /// Identified DBMS backend.
    pub dbms: Dbms,
    /// Name of the vulnerable parameter.
    pub parameter: String,
    /// Where the parameter lives (query, body, header, etc.).
    pub injection_point: InjectionPoint,
    /// The payload that triggered the detection.
    pub payload: String,
    /// The URL that was tested.
    pub url: String,
    /// Any data extracted during detection (version, DB name, etc.).
    pub extracted_data: Option<String>,
    /// How confident we are in this finding.
    pub confidence: Confidence,
}
