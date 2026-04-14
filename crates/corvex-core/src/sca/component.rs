//! Component model — the universal unit for software composition analysis.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Software ecosystem identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    Cargo,
    Npm,
    PyPI,
    Maven,
    Go,
    RubyGems,
    Packagist,
    NuGet,
    Unknown,
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cargo => write!(f, "crates.io"),
            Self::Npm => write!(f, "npm"),
            Self::PyPI => write!(f, "PyPI"),
            Self::Maven => write!(f, "Maven"),
            Self::Go => write!(f, "Go"),
            Self::RubyGems => write!(f, "RubyGems"),
            Self::Packagist => write!(f, "Packagist"),
            Self::NuGet => write!(f, "NuGet"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// A detected software component (dependency, library, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    /// Package URL (e.g., `pkg:npm/express@4.18.2`).
    pub purl: Option<String>,
    /// CPE 2.3 string for CVE matching.
    pub cpe: Option<String>,
    /// File that declared this component.
    pub source_file: Option<PathBuf>,
    /// Component author/vendor (if known).
    pub vendor: Option<String>,
    /// License identifier (if known).
    pub license: Option<String>,
    /// Description of the component.
    pub description: Option<String>,
}

impl Component {
    pub fn new(name: &str, version: &str, ecosystem: Ecosystem) -> Self {
        let purl = build_purl(ecosystem, name, version);
        Self {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem,
            purl: Some(purl),
            cpe: None,
            source_file: None,
            vendor: None,
            license: None,
            description: None,
        }
    }

    /// Set the source file path.
    pub fn with_source(mut self, path: PathBuf) -> Self {
        self.source_file = Some(path);
        self
    }
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{} ({})", self.name, self.version, self.ecosystem)
    }
}

/// Build a Package URL string.
fn build_purl(ecosystem: Ecosystem, name: &str, version: &str) -> String {
    let pkg_type = match ecosystem {
        Ecosystem::Cargo => "cargo",
        Ecosystem::Npm => "npm",
        Ecosystem::PyPI => "pypi",
        Ecosystem::Maven => "maven",
        Ecosystem::Go => "golang",
        Ecosystem::RubyGems => "gem",
        Ecosystem::Packagist => "composer",
        Ecosystem::NuGet => "nuget",
        Ecosystem::Unknown => "generic",
    };
    format!("pkg:{}/{}@{}", pkg_type, name, version)
}
