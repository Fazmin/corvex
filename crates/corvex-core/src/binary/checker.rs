//! Binary checker trait and detected library model.

use regex::Regex;

/// A library detected in a binary file.
#[derive(Debug, Clone)]
pub struct DetectedLibrary {
    pub name: String,
    pub version: String,
    pub cpe_vendor: String,
    pub cpe_product: String,
}

/// Trait for binary component checkers.
pub trait BinaryChecker: Send + Sync {
    /// The human-readable name of the library.
    fn name(&self) -> &str;
    /// CPE vendor identifier.
    fn cpe_vendor(&self) -> &str;
    /// CPE product identifier.
    fn cpe_product(&self) -> &str;
    /// Attempt to detect this library in the extracted strings.
    fn detect(&self, strings: &[String]) -> Option<DetectedLibrary>;
}

/// A regex-based binary checker. Most checkers use this.
pub struct RegexChecker {
    pub lib_name: &'static str,
    pub vendor: &'static str,
    pub product: &'static str,
    pub patterns: Vec<CheckerPattern>,
}

/// A pattern to search for, with a version capture group.
pub struct CheckerPattern {
    pub regex: Regex,
    /// Which capture group contains the version (usually 1).
    pub version_group: usize,
}

impl BinaryChecker for RegexChecker {
    fn name(&self) -> &str {
        self.lib_name
    }

    fn cpe_vendor(&self) -> &str {
        self.vendor
    }

    fn cpe_product(&self) -> &str {
        self.product
    }

    fn detect(&self, strings: &[String]) -> Option<DetectedLibrary> {
        for s in strings {
            for pattern in &self.patterns {
                if let Some(caps) = pattern.regex.captures(s) {
                    if let Some(ver) = caps.get(pattern.version_group) {
                        return Some(DetectedLibrary {
                            name: self.lib_name.to_string(),
                            version: ver.as_str().to_string(),
                            cpe_vendor: self.vendor.to_string(),
                            cpe_product: self.product.to_string(),
                        });
                    }
                }
            }
        }
        None
    }
}

/// Helper to create a simple regex pattern with version in group 1.
pub fn pattern(re: &str) -> CheckerPattern {
    CheckerPattern {
        regex: Regex::new(re).unwrap(),
        version_group: 1,
    }
}
