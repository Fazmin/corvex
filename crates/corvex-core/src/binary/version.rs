//! Version string parsing and normalization for binary analysis.

use regex::Regex;
use once_cell::sync::Lazy;

/// Common version pattern: major.minor.patch with optional pre-release.
static VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z][-a-zA-Z0-9]*)?)").unwrap()
});

/// Extract version strings from a text string.
/// Returns all version-like patterns found.
pub fn extract_versions(text: &str) -> Vec<String> {
    VERSION_RE
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Normalize a version string by removing common prefixes.
pub fn normalize_version(v: &str) -> String {
    v.trim()
        .trim_start_matches('v')
        .trim_start_matches('V')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_versions() {
        assert_eq!(extract_versions("OpenSSL 1.1.1k"), vec!["1.1.1k"]);
        assert_eq!(extract_versions("libpng 1.6.37"), vec!["1.6.37"]);
        assert_eq!(extract_versions("curl 7.79.1"), vec!["7.79.1"]);
    }

    #[test]
    fn test_normalize_version() {
        assert_eq!(normalize_version("v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("1.2.3"), "1.2.3");
    }
}
