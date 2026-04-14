//! CPE 2.3 parser and version-range matching.

use std::cmp::Ordering;

/// Parsed CPE 2.3 formatted string.
///
/// Format: `cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpe {
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub update: String,
    pub edition: String,
    pub language: String,
    pub sw_edition: String,
    pub target_sw: String,
    pub target_hw: String,
    pub other: String,
}

impl Cpe {
    /// Parse a CPE 2.3 formatted string.
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 5 || parts[0] != "cpe" || parts[1] != "2.3" {
            return None;
        }
        Some(Cpe {
            part: parts.get(2).unwrap_or(&"*").to_string(),
            vendor: parts.get(3).unwrap_or(&"*").to_string(),
            product: parts.get(4).unwrap_or(&"*").to_string(),
            version: parts.get(5).unwrap_or(&"*").to_string(),
            update: parts.get(6).unwrap_or(&"*").to_string(),
            edition: parts.get(7).unwrap_or(&"*").to_string(),
            language: parts.get(8).unwrap_or(&"*").to_string(),
            sw_edition: parts.get(9).unwrap_or(&"*").to_string(),
            target_sw: parts.get(10).unwrap_or(&"*").to_string(),
            target_hw: parts.get(11).unwrap_or(&"*").to_string(),
            other: parts.get(12).unwrap_or(&"*").to_string(),
        })
    }

    /// Build a CPE 2.3 string from vendor, product, version.
    pub fn build(vendor: &str, product: &str, version: &str) -> String {
        format!(
            "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
            vendor.to_lowercase().replace(' ', "_"),
            product.to_lowercase().replace(' ', "_"),
            version,
        )
    }

    /// Format this CPE as a 2.3 string.
    pub fn to_uri(&self) -> String {
        format!(
            "cpe:2.3:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.part, self.vendor, self.product, self.version,
            self.update, self.edition, self.language,
            self.sw_edition, self.target_sw, self.target_hw, self.other
        )
    }
}

/// Compare two version strings using semantic-ish comparison.
///
/// Splits on `.` and `-`, compares each segment numerically where possible,
/// lexicographically otherwise.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let seg_a = version_segments(a);
    let seg_b = version_segments(b);

    for (sa, sb) in seg_a.iter().zip(seg_b.iter()) {
        let ord = match (sa.parse::<u64>(), sb.parse::<u64>()) {
            (Ok(na), Ok(nb)) => na.cmp(&nb),
            _ => sa.cmp(sb),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    seg_a.len().cmp(&seg_b.len())
}

fn version_segments(v: &str) -> Vec<String> {
    v.split(|c: char| c == '.' || c == '-' || c == '_' || c == '+')
        .map(|s| s.to_string())
        .collect()
}

/// Check whether `target_version` falls within the range defined by a CPE match entry.
pub fn version_in_range(
    target_version: &str,
    start_incl: Option<&str>,
    start_excl: Option<&str>,
    end_incl: Option<&str>,
    end_excl: Option<&str>,
) -> bool {
    if let Some(si) = start_incl {
        if compare_versions(target_version, si) == Ordering::Less {
            return false;
        }
    }
    if let Some(se) = start_excl {
        if compare_versions(target_version, se) != Ordering::Greater {
            return false;
        }
    }
    if let Some(ei) = end_incl {
        if compare_versions(target_version, ei) == Ordering::Greater {
            return false;
        }
    }
    if let Some(ee) = end_excl {
        if compare_versions(target_version, ee) != Ordering::Less {
            return false;
        }
    }
    true
}

/// Check if a CPE URI pattern matches a target vendor:product.
/// Supports `*` wildcards in vendor/product fields.
pub fn cpe_matches_target(pattern_cpe: &str, vendor: &str, product: &str) -> bool {
    let Some(parsed) = Cpe::parse(pattern_cpe) else {
        return false;
    };
    let vendor_match = parsed.vendor == "*" || parsed.vendor == vendor.to_lowercase();
    let product_match = parsed.product == "*" || parsed.product == product.to_lowercase();
    vendor_match && product_match
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cpe() {
        let cpe = Cpe::parse("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*").unwrap();
        assert_eq!(cpe.vendor, "openssl");
        assert_eq!(cpe.product, "openssl");
        assert_eq!(cpe.version, "1.1.1k");
    }

    #[test]
    fn test_compare_versions() {
        assert_eq!(compare_versions("1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(compare_versions("1.2.3", "1.2.4"), Ordering::Less);
        assert_eq!(compare_versions("2.0.0", "1.9.9"), Ordering::Greater);
        assert_eq!(compare_versions("1.10.0", "1.9.0"), Ordering::Greater);
    }

    #[test]
    fn test_version_in_range() {
        assert!(version_in_range("1.5.0", Some("1.0.0"), None, Some("2.0.0"), None));
        assert!(!version_in_range("0.9.0", Some("1.0.0"), None, Some("2.0.0"), None));
        assert!(!version_in_range("2.0.1", Some("1.0.0"), None, Some("2.0.0"), None));
        // Exclusive bounds
        assert!(!version_in_range("1.0.0", None, Some("1.0.0"), None, Some("2.0.0")));
        assert!(version_in_range("1.0.1", None, Some("1.0.0"), None, Some("2.0.0")));
    }

    #[test]
    fn test_cpe_matches_target() {
        assert!(cpe_matches_target(
            "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "openssl",
            "openssl"
        ));
        assert!(!cpe_matches_target(
            "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "curl",
            "curl"
        ));
    }
}
