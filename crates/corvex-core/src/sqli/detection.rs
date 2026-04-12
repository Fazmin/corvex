//! Response comparison utilities for SQL injection detection.
//!
//! Provides page similarity measurement, dynamic content removal,
//! error signature extraction, and UNION data extraction.

use regex::Regex;
use std::sync::LazyLock;

use super::dbms::{self, Dbms, ErrorMatch};

// ---------------------------------------------------------------------------
// Page similarity (SequenceMatcher-inspired)
// ---------------------------------------------------------------------------

/// Compute a similarity ratio between two byte slices (0.0 = completely
/// different, 1.0 = identical). Uses a quick length-based heuristic first,
/// then falls back to a trigram overlap for bodies of different length.
pub fn page_ratio(a: &[u8], b: &[u8]) -> f64 {
    if a == b {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

    // Quick length ratio check — if lengths differ significantly the pages
    // are almost certainly different.
    let len_a = a.len() as f64;
    let len_b = b.len() as f64;
    let len_ratio = if len_a > len_b {
        len_b / len_a
    } else {
        len_a / len_b
    };

    // If lengths are very different, we can return early.
    if len_ratio < 0.5 {
        return len_ratio;
    }

    // Trigram-based similarity for more accurate comparison.
    // Convert to lowercase strings for comparison.
    let sa = String::from_utf8_lossy(a);
    let sb = String::from_utf8_lossy(b);
    trigram_ratio(&sa, &sb)
}

/// Trigram similarity between two strings.
fn trigram_ratio(a: &str, b: &str) -> f64 {
    if a.len() < 3 || b.len() < 3 {
        // For very short strings, use character-level comparison.
        return char_ratio(a, b);
    }

    let trigrams_a = trigrams(a);
    let trigrams_b = trigrams(b);

    if trigrams_a.is_empty() && trigrams_b.is_empty() {
        return 1.0;
    }

    let mut common = 0usize;
    let mut used = vec![false; trigrams_b.len()];

    for ta in &trigrams_a {
        for (j, tb) in trigrams_b.iter().enumerate() {
            if !used[j] && ta == tb {
                common += 1;
                used[j] = true;
                break;
            }
        }
    }

    let total = trigrams_a.len() + trigrams_b.len();
    if total == 0 {
        return 1.0;
    }
    (2.0 * common as f64) / total as f64
}

fn trigrams(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    if bytes.len() < 3 {
        return vec![];
    }
    // Only ASCII-safe trigrams for performance
    (0..bytes.len() - 2)
        .filter_map(|i| std::str::from_utf8(&bytes[i..i + 3]).ok())
        .collect()
}

fn char_ratio(a: &str, b: &str) -> f64 {
    let ca: Vec<char> = a.chars().collect();
    let cb: Vec<char> = b.chars().collect();
    let total = ca.len() + cb.len();
    if total == 0 {
        return 1.0;
    }
    let common = ca.iter().filter(|c| cb.contains(c)).count();
    (2.0 * common as f64) / total as f64
}

// ---------------------------------------------------------------------------
// Dynamic content removal
// ---------------------------------------------------------------------------

static DYNAMIC_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // CSRF tokens and nonces in form fields
        Regex::new(r#"(?i)name=["'](csrf[^"']*|[^"']*token[^"']*|nonce|authenticity_token|_token|__RequestVerificationToken)["']\s+value=["'][^"']*["']"#).unwrap(),
        // CSRF tokens in JSON/JS: "token": "value"
        Regex::new(r#"(?i)["'](csrf|token|nonce|_token)["']\s*:\s*["'][a-zA-Z0-9+/=_-]{16,}["']"#).unwrap(),
        // Session IDs in hidden fields
        Regex::new(r#"(?i)name=["'](PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session_id)["']\s+value=["'][^"']*["']"#).unwrap(),
        // Timestamps (various formats)
        Regex::new(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}").unwrap(),
        // Unix timestamps
        Regex::new(r"\b1[3-9]\d{8}\b").unwrap(),
        // Random/unique identifiers (UUIDs)
        Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap(),
        // Cache busters in URLs
        Regex::new(r"[?&](v|_|t|ts|cb|cachebust)=[0-9a-zA-Z]+").unwrap(),
    ]
});

/// Remove dynamic content (timestamps, tokens, session IDs) from a response
/// body to enable more stable page comparisons.
pub fn remove_dynamic_content(body: &str) -> String {
    let mut result = body.to_string();
    for pat in DYNAMIC_PATTERNS.iter() {
        result = pat.replace_all(&result, "[DYNAMIC]").to_string();
    }
    result
}

// ---------------------------------------------------------------------------
// Error signature extraction
// ---------------------------------------------------------------------------

/// Scan a response body for known DBMS error signatures. Returns all
/// (DBMS, description) pairs found.
pub fn contains_error_signature(body: &str) -> Vec<(Dbms, String)> {
    dbms::fingerprint_from_error(body)
        .into_iter()
        .map(|m| (m.dbms, m.description.to_string()))
        .collect()
}

/// Full error match extraction with matched text.
pub fn error_matches(body: &str) -> Vec<ErrorMatch> {
    dbms::fingerprint_from_error(body)
}

// ---------------------------------------------------------------------------
// UNION data extraction
// ---------------------------------------------------------------------------

/// Given a response body and a unique marker pair, extract the data between
/// the markers. The reference tool uses `q<char>q<char>q` style markers.
pub fn extract_data_from_union(body: &str, marker: &str) -> Option<String> {
    let start_marker = format!("{marker}");
    let end_marker = format!("{marker}");

    let start = body.find(&start_marker)?;
    let after_start = start + start_marker.len();
    let end = body[after_start..].find(&end_marker)?;

    let data = &body[after_start..after_start + end];
    if data.is_empty() {
        None
    } else {
        Some(data.to_string())
    }
}

/// Generate a unique marker string for UNION-based extraction.
/// Uses a format unlikely to appear in normal page content.
pub fn union_marker() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("q6zq9q{:x}q6zq9q", ts & 0xFFFF_FFFF)
}

// ---------------------------------------------------------------------------
// Response comparison helpers
// ---------------------------------------------------------------------------

/// Check if two responses are "the same page" (similar enough to be considered
/// identical after removing dynamic content).
pub fn is_same_page(body_a: &[u8], body_b: &[u8], threshold: f64) -> bool {
    let sa = String::from_utf8_lossy(body_a);
    let sb = String::from_utf8_lossy(body_b);
    let clean_a = remove_dynamic_content(&sa);
    let clean_b = remove_dynamic_content(&sb);
    page_ratio(clean_a.as_bytes(), clean_b.as_bytes()) >= threshold
}

/// Check if two responses are "different pages".
pub fn is_different_page(body_a: &[u8], body_b: &[u8], threshold: f64) -> bool {
    !is_same_page(body_a, body_b, threshold)
}

/// Heuristic: does the body contain SQL error keywords (without matching a
/// specific DBMS)?
pub fn has_generic_sql_error(body: &str) -> bool {
    let lower = body.to_lowercase();
    lower.contains("sql syntax")
        || lower.contains("sql error")
        || lower.contains("syntax error")
        || lower.contains("unexpected end of sql")
        || lower.contains("unclosed quotation")
        || lower.contains("unterminated string")
        || lower.contains("invalid query")
        || lower.contains("query failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_pages_ratio_1() {
        let a = b"<html><body>Hello World</body></html>";
        assert!((page_ratio(a, a) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn empty_page_ratio_0() {
        assert!((page_ratio(b"", b"hello") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn similar_pages_high_ratio() {
        let a = b"<html><body><p>User profile for Alice</p><p>Email: alice@test.com</p></body></html>";
        let b = b"<html><body><p>User profile for Alice</p><p>Email: alice@test.com</p></body></html>";
        assert!(page_ratio(a, b) > 0.9);
    }

    #[test]
    fn different_pages_low_ratio() {
        let a = b"<html><body>Login successful! Welcome admin.</body></html>";
        let b = b"<html><body>Error 404: Page not found.</body></html>";
        assert!(page_ratio(a, b) < 0.6);
    }

    #[test]
    fn dynamic_content_removed() {
        let body = r#"<input name="csrf_token" value="abc123def456ghi789jkl012mno345">"#;
        let cleaned = remove_dynamic_content(body);
        assert!(cleaned.contains("[DYNAMIC]"), "cleaned: {cleaned}");
    }

    #[test]
    fn union_marker_extraction() {
        let marker = "q6zq9qTESTq6zq9q";
        let body = format!("some content {}admin{} more content", marker, marker);
        let data = extract_data_from_union(&body, marker);
        assert_eq!(data, Some("admin".to_string()));
    }

    #[test]
    fn generic_sql_error_detection() {
        assert!(has_generic_sql_error("You have an error in your SQL syntax near"));
        assert!(!has_generic_sql_error("Welcome to our website"));
    }
}
