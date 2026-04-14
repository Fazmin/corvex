//! Binary string extraction — extracts printable ASCII strings from binary files.

use std::io::Read;
use std::path::Path;

/// Minimum length for extracted strings.
const MIN_STRING_LEN: usize = 4;

/// Extract printable ASCII strings from a file.
/// Returns strings of at least `MIN_STRING_LEN` characters.
pub fn extract_strings(path: &Path) -> Result<Vec<String>, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;

    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|e| format!("read {}: {e}", path.display()))?;

    Ok(extract_strings_from_bytes(&buf))
}

/// Extract printable ASCII strings from a byte slice.
pub fn extract_strings_from_bytes(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in data {
        if byte >= 0x20 && byte < 0x7F {
            current.push(byte as char);
        } else {
            if current.len() >= MIN_STRING_LEN {
                strings.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
    }

    if current.len() >= MIN_STRING_LEN {
        strings.push(current);
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_strings() {
        let data = b"hello\x00wo\x00OpenSSL 1.1.1k\x00\x01\x02ab\x00test string here\x00";
        let strings = extract_strings_from_bytes(data);
        assert!(strings.contains(&"hello".to_string()));
        assert!(strings.contains(&"OpenSSL 1.1.1k".to_string()));
        assert!(strings.contains(&"test string here".to_string()));
        // "wo" and "ab" are too short
        assert!(!strings.contains(&"wo".to_string()));
    }
}
