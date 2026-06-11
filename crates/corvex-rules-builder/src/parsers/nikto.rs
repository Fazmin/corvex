//! Nikto `db_tests` CSV parser.
//!
//! The format and column layout are identical to what
//! `crates/corvex-core/build.rs::load_tests` already consumes — see lines
//! 190-216 there. We re-implement the CSV reader here (rather than depending
//! on `corvex-core`) because the builder is independent of the runtime crate
//! and we don't want to pull the bincode pipeline into this binary.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;

use crate::normalized::{NormalizedRule, ParseStats, SourceTool};
use crate::severity;

/// Parse a Nikto `db_tests` file into normalised rules.
///
/// Returns the rules plus parse stats. Any malformed row is skipped and
/// counted by reason so the report can show ingestion fidelity.
pub fn parse(path: &Path) -> Result<(Vec<NormalizedRule>, ParseStats)> {
    let raw = read_filtered(path)?;

    let mut rules = Vec::new();
    let mut stats = ParseStats::default();

    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        // Nikto's `db_tests` is NOT standard CSV: the match column (field 5)
        // is a regex where backslash is a metacharacter (`\[`, `\.`, `\s`),
        // and an embedded quote is written `\"`. A generic CSV reader with
        // `escape = '\\'` consumes those backslashes and corrupts the regex
        // — e.g. `\[winnt\]` (literal `[winnt]`) becomes `[winnt]`, a
        // character class that matches almost any response. `split_nikto_csv`
        // mirrors Nikto's own parser: `\"` stays an in-field quote, but every
        // backslash is PRESERVED so the downstream regex engine sees the
        // pattern the author wrote.
        let rec = split_nikto_csv(line);

        // Skip optional CSV header row.
        if i == 0
            && rec
                .first()
                .map(|s| s.eq_ignore_ascii_case("id") || s.eq_ignore_ascii_case("nikto_id"))
                .unwrap_or(false)
        {
            continue;
        }

        if rec.is_empty() {
            stats.skip("empty_row");
            continue;
        }

        let id = field(&rec, 0).trim().to_string();
        if id.is_empty() {
            stats.skip("missing_id");
            continue;
        }

        let references = field(&rec, 1).to_string();
        let tuning = field(&rec, 2).to_string();
        let uri = field(&rec, 3).to_string();
        let method = field(&rec, 4).to_string();
        let dsl = field(&rec, 5).to_string();
        // The match column (dsl) keeps its backslashes — they're regex
        // metacharacters. The message is human-readable text, so the only
        // backslash escape that occurs there (`\"`) is unescaped for display.
        let message = field(&rec, 6).replace(r#"\""#, "\"");
        let data = field(&rec, 7).to_string();
        let headers = field(&rec, 8).to_string();

        let sev = severity::severity_from_nikto_tuning(&tuning);

        let refs_vec: Vec<String> = references
            .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let category = nikto_category_from_tuning(&tuning);

        let rule = NormalizedRule {
            source_tool: SourceTool::Nikto,
            source_rule_id: id,
            name: short_name(&message),
            description: if message.is_empty() { None } else { Some(message.clone()) },
            severity: sev,
            confidence: None,
            category,
            owasp_2025: nikto_owasp_from_tuning(&tuning),
            cwe: None,
            references: refs_vec,
            http_method: if method.is_empty() {
                Some("GET".to_string())
            } else {
                Some(method.clone())
            },
            uri_template: if uri.is_empty() { None } else { Some(uri.clone()) },
            request_body: if data.is_empty() { None } else { Some(data.clone()) },
            request_headers: if headers.is_empty() {
                None
            } else {
                Some(headers.clone())
            },
            payloads: Vec::new(),
            detection: json!({
                "kind": "nikto_dsl",
                "raw": dsl,
                "tuning": tuning,
            }),
            source_meta: json!({
                "raw_message": message,
            }),
        };

        rules.push(rule);
        stats.ingested += 1;
    }

    Ok((rules, stats))
}

/// Field accessor that mirrors the old `StringRecord::get(n).unwrap_or_default()`
/// behaviour over a plain `Vec<String>` of columns.
fn field(rec: &[String], n: usize) -> &str {
    rec.get(n).map(|s| s.as_str()).unwrap_or("")
}

/// Split one `db_tests` line into columns the way Nikto itself does.
///
/// Columns are comma-separated and optionally double-quoted. Inside a quoted
/// column a backslash escapes the next character *for field-termination
/// purposes only* — so `\"` does not close the field — but the backslash is
/// kept in the emitted value. Nikto feeds these column strings straight to its
/// regex engine, where `\[`, `\.`, `\s`, `\(` and friends are meaningful, so
/// stripping the backslash (as a CSV `escape` setting does) silently rewrites
/// the pattern. Preserving it is the whole point of this function.
fn split_nikto_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        let mut field = String::new();
        if matches!(chars.peek(), Some('"')) {
            chars.next(); // consume opening quote
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        // Keep the backslash AND the escaped char; `\"` is an
                        // in-field quote, every other `\x` is regex content.
                        field.push('\\');
                        if let Some(next) = chars.next() {
                            field.push(next);
                        }
                    }
                    '"' => break, // closing quote
                    other => field.push(other),
                }
            }
            // Tolerate stray characters between the closing quote and the
            // separator (Nikto's CSV regex allows an optional comma there).
            while let Some(&c) = chars.peek() {
                if c == ',' {
                    break;
                }
                chars.next();
            }
        } else {
            // Unquoted column — runs to the next comma.
            while let Some(&c) = chars.peek() {
                if c == ',' {
                    break;
                }
                field.push(c);
                chars.next();
            }
        }
        fields.push(field);
        match chars.peek() {
            Some(',') => {
                chars.next();
                // A trailing comma denotes a final empty column.
                if chars.peek().is_none() {
                    fields.push(String::new());
                    break;
                }
            }
            _ => break,
        }
    }
    fields
}

/// Read the file, stripping `#` comment lines and blank lines (the same
/// pre-filter applied in corvex-core's build.rs).
fn read_filtered(path: &Path) -> Result<String> {
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut out = String::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

/// Truncate the Nikto message to a short, human-readable name. Falls back to
/// "Nikto rule" for empty messages.
fn short_name(msg: &str) -> String {
    let trimmed = msg.trim();
    if trimmed.is_empty() {
        return "Nikto rule".to_string();
    }
    let first_line = trimmed.lines().next().unwrap_or(trimmed);
    if first_line.len() <= 120 {
        first_line.to_string()
    } else {
        // Slice on a char boundary so non-ASCII messages don't panic.
        let mut end = 117usize.min(first_line.len());
        while !first_line.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{}…", &first_line[..end])
    }
}

/// Map the highest-priority Nikto tuning category to a coarse vuln class.
fn nikto_category_from_tuning(tuning: &str) -> Option<String> {
    let mut best: Option<&'static str> = None;
    let mut best_rank = -1i32;
    for c in tuning.chars() {
        let (cat, rank) = match c {
            '8' => ("rce", 9),
            '9' => ("sqli", 8),
            '4' => ("xss", 7),
            'f' => ("xml-injection", 7),
            '5' | 'c' => ("rfi", 6),
            'a' => ("auth-bypass", 6),
            '0' => ("file-upload", 5),
            '6' => ("dos", 5),
            '7' => ("rfr", 4),
            '2' => ("misconfig", 3),
            'e' => ("admin-console", 3),
            '3' => ("info-disclosure", 2),
            '1' => ("interesting-files", 1),
            'd' => ("webservice", 1),
            'b' => ("software-id", 0),
            _ => continue,
        };
        if rank > best_rank {
            best = Some(cat);
            best_rank = rank;
        }
    }
    best.map(|s| s.to_string())
}

/// Best-effort OWASP Top 10 (2025) bucket for Nikto categories. The mapping
/// is coarse — just enough to be useful for filtering. A `None` here is
/// honest: many Nikto rules don't fit a single OWASP slot.
fn nikto_owasp_from_tuning(tuning: &str) -> Option<String> {
    for c in tuning.chars() {
        let bucket = match c {
            // A03 — Injection
            '8' | '9' | '4' | 'f' | '5' | 'c' => "A03",
            // A01 — Broken Access Control
            'a' => "A01",
            // A05 — Security Misconfiguration
            '2' | 'e' => "A05",
            // A04 — Insecure Design / sensitive data
            '3' => "A04",
            // A06 — Vulnerable & Outdated Components
            'b' => "A06",
            _ => continue,
        };
        return Some(bucket.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_regex_backslashes_in_match_column() {
        // The exact db_tests row behind the recurring false-positive critical.
        // The match column must come back with its backslashes intact so the
        // regex engine sees the literal `[winnt]`, not a character class.
        let line = r#""000494","","8","/msadc/..%255c../winnt/system32/cmd.exe?/c+dir+c:%5c","GET","BODY:\[winnt\]&&!BODY:Internal server error","Can issue arbitrary commands to host.","","""#;
        let rec = split_nikto_csv(line);
        assert_eq!(field(&rec, 0), "000494");
        assert_eq!(field(&rec, 2), "8");
        assert_eq!(field(&rec, 4), "GET");
        assert_eq!(
            field(&rec, 5),
            r"BODY:\[winnt\]&&!BODY:Internal server error"
        );
        assert_eq!(field(&rec, 6), "Can issue arbitrary commands to host.");
    }

    #[test]
    fn handles_escaped_quotes_and_embedded_commas() {
        // `\"` keeps the field open; a comma inside the quotes is content.
        let line = r#""000065","","8","@CGIDIRSexcite;IFS=\"$\";/bin/cat%20@LFI(nix,abs)","GET","CODE:200""#;
        let rec = split_nikto_csv(line);
        assert_eq!(field(&rec, 0), "000065");
        assert_eq!(
            field(&rec, 3),
            r#"@CGIDIRSexcite;IFS=\"$\";/bin/cat%20@LFI(nix,abs)"#
        );
        assert_eq!(field(&rec, 4), "GET");
        assert_eq!(field(&rec, 5), "CODE:200");
    }

    #[test]
    fn empty_columns_and_trailing_comma() {
        let rec = split_nikto_csv(r#""a","","c","#);
        assert_eq!(rec.len(), 4);
        assert_eq!(field(&rec, 0), "a");
        assert_eq!(field(&rec, 1), "");
        assert_eq!(field(&rec, 2), "c");
        assert_eq!(field(&rec, 3), "");
    }
}
