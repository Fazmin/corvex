//! Parser for the Corvex test DSL.
//!
//! Grammar (informal):
//!     dsl      := matcher ("&&" matcher)*
//!     matcher  := "!"? selector ":" rest
//!     selector := "CODE" | "BODY" | "HEADER" | "COOKIE"
//!     rest     := for CODE/BODY, a regex up to next "&&";
//!                 for HEADER/COOKIE, NAME ":" regex up to next "&&"
//!
//! The regex itself may contain `|` (alternation) and `&&` inside
//! character classes or escapes, so splitting on `&&` is heuristic:
//! split at top-level `&&` not inside `[]` or `()`.

use crate::error::{CorvexError, Result};
use regex::Regex;

#[derive(Debug, Clone)]
pub enum Matcher {
    Code(Regex),
    Body(Regex),
    Header { name: String, value: Regex },
    Cookie { name: String, value: Regex },
}

#[derive(Debug, Clone)]
pub struct Dsl {
    /// (matcher, negated) pairs, AND-joined.
    pub matchers: Vec<(Matcher, bool)>,
}

impl Dsl {
    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }
}

pub fn parse(src: &str) -> Result<Dsl> {
    let mut matchers = Vec::new();
    for piece in split_top_level(src, "&&") {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let (neg, rest) = match piece.strip_prefix('!') {
            Some(r) => (true, r),
            None => (false, piece),
        };
        let (kind, body) = match rest.split_once(':') {
            Some(p) => p,
            None => {
                return Err(CorvexError::Dsl(format!(
                    "expected SELECTOR:..., got `{rest}`"
                )))
            }
        };
        let matcher = match kind.to_ascii_uppercase().as_str() {
            "CODE" => Matcher::Code(compile_regex(body)?),
            "BODY" => Matcher::Body(compile_regex(body)?),
            "HEADER" => {
                let (name, value) = body.split_once(':').ok_or_else(|| {
                    CorvexError::Dsl(format!("HEADER needs name:regex, got `{body}`"))
                })?;
                Matcher::Header {
                    name: name.trim().to_string(),
                    value: compile_regex(value)?,
                }
            }
            "COOKIE" => {
                let (name, value) = body.split_once(':').ok_or_else(|| {
                    CorvexError::Dsl(format!("COOKIE needs name:regex, got `{body}`"))
                })?;
                Matcher::Cookie {
                    name: name.trim().to_string(),
                    value: compile_regex(value)?,
                }
            }
            other => return Err(CorvexError::Dsl(format!("unknown selector `{other}`"))),
        };
        matchers.push((matcher, neg));
    }
    Ok(Dsl { matchers })
}

fn compile_regex(src: &str) -> Result<Regex> {
    // Corvex DSL regexes are Perl-flavored. The `regex` crate is RE2 and
    // rejects some constructs (backrefs, lookaround). We try as-is; on
    // failure, return a friendly DSL error.
    Regex::new(src).map_err(|e| CorvexError::Dsl(format!("regex `{src}`: {e}")))
}

/// Split `s` at top-level occurrences of `sep`, ignoring occurrences
/// inside `[]`, `{}`, or `()` (matching `regex` character classes &
/// groups) and escaped by `\`.
fn split_top_level(s: &str, sep: &str) -> Vec<String> {
    let sep_bytes = sep.as_bytes();
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut depth_paren = 0i32;
    let mut depth_brack = 0i32;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        match c {
            b'(' => depth_paren += 1,
            b')' => depth_paren -= 1,
            b'[' => depth_brack += 1,
            b']' => depth_brack -= 1,
            _ => {}
        }
        if depth_paren == 0
            && depth_brack == 0
            && bytes[i..].starts_with(sep_bytes)
        {
            out.push(
                std::str::from_utf8(&bytes[start..i])
                    .unwrap_or("")
                    .to_string(),
            );
            i += sep_bytes.len();
            start = i;
            continue;
        }
        i += 1;
    }
    out.push(std::str::from_utf8(&bytes[start..]).unwrap_or("").to_string());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_body() {
        let d = parse("BODY:Calypso Server").unwrap();
        assert_eq!(d.matchers.len(), 1);
        assert!(matches!(d.matchers[0].0, Matcher::Body(_)));
    }

    #[test]
    fn parses_and_joined() {
        let d = parse("CODE:200&&BODY:phpinfo\\(\\)").unwrap();
        assert_eq!(d.matchers.len(), 2);
    }

    #[test]
    fn parses_header() {
        let d = parse("HEADER:server:(?i)nginx").unwrap();
        assert_eq!(d.matchers.len(), 1);
    }

    #[test]
    fn negation() {
        let d = parse("!CODE:404").unwrap();
        assert!(d.matchers[0].1);
    }
}
