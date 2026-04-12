//! Tuning filter — `-Tuning` flag.
//!
//! The flag value is a string of category chars (0..9, a..f, g, x). When
//! `x` appears, the remaining chars are *excluded* rather than included;
//! the default (no `-Tuning`) is "all categories allowed".
//!
//! Category `g` is reserved for the active-fuzzing engine. Including `g`
//! (explicitly or via the `--active` flag) enables the crawler + active
//! injection probes. Without `g`, only the signature engine runs.

#[derive(Debug, Clone, Default)]
pub struct TuningFilter {
    pub include: Option<String>, // None = all allowed
    pub exclude: String,
}

impl TuningFilter {
    pub fn parse(s: &str) -> Self {
        let mut include = None;
        let mut exclude = String::new();
        let mut inverted = false;
        for c in s.chars() {
            if c == 'x' || c == 'X' {
                inverted = true;
                continue;
            }
            if inverted {
                exclude.push(c);
            } else {
                include.get_or_insert_with(String::new).push(c);
            }
        }
        Self { include, exclude }
    }

    pub fn allows(&self, category_chars: &str) -> bool {
        if category_chars.is_empty() {
            return true;
        }
        let mut any_allowed = self.include.is_none();
        for c in category_chars.chars() {
            if self.exclude.contains(c) {
                return false;
            }
            if let Some(inc) = &self.include {
                if inc.contains(c) {
                    any_allowed = true;
                }
            }
        }
        any_allowed
    }
}
