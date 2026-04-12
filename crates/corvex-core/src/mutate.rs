//! `-mutate` directory / filename mutation hooks.
//!
//! Placeholder: the full Perl implementation expands paths with several
//! fuzz strategies (WordPress, Joomla, Drupal, etc). For the initial port
//! we only carry the flag through so tests run; the mutation logic can
//! be filled in without architectural changes.

#[derive(Debug, Clone, Default)]
pub struct MutateOptions {
    pub modes: Vec<String>,
    pub options: Option<String>,
}

impl MutateOptions {
    pub fn parse(modes: &str, options: Option<&str>) -> Self {
        Self {
            modes: modes
                .split(|c| c == ',' || c == ';')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            options: options.map(|s| s.to_string()),
        }
    }
}
