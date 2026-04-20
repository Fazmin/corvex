//! Template loader — YAML → `Template` plus a structured
//! `Supported`/`Skipped(reason)` classification.

use std::path::{Path, PathBuf};

use crate::dsl;
use crate::schema::{
    AttackMode, Extractor, HttpRequest, Matcher, PayloadValue, Template,
};

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

#[derive(Debug, Clone)]
pub enum LoadOutcome {
    Supported(Template),
    Skipped {
        id: Option<String>,
        path: PathBuf,
        reason: SkipReason,
    },
}

impl LoadOutcome {
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported(_))
    }

    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Supported(t) => Some(&t.id),
            Self::Skipped { id, .. } => id.as_deref(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// Non-HTTP protocol block present (network/dns/ssl/code/headless/…).
    Protocol(String),
    /// DSL expression references a helper function we don't implement.
    DslFn(String),
    /// Template keys off interactsh/OOB signals.
    Interactsh,
    /// Malformed YAML or missing required fields.
    ParseError(String),
    /// Feature we don't yet implement (raw requests, race, unsafe, …).
    UnsupportedFeature(String),
    /// No HTTP requests at all.
    NoHttp,
}

impl SkipReason {
    pub fn bucket(&self) -> &'static str {
        match self {
            Self::Protocol(_) => "protocol",
            Self::DslFn(_) => "dsl_fn",
            Self::Interactsh => "interactsh",
            Self::ParseError(_) => "parse_error",
            Self::UnsupportedFeature(_) => "unsupported_feature",
            Self::NoHttp => "no_http",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Self::Protocol(p) => p.clone(),
            Self::DslFn(f) => f.clone(),
            Self::Interactsh => "interactsh".to_string(),
            Self::ParseError(e) => e.clone(),
            Self::UnsupportedFeature(f) => f.clone(),
            Self::NoHttp => "no_http".to_string(),
        }
    }
}

/// Parse a template from YAML bytes, classifying it as Supported or
/// Skipped based on the v1 feature set.
pub fn load_bytes(path: impl AsRef<Path>, yaml: &[u8]) -> LoadOutcome {
    let path = path.as_ref();
    let mut tpl: Template = match serde_yaml::from_slice(yaml) {
        Ok(t) => t,
        Err(e) => {
            // Try to pull an id out of the raw YAML for the skipped-index
            // even when strict parsing failed.
            let id = quick_extract_id(yaml);
            return LoadOutcome::Skipped {
                id,
                path: path.to_path_buf(),
                reason: SkipReason::ParseError(e.to_string()),
            };
        }
    };
    tpl.source_path = Some(path.to_path_buf());

    classify(tpl)
}

/// Load a template from disk.
pub fn load_file(path: impl AsRef<Path>) -> Result<LoadOutcome, LoadError> {
    let path = path.as_ref();
    let bytes = std::fs::read(path)?;
    Ok(load_bytes(path, &bytes))
}

fn classify(tpl: Template) -> LoadOutcome {
    // 1. Non-HTTP protocols are hard-skipped.
    let other = tpl.non_http_protocol_keys();
    if !other.is_empty() {
        let first = other[0].to_string();
        return LoadOutcome::Skipped {
            id: Some(tpl.id.clone()),
            path: tpl.source_path.clone().unwrap_or_default(),
            reason: SkipReason::Protocol(first),
        };
    }

    // 2. Must have at least one HTTP request.
    if tpl.http_requests().is_empty() {
        return LoadOutcome::Skipped {
            id: Some(tpl.id.clone()),
            path: tpl.source_path.clone().unwrap_or_default(),
            reason: SkipReason::NoHttp,
        };
    }

    // 3. Walk each HTTP request for features we can't run in v1.
    for req in tpl.http_requests() {
        if !req.raw.is_empty() {
            return skip(&tpl, SkipReason::UnsupportedFeature("raw".into()));
        }
        if req.self_contained {
            return skip(
                &tpl,
                SkipReason::UnsupportedFeature("self-contained".into()),
            );
        }
        if req.race {
            return skip(&tpl, SkipReason::UnsupportedFeature("race".into()));
        }
        if req.unsafe_mode {
            return skip(&tpl, SkipReason::UnsupportedFeature("unsafe".into()));
        }
        if req.pipeline {
            return skip(&tpl, SkipReason::UnsupportedFeature("pipeline".into()));
        }
        if matches!(req.attack, AttackMode::ClusterBomb | AttackMode::Pitchfork)
            && req.payloads.is_empty()
        {
            // Non-batteringram attack without payloads is nonsensical; treat
            // as malformed rather than run it.
            return skip(
                &tpl,
                SkipReason::UnsupportedFeature("attack_without_payloads".into()),
            );
        }

        // Payload file references (e.g. `helpers/wordlists/...txt`) aren't
        // resolvable in our bundled subset.
        for v in req.payloads.values() {
            if matches!(v, PayloadValue::File(_)) {
                return skip(
                    &tpl,
                    SkipReason::UnsupportedFeature("payload-file".into()),
                );
            }
        }

        // Matchers: look for interactsh and unsupported DSL fns.
        for m in &req.matchers {
            if let Some(reason) = matcher_skip_reason(m) {
                return skip(&tpl, reason);
            }
        }

        // Extractors: same scan.
        for e in &req.extractors {
            if let Some(reason) = extractor_skip_reason(e) {
                return skip(&tpl, reason);
            }
        }

        // Body / headers / paths: DSL helpers inside `{{...}}`.
        if let Some(reason) = scan_strings_for_dsl(&request_strings(req)) {
            return skip(&tpl, reason);
        }
    }

    LoadOutcome::Supported(tpl)
}

fn skip(tpl: &Template, reason: SkipReason) -> LoadOutcome {
    LoadOutcome::Skipped {
        id: Some(tpl.id.clone()),
        path: tpl.source_path.clone().unwrap_or_default(),
        reason,
    }
}

fn matcher_skip_reason(m: &Matcher) -> Option<SkipReason> {
    match m {
        Matcher::Word(w) => {
            if w.part.contains("interactsh") {
                return Some(SkipReason::Interactsh);
            }
            for s in &w.words {
                if s.contains("interactsh") {
                    return Some(SkipReason::Interactsh);
                }
            }
        }
        Matcher::Regex(r) => {
            if r.part.contains("interactsh") {
                return Some(SkipReason::Interactsh);
            }
        }
        Matcher::Binary(b) => {
            if b.part.contains("interactsh") {
                return Some(SkipReason::Interactsh);
            }
        }
        Matcher::Dsl(d) => {
            for expr in &d.dsl {
                if expr.contains("interactsh") {
                    return Some(SkipReason::Interactsh);
                }
                if let Some(reason) = dsl_expr_skip(expr) {
                    return Some(reason);
                }
            }
        }
        _ => {}
    }
    None
}

fn extractor_skip_reason(e: &Extractor) -> Option<SkipReason> {
    if let Extractor::Dsl(d) = e {
        for expr in &d.dsl {
            if expr.contains("interactsh") {
                return Some(SkipReason::Interactsh);
            }
            if let Some(reason) = dsl_expr_skip(expr) {
                return Some(reason);
            }
        }
    }
    None
}

/// Collect every string in a request that can contain `{{...}}`
/// placeholders (path, headers, body).
fn request_strings(req: &HttpRequest) -> Vec<String> {
    let mut out = req.path.clone();
    for (k, v) in &req.headers {
        out.push(k.clone());
        out.push(v.clone());
    }
    if let Some(b) = &req.body {
        out.push(b.clone());
    }
    out
}

/// Look for `{{expr}}` placeholders in strings and verify every DSL
/// helper function referenced is in our allowlist.
fn scan_strings_for_dsl(strings: &[String]) -> Option<SkipReason> {
    for s in strings {
        let mut rest = s.as_str();
        while let Some(start) = rest.find("{{") {
            rest = &rest[start + 2..];
            let Some(end) = rest.find("}}") else { break };
            let expr = &rest[..end];
            rest = &rest[end + 2..];

            // Plain variable names (BaseURL, Hostname, …) aren't DSL.
            if is_plain_variable(expr) {
                continue;
            }
            if let Some(reason) = dsl_expr_skip(expr) {
                return Some(reason);
            }
        }
    }
    None
}

fn is_plain_variable(expr: &str) -> bool {
    let e = expr.trim();
    !e.is_empty() && e.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn dsl_expr_skip(expr: &str) -> Option<SkipReason> {
    match dsl::parser::parse(expr) {
        Ok(ast) => {
            let referenced = dsl::parser::referenced_functions(&ast);
            for f in referenced {
                if !dsl::fns::is_known(&f) {
                    return Some(SkipReason::DslFn(f));
                }
            }
            None
        }
        // An expression we can't even parse is treated as an unknown
        // function so it lands in the DSL bucket rather than parse_error.
        Err(_) => Some(SkipReason::DslFn("<unparseable>".to_string())),
    }
}

fn quick_extract_id(yaml: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(yaml).ok()?;
    for line in text.lines().take(12) {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("id:") {
            return Some(rest.trim().trim_matches('"').trim_matches('\'').to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUPPORTED: &str = r#"
id: corvex-smoke-ok
info:
  name: Smoke test
  author: corvex
  severity: info
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status: [200]
"#;

    const SKIP_NETWORK: &str = r#"
id: corvex-smoke-network
info:
  name: Network skipped
  author: corvex
  severity: low
network:
  - host:
      - "{{Hostname}}"
"#;

    const SKIP_UNKNOWN_DSL: &str = r#"
id: corvex-smoke-dsl
info:
  name: DSL unknown
  author: corvex
  severity: low
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: dsl
        dsl:
          - "magic_fn_that_does_not_exist(body)"
"#;

    #[test]
    fn supported_template_round_trips() {
        let out = load_bytes("tests/ok.yaml", SUPPORTED.as_bytes());
        assert!(matches!(out, LoadOutcome::Supported(_)));
    }

    #[test]
    fn non_http_protocol_is_skipped() {
        let out = load_bytes("tests/net.yaml", SKIP_NETWORK.as_bytes());
        match out {
            LoadOutcome::Skipped { reason: SkipReason::Protocol(p), .. } => {
                assert_eq!(p, "network");
            }
            other => panic!("expected protocol skip, got {other:?}"),
        }
    }

    #[test]
    fn unknown_dsl_fn_is_skipped() {
        let out = load_bytes("tests/dsl.yaml", SKIP_UNKNOWN_DSL.as_bytes());
        match out {
            LoadOutcome::Skipped { reason: SkipReason::DslFn(_), .. } => {}
            other => panic!("expected dsl skip, got {other:?}"),
        }
    }
}
