//! Per-source detection-info → `MatchSpec` lowering.
//!
//! Phase 2a covers Nikto DSL → MatchSpec losslessly (CODE/BODY/HEADER/COOKIE
//! conjunction → flat `Vec<LeafCond>`).
//!
//! Phase 2b adds **best-effort ZAP lowering** for the rule shapes the
//! current extractor surfaces:
//!   * Rules with `patterns` and no payloads → passive shape: a single GET
//!     `/` step plus a `Body` matcher whose regex is the alternation of
//!     all extracted patterns.
//!   * Rules with `payloads` and `patterns` → active shape: same single GET
//!     step but with a `Payload::FromList` binding feeding `?fuzz={{ZAP}}`,
//!     and the same body-pattern matcher. Phase-2a runner takes the first
//!     payload value only; full per-payload fan-out is a Phase-2b stretch
//!     goal that lives in the runner, not here.
//!   * Rules with payloads-only or neither — left un-lowered. The detection
//!     blob stays in `detection_json` for future iterations.
//!
//! Burp BCheck lowering remains Phase 2c (separate parser for the
//! `given/if/then` DSL).

use anyhow::Result;
use corvex_core::dsl;
use corvex_rules::matcher::{
    Alphabet, LeafCond, MatchSpec, Matcher, Payload, StepId, StepSpec,
};

use crate::normalized::{NormalizedRule, SourceTool};

const DEFAULT_STEP: &str = "r0";

/// Lower a single normalised rule's detection info into a `MatchSpec`.
pub fn try_lower(rule: &NormalizedRule) -> Result<Option<MatchSpec>> {
    match rule.source_tool {
        SourceTool::Nikto => Ok(lower_nikto(rule)),
        SourceTool::Zap => Ok(lower_zap(rule)),
        SourceTool::Burp => Ok(lower_burp(rule)),
    }
}

fn lower_nikto(rule: &NormalizedRule) -> Option<MatchSpec> {
    let uri = rule.uri_template.as_deref().unwrap_or("");
    if uri.is_empty() {
        return None;
    }

    let raw_dsl = rule.detection.get("raw")?.as_str()?.to_string();
    let parsed = dsl::parse(&raw_dsl).ok()?;

    let leaves: Vec<LeafCond> = parsed
        .matchers
        .iter()
        .map(|(matcher, neg)| LeafCond {
            matcher: matcher_to_leaf(matcher),
            negate: *neg,
        })
        .collect();

    if leaves.is_empty() {
        return None;
    }

    let step = StepSpec {
        id: StepId::new(DEFAULT_STEP),
        method: rule
            .http_method
            .clone()
            .unwrap_or_else(|| "GET".to_string()),
        uri: uri.to_string(),
        headers: parse_nikto_headers(rule.request_headers.as_deref().unwrap_or("")),
        body: rule.request_body.clone(),
        payload: None,
        readonly_cookies: false,
    };

    Some(MatchSpec {
        steps: vec![step],
        when: leaves,
    })
}

fn matcher_to_leaf(matcher: &dsl::Matcher) -> Matcher {
    use dsl::Matcher::*;
    let step = StepId::new(DEFAULT_STEP);
    match matcher {
        Code(rx) => Matcher::Status {
            step,
            regex: rx.as_str().to_string(),
        },
        Body(rx) => Matcher::Body {
            step,
            regex: rx.as_str().to_string(),
        },
        Header { name, value } => Matcher::Header {
            step,
            name: name.clone(),
            regex: value.as_str().to_string(),
        },
        Cookie { name, value } => Matcher::Cookie {
            step,
            name: name.clone(),
            regex: value.as_str().to_string(),
        },
    }
}

fn parse_nikto_headers(raw: &str) -> Vec<(String, String)> {
    raw.split('\n')
        .filter_map(|line| {
            let (k, v) = line.split_once(':')?;
            let k = k.trim();
            let v = v.trim();
            if k.is_empty() {
                return None;
            }
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

// --- ZAP lowering -----------------------------------------------------------

/// Lower a ZAP rule's `detection_json` into a `MatchSpec` when its shape is
/// portable. Returns `None` for the cases we don't yet handle (rules with
/// neither payloads nor patterns, rules whose patterns include
/// Java-flavoured constructs we'd reject at runtime, etc.).
fn lower_zap(rule: &NormalizedRule) -> Option<MatchSpec> {
    let det = &rule.detection;
    if det.get("kind").and_then(|v| v.as_str()) != Some("zap_metadata") {
        return None;
    }

    let payloads: Vec<String> = det
        .get("payloads")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let patterns: Vec<String> = det
        .get("patterns")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Filter patterns to ones the Rust regex engine can actually compile.
    // Java's java.util.regex supports backreferences and lookaround, both of
    // which the `regex` crate (RE2) rejects. Drop unsupported patterns and
    // — if nothing survives — refuse to lower.
    let supported: Vec<String> = patterns
        .into_iter()
        .filter(|p| regex::Regex::new(p).is_ok())
        .collect();

    if supported.is_empty() {
        return None;
    }

    // Combine surviving patterns into one alternation. Capture-group prefixes
    // would inflate match-counts; we wrap each pattern in a non-capturing
    // group to keep the alternation flat.
    let body_regex = if supported.len() == 1 {
        supported[0].clone()
    } else {
        let parts: Vec<String> = supported
            .iter()
            .map(|p| format!("(?:{p})"))
            .collect();
        parts.join("|")
    };

    // Build the request step. Active rules with payloads bind `{{ZAP}}` into
    // a synthetic `?fuzz=` query parameter so the body-pattern matcher has
    // a chance to fire on a target that echoes the payload.
    let (uri, payload) = if payloads.is_empty() {
        ("/".to_string(), None)
    } else {
        // Cap the binding list — the runner takes the first value in 2a;
        // capping at 16 keeps the persisted JSON bounded.
        let values: Vec<String> = payloads.into_iter().take(16).collect();
        (
            "/?fuzz={{ZAP}}".to_string(),
            Some(Payload::FromList {
                values,
                bind: "ZAP".to_string(),
            }),
        )
    };

    let _ = Alphabet::AlphaNum; // mark Alphabet imported; only used by
                                // RandomToken which we don't synthesise here

    let step = StepSpec {
        id: StepId::new(DEFAULT_STEP),
        method: "GET".to_string(),
        uri,
        headers: vec![],
        body: None,
        payload,
        readonly_cookies: false,
    };

    Some(MatchSpec {
        steps: vec![step],
        when: vec![LeafCond {
            matcher: Matcher::Body {
                step: StepId::new(DEFAULT_STEP),
                regex: body_regex,
            },
            negate: false,
        }],
    })
}

// --- Burp BCheck lowering ---------------------------------------------------

/// Lower a Burp BCheck rule into a `MatchSpec` when its shape fits one of
/// our supported templates. The BCheck DSL is rich enough that we
/// pattern-match a small subset:
///
///   1. **Passive single-pattern**: `given response then if {latest.response}
///      matches "REGEX" then report issue: ...` → single GET `/` + body
///      matcher.
///   2. **Active literal-path single-request**: `send request called X: ...
///      path: "PATH"; if {X.response.body} matches "REGEX" then report ...`
///      → single GET `<PATH>` + body matcher.
///   3. **Active path-list single-request** (uses `run for each: paths =
///      "/a", "/b"`): same as (2) but URI becomes `{{burp_path}}` with a
///      `Payload::FromList` binding. Phase 2a runner takes the first value
///      only — full fan-out lands in Phase 2c.5.
///
/// Rules with multi-step `send`s, compound `define:` blocks beyond simple
/// path lists, header / status-code predicates without an accompanying body
/// matcher, or any non-`matches`/`in` predicate are left un-lowered. The
/// detection blob stays in `detection_json` for future iterations.
fn lower_burp(rule: &NormalizedRule) -> Option<MatchSpec> {
    let det = &rule.detection;
    if det.get("kind").and_then(|v| v.as_str()) != Some("bcheck") {
        return None;
    }
    let body = det.get("body").and_then(|v| v.as_str())?.to_string();

    if count_send_blocks(&body) > 1 {
        return None; // multi-step → defer to recursive Cond
    }

    // First, try the passive shape: no `send request`, just a `given response`
    // block with a single `matches` predicate.
    if !body.contains("send request called") {
        if let Some(spec) = lower_burp_passive(&body) {
            return Some(spec);
        }
        return None;
    }

    // Otherwise it's an active rule with one `send request`. Extract the
    // path (literal or run-for-each), the predicate, and turn into a step.
    lower_burp_active(&body)
}

fn count_send_blocks(body: &str) -> usize {
    body.lines()
        .filter(|l| {
            let t = l.trim();
            t.starts_with("send request called")
        })
        .count()
}

fn lower_burp_passive(body: &str) -> Option<MatchSpec> {
    // Look for `if {latest.response[.body]} matches "REGEX"` or
    // `if {latest.response[.body]} matches \`REGEX\``. The two BCheck
    // string-literal styles use double-quote and backtick.
    let regex = extract_passive_body_regex(body)?;
    if regex::Regex::new(&regex).is_err() {
        return None;
    }

    let step = StepSpec {
        id: StepId::new(DEFAULT_STEP),
        method: "GET".to_string(),
        uri: "/".to_string(),
        headers: vec![],
        body: None,
        payload: None,
        readonly_cookies: false,
    };
    Some(MatchSpec {
        steps: vec![step],
        when: vec![LeafCond {
            matcher: Matcher::Body {
                step: StepId::new(DEFAULT_STEP),
                regex,
            },
            negate: false,
        }],
    })
}

fn extract_passive_body_regex(body: &str) -> Option<String> {
    // Handles: `if {latest.response} matches "X"` and
    //          `if {latest.response.body} matches "X"`.
    // We're intentionally narrow — anything that strays from this shape
    // (header checks, compound predicates, `not matches`, …) is skipped so
    // the rule lands in `unlowered_reasons_burp_json` rather than producing
    // a wrong MatchSpec.
    for raw in body.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("if ") {
            // Reject compound predicates for this simple template.
            if rest.contains(" and ") || rest.contains(" or ") {
                continue;
            }
            // Match the payload, with `latest.response` or
            // `latest.response.body` either accepted.
            if let Some(reg) = parse_matches_payload(rest, "latest.response")
                .or_else(|| parse_matches_payload(rest, "latest.response.body"))
            {
                return Some(reg);
            }
        }
    }
    None
}

/// Parse `if {SUBJECT} matches "REGEX"` (or backtick-quoted) tail of a line.
fn parse_matches_payload(rest: &str, subject: &str) -> Option<String> {
    let needle = format!("{{{}}} matches ", subject);
    let idx = rest.find(&needle)?;
    let after = &rest[idx + needle.len()..];
    extract_quoted(after)
}

fn extract_quoted(s: &str) -> Option<String> {
    let s = s.trim_start();
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let (quote, body) = match bytes[0] {
        b'"' => (b'"', &s[1..]),
        b'`' => (b'`', &s[1..]),
        _ => return None,
    };
    let mut out = String::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push('\\');
                out.push(next);
            }
            continue;
        }
        if c as u8 == quote {
            return Some(out);
        }
        out.push(c);
    }
    None
}

fn lower_burp_active(body: &str) -> Option<MatchSpec> {
    let send_block = extract_send_block(body)?;
    let send_name = send_block.name.clone();

    // Path: prefer literal, fall back to run-for-each variable resolution.
    let (uri, payload) = match (&send_block.path_literal, &send_block.path_var) {
        (Some(literal), _) => (literal.clone(), None),
        (None, Some(var)) => {
            let values = resolve_path_var(body, var)?;
            (
                "{{burp_path}}".to_string(),
                Some(Payload::FromList {
                    values: values.into_iter().take(16).collect(),
                    bind: "burp_path".to_string(),
                }),
            )
        }
        _ => return None,
    };

    let regex = extract_active_body_regex(body, &send_name)?;
    if regex::Regex::new(&regex).is_err() {
        return None;
    }

    let method = send_block.method.unwrap_or_else(|| "GET".to_string());
    let step = StepSpec {
        id: StepId::new(DEFAULT_STEP),
        method,
        uri,
        headers: vec![],
        body: None,
        payload,
        readonly_cookies: false,
    };
    Some(MatchSpec {
        steps: vec![step],
        when: vec![LeafCond {
            matcher: Matcher::Body {
                step: StepId::new(DEFAULT_STEP),
                regex,
            },
            negate: false,
        }],
    })
}

#[derive(Default)]
struct SendBlock {
    name: String,
    method: Option<String>,
    path_literal: Option<String>,
    path_var: Option<String>,
}

fn extract_send_block(body: &str) -> Option<SendBlock> {
    let mut iter = body.lines().peekable();
    while let Some(line) = iter.next() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("send request called ") {
            let name = rest.trim_end_matches(':').trim().to_string();
            let mut block = SendBlock {
                name,
                ..Default::default()
            };
            // Read indented continuation lines until the indent goes back to 0
            // or until we hit the next top-level statement.
            while let Some(peek) = iter.peek() {
                let pt = peek.trim();
                let leading_ws = peek.len() - peek.trim_start().len();
                if pt.is_empty() {
                    iter.next();
                    continue;
                }
                if leading_ws == 0 {
                    break;
                }
                let inner = iter.next().unwrap();
                if let Some(v) = inner_kv(inner, "method") {
                    block.method = Some(v.trim_matches('"').to_string());
                } else if let Some(v) = inner_kv(inner, "path") {
                    let v = v.trim();
                    if v.starts_with('"') {
                        if let Some(s) = extract_quoted(v) {
                            block.path_literal = Some(s);
                        }
                    } else if let Some(var) = v.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                        block.path_var = Some(var.trim().to_string());
                    }
                }
            }
            return Some(block);
        }
    }
    None
}

fn inner_kv<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let t = line.trim();
    let needle = format!("{key}:");
    if let Some(rest) = t.strip_prefix(&needle) {
        return Some(rest.trim());
    }
    None
}

/// Find a `define:` or `run for each:` variable named `var` and return its
/// quoted-string-list values.
fn resolve_path_var(body: &str, var: &str) -> Option<Vec<String>> {
    let mut iter = body.lines().peekable();
    while let Some(line) = iter.next() {
        let t = line.trim();
        if !(t == "run for each:" || t == "define:") {
            continue;
        }
        // Read indented assignments until indent goes back to 0.
        while let Some(peek) = iter.peek() {
            let pt = peek.trim();
            let leading_ws = peek.len() - peek.trim_start().len();
            if pt.is_empty() {
                iter.next();
                continue;
            }
            if leading_ws == 0 {
                break;
            }
            let inner = iter.next().unwrap();
            let inner_t = inner.trim();
            if inner_t.starts_with('#') {
                continue;
            }
            if let Some((name, value)) = inner_t.split_once('=') {
                if name.trim() == var {
                    let mut out = Vec::new();
                    let mut rest = value;
                    loop {
                        match extract_quoted(rest) {
                            Some(s) => out.push(s),
                            None => break,
                        }
                        // Advance past the consumed quoted string + optional
                        // comma + whitespace.
                        let trimmed = rest.trim_start();
                        let after_open = match trimmed.bytes().next() {
                            Some(b'"') | Some(b'`') => &trimmed[1..],
                            _ => break,
                        };
                        let mut consumed = 1; // for the open quote
                        let mut chars = after_open.chars();
                        while let Some(c) = chars.next() {
                            consumed += c.len_utf8();
                            if c == '\\' {
                                if let Some(n) = chars.next() {
                                    consumed += n.len_utf8();
                                }
                                continue;
                            }
                            if c == '"' || c == '`' {
                                break;
                            }
                        }
                        let after_close = &trimmed[consumed..];
                        let next = after_close.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
                        if next.is_empty() || next.starts_with('#') {
                            break;
                        }
                        rest = next;
                    }
                    if !out.is_empty() {
                        return Some(out);
                    }
                }
            }
        }
    }
    None
}

/// Find an `if {<send_name>.response.body} matches "REGEX"` (or `in` form)
/// predicate in the body and return the regex.
fn extract_active_body_regex(body: &str, send_name: &str) -> Option<String> {
    let body_subject = format!("{send_name}.response.body");
    let response_subject = format!("{send_name}.response");
    for raw in body.lines() {
        let line = raw.trim();
        if !line.starts_with("if ") {
            continue;
        }
        let rest = &line[3..];
        if rest.contains(" and ") || rest.contains(" or ") {
            continue;
        }
        if let Some(reg) = parse_matches_payload(rest, &body_subject)
            .or_else(|| parse_matches_payload(rest, &response_subject))
        {
            return Some(reg);
        }
        // Handle: `if "literal" in {NAME.response.body}` (substring containment)
        if let Some(reg) = parse_in_payload(rest, &body_subject)
            .or_else(|| parse_in_payload(rest, &response_subject))
        {
            return Some(reg);
        }
    }
    None
}

/// Parse `if "literal" in {SUBJECT}` and return a regex-escaped form of the
/// literal so the runtime body matcher fires on substring presence.
fn parse_in_payload(rest: &str, subject: &str) -> Option<String> {
    // Expected shape: `"literal" in {SUBJECT}`
    let after_quote = extract_quoted(rest)?;
    let after_quote_idx = match rest.bytes().next() {
        Some(b'"') => rest[1..].find('"').map(|i| i + 2),
        Some(b'`') => rest[1..].find('`').map(|i| i + 2),
        _ => None,
    }?;
    let after = rest[after_quote_idx..].trim_start();
    let needle = format!("in {{{}}}", subject);
    if !after.starts_with(&needle) {
        return None;
    }
    Some(regex::escape(&after_quote))
}

