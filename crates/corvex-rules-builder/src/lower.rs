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
    Alphabet, CondGraph, CondNode, LeafCond, MatchSpec, Matcher, Payload, StepId, StepSpec,
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
        when_cond: None,
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
        when_cond: None,
    })
}

// --- Burp BCheck lowering ---------------------------------------------------

/// Lower a Burp BCheck rule into a `MatchSpec` when its shape fits a
/// supported single-step template.
///
/// Phase 2c handled body matchers only. Phase 2c.1 (this code) widens
/// coverage by emitting a `LeafCond` per supported predicate kind:
///
///   * `Body`   from `{X.response[.body]} matches "REGEX"` and
///              `"literal" in {X.response[.body]}` predicates.
///   * `Status` from `{X.response.status_code} is "N"` (equality) and
///              `... matches "REGEX"` predicates.
///   * `Header` from `{X.response.headers/NAME} matches "REGEX"` /
///              `... is "VALUE"` / `"literal" in {...}` predicates.
///   * `Cookie` from `{X.response.cookies/NAME} ...` predicates (rare in
///              upstream BChecks but supported for completeness).
///
/// Multiple non-compound `if` lines targeting the same `send` (or
/// `latest.response`) AND-join automatically because `MatchSpec.when` is a
/// flat `Vec<LeafCond>`. This naturally handles:
///
///   * Sequential predicates: `if status is "200" then ... if body matches
///     "X" then report ...` — both LeafConds emitted.
///   * Nested predicates: `if status is "200" then if body matches "X" then
///     report ...` — flattened to AND of two LeafConds.
///   * Single predicate of any kind — emitted as a one-element `Vec`.
///
/// Rules with multi-step `send`s, compound `if A and B`/`if A or B`
/// predicates, or `define:` blocks beyond simple path lists are still left
/// un-lowered (need the recursive `Cond` work to express OR / cross-step
/// deltas).
fn lower_burp(rule: &NormalizedRule) -> Option<MatchSpec> {
    let det = &rule.detection;
    if det.get("kind").and_then(|v| v.as_str()) != Some("bcheck") {
        return None;
    }
    let body = det.get("body").and_then(|v| v.as_str())?.to_string();

    // Reject rules whose predicates encode cross-step relationships we
    // don't yet lower. `{a} differs from {b}` and `{a.response.X} is
    // {b.response.X}` need a `CondNode::HeaderDiff` / `BodyLenDeltaPct` /
    // similar with a real semantic mapping; the per-step lowerer below
    // would silently produce a wrong MatchSpec that fires when each
    // step's predicates are independently satisfied.
    if has_cross_step_comparison(&body) {
        return None;
    }

    let send_count = count_send_blocks(&body);

    // Passive shape: no `send request` blocks at all — just a `given
    // response` block with predicates against `latest.response`.
    if send_count == 0 {
        return lower_burp_passive(&body);
    }

    // Single-step active rule (the Phase 2c.1 path). Stays unchanged for
    // backward-compat with existing lowered rules.
    if send_count == 1 {
        return lower_burp_active(&body);
    }

    // Phase 2c.3: multi-step rules with independent per-step predicates.
    // Each `send request called X:` becomes its own `StepSpec`, and every
    // `if` predicate referencing `X.response.*` produces a LeafCond bound
    // to that step.
    lower_burp_multistep(&body)
}

/// Detect predicate shapes that compare two responses directly. Any of
/// these means the rule's logic depends on cross-step relationships we
/// don't yet lower into the explicit `CondNode::*Delta` / `HeaderDiff`
/// variants.
fn has_cross_step_comparison(body: &str) -> bool {
    body.lines().any(|raw| {
        let t = raw.trim();
        if !t.starts_with("if ") && !t.contains(" and ") && !t.contains(" or ") {
            return false;
        }
        // `differs from` and `is the same as` are direct cross-step ops.
        if t.contains(" differs from ") || t.contains(" is the same as ") {
            return true;
        }
        // `{X.response.X} is {Y.response.X}` or `... matches {Y.response.X}`
        // — RHS is a brace-delimited reference to another send's response.
        let mut chars = t.chars().peekable();
        let mut had_op = false;
        while let Some(c) = chars.next() {
            if c == ' ' && (chars.clone().take(8).collect::<String>().starts_with("is {") ||
                             chars.clone().take(12).collect::<String>().starts_with("matches {")) {
                // Look ahead: open-brace already past; if the brace-delimited
                // value contains `.response.`, it's a cross-step reference.
                let tail: String = chars.clone().collect();
                if let Some(open) = tail.find('{') {
                    if let Some(close_rel) = tail[open + 1..].find('}') {
                        let inner = &tail[open + 1..open + 1 + close_rel];
                        if inner.contains(".response.") {
                            return true;
                        }
                    }
                }
                had_op = true;
            }
        }
        let _ = had_op;
        false
    })
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
    let extracted = extract_burp_predicates(body, "latest");
    if extracted.is_empty() {
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
        when: extracted.flat_leaves,
        when_cond: extracted.cond_graph,
    })
}

/// What `extract_burp_predicates` returns: a flat AND-list of LeafConds for
/// the simple shape (Phase 2c.1) plus an optional `CondGraph` for compound
/// predicates (Phase 2c.2). The runtime AND-joins both — a rule can have
/// both flat and recursive sub-conditions and the evaluator handles them
/// uniformly.
#[derive(Default)]
struct BurpPredicates {
    flat_leaves: Vec<LeafCond>,
    cond_graph: Option<CondGraph>,
}

impl BurpPredicates {
    fn is_empty(&self) -> bool {
        self.flat_leaves.is_empty() && self.cond_graph.is_none()
    }
}

/// Top-level predicate extractor: scans every `if ...` line in the body,
/// classifies it, and accumulates either a `LeafCond` (simple shape) or a
/// `CondGraph` sub-tree (compound `if A and B then ...` / `if A or B then
/// ...`). Multiple `if` lines AND-join.
fn extract_burp_predicates(body: &str, send_name: &str) -> BurpPredicates {
    let mut out = BurpPredicates::default();
    let mut seen = std::collections::HashSet::new();
    let mut compound_subtrees: Vec<CondGraph> = Vec::new();

    for raw in body.lines() {
        let line = raw.trim();
        let rest = match line.strip_prefix("if ") {
            Some(r) => r,
            None => continue,
        };
        // Compound predicate: try to lower into a CondGraph node. If the
        // recogniser fails (rare structural mix of `and` and `or`, or
        // unrecognised subjects), skip the line silently — Phase 2c.3+ may
        // pick it up.
        if rest.contains(" and ") || rest.contains(" or ") {
            if let Some(graph) = parse_compound_predicate(rest, send_name) {
                compound_subtrees.push(graph);
            }
            continue;
        }
        // Simple predicate: try header-with-name first (more specific),
        // then the four scalar subjects.
        if let Some(leaf) = parse_header_predicate(rest, send_name) {
            if seen.insert(leaf_key(&leaf)) {
                out.flat_leaves.push(leaf);
            }
            continue;
        }
        let subjects: [(String, MatcherKind); 4] = [
            (
                format!("{send_name}.response.status_code"),
                MatcherKind::Status,
            ),
            (format!("{send_name}.response.body"), MatcherKind::Body),
            (format!("{send_name}.response"), MatcherKind::Body),
            (
                format!("{send_name}.response.headers"),
                MatcherKind::HeadersBucket,
            ),
        ];
        for (subject, kind) in &subjects {
            if let Some(leaf) = parse_simple_predicate(rest, subject, *kind) {
                if seen.insert(leaf_key(&leaf)) {
                    out.flat_leaves.push(leaf);
                }
                break;
            }
        }
    }

    out.cond_graph = combine_compound_subtrees(compound_subtrees);
    out
}

/// Parse a single compound predicate like `{X.response.status_code} is "200"
/// and {X.response.body} matches "REGEX"` into a `CondGraph`. Mixing `and`
/// and `or` in one expression is treated as a parse failure — BCheck
/// authors don't often do it, and recognising mixed precedence cleanly
/// would require a real expression parser. Pure-AND and pure-OR shapes
/// cover the bulk of the corpus.
fn parse_compound_predicate(rest: &str, send_name: &str) -> Option<CondGraph> {
    let has_and = rest.contains(" and ");
    let has_or = rest.contains(" or ");
    if has_and && has_or {
        return None;
    }
    let (sep, combinator): (&str, fn(Vec<u32>) -> CondNode) = if has_and {
        (
            " and ",
            (|c| CondNode::All { children: c }) as fn(Vec<u32>) -> CondNode,
        )
    } else {
        (
            " or ",
            (|c| CondNode::Any { children: c }) as fn(Vec<u32>) -> CondNode,
        )
    };
    // `then` (and any trailing tokens like `then end if`) marks the end of
    // the predicate. Cut there before splitting on the combinator so we
    // don't consume body text.
    let predicate_part = match rest.find(" then") {
        Some(idx) => &rest[..idx],
        None => rest,
    };
    let parts: Vec<&str> = predicate_part.split(sep).collect();
    if parts.len() < 2 {
        return None;
    }
    let mut nodes: Vec<CondNode> = Vec::with_capacity(parts.len() + 1);
    let mut child_indices: Vec<u32> = Vec::with_capacity(parts.len());
    for part in parts {
        let leaf = parse_atomic_predicate(part.trim(), send_name)?;
        nodes.push(CondNode::Leaf(leaf));
        child_indices.push((nodes.len() - 1) as u32);
    }
    nodes.push(combinator(child_indices));
    let root = (nodes.len() - 1) as u32;
    Some(CondGraph { root, nodes })
}

/// Parse one atomic predicate — i.e. one operand of an `and` / `or`
/// expression. Same shape recognisers as `parse_simple_predicate` /
/// `parse_header_predicate` but without the leading `if `.
fn parse_atomic_predicate(piece: &str, send_name: &str) -> Option<LeafCond> {
    let piece = piece.trim();
    if let Some(leaf) = parse_header_predicate(piece, send_name) {
        return Some(leaf);
    }
    let subjects: [(String, MatcherKind); 4] = [
        (
            format!("{send_name}.response.status_code"),
            MatcherKind::Status,
        ),
        (format!("{send_name}.response.body"), MatcherKind::Body),
        (format!("{send_name}.response"), MatcherKind::Body),
        (
            format!("{send_name}.response.headers"),
            MatcherKind::HeadersBucket,
        ),
    ];
    for (subject, kind) in &subjects {
        if let Some(leaf) = parse_simple_predicate(piece, subject, *kind) {
            return Some(leaf);
        }
    }
    None
}

/// Combine multiple `if` lines worth of compound sub-trees into one
/// `CondGraph` rooted in an `All` node (since multiple top-level `if`
/// blocks AND-join semantically). Returns `None` when there are no
/// compound sub-trees.
fn combine_compound_subtrees(subtrees: Vec<CondGraph>) -> Option<CondGraph> {
    match subtrees.len() {
        0 => None,
        1 => Some(subtrees.into_iter().next().unwrap()),
        _ => {
            // Stitch every sub-tree into one larger arena. Each sub-tree's
            // node indices are offset by the running `nodes.len()` so the
            // final root's children point at each sub-tree's offset root.
            let mut nodes: Vec<CondNode> = Vec::new();
            let mut roots: Vec<u32> = Vec::new();
            for sub in subtrees {
                let offset = nodes.len() as u32;
                roots.push(sub.root + offset);
                for node in sub.nodes {
                    nodes.push(reindex_node(node, offset));
                }
            }
            nodes.push(CondNode::All { children: roots });
            let root = (nodes.len() - 1) as u32;
            Some(CondGraph { root, nodes })
        }
    }
}

fn reindex_node(node: CondNode, offset: u32) -> CondNode {
    match node {
        CondNode::Leaf(l) => CondNode::Leaf(l),
        CondNode::All { children } => CondNode::All {
            children: children.into_iter().map(|c| c + offset).collect(),
        },
        CondNode::Any { children } => CondNode::Any {
            children: children.into_iter().map(|c| c + offset).collect(),
        },
        CondNode::Not { child } => CondNode::Not {
            child: child + offset,
        },
        // Cross-step variants reference StepIds, not arena indices, so the
        // offset-shift only matters for inner-arena children — these have
        // none. Pass through unchanged.
        other @ (CondNode::StatusDelta { .. }
        | CondNode::BodyLenDeltaPct { .. }
        | CondNode::ElapsedDeltaMs { .. }
        | CondNode::HeaderDiff { .. }) => other,
    }
}

/// Walk every `if ...` line in the body and turn each non-compound
/// predicate that targets `<send_name>.response[...]` (or `latest.response`)
/// into a `LeafCond`. Kept for backwards-compat / external callers — the
/// new entry point is `extract_burp_predicates` which also handles compound
/// predicates.
#[allow(dead_code)]
fn extract_burp_leaves(body: &str, send_name: &str) -> Vec<LeafCond> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let subjects: [(String, MatcherKind); 4] = [
        (
            format!("{send_name}.response.status_code"),
            MatcherKind::Status,
        ),
        (format!("{send_name}.response.body"), MatcherKind::Body),
        (format!("{send_name}.response"), MatcherKind::Body),
        (format!("{send_name}.response.headers"), MatcherKind::HeadersBucket),
    ];

    for raw in body.lines() {
        let line = raw.trim();
        let rest = match line.strip_prefix("if ") {
            Some(r) => r,
            None => continue,
        };
        // Compound predicates need the recursive Cond — skip cleanly so the
        // rule lands as un-lowered rather than producing a wrong MatchSpec.
        if rest.contains(" and ") || rest.contains(" or ") {
            continue;
        }
        // Try header-with-name first because it's a more specific pattern
        // than the generic header-bucket subject. `headers/Name` lives
        // inside the `{...}` braces.
        if let Some(leaf) = parse_header_predicate(rest, send_name) {
            if seen.insert(leaf_key(&leaf)) {
                out.push(leaf);
            }
            continue;
        }
        for (subject, kind) in &subjects {
            if let Some(leaf) = parse_simple_predicate(rest, subject, *kind) {
                if seen.insert(leaf_key(&leaf)) {
                    out.push(leaf);
                }
                break;
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatcherKind {
    Status,
    Body,
    /// `{X.response.headers/NAME}` — name carried separately on the leaf.
    Header,
    /// Generic `{X.response.headers}` (no `/Name`) — represented at parse
    /// time only; we don't currently emit a LeafCond for it because our
    /// `Matcher::Header` requires a specific name. Skipped silently.
    HeadersBucket,
}

/// `if {SUBJECT} OP "VALUE"` or `if "literal" in {SUBJECT}` for the simple
/// (non-header-name) subjects. Returns the lowered LeafCond when the line
/// matches the expected shape and produces a regex the runtime can compile.
fn parse_simple_predicate(rest: &str, subject: &str, kind: MatcherKind) -> Option<LeafCond> {
    // `{SUBJECT} matches "REGEX"` — body/status as regex
    if let Some(regex) = parse_matches_payload(rest, subject) {
        return build_leaf(kind, None, regex);
    }
    // `{SUBJECT} is "VALUE"` — equality. Body equality is unusual but legal;
    // status equality is the common case (`status_code is "200"`).
    if let Some(value) = parse_is_payload(rest, subject) {
        let regex = format!("^{}$", regex::escape(&value));
        return build_leaf(kind, None, regex);
    }
    // `{SUBJECT} contains "literal"` — equivalent to body/header substring.
    if let Some(value) = parse_op_payload(rest, subject, "contains") {
        return build_leaf(kind, None, regex::escape(&value));
    }
    // `"literal" in {SUBJECT}` — the inverted-syntax form of the above.
    if let Some(value) = parse_in_payload_value(rest, subject) {
        return build_leaf(kind, None, regex::escape(&value));
    }
    None
}

/// `if {<send>.response.headers/HEADER_NAME} OP "..."` predicates.
fn parse_header_predicate(rest: &str, send_name: &str) -> Option<LeafCond> {
    let prefix_resp = format!("{{{send_name}.response.headers/");
    let prefix_latest = "{latest.response.headers/";
    let (header_name, after_brace) = parse_header_subject(rest, &prefix_resp)
        .or_else(|| parse_header_subject(rest, prefix_latest))?;
    // After the closing `}` we expect ` matches "X"`, ` is "X"`, ` contains "X"`.
    let trimmed = after_brace.trim_start();
    if let Some(regex) = trimmed
        .strip_prefix("matches ")
        .and_then(|r| extract_quoted(r))
    {
        return build_leaf(MatcherKind::Header, Some(header_name), regex);
    }
    if let Some(value) = trimmed
        .strip_prefix("is ")
        .and_then(|r| extract_quoted(r))
    {
        return build_leaf(
            MatcherKind::Header,
            Some(header_name),
            format!("^{}$", regex::escape(&value)),
        );
    }
    if let Some(value) = trimmed
        .strip_prefix("contains ")
        .and_then(|r| extract_quoted(r))
    {
        return build_leaf(MatcherKind::Header, Some(header_name), regex::escape(&value));
    }
    None
}

/// Extract `HEADER_NAME` from `if "..." in {<prefix>HEADER_NAME}` or from
/// `if {<prefix>HEADER_NAME} OP ...`. Returns the name plus the suffix
/// after the closing brace so the caller can parse the operator.
fn parse_header_subject<'a>(rest: &'a str, prefix: &str) -> Option<(String, &'a str)> {
    let idx = rest.find(prefix)?;
    let inner_start = idx + prefix.len();
    let close = rest[inner_start..].find('}')?;
    let header_name = rest[inner_start..inner_start + close]
        .trim()
        .to_string();
    if header_name.is_empty() {
        return None;
    }
    let after = &rest[inner_start + close + 1..];
    Some((header_name, after))
}

fn build_leaf(kind: MatcherKind, header_name: Option<String>, regex: String) -> Option<LeafCond> {
    if regex.is_empty() {
        return None;
    }
    if regex::Regex::new(&regex).is_err() {
        return None;
    }
    let step = StepId::new(DEFAULT_STEP);
    let matcher = match kind {
        MatcherKind::Status => Matcher::Status { step, regex },
        MatcherKind::Body => Matcher::Body { step, regex },
        MatcherKind::Header => Matcher::Header {
            step,
            name: header_name?,
            regex,
        },
        // Generic `headers` bucket without a name has no equivalent in our
        // matcher set today.
        MatcherKind::HeadersBucket => return None,
    };
    Some(LeafCond {
        matcher,
        negate: false,
    })
}

/// Stable key used to suppress accidental duplicate emissions when two
/// `if` lines target the same subject with the same regex (legal but
/// noisy).
fn leaf_key(leaf: &LeafCond) -> String {
    match &leaf.matcher {
        Matcher::Status { regex, .. } => format!("status::{regex}"),
        Matcher::Body { regex, .. } => format!("body::{regex}"),
        Matcher::Header { name, regex, .. } => format!("header::{name}::{regex}"),
        Matcher::Cookie { name, regex, .. } => format!("cookie::{name}::{regex}"),
    }
}

/// Parse `if {SUBJECT} matches "REGEX"` (or backtick-quoted) tail of a line.
fn parse_matches_payload(rest: &str, subject: &str) -> Option<String> {
    parse_op_payload(rest, subject, "matches")
}

/// Parse `if {SUBJECT} is "VALUE"` tail of a line.
fn parse_is_payload(rest: &str, subject: &str) -> Option<String> {
    parse_op_payload(rest, subject, "is")
}

/// Generic `if {SUBJECT} <op> "ARG"` parser. Returns the quoted argument.
fn parse_op_payload(rest: &str, subject: &str, op: &str) -> Option<String> {
    let needle = format!("{{{}}} {} ", subject, op);
    let idx = rest.find(&needle)?;
    let after = &rest[idx + needle.len()..];
    extract_quoted(after)
}

/// Parse `"literal" in {SUBJECT}` and return the literal (unescaped).
fn parse_in_payload_value(rest: &str, subject: &str) -> Option<String> {
    let (literal, consumed) = extract_quoted_with_len(rest)?;
    let after = rest[consumed..].trim_start();
    let needle = format!("in {{{}}}", subject);
    if !after.starts_with(&needle) {
        return None;
    }
    Some(literal)
}

fn extract_quoted(s: &str) -> Option<String> {
    extract_quoted_with_len(s).map(|(v, _)| v)
}

/// Same as `extract_quoted` but additionally returns the byte length of
/// the consumed prefix (the open quote, the body, and the close quote)
/// relative to the **trimmed** string. Callers that need to continue
/// parsing after the literal use this instead of doing a naive
/// `find('"')` which gets confused by escaped quotes inside the body
/// (e.g. `"\"type\":\"app\""`).
fn extract_quoted_with_len(s: &str) -> Option<(String, usize)> {
    let trimmed = s.trim_start();
    let lead = s.len() - trimmed.len();
    let bytes = trimmed.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let quote = match bytes[0] {
        b'"' => b'"',
        b'`' => b'`',
        _ => return None,
    };
    let body = &trimmed[1..];
    let mut out = String::new();
    let mut consumed = 1; // the opening quote
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        consumed += c.len_utf8();
        if c == '\\' {
            if let Some(next) = chars.next() {
                consumed += next.len_utf8();
                out.push('\\');
                out.push(next);
            }
            continue;
        }
        if c as u8 == quote {
            return Some((out, lead + consumed));
        }
        out.push(c);
    }
    None
}

/// Lower a multi-step BCheck (≥2 `send request called`) into a
/// multi-step `MatchSpec`. Every send becomes its own `StepSpec` keyed by
/// its BCheck name; every `if` predicate referencing
/// `<send_name>.response.*` produces a LeafCond bound to that step.
///
/// Rules with cross-step `differs from` / `is {OTHER.response.X}` were
/// already filtered out by `has_cross_step_comparison` before we got
/// here.
fn lower_burp_multistep(body: &str) -> Option<MatchSpec> {
    let sends = extract_all_send_blocks(body);
    if sends.len() < 2 {
        tracing::debug!(target: "burp_lower", "multi-step: <2 sends extracted ({} found)", sends.len());
        return None;
    }

    let mut steps: Vec<StepSpec> = Vec::with_capacity(sends.len());
    let mut all_leaves: Vec<LeafCond> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut compound_subtrees: Vec<CondGraph> = Vec::new();

    for send in &sends {
        // Each send gets its own payload-bind name so multi-step rules with
        // different per-step paths don't trample each other's binding.
        let bind_name = format!("burp_path_{}", send.name);
        // Path / payload resolution mirrors the single-step active path.
        let (uri, payload) = match (&send.path_literal, &send.path_var) {
            (Some(literal), _) => (literal.clone(), None),
            (None, Some(var)) => match resolve_path_var(body, var) {
                Some(values) => (
                    format!("{{{{{}}}}}", bind_name),
                    Some(Payload::FromList {
                        values: values.into_iter().take(16).collect(),
                        bind: bind_name,
                    }),
                ),
                None => {
                    tracing::debug!(
                        target: "burp_lower",
                        "multi-step: resolve_path_var({}) for send `{}` failed",
                        var,
                        send.name
                    );
                    return None;
                }
            },
            _ => {
                tracing::debug!(
                    target: "burp_lower",
                    "multi-step: send `{}` has no path",
                    send.name
                );
                return None;
            }
        };

        let method = send
            .method
            .clone()
            .unwrap_or_else(|| "GET".to_string());
        steps.push(StepSpec {
            id: StepId::new(send.name.clone()),
            method,
            uri,
            headers: vec![],
            body: None,
            payload,
            readonly_cookies: false,
        });

        // Each send's predicates contribute their leaves / sub-trees,
        // bound to the send's StepId. We retarget the matchers' `step`
        // fields after extraction because `extract_burp_predicates` always
        // emits `DEFAULT_STEP` ("r0").
        let extracted = extract_burp_predicates(body, &send.name);
        for mut leaf in extracted.flat_leaves {
            retarget_leaf(&mut leaf, &send.name);
            if seen.insert(leaf_key(&leaf)) {
                all_leaves.push(leaf);
            }
        }
        if let Some(mut sub) = extracted.cond_graph {
            retarget_graph(&mut sub, &send.name);
            compound_subtrees.push(sub);
        }
    }

    // Reject rules where no send produced any predicate — multi-step rules
    // with zero predicate bindings would fire on every response.
    if all_leaves.is_empty() && compound_subtrees.is_empty() {
        return None;
    }

    let when_cond = combine_compound_subtrees(compound_subtrees);

    Some(MatchSpec {
        steps,
        when: all_leaves,
        when_cond,
    })
}

/// Walk every `send request called X:` block in the body, returning each
/// send's metadata in order.
///
/// BCheck files commonly nest sends under a `given host then` block, so the
/// inner loop can't bail on column-0 dedent (everything is indented). It
/// instead consumes lines until the next `send request called` statement
/// or the end of file. Method / path lines anywhere in that span belong to
/// the current send; structural keywords (`if`, `report`, `end if`, …)
/// are silently skipped — they're parsed by separate helpers later.
fn extract_all_send_blocks(body: &str) -> Vec<SendBlock> {
    let mut out = Vec::new();
    let mut current: Option<SendBlock> = None;

    for line in body.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("send request called ") {
            // Flush whatever we were building.
            if let Some(prev) = current.take() {
                out.push(prev);
            }
            let name = rest.trim_end_matches(':').trim().to_string();
            current = Some(SendBlock {
                name,
                ..Default::default()
            });
            continue;
        }
        let Some(block) = current.as_mut() else {
            continue; // pre-first-send chatter — metadata, define, etc.
        };
        if let Some(v) = inner_kv(line, "method") {
            block.method = Some(v.trim_matches('"').to_string());
        } else if let Some(v) = inner_kv(line, "path") {
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
    if let Some(last) = current.take() {
        out.push(last);
    }
    out
}

/// Rewrite a `LeafCond`'s matcher to reference a specific step id rather
/// than the default `r0` `extract_burp_predicates` emits.
fn retarget_leaf(leaf: &mut LeafCond, step_name: &str) {
    let step = StepId::new(step_name);
    leaf.matcher = match std::mem::replace(
        &mut leaf.matcher,
        Matcher::Body {
            step: StepId::new(""),
            regex: String::new(),
        },
    ) {
        Matcher::Status { regex, .. } => Matcher::Status { step, regex },
        Matcher::Body { regex, .. } => Matcher::Body { step, regex },
        Matcher::Header { name, regex, .. } => Matcher::Header { step, name, regex },
        Matcher::Cookie { name, regex, .. } => Matcher::Cookie { step, name, regex },
    };
}

/// Same as `retarget_leaf`, but for every leaf inside a `CondGraph`.
fn retarget_graph(graph: &mut CondGraph, step_name: &str) {
    for node in &mut graph.nodes {
        if let CondNode::Leaf(leaf) = node {
            retarget_leaf(leaf, step_name);
        }
    }
}

fn lower_burp_active(body: &str) -> Option<MatchSpec> {
    let send_block = extract_send_block(body)?;
    let send_name = send_block.name.clone();

    let extracted = extract_burp_predicates(body, &send_name);
    if extracted.is_empty() {
        return None;
    }

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
        when: extracted.flat_leaves,
        when_cond: extracted.cond_graph,
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


